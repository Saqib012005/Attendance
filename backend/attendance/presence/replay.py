"""Replay defence: one piece of evidence may be counted exactly once.

A signature proves who made a proof. It says nothing about how many times that
proof has been submitted, and nothing about when it was made - so a valid,
correctly signed proof is still worthless as evidence until three questions have
been answered against server-held state.

**Has this exact proof been seen?** Canonical encoding gives every proof exactly
one byte string and therefore one digest (`codec.decode` re-encodes and compares
for precisely this reason). A repeat digest is normally a client retrying a sync
it could not confirm, which is why `DUPLICATE_PROOF` is the one code here a caller
should answer idempotently rather than treat as an attack.

**Has this device used this nonce before?** A resubmission with one field edited
has a different digest, so the digest check alone does not catch it. The nonce is
scoped to the device, not to the deployment: a globally unique nonce would let one
handset burn nonces another handset might later choose.

**Could this proof have been made when it claims?** This is where §39 bites. A
proof carries `captured_at`, and that field is a client claim: attacker-controlled,
signed, therefore attributable, and never authoritative. The authoritative time
comes from the challenge instead - a challenge for step *n* cannot exist before
step *n* began, because producing its value needs an epoch key the handset does
not hold. So the queue age this module bounds is `received_at - step_start`, and
`captured_at` is compared against that only to produce *signals* for fusion.
Signals never reject on their own; they are evidence that a device's own account
of itself does not add up.

Nothing here reads a clock and nothing here touches the database. `received_at` is
passed in, and persistence is a `Ledger` the caller supplies - an in-memory one
for tests and offline tooling, a table-backed one once the presence models land.
`record` is the authority for uniqueness, not the checks that precede it: in a
real deployment two proofs can arrive concurrently, and the only thing that can
settle that is the write itself.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from threading import Lock
from typing import Dict, Optional, Tuple

from . import challenge as challenge_mod
from . import codec, config

SECONDS_PER_HOUR = 3600

# Length of the proof nonce, taken from the schema rather than restated, so a
# change to the wire format cannot leave a stale constant behind here.
NONCE_LEN = codec.ATTENDANCE_PROOF.fields[
    codec.ATTENDANCE_PROOF.index("nonce")
].size

# Likewise measured rather than declared. A digest is a proof's identity in this
# ledger, so one of the wrong length is not a near-miss to be tolerated - it is a
# caller that computed identity some other way, and two proofs whose identities
# were computed differently cannot be compared at all.
DIGEST_LEN = len(codec.digest_bytes(b""))

# --- Reason codes: hard rejects. Every one of these fails a proof closed. -----

DUPLICATE_PROOF = "replay_duplicate_proof"
NONCE_REUSED = "replay_nonce_reused"
TOO_OLD = "replay_too_old"
STEP_REGRESSION = "replay_step_regression"
STEP_NOT_YET_ISSUED = "replay_step_not_yet_issued"
MALFORMED = "replay_malformed"

REASON_CODES = frozenset({
    DUPLICATE_PROOF,
    NONCE_REUSED,
    TOO_OLD,
    STEP_REGRESSION,
    STEP_NOT_YET_ISSUED,
    MALFORMED,
})

# --- Signals: recorded, never fatal on their own. -----------------------------
#
# A signal is the client's account of itself disagreeing with what the server can
# derive. On its own each has innocent explanations - a wrong device clock, a slow
# scan - so none of them rejects anything. They travel to fusion as evidence and
# they travel to the audit trail as fact.

SIGNAL_FUTURE_CLAIM = "signal_capture_claim_ahead_of_server"
SIGNAL_CLAIM_PREDATES_CHALLENGE = "signal_capture_claim_predates_challenge"

SIGNALS = frozenset({
    SIGNAL_FUTURE_CLAIM,
    SIGNAL_CLAIM_PREDATES_CHALLENGE,
})

# There is deliberately no "queued a long time" signal. Every candidate for one
# needed a fraction of the offline allowance that no artifact declares, and an
# undeclared fraction is exactly what the config registry exists to refuse. The
# receipt carries `queued_seconds` as a number instead, so fusion can weigh the
# fact without anyone inventing a boundary for it here.


class ReplayError(Exception):
    """A proof failed replay defence. `code` is one of REASON_CODES."""

    def __init__(self, code: str, message: str):
        if code not in REASON_CODES:
            raise AssertionError("undeclared replay reason code %r" % (code,))
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Bounds:
    """The retention and staleness numbers, read once per operation.

    Same discipline as `challenge.Timing`: one read of the active artifact per
    operation, so a staged rollout cannot change a bound between the check and
    the write, and `version` travels into whatever decision this produces.
    """

    max_offline_hours: int
    nonce_retention_hours: int
    max_future_skew_seconds: int
    clock_skew_seconds: int
    version: str

    @classmethod
    def active(cls) -> "Bounds":
        return cls.from_artifact(config.active())

    @classmethod
    def from_artifact(cls, a: config.Artifact) -> "Bounds":
        """One named artifact's bounds. Same reason as `challenge.Timing`.

        The offline allowance in particular must come from the session's own
        artifact: shortening it after a lesson would retroactively expire proofs
        that were inside the window when they were built.
        """
        return cls(
            max_offline_hours=a["proof.max_offline_hours"],
            nonce_retention_hours=a["proof.nonce_retention_hours"],
            max_future_skew_seconds=a["proof.max_future_skew_seconds"],
            clock_skew_seconds=a["challenge.clock_skew_seconds"],
            version=a.version,
        )

    @property
    def max_offline_seconds(self) -> int:
        return self.max_offline_hours * SECONDS_PER_HOUR

    @property
    def nonce_retention_seconds(self) -> int:
        return self.nonce_retention_hours * SECONDS_PER_HOUR


def _bounds(bounds: Optional[Bounds]) -> Bounds:
    return Bounds.active() if bounds is None else bounds


@dataclass(frozen=True)
class Entry:
    """One proof, as the ledger remembers it.

    Deliberately not the proof: a digest, the device that signed it, its nonce and
    the step it referenced are everything replay defence needs, and keeping the
    body out means the ledger can be pruned on schedule without deciding what to
    do about the evidence inside it.
    """

    digest: bytes
    session_id: bytes
    device_key_id: bytes
    nonce: bytes
    step: int
    received_at: int


@dataclass(frozen=True)
class Receipt:
    """What was recorded, and what about it is worth passing on.

    `queued_seconds` is server-derived - receipt time minus the step the challenge
    belongs to - so it is a fact rather than a claim. `signals` are the claims
    that did not line up with it.
    """

    entry: Entry
    queued_seconds: int
    signals: Tuple[str, ...]
    config_version: str

    def __post_init__(self):
        for signal in self.signals:
            if signal not in SIGNALS:
                raise AssertionError("undeclared replay signal %r" % (signal,))


class Ledger(ABC):
    """Server-held memory of proofs already seen.

    Two responsibilities, and the second is the one that matters: answer the cheap
    questions, and be the place where uniqueness is finally enforced. `record`
    must raise rather than overwrite, because a check followed by a write is not
    atomic and concurrent submission of the same proof is the ordinary case, not
    the exotic one.
    """

    @abstractmethod
    def seen_digest(self, digest: bytes) -> Optional[Entry]:
        """The entry with this digest, if it is remembered."""

    @abstractmethod
    def seen_nonce(self, device_key_id: bytes, nonce: bytes) -> Optional[Entry]:
        """The entry where this device already used this nonce, if any."""

    @abstractmethod
    def highest_step(self, session_id: bytes, device_key_id: bytes) -> Optional[int]:
        """The furthest step this device has already had accepted this session."""

    @abstractmethod
    def record(self, entry: Entry) -> None:
        """Persist, or raise ReplayError. The authority on uniqueness."""

    @abstractmethod
    def prune(self, before: int) -> int:
        """Forget entries received before `before`. Returns how many."""


class MemoryLedger(Ledger):
    """An in-process ledger, for tests, the adversarial lab and offline tooling.

    Lock-guarded so `record` is genuinely the serialisation point even when a test
    submits concurrently. It is not a deployment target: nothing survives a
    restart, and a restart would therefore forget every nonce - which is exactly
    the replay window the retention bound exists to close.
    """

    def __init__(self):
        self._lock = Lock()
        self._by_digest: Dict[bytes, Entry] = {}
        self._by_nonce: Dict[Tuple[bytes, bytes], Entry] = {}
        self._high: Dict[Tuple[bytes, bytes], int] = {}

    def seen_digest(self, digest: bytes) -> Optional[Entry]:
        return self._by_digest.get(bytes(digest))

    def seen_nonce(self, device_key_id: bytes, nonce: bytes) -> Optional[Entry]:
        return self._by_nonce.get((bytes(device_key_id), bytes(nonce)))

    def highest_step(self, session_id: bytes, device_key_id: bytes) -> Optional[int]:
        return self._high.get((bytes(session_id), bytes(device_key_id)))

    def record(self, entry: Entry) -> None:
        with self._lock:
            if entry.digest in self._by_digest:
                raise ReplayError(
                    DUPLICATE_PROOF,
                    "a proof with digest %s is already recorded" % entry.digest.hex(),
                )
            nonce_key = (entry.device_key_id, entry.nonce)
            if nonce_key in self._by_nonce:
                raise ReplayError(
                    NONCE_REUSED,
                    "device %s has already submitted a proof with this nonce"
                    % entry.device_key_id.hex(),
                )
            self._by_digest[entry.digest] = entry
            self._by_nonce[nonce_key] = entry
            high_key = (entry.session_id, entry.device_key_id)
            previous = self._high.get(high_key)
            if previous is None or entry.step > previous:
                self._high[high_key] = entry.step

    def prune(self, before: int) -> int:
        with self._lock:
            stale = [e for e in self._by_digest.values() if e.received_at < before]
            for entry in stale:
                self._by_digest.pop(entry.digest, None)
                self._by_nonce.pop((entry.device_key_id, entry.nonce), None)
            # High-water marks are not pruned. They are one small integer per
            # (session, device) and a session is finite, while forgetting one
            # would re-open the regression it exists to refuse.
            return len(stale)

    def __len__(self) -> int:
        return len(self._by_digest)


# --- Policy ------------------------------------------------------------------

def _check_shape(
    digest: bytes, session_id: bytes, device_key_id: bytes, nonce: bytes, step: int
) -> None:
    if len(bytes(nonce)) != NONCE_LEN:
        raise ReplayError(
            MALFORMED,
            "proof nonce is %d bytes, expected %d" % (len(bytes(nonce)), NONCE_LEN),
        )
    if not isinstance(step, int) or isinstance(step, bool) or step < 0:
        raise ReplayError(MALFORMED, "challenge step %r is not a step index" % (step,))
    if not bytes(session_id) or not bytes(device_key_id):
        raise ReplayError(MALFORMED, "a proof must name a session and a device")
    if len(bytes(digest)) != DIGEST_LEN:
        raise ReplayError(
            MALFORMED,
            "proof digest is %d bytes, expected %d from the canonical codec"
            % (len(bytes(digest)), DIGEST_LEN),
        )


def queue_age(
    session_start: int,
    step: int,
    received_at: int,
    timing: Optional[challenge_mod.Timing] = None,
) -> int:
    """How long the proof sat between its challenge's step and its arrival.

    Server-derived, and that is the whole point: the earliest instant a proof for
    step *n* could have been made is the instant step *n* began, because the
    challenge value inside it cannot be computed without that step's epoch key.
    No client-supplied field participates.
    """
    step_start, _ = challenge_mod.step_bounds(session_start, step, timing)
    return int(received_at) - step_start


def claim_signals(
    *,
    captured_at: int,
    session_start: int,
    step: int,
    received_at: int,
    bounds: Optional[Bounds] = None,
    timing: Optional[challenge_mod.Timing] = None,
) -> Tuple[str, ...]:
    """What the device's own account of itself fails to explain.

    Each of these has an innocent reading - a handset clock nobody has set, a
    student who scanned and then lost signal for a day - so none of them rejects
    anything here. They are recorded because a device that is wrong about itself
    is worth knowing about, and because a pattern across devices is worth more
    than any single instance.
    """
    b = _bounds(bounds)
    step_start, _ = challenge_mod.step_bounds(session_start, step, timing)
    found = []
    if int(captured_at) > int(received_at) + b.max_future_skew_seconds:
        found.append(SIGNAL_FUTURE_CLAIM)
    if int(captured_at) < step_start - b.clock_skew_seconds:
        found.append(SIGNAL_CLAIM_PREDATES_CHALLENGE)
    return tuple(found)


def admit(
    ledger: Ledger,
    *,
    digest: bytes,
    session_id: bytes,
    device_key_id: bytes,
    nonce: bytes,
    step: int,
    session_start: int,
    received_at: int,
    captured_at: Optional[int] = None,
    bounds: Optional[Bounds] = None,
    timing: Optional[challenge_mod.Timing] = None,
) -> Receipt:
    """Admit one proof into the ledger, or raise.

    Ordered cheapest and most specific first, so the recorded reason is the most
    informative one available rather than whichever check happened to run: a proof
    that is both a duplicate and too old is reported as a duplicate, because that
    is what a client retrying a sync needs to hear.

    `captured_at` is optional and it is only ever read to produce signals. Passing
    it changes what is recorded about the proof and never whether it is accepted.
    """
    b = _bounds(bounds)
    _check_shape(digest, session_id, device_key_id, nonce, step)

    digest = bytes(digest)
    session_id = bytes(session_id)
    device_key_id = bytes(device_key_id)
    nonce = bytes(nonce)
    step = int(step)
    received_at = int(received_at)

    existing = ledger.seen_digest(digest)
    if existing is not None:
        raise ReplayError(
            DUPLICATE_PROOF,
            "this proof was already recorded at %d; if the client is retrying a "
            "sync it could not confirm, answer with the verdict already stored "
            "rather than treating this as an attack" % existing.received_at,
        )

    reused = ledger.seen_nonce(device_key_id, nonce)
    if reused is not None:
        raise ReplayError(
            NONCE_REUSED,
            "device %s used this nonce at %d for step %d and is now presenting it "
            "for step %d: the bytes differ, so this is not a retry"
            % (device_key_id.hex(), reused.received_at, reused.step, step),
        )

    age = queue_age(session_start, step, received_at, timing)
    if age < 0:
        raise ReplayError(
            STEP_NOT_YET_ISSUED,
            "proof references step %d, which this session does not reach for "
            "another %d seconds" % (step, -age),
        )
    if age > b.max_offline_seconds:
        raise ReplayError(
            TOO_OLD,
            "proof for step %d arrived %d seconds after that step, beyond the %d "
            "hours a queued proof may wait" % (step, age, b.max_offline_hours),
        )

    highest = ledger.highest_step(session_id, device_key_id)
    if highest is not None and step < highest:
        # Equal is allowed through. Two proofs for one step is a question about
        # how many marks a student may have, which belongs to the record layer's
        # uniqueness constraint; refusing it here would also refuse a legitimate
        # resubmission after a partially failed sync.
        raise ReplayError(
            STEP_REGRESSION,
            "device %s already had step %d accepted this session and is now "
            "presenting the earlier step %d"
            % (device_key_id.hex(), highest, step),
        )

    signals = ()
    if captured_at is not None:
        signals = claim_signals(
            captured_at=int(captured_at),
            session_start=int(session_start),
            step=step,
            received_at=received_at,
            bounds=b,
            timing=timing,
        )

    entry = Entry(
        digest=digest,
        session_id=session_id,
        device_key_id=device_key_id,
        nonce=nonce,
        step=step,
        received_at=received_at,
    )
    # The authority, not the checks above: concurrent submission of the same proof
    # is ordinary, and only the write can settle it.
    ledger.record(entry)
    return Receipt(
        entry=entry,
        queued_seconds=age,
        signals=signals,
        config_version=b.version,
    )


def retention_horizon(received_at: int, bounds: Optional[Bounds] = None) -> int:
    """The instant before which entries may be forgotten.

    Retention exceeds the offline allowance by construction - the config
    registry's cross-check refuses an artifact where it does not - because
    forgetting a nonce while a proof carrying it could still be accepted is a
    replay window, not a housekeeping decision.
    """
    b = _bounds(bounds)
    return int(received_at) - b.nonce_retention_seconds
