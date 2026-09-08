"""The rolling challenge that replaces the static QR payload.

What it replaces. `AttendanceSession.qr_code_data` was plain JSON containing the
session id and a two-digit `pattern_code` from `random.randint(10, 99)` - ninety
possible values, stable for the whole session. Possession of the session UUID was
enough to be marked present, so a screenshot forwarded to somebody in the
corridor worked as well as being in the room, and worked all lesson.

What is here instead. A per-session secret drives a chain of short-lived values:

    session root secret
      -> HKDF epoch key, one per epoch          (keys.SessionKeys.epoch_key)
      -> HMAC-SHA256(epoch_key, session||epoch||step), truncated to 8 bytes
      -> each step carries the previous step's value as prev_link

Each value is current for one step (see `challenge.step_seconds`), is bound to
its session, and is signed by the session's Ed25519 key. Three consequences,
which are the point of the design:

* **A screenshot goes stale.** The step number and the expiry are both inside the
  signed bytes, so re-presenting an old capture fails on either.
* **A student can check authenticity offline but cannot manufacture a
  challenge.** Verification needs only the session public key; production needs
  the root secret, which never leaves the server and the teacher's device.
* **A forged challenge fails against the derivation.** The server recomputes the
  value from the epoch key rather than taking the client's word for it.

The one hand-rolled byte layout in this layer is the MAC input, and it is
deliberately trivial: three fixed-width fields, no variable-length values, no
length prefixes, nothing to encode ambiguously. Everything that is *signed*
rather than MACed goes through `codec`, which is where canonical encoding
belongs. Both facts have to hold identically in Dart, so both are stated in
`docs/campusguard/01-protocol-spec.md` as wire format rather than as
implementation detail.

Nothing in this module reads the clock on its own. Every entry point takes `at`
as an integer Unix timestamp, so a test can place itself anywhere in a session
and so no code path can accidentally trust a device clock it was handed.
"""
import base64
from dataclasses import dataclass
from typing import Optional, Tuple

from . import codec, config
from .keys import (
    KeyMaterialError,
    SessionKeys,
    SignatureError,
    VerifyKey,
    equal,
    mac_truncated,
)

# Wire constants. These are format, not policy: changing one is a protocol
# change, which is why they are here and not in `config`.
CHALLENGE_LEN = 8
LINK_LEN = 8
SIGNATURE_LEN = 64
SENTINEL = (1 << 64) - 1  # stands in for "no previous step" at step 0

PROTOCOL_VERSION = 1

# Reason codes. These travel into PresenceDecision.reason_codes and from there
# into an AttendanceFlag, so they are stable strings rather than an enum whose
# member names could be refactored underneath persisted data.
MALFORMED = "challenge_malformed"
WRONG_SESSION = "challenge_wrong_session"
UNKNOWN_KEY = "challenge_unknown_key"
BAD_SIGNATURE = "challenge_bad_signature"
EXPIRED = "challenge_expired"
NOT_YET_VALID = "challenge_not_yet_valid"
TIMING_INCONSISTENT = "challenge_timing_inconsistent"
FORGED = "challenge_forged"
LINK_BROKEN = "challenge_link_broken"
STALE_STEP = "challenge_stale_step"
FUTURE_STEP = "challenge_future_step"

REASON_CODES = frozenset({
    MALFORMED,
    WRONG_SESSION,
    UNKNOWN_KEY,
    BAD_SIGNATURE,
    EXPIRED,
    NOT_YET_VALID,
    TIMING_INCONSISTENT,
    FORGED,
    LINK_BROKEN,
    STALE_STEP,
    FUTURE_STEP,
})


class ChallengeError(Exception):
    """A challenge did not verify. `code` is one of REASON_CODES."""

    def __init__(self, code: str, message: str):
        if code not in REASON_CODES:
            raise AssertionError("undeclared challenge reason code %r" % (code,))
        super().__init__(message)
        self.code = code


# --- Timing: read from the artifact, never from this file -------------------

@dataclass(frozen=True)
class Timing:
    """The five timing parameters, snapshotted from one configuration artifact.

    Read once per operation rather than parameter-by-parameter. A staged rollout
    can swap the active artifact between two requests; it must not be able to
    swap it between two reads *inside* one verification, which is how a challenge
    ends up checked against a step length and a lifetime that never coexisted.

    `version` travels with the result so `PresenceDecision.config_version` records
    the parameters that actually produced the verdict.
    """

    step_seconds: int
    steps_per_epoch: int
    lifetime_seconds: int
    clock_skew_seconds: int
    accept_window_steps: int
    version: str

    @classmethod
    def active(cls) -> "Timing":
        return cls.from_artifact(config.active())

    @classmethod
    def from_artifact(cls, a: config.Artifact) -> "Timing":
        """One named artifact's timing, for a caller that must not read today's.

        A session pins the artifact it opened under, so a proof queued offline is
        checked against the windows that were in force during the lesson.

        Anything scoped to a session reads through here, issuance included: which
        step a moment falls in is a function of `step_seconds`, so a challenge
        displayed under a newer artifact would be one the verifier - reading the
        pinned one - would correctly refuse to recognise. `active` is for a caller
        with no session to pin, which in practice means a default.
        """
        return cls(
            step_seconds=a["challenge.step_seconds"],
            steps_per_epoch=a["challenge.steps_per_epoch"],
            lifetime_seconds=a["challenge.lifetime_seconds"],
            clock_skew_seconds=a["challenge.clock_skew_seconds"],
            accept_window_steps=a["challenge.accept_window_steps"],
            version=a.version,
        )


def _timing(timing: Optional[Timing]) -> Timing:
    return timing if timing is not None else Timing.active()


# --- Step arithmetic --------------------------------------------------------

def step_index(session_start: int, at: int, timing: Optional[Timing] = None) -> int:
    """Which step a moment falls in, counting from session start.

    Floor division, so every instant inside a step maps to the same index and a
    challenge is a pure function of (session, step) rather than of the moment it
    was asked for. Two devices generating the same step offline produce identical
    bytes, which is what lets the server recompute what the teacher displayed.

    Negative when `at` precedes the session; callers treat that as
    NOT_YET_VALID rather than clamping it, because clamping would silently accept
    a challenge stamped before its session began.
    """
    t = _timing(timing)
    delta = int(at) - int(session_start)
    return delta // t.step_seconds if delta >= 0 else -((-delta + t.step_seconds - 1) // t.step_seconds)


def epoch_of(seq: int, timing: Optional[Timing] = None) -> int:
    """The epoch a step belongs to. Both are on the wire, and both are MACed."""
    if seq < 0:
        raise ValueError("step index must not be negative")
    return seq // _timing(timing).steps_per_epoch


def step_bounds(session_start: int, seq: int, timing: Optional[Timing] = None) -> Tuple[int, int]:
    """(issued_at, expires_at) for one step.

    `issued_at` is the step boundary, not the moment of the call. `expires_at`
    deliberately outlives the step - see `challenge.lifetime_seconds` - so a scan
    that straddles a rotation is not punished for the timing of the rotation.
    """
    t = _timing(timing)
    issued = int(session_start) + int(seq) * t.step_seconds
    return issued, issued + t.lifetime_seconds


# --- Derivation -------------------------------------------------------------

def mac_input(session_id: bytes, epoch: int, seq: int) -> bytes:
    """The exact bytes the challenge MAC is taken over: 16 || 8 || 8, big-endian.

    Hand-rolled rather than a codec schema, and that is a considered choice. All
    three fields are fixed-width, so there is no length prefix to disagree about,
    no ordering question and no encoding ambiguity - the properties `codec` exists
    to guarantee are free here. A schema would also spend one of the permanent
    tags and change the pinned schema fingerprint for a structure that is never
    transmitted, only recomputed on both sides.

    Big-endian because it is the network order every language's standard library
    agrees on without a flag.
    """
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes, got %d" % len(session_id))
    for name, value in (("epoch", epoch), ("seq", seq)):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= SENTINEL:
            raise ValueError("%s must be a uint64, got %r" % (name, value))
    return bytes(session_id) + epoch.to_bytes(8, "big") + seq.to_bytes(8, "big")


def challenge_value(epoch_key: bytes, session_id: bytes, epoch: int, seq: int) -> bytes:
    """One step's challenge. Truncated to 8 bytes because it has to be scannable.

    Truncation is safe here in a way it would not be for a long-lived
    authenticator: the value is worthless outside its step, the server rejects a
    step outside its acceptance window, and a wrong guess is a rejected scan
    rather than an oracle. `keys.mac_truncated` states the same caveat.
    """
    return mac_truncated(epoch_key, mac_input(session_id, epoch, seq), CHALLENGE_LEN)


def genesis_link(session_keys: SessionKeys, timing: Optional[Timing] = None) -> bytes:
    """What step 0 carries in `prev_link`, since it has no predecessor.

    A sentinel rather than zeros: eight zero bytes are a value an attacker can
    write by hand, while this one requires the epoch key. Epoch and step are both
    set to 2**64-1, which no real step can reach, so the genesis link can never
    collide with a genuine step's challenge.
    """
    return challenge_value(
        session_keys.epoch_key(0), session_keys.session_id, SENTINEL, SENTINEL
    )


def link_for(session_keys: SessionKeys, seq: int, timing: Optional[Timing] = None) -> bytes:
    """The `prev_link` a given step must carry: step seq-1's challenge, or genesis."""
    t = _timing(timing)
    if seq == 0:
        return genesis_link(session_keys, t)
    previous = seq - 1
    return challenge_value(
        session_keys.epoch_key(epoch_of(previous, t)),
        session_keys.session_id,
        epoch_of(previous, t),
        previous,
    )


# --- The challenge itself ---------------------------------------------------

@dataclass(frozen=True)
class Challenge:
    """One step's challenge, as displayed and as transmitted.

    The payload is `codec.encode("qr_challenge", ...)` followed by a 64-byte
    Ed25519 signature over exactly those encoded bytes. There is no signing
    wrapper: the schema tag and version are already the first two elements of the
    encoding, so the bytes are domain-separated without one, and every byte a
    verifier must reconstruct is a byte it already has to parse. One fewer
    structure for the Dart implementation to get wrong.
    """

    session_id: bytes
    key_id: bytes
    epoch: int
    seq: int
    challenge: bytes
    prev_link: bytes
    issued_at: int
    expires_at: int
    signature: bytes

    @property
    def values(self) -> dict:
        """The signed struct, in codec terms. Field order comes from the schema."""
        return {
            "session_id": self.session_id,
            "key_id": self.key_id,
            "epoch": self.epoch,
            "seq": self.seq,
            "challenge": self.challenge,
            "prev_link": self.prev_link,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    @property
    def signed_bytes(self) -> bytes:
        return codec.encode(codec.QR_CHALLENGE.name, self.values)

    @property
    def payload(self) -> bytes:
        """What the QR carries: canonical struct, then signature."""
        return self.signed_bytes + self.signature

    @property
    def digest(self) -> bytes:
        """Identity of this challenge, for a replay cache to key on."""
        return codec.digest(codec.QR_CHALLENGE.name, self.values)

    def display_code(self) -> str:
        """The short human-readable form, for the fallback the teacher reads aloud.

        Base32 of the truncated MAC, minus padding: 13 characters from the same
        bytes the QR carries, using an alphabet with no lowercase and no 0/O/1/I
        confusion in most fonts. It authenticates nothing on its own - it is an
        index into the same step, and the signed payload is what verifies - so it
        is safe for a student to type and useless to a student in the corridor,
        who cannot produce the accompanying proof for a device that was never
        bound in this room.
        """
        return base64.b32encode(self.challenge).decode("ascii").rstrip("=")


def issue(
    session_keys: SessionKeys,
    *,
    session_start: int,
    at: int,
    timing: Optional[Timing] = None,
) -> Challenge:
    """The challenge current at `at`, for the session that began at `session_start`.

    Deterministic in (session, step): calling this twice inside one step returns
    byte-identical payloads. That is what makes the teacher's offline device and
    the server agree, and it means the displayed QR only has to be redrawn when
    the step turns over.
    """
    t = _timing(timing)
    seq = step_index(session_start, at, t)
    if seq < 0:
        raise ChallengeError(
            NOT_YET_VALID,
            "cannot issue a challenge %d seconds before the session starts"
            % (int(session_start) - int(at)),
        )
    epoch = epoch_of(seq, t)
    issued_at, expires_at = step_bounds(session_start, seq, t)
    values = {
        "session_id": session_keys.session_id,
        "key_id": session_keys.public().key_id,
        "epoch": epoch,
        "seq": seq,
        "challenge": challenge_value(
            session_keys.epoch_key(epoch), session_keys.session_id, epoch, seq
        ),
        "prev_link": link_for(session_keys, seq, t),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    signature = session_keys.signing.sign(
        codec.encode(codec.QR_CHALLENGE.name, values)
    )
    return Challenge(signature=signature, **values)


def parse(payload: bytes) -> Challenge:
    """Bytes to Challenge, with no authenticity claim whatsoever.

    Split before verify, because the signature covers a prefix of the payload and
    something has to establish where that prefix ends. `codec.decode` runs strict,
    so a payload with trailing junk or non-canonical encoding is rejected here
    rather than becoming a second valid form of one challenge.
    """
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise ChallengeError(MALFORMED, "challenge payload must be bytes")
    raw = bytes(payload)
    if len(raw) <= SIGNATURE_LEN:
        raise ChallengeError(
            MALFORMED,
            "challenge payload is %d bytes, too short to hold a %d-byte signature "
            "and a struct" % (len(raw), SIGNATURE_LEN),
        )
    body, signature = raw[:-SIGNATURE_LEN], raw[-SIGNATURE_LEN:]
    try:
        values = codec.decode(body, codec.QR_CHALLENGE.name)
    except codec.CodecError as exc:
        raise ChallengeError(MALFORMED, "challenge does not decode: %s" % (exc,))
    return Challenge(signature=signature, **values)


# --- Checks -----------------------------------------------------------------
#
# Separate, single-purpose, and each raising one reason code. Composed by the two
# entry points below rather than inlined into them, so that a gate which wants
# only part of the story - and there will be one - does not have to reimplement
# any of it.

def _check_binding(ch: Challenge, session_id: bytes, verify_key: VerifyKey) -> None:
    if not equal(ch.session_id, session_id):
        raise ChallengeError(
            WRONG_SESSION,
            "challenge is for session %s, not %s"
            % (ch.session_id.hex(), bytes(session_id).hex()),
        )
    if not equal(ch.key_id, verify_key.key_id):
        raise ChallengeError(
            UNKNOWN_KEY,
            "challenge names key %s; this session's key is %s"
            % (ch.key_id.hex(), verify_key.key_id.hex()),
        )


def _check_signature(ch: Challenge, verify_key: VerifyKey) -> None:
    try:
        verify_key.verify(ch.signed_bytes, ch.signature)
    except SignatureError as exc:
        raise ChallengeError(BAD_SIGNATURE, str(exc))


def _check_structure(ch: Challenge, session_start: int, timing: Timing) -> None:
    """The self-declared fields must agree with the session's step arithmetic.

    Cheap, and it is what lets a student's device catch an inconsistency it has no
    key to detect otherwise: without the epoch key it cannot recompute the
    challenge, but it can tell that a struct claiming epoch 3 at step 7 does not
    describe any step this session could have produced.
    """
    if ch.epoch != epoch_of(ch.seq, timing):
        raise ChallengeError(
            TIMING_INCONSISTENT,
            "challenge claims epoch %d at step %d, but %d steps per epoch puts "
            "that step in epoch %d"
            % (ch.epoch, ch.seq, timing.steps_per_epoch, epoch_of(ch.seq, timing)),
        )
    issued_at, expires_at = step_bounds(session_start, ch.seq, timing)
    if ch.issued_at != issued_at or ch.expires_at != expires_at:
        raise ChallengeError(
            TIMING_INCONSISTENT,
            "challenge for step %d declares %d..%d; this session's step %d is "
            "%d..%d" % (ch.seq, ch.issued_at, ch.expires_at, ch.seq, issued_at, expires_at),
        )


def _check_freshness(ch: Challenge, at: int, timing: Timing, skew: int) -> None:
    at = int(at)
    if at + skew < ch.issued_at:
        raise ChallengeError(
            NOT_YET_VALID,
            "challenge is not valid for another %d seconds" % (ch.issued_at - at),
        )
    if at - skew > ch.expires_at:
        raise ChallengeError(
            EXPIRED,
            "challenge expired %d seconds ago%s"
            % (
                at - ch.expires_at,
                " (%d seconds of clock tolerance already allowed)" % skew if skew else "",
            ),
        )


def _check_window(ch: Challenge, session_start: int, at: int, timing: Timing) -> None:
    """How far behind the server's current step a submitted challenge may be.

    Never ahead: a step the server has not reached cannot have been displayed, so
    a challenge from the future is a forgery or a clock lie, not latency. Behind is
    allowed up to `challenge.accept_window_steps`, which covers the time between
    the camera capturing a code and the request arriving.

    This bound and `expires_at` overlap, and under the artifact shipping today the
    expiry is the tighter of the two: a challenge is dead at 30 s while three steps
    is 45 s, so STALE_STEP only becomes reachable if `lifetime_seconds` rises above
    `(accept_window_steps + 1) * step_seconds`. Both checks stay, because they rest
    on different things - one on the server's own clock, one on a field inside the
    struct - and a configuration that makes either the binding one is a
    configuration this code should still enforce correctly.
    """
    current = step_index(session_start, at, timing)
    if ch.seq > current:
        raise ChallengeError(
            FUTURE_STEP,
            "challenge is for step %d; the session has only reached step %d"
            % (ch.seq, current),
        )
    if current - ch.seq > timing.accept_window_steps:
        raise ChallengeError(
            STALE_STEP,
            "challenge is %d steps behind the current step %d; at most %d is "
            "accepted" % (current - ch.seq, current, timing.accept_window_steps),
        )


def _check_derivation(ch: Challenge, session_keys: SessionKeys, timing: Timing) -> None:
    """Recompute the challenge and its link. Server only - it needs the secret.

    This is the check the signature cannot substitute for. A signature says the
    struct came from something holding the session signing key; this says the
    challenge value inside it is the one this session's chain actually produces at
    that step. Both must hold.
    """
    expected = challenge_value(
        session_keys.epoch_key(ch.epoch), session_keys.session_id, ch.epoch, ch.seq
    )
    if not equal(ch.challenge, expected):
        raise ChallengeError(
            FORGED,
            "challenge value does not match the chain for session %s step %d"
            % (session_keys.session_id.hex(), ch.seq),
        )
    if not equal(ch.prev_link, link_for(session_keys, ch.seq, timing)):
        raise ChallengeError(
            LINK_BROKEN,
            "challenge for step %d does not carry %s"
            % (
                ch.seq,
                "this session's genesis link" if ch.seq == 0
                else "step %d's value" % (ch.seq - 1,),
            ),
        )


# --- The two entry points ---------------------------------------------------

def verify_public(
    payload: bytes,
    *,
    verify_key: VerifyKey,
    session_id: bytes,
    at: int,
    session_start: Optional[int] = None,
    timing: Optional[Timing] = None,
) -> Challenge:
    """What a student's device can check, offline, with no secret at all.

    Needs the session public key and nothing more, so it is safe to hold on every
    handset. It establishes that the challenge was signed by this session's key,
    names this session, and is current - which is enough for the app to refuse an
    obviously stale or foreign code before building a proof around it, and to say
    why.

    It cannot establish that the challenge value came from the session's chain.
    Only `verify_authoritative` does that, because only the server and the
    teacher's device hold the root secret. A student's device passing this check
    is therefore not a verdict; it is a local sanity gate that saves a pointless
    round trip and gives an honest error in the corridor.

    `clock_skew_seconds` is applied in both directions here and only here. The
    handset clock is attacker-controlled, so this is a usability allowance for an
    honest student whose phone drifted, never a source of authority: a device that
    lies about the time still fails the server's step-window check.

    `session_start` is optional because a device may hold a challenge before it
    has synced the session's start time. Without it the step arithmetic cannot be
    checked, so the caller gets a weaker check rather than a fabricated one - the
    same rule the analytics layer follows about never inventing a value.
    """
    t = _timing(timing)
    ch = parse(payload)
    _check_binding(ch, session_id, verify_key)
    _check_signature(ch, verify_key)
    if session_start is not None:
        _check_structure(ch, int(session_start), t)
    _check_freshness(ch, at, t, skew=t.clock_skew_seconds)
    return ch


def verify_authoritative(
    payload: bytes,
    *,
    session_keys: SessionKeys,
    session_start: int,
    at: Optional[int],
    timing: Optional[Timing] = None,
) -> Challenge:
    """Everything the server can check. No client-supplied claim is taken on trust.

    Order matters: cheap structural and signature checks first, derivation last,
    so a malformed or unsigned payload never reaches an HMAC computation.

    `at` is the moment liveness is judged against, and passing `None` disables the
    liveness check deliberately and visibly. A live scan passes the server's clock.
    A proof that sat in an offline queue passes `None`, because by then the
    challenge is legitimately long expired and the question has become how long the
    proof may have been queued - which is `proof.max_offline_hours`, enforced where
    that parameter lives. Making the omission explicit is the point: a default
    would let the liveness check be skipped by accident.

    No clock skew is allowed here. The server's clock is the authority; a handset's
    disagreement with it is not evidence of anything.
    """
    t = _timing(timing)
    ch = parse(payload)
    _check_binding(ch, session_keys.session_id, session_keys.public())
    _check_signature(ch, session_keys.public())
    _check_structure(ch, int(session_start), t)
    if at is not None:
        # Window before freshness, deliberately. Both express the same bound, but
        # the window is derived entirely from the server's clock and the session's
        # start, while `expires_at` is a field inside the struct. When both are
        # violated the server-derived reason is the more informative one to record.
        _check_window(ch, int(session_start), int(at), t)
        _check_freshness(ch, at, t, skew=0)
    _check_derivation(ch, session_keys, t)
    return ch



def verify_committed(
    session_keys: SessionKeys,
    *,
    epoch: int,
    seq: int,
    value: bytes,
    session_start: int,
    at: int,
    timing: Optional[Timing] = None,
) -> Tuple[int, int]:
    """What a proof commits to, verified without the QR payload.

    A proof carries the challenge *value*, its epoch and its step - not the signed
    QR struct. That is the whole payload the client never has to upload: the value
    is a MAC over (session, epoch, step) under an epoch key only this session
    holds, so recomputing it proves the same thing the struct's signature would
    and costs eighty fewer bytes on a queue that may hold a day of them.

    Three of `verify_authoritative`'s checks have no counterpart here, and each
    absence is deliberate rather than an omission.

    There is no signature check, because there is no signed struct - the proof's
    own signature covers these three fields, and the derivation below is what says
    the value was not invented.

    There is no `prev_link` check, because the link is not committed to. The link
    exists so a *handset* can notice a spliced chain with no epoch key to
    recompute anything; a server holding the epoch key needs nothing weaker.

    There is no expiry check. A queued proof is legitimately long expired by the
    time it arrives, and how late a proof may arrive is `proof.max_offline_hours`,
    enforced once in `replay` against the server's own clock. Checking it twice
    with two different notions of late is how an offline system starts rejecting
    the students it was built for.

    What is checked, and cannot be skipped: a step the server has not reached
    cannot have been displayed, so a challenge from the future is a fabrication
    however good its arithmetic. Returns the step's bounds, which is what a
    caller needs to judge attached observations against.
    """
    t = _timing(timing)
    session_start = int(session_start)

    for name, number in (("epoch", epoch), ("step", seq)):
        if not isinstance(number, int) or isinstance(number, bool) or number < 0:
            raise ChallengeError(
                MALFORMED, "%s must be a non-negative integer, got %r" % (name, number)
            )
    value = bytes(value)
    if len(value) != CHALLENGE_LEN:
        raise ChallengeError(
            MALFORMED,
            "a challenge value is %d bytes, got %d" % (CHALLENGE_LEN, len(value)),
        )

    if epoch != epoch_of(seq, t):
        raise ChallengeError(
            TIMING_INCONSISTENT,
            "proof commits to epoch %d at step %d, but %d steps per epoch puts "
            "that step in epoch %d" % (epoch, seq, t.steps_per_epoch, epoch_of(seq, t)),
        )

    reached = step_index(session_start, int(at), t)
    if seq > reached:
        raise ChallengeError(
            FUTURE_STEP,
            "proof commits to step %d; this session has only reached step %d"
            % (seq, reached),
        )

    expected = challenge_value(
        session_keys.epoch_key(epoch), session_keys.session_id, epoch, seq
    )
    if not equal(value, expected):
        raise ChallengeError(
            FORGED,
            "committed challenge value does not match the chain for session %s "
            "step %d" % (session_keys.session_id.hex(), seq),
        )

    return step_bounds(session_start, seq, t)


def describe(ch: Challenge) -> str:
    """A one-line rendering for logs and audit records. No secret material.

    The challenge value is included because it is public by construction - it is
    printed on a screen in a classroom - and because an audit trail that cannot
    identify which challenge was presented cannot reconstruct a disputed decision.
    """
    return "session=%s key=%s epoch=%d step=%d challenge=%s valid=%d..%d" % (
        ch.session_id.hex(),
        ch.key_id.hex(),
        ch.epoch,
        ch.seq,
        ch.challenge.hex(),
        ch.issued_at,
        ch.expires_at,
    )
