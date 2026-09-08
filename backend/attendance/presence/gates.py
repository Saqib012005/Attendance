"""The hard gates: whether a proof is admissible evidence at all.

A gate answers a different question from everything downstream of it. Fusion asks
how much a body of evidence is worth; a gate asks whether this submission is
evidence in the first place. Those must not be the same mechanism, because a
probability can always be argued with - enough weak positives eventually outvote
one strong negative - and "the signature does not verify" is not a thing that
should be outvoted. So every check here is a refusal, none of them contributes to
a score, and all of them run before a single likelihood is computed.

The list is short on purpose. A gate earns its place only if a failure means the
submission cannot be reasoned about: it was not signed by a device this server has
bound, it does not name a challenge this session produced, it has already been
counted, or it arrived outside the window this system admits at all. Everything
else is evidence, and evidence goes downstream.

Three things a reader might expect to find here and will not, each because putting
it here would be a mistake rather than an oversight.

**A failed biometric is not a gate.** It is strong negative evidence and it is
weighed as such. As a gate it would make a wet fingertip indistinguishable from an
impostor, with no path back for the student and nothing on the record for the
teacher to override against. The place a biometric failure should cost a student
is a confidence number and a reason code a human can read, not a closed door.

**Attached evidence that fails to verify does not reject the proof.** It is
dropped, with its reason recorded, and the proof stands on what remains. This is
the one place this module deliberately departs from the plan's one-line summary of
"unauthorized relay" as a gate, and the reason is an attack the gate reading would
open: a rogue device can append a hop to anyone's chain, so rejecting a proof
whose chain fails to verify would let an attacker deny attendance to any student
within radio range by relaying garbage at them. Dropping costs that student
evidence, which is recoverable; refusing costs them the lesson, which is not.
`chain.py` was written to that rule and this module keeps it.

**Liveness is not gated, and cannot be.** A challenge is a function of the session
and the step, so a proof built from step *n* is byte-identical whether it was
scanned during step *n* or copied from a screenshot of it hours later. The server
has no way to tell those apart from the proof alone. What it can do, and does, is
bound how late a proof may arrive (`proof.max_offline_hours`, enforced in
`replay`), refuse a step the session has not reached, refuse a device that has
already been counted further into the session, and record the server-derived
`queued_seconds` so fusion can weigh lateness. The remaining gap - a code shared
out of the room and used later on a bound device - is the same residual risk the
missing spatial evidence leaves open, and it is closed by anchors, not by
arithmetic. It is recorded in the threat model, not papered over here.

**Order matters, and the last position is load-bearing.** Cheap and specific first
so the recorded reason is the informative one. `replay.admit` runs last and only
last, because it writes: burning a nonce on a proof that was going to be refused
anyway would let anyone who can replay one malformed copy of a submission stop the
genuine one from ever being accepted.

**No database.** Every fact this module cannot compute arrives as an argument: the
session's keys, when it opened and closed, a resolver for device registrations, a
resolver for relay pseudonyms, and a ledger. That is what lets the same code path
run in a request, in a test and in the adversarial lab and reach the same verdict.
"""
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from . import chain, challenge, codec, keys, origin, proof, replay

# --- Vocabulary -------------------------------------------------------------

UNKNOWN_DEVICE = "gate_unknown_device"
DEVICE_REVOKED = "gate_device_revoked"
DEVICE_NOT_ENROLLED = "gate_device_not_enrolled"
SESSION_NOT_OPEN = "gate_session_not_open"
OBSERVATION_NOT_COMMITTED = "gate_observation_not_committed"

OWN_REASON_CODES = frozenset({
    UNKNOWN_DEVICE,
    DEVICE_REVOKED,
    DEVICE_NOT_ENROLLED,
    SESSION_NOT_OPEN,
    OBSERVATION_NOT_COMMITTED,
})

# A refusal from a module this one composes keeps that module's reason code, so
# the code recorded against a rejected proof names the check that actually failed
# rather than the layer that noticed. `GateError` is the single exception type a
# caller has to catch; the vocabulary it may carry is the union.
BORROWED_REASON_CODES = (
    proof.REASON_CODES | challenge.REASON_CODES | replay.REASON_CODES
)
REASON_CODES = OWN_REASON_CODES | BORROWED_REASON_CODES

# Why an attached observation was set aside. Not refusals: a proof with every
# observation dropped is still a proof, and is judged on what is left.
UNRECOGNISED_OBSERVATION = "gate_observation_unrecognised"
DROP_REASONS = (
    frozenset({UNRECOGNISED_OBSERVATION}) | origin.REASON_CODES | chain.REASON_CODES
)

# Worth recording about an admitted proof, and never a reason to refuse one.
UNKNOWN_CAPABILITY = "gate_unknown_capability_bit"
OWN_SIGNALS = frozenset({UNKNOWN_CAPABILITY})
SIGNALS = OWN_SIGNALS | origin.SIGNALS | chain.SIGNALS | replay.SIGNALS


class GateError(Exception):
    """A refusal, carrying the reason code of the check that produced it."""

    def __init__(self, code: str, message: str):
        assert code in REASON_CODES, "undeclared gate reason code %r" % (code,)
        super().__init__(message)
        self.code = code


# --- Facts the caller resolves ----------------------------------------------

@dataclass(frozen=True)
class SessionContext:
    """The session as the server knows it, not as the proof describes it.

    `closed_at` is the moment the teacher ended the session, or None while it is
    still running. It is a separate fact from the step arithmetic because nothing
    inside a challenge records it: step 40 of a session the teacher closed after
    step 12 is arithmetically impeccable and must still be refused.
    """

    session_keys: keys.SessionKeys
    session_start: int
    closed_at: Optional[int] = None

    def __post_init__(self):
        if not isinstance(self.session_start, int) or isinstance(self.session_start, bool):
            raise GateError(
                SESSION_NOT_OPEN, "session_start must be an integer, got %r" % (self.session_start,)
            )
        if self.closed_at is not None and self.closed_at < self.session_start:
            raise GateError(
                SESSION_NOT_OPEN,
                "session closed at %d, before it started at %d"
                % (self.closed_at, self.session_start),
            )


@dataclass(frozen=True)
class Registration:
    """One device binding, as the caller read it out of the database.

    Three separate facts rather than one `ok` flag, because the three refusals they
    produce mean different things to the person reading them: a key nobody has
    registered, a key that was registered and then revoked, and a key belonging to
    a student who is not on this class's roster. Collapsing them would make the
    common case - a student who transferred class - look like a stolen device.
    """

    verify_key: keys.VerifyKey
    revoked: bool = False
    enrolled: bool = True


@dataclass(frozen=True)
class Dropped:
    """One attached observation that was set aside, and why."""

    index: int
    kind: str
    code: str
    detail: str

    def __post_init__(self):
        assert self.code in DROP_REASONS, "undeclared drop reason %r" % (self.code,)

    def describe(self) -> Dict[str, Any]:
        return {"index": self.index, "kind": self.kind, "code": self.code}


@dataclass(frozen=True)
class Cleared:
    """Everything that survived the gates, ready to become an evidence vector.

    `signed` is the proof and the bytes it was verified over. `sightings` and `hops`
    are whatever attached evidence verified - both legitimately empty, which is the
    ordinary case on a build with no radio. `dropped` is the audit trail for
    evidence that did not survive, and it exists so that "no relay evidence" and
    "relay evidence that failed to verify" are never the same record.

    `claims` is carried through unread. Nothing in this module or downstream of it
    treats a client's own account of its status, confidence or hop count as an
    input; they are recorded so a disagreement with the server's re-derivation is
    visible, which is interesting whichever way it runs.
    """

    signed: proof.Signed
    receipt: replay.Receipt
    step_bounds: Tuple[int, int]
    sightings: Tuple[origin.Sighting, ...] = ()
    hops: Tuple[chain.Hop, ...] = ()
    dropped: Tuple[Dropped, ...] = ()
    signals: Tuple[str, ...] = ()
    config_version: str = ""

    def __post_init__(self):
        for signal in self.signals:
            if signal not in SIGNALS:
                raise AssertionError("undeclared gate signal %r" % (signal,))

    @property
    def claims(self) -> proof.Claims:
        return self.signed.proof.claims

    def describe(self) -> Dict[str, Any]:
        """For an audit record. Claims are named as claims; no key material."""
        described = {
            "proof": self.signed.proof.describe(),
            "queued_seconds": self.receipt.queued_seconds,
            "step_bounds": list(self.step_bounds),
            "relay_depth": len(self.hops),
            "origin_sightings": [s.describe() for s in self.sightings],
            "dropped": [d.describe() for d in self.dropped],
            "signals": list(self.signals),
            "config_version": self.config_version,
        }
        return described


# --- Refusal translation ----------------------------------------------------

def _refuse(exc: Exception) -> GateError:
    """One exception type out, with the failing module's own reason code kept."""
    code = getattr(exc, "code", None)
    if code not in REASON_CODES:
        raise exc
    return GateError(code, str(exc))


def _timing(timing: Optional[challenge.Timing]) -> challenge.Timing:
    return timing if timing is not None else challenge.Timing.active()


# --- Sorting the attached evidence ------------------------------------------


def _admit_observations(
    signed: proof.Signed,
    observations: Sequence[bytes],
    *,
    context: SessionContext,
    step_bounds: Tuple[int, int],
    resolve_relay: Optional[Callable[[bytes], Optional[keys.VerifyKey]]],
    timing: challenge.Timing,
) -> Tuple[Tuple[origin.Sighting, ...], Tuple[chain.Hop, ...], Tuple[Dropped, ...], Tuple[str, ...]]:
    """Route each attached body to its verifier, keep what verifies, record the rest.

    The commitment check comes first and is a gate: a body the signed proof does not
    account for is not evidence that failed, it is evidence somebody added
    afterwards, and admitting it would make the proof's signature mean less than it
    says. The reverse - a commitment whose body never arrived - is allowed, because
    a dropped packet is not an attack and `proof.committed_to` is written to that
    asymmetry.

    Sightings are judged against the instant the challenge's own step began rather
    than against the moment the proof arrived. That is the only server-derived
    instant available for a proof that sat in a queue, and it is the right one: a
    frame the student heard while scanning belongs to that step, plus or minus
    `challenge.accept_window_steps`, which is exactly the window `origin` already
    enforces. Using receipt time instead would refuse every sighting in every
    queued proof, which is to say all of them. Using the step's *expiry* would be
    subtler and still wrong - a challenge outlives its step by
    `challenge.lifetime_seconds`, so the window would slide forward and drop a
    frame the student legitimately heard a step or two before scanning, which is
    the innocent direction to get wrong.
    """
    if observations and not proof.committed_to(signed.proof, observations):
        raise GateError(
            OBSERVATION_NOT_COMMITTED,
            "an attached observation is not among the %d this proof commits to"
            % (len(signed.proof.observations),),
        )

    at = step_bounds[0]
    sightings = []
    hop_bodies = []
    dropped = []
    signals = []

    for index, raw in enumerate(bytes(r) for r in observations):
        schema = codec.identify(raw)
        name = schema.name if schema is not None else "unrecognised"
        if schema is codec.ORIGIN_SIGHTING:
            try:
                sighting, found = origin.verify_sighting(
                    raw,
                    context.session_keys,
                    session_start=context.session_start,
                    at=at,
                    timing=timing,
                )
            except origin.OriginError as exc:
                dropped.append(Dropped(index, name, exc.code, str(exc)))
                continue
            sightings.append(sighting)
            signals.extend(found)
        elif schema is codec.RELAY_HOP:
            hop_bodies.append((index, raw))
        else:
            dropped.append(
                Dropped(
                    index,
                    name,
                    UNRECOGNISED_OBSERVATION,
                    "this build has no verifier for %s" % (name,),
                )
            )

    hops, hop_dropped, hop_signals = _admit_chain(
        hop_bodies, sightings, resolve_relay=resolve_relay, context=context
    )
    dropped.extend(hop_dropped)
    signals.extend(hop_signals)
    return tuple(sightings), hops, tuple(dropped), tuple(signals)


def _admit_chain(
    hop_bodies: Sequence[Tuple[int, bytes]],
    sightings: Sequence[origin.Sighting],
    *,
    resolve_relay: Optional[Callable[[bytes], Optional[keys.VerifyKey]]],
    context: SessionContext,
) -> Tuple[Tuple[chain.Hop, ...], Tuple[Dropped, ...], Tuple[str, ...]]:
    """The relay chain, verified against whichever verified sighting roots it.

    A chain's first link is the digest of the first relay's own origin sighting, and
    that sighting travels beside the chain as another observation. So the root is not
    something the server is told; it is discovered, by trying each sighting that has
    already verified and keeping the chain under whichever one links. A chain that
    links to none of them is unrooted, and an unrooted chain is one that could have
    been grafted onto a different session's sighting.

    Every failure here drops the chain and none of them refuses the proof. The
    reason is in this module's docstring and it is the difference between a rogue
    relay costing a student some evidence and a rogue relay costing a student the
    lesson.

    A caller with no cohort resolver gets its chain dropped rather than trusted. The
    handset-side structural check is genuinely useful and genuinely weaker, and the
    server has no business treating the weaker result as the stronger one.
    """
    if not hop_bodies:
        return (), (), ()

    indices = [index for index, _ in hop_bodies]
    wire = [raw for _, raw in hop_bodies]
    first = indices[0]

    def drop(code: str, detail: str) -> Tuple[Tuple[chain.Hop, ...], Tuple[Dropped, ...], Tuple[str, ...]]:
        return (), (Dropped(first, codec.RELAY_HOP.name, code, detail),), ()

    if resolve_relay is None:
        return drop(
            chain.UNKNOWN_RELAY,
            "no cohort resolver was supplied, so no hop signature could be checked",
        )

    last: Optional[chain.ChainError] = None
    for sighting in sightings:
        try:
            root = chain.root_link(sighting.encode())
        except chain.ChainError as exc:      # pragma: no cover - sighting verified
            last = exc
            continue
        try:
            hops = chain.verify_chain(
                wire,
                session_id=context.session_keys.session_id,
                root=root,
                resolve=resolve_relay,
            )
        except chain.ChainError as exc:
            last = exc
            continue
        return hops, (), chain.signals(hops)

    if last is None:
        return drop(
            chain.BROKEN_LINK,
            "a chain of %d hops arrived with no verified origin sighting to root it"
            % (len(wire),),
        )
    return drop(last.code, str(last))


# --- The gate ---------------------------------------------------------------

def clear(
    body: bytes,
    signature: bytes,
    *,
    context: SessionContext,
    resolve_device: Callable[[bytes], Optional[Registration]],
    ledger: replay.Ledger,
    received_at: int,
    observations: Sequence[bytes] = (),
    resolve_relay: Optional[Callable[[bytes], Optional[keys.VerifyKey]]] = None,
    timing: Optional[challenge.Timing] = None,
    bounds: Optional[replay.Bounds] = None,
) -> Cleared:
    """Admit one submitted proof, or refuse it with a reason code.

    The order below is the module's argument, so it is worth reading as one.

    Shape, because a malformed body reported as a bad signature sends an integrator
    hunting the wrong bug - and because the device key id has to be legible before
    anyone can be asked for a key. Nothing from that first parse is trusted for
    anything except the lookup, and `proof.verify` independently refuses a body
    whose named device is not the key it was checked against.

    Registration, because a signature is only worth checking against a key this
    institution has bound to a student on this roster. Three distinct refusals,
    for the reason `Registration` gives.

    Signature and session binding, which is where the body stops being bytes
    somebody sent and starts being a proof.

    The committed challenge, re-derived from this session's own epoch key. A step
    the session has not reached is refused here however well-formed it is.

    Whether the session was open at that step, which no challenge records.

    Attached observations, none of which can refuse the proof.

    Uniqueness, last, because it writes.
    """
    t = _timing(timing)
    received_at = int(received_at)

    try:
        peek = proof.parse(bytes(body))
    except proof.ProofError as exc:
        raise _refuse(exc)

    registration = resolve_device(peek.device_key_id)
    if registration is None:
        raise GateError(
            UNKNOWN_DEVICE,
            "no registered device holds key %s; a device must be bound before a "
            "proof it signed can be read" % (peek.device_key_id.hex(),),
        )
    if registration.revoked:
        raise GateError(
            DEVICE_REVOKED,
            "device %s is registered but revoked" % (peek.device_key_id.hex(),),
        )
    if not registration.enrolled:
        raise GateError(
            DEVICE_NOT_ENROLLED,
            "device %s belongs to a student who is not enrolled in this class"
            % (peek.device_key_id.hex(),),
        )

    try:
        signed = proof.verify(
            bytes(body),
            bytes(signature),
            registration.verify_key,
            session_id=context.session_keys.session_id,
        )
    except proof.ProofError as exc:
        raise _refuse(exc)

    p = signed.proof
    try:
        step_bounds = challenge.verify_committed(
            context.session_keys,
            epoch=p.challenge_epoch,
            seq=p.challenge_seq,
            value=p.challenge,
            session_start=context.session_start,
            at=received_at,
            timing=t,
        )
    except challenge.ChallengeError as exc:
        raise _refuse(exc)

    if context.closed_at is not None and step_bounds[0] >= context.closed_at:
        raise GateError(
            SESSION_NOT_OPEN,
            "step %d begins at %d, after this session was ended at %d"
            % (p.challenge_seq, step_bounds[0], context.closed_at),
        )

    sightings, hops, dropped, evidence_signals = _admit_observations(
        signed,
        observations,
        context=context,
        step_bounds=step_bounds,
        resolve_relay=resolve_relay,
        timing=t,
    )

    try:
        receipt = replay.admit(
            ledger,
            digest=p.digest(),
            session_id=p.session_id,
            device_key_id=p.device_key_id,
            nonce=p.nonce,
            step=p.challenge_seq,
            session_start=context.session_start,
            received_at=received_at,
            captured_at=p.captured_at,
            bounds=bounds,
            timing=t,
        )
    except replay.ReplayError as exc:
        raise _refuse(exc)

    signals = list(evidence_signals) + list(receipt.signals)
    if p.unknown_capabilities:
        # A newer client declared something this build has no name for. Recorded,
        # never counted: the point of a capability set is that absent evidence can
        # be explained by the handset instead of charged to the student.
        signals.append(UNKNOWN_CAPABILITY)

    return Cleared(
        signed=signed,
        receipt=receipt,
        step_bounds=step_bounds,
        sightings=sightings,
        hops=hops,
        dropped=dropped,
        signals=tuple(signals),
        config_version=t.version,
    )
