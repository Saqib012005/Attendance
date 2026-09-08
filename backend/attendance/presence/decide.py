"""The policy layer: what a score and a refusal are allowed to mean.

Every other module in this package answers a question of fact. This one answers a
question of institutional policy, and the separation is the point. `fusion` knows
what the admitted evidence came to and deliberately holds no threshold; `gates`
knows which proofs cannot be accepted at all and deliberately holds no opinion
about the ones that can. A layer that both scored and ruled would be a layer where
an operating point could hide inside the arithmetic, and then no reviewer could
tell a scoring change from a policy change.

Four things follow from that, and they are the whole design.

**It reads facts, never a claim.** `decide` takes a `fusion.Fused` and one signed
outcome. A `gates.Cleared` carries the client's own `status`, `confidence_milli` and
`hop_count`, and this function is structurally incapable of reaching them - the same
discipline that keeps `fusion` from importing `proof` for anything, expressed here as
an argument list rather than as a rule somebody has to remember. The line is between
a fact the server has verified a signature over and a verdict the client would like:
the biometric outcome is the former and is passed in explicitly, `claims` is the
latter and has no way in. `proof` is imported for two vocabularies only - the four
status integers and the four biometric outcomes - so the verdict the server computes
and the verdict a client claims are spoken in one language.

**A refusal is not a low score.** A proof that fails a gate produces no `Fused` at
all, so it arrives here as a `GateError` through `refuse` instead. Its status comes
from a classification of the reason code, not from arithmetic, because there is no
arithmetic: nothing about a forged signature is a matter of degree.

**Suspicion is reserved for self-contradiction.** On the admitted path the only
route to SUSPICIOUS is a document that disagrees with itself - a capture instant
ahead of the server, a capture that predates the challenge it answers, hop times
that do not increase. A failed biometric is not suspicious; a dropped foreign frame
is not suspicious. `gates` already explains why: a rogue device can append a hop to
any chain within radio range, so treating attached-and-unverifiable evidence as
incriminating would hand an attacker the power to deny attendance to any student
nearby. Adverse evidence lowers a verdict toward review. It never accuses.

**A local check that answered "not this person" does not mark anybody present.**
This is the one rule here that is not about a number, and it is the one most easily
mistaken for a contradiction of the layer below. `features` files a failed biometric
as a value rather than an absence and `fusion` credits it in full, both correctly:
an absence would make a wet thumb indistinguishable from a forged proof. Neither
argument says an unauditable local check that came back negative should clear a
student unattended. So FAILED and CANCELLED route to review. The student with the
wet thumb pays one tap from a teacher; the student holding a borrowed phone pays the
thing they were trying to avoid. A check that never ran is not in this rule at all -
the score already accounts for an uncredited weight, and charging it twice would
punish a handset for lacking hardware.

**A high score over thin coverage is not PRESENT.** This is the obligation `fuse`
hands over in as many words: a posterior is a probability under the artifact's own
weights and says nothing about how much of the evidence base existed. On this build
the two largest weights in the table are RESERVED and unbuildable, so a flawless
handset reaches about a quarter of the designed ceiling. `min_coverage_pct` is that
accepted residual risk written down as a number a reviewer can move, rather than as
a caveat someone has to remember to repeat.

**What this module does not carry.** There is no `model_version`, though the plan
lists one. No model has been fitted - `calibrate.py` does not exist yet - so the
field would hold either a lie or a placeholder, and an audit row is worth less with
a fabricated version in it than with an absent one. When a fitted model arrives it
gets a field and an artifact entry together.

**An honest consequence of the operating points below, stated where it cannot be
missed:** on this artifact PRESENT requires the complete authentication block, and
a handset with no platform biometric cannot assemble one. Such a student lands in
SECONDARY - a review queue, not a rejection, and never a lower score for owning the
wrong phone. That is decision 3 working as agreed rather than a defect, and
`present_millinats` is the single number that changes it.
"""
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple

from . import chain, challenge, config, fusion, gates, origin, proof, replay

# One vocabulary for the verdict, shared with the wire format a client speaks.
PRESENT = proof.STATUS_PRESENT
SECONDARY = proof.STATUS_SECONDARY
NOT_VERIFIED = proof.STATUS_NOT_VERIFIED
SUSPICIOUS = proof.STATUS_SUSPICIOUS

PARAMETER_PREFIX = "decide."


class DecisionError(Exception):
    """A decision that cannot be stated, which is never answered with a guess."""


# --- Why a verdict is what it is -------------------------------------------
#
# A reason code is the only part of a decision a person reads, so each one names
# the check that produced it and nothing about how the check works. The refusal
# path adds none of its own: it reports the gate's code verbatim, because
# inventing a second name for a refusal already named would leave two vocabularies
# describing one event.

BELOW_PRESENT = "decide_score_below_present"
BELOW_SECONDARY = "decide_score_below_secondary"
COVERAGE_TOO_THIN = "decide_coverage_below_minimum"
SUPPLIED_TOO_THIN = "decide_supplied_below_minimum"
ADVERSE_EVIDENCE = "decide_adverse_evidence_present"
BIOMETRIC_NOT_AFFIRMATIVE = "decide_biometric_not_affirmative"
SELF_CONTRADICTION = "decide_self_contradiction"

REASON_CODES = frozenset({
    BELOW_PRESENT,
    BELOW_SECONDARY,
    COVERAGE_TOO_THIN,
    SUPPLIED_TOO_THIN,
    ADVERSE_EVIDENCE,
    BIOMETRIC_NOT_AFFIRMATIVE,
    SELF_CONTRADICTION,
})

# The one biometric outcome that clears a student without a person looking.
#
# `features` is right that a failed check is a value and not an absence, and
# `fusion` is right to credit it in full: filing it as an absence would make a wet
# thumb indistinguishable from a forged proof, and a negative weight would need a
# likelihood ratio for failed-given-proxying that nobody has measured. Neither of
# those arguments says an unaudited local check that answered "not this person"
# should mark somebody present unattended. That is a routing question, it needs no
# arithmetic, and this is the layer for it - so FAILED and CANCELLED go to review,
# which costs the student with the wet thumb one tap from a teacher and costs
# somebody holding a borrowed phone the thing they were trying to avoid.
AFFIRMATIVE_BIOMETRIC = frozenset({proof.BIOMETRIC_SUCCESS})


# --- What a refusal was shaped like ----------------------------------------
#
# Every reason code `gates` can raise is classified here, exactly once, into one of
# two shapes. The partition is asserted total against `gates.REASON_CODES` at import
# and again in the tests, so a new reason code added anywhere downstream fails the
# build until somebody decides what it means. That is deliberate: the alternative is
# a default arm, and a default arm is how a forgery-shaped refusal quietly starts
# reporting as a network problem.
#
# FORGERY_SHAPED is not an accusation of a person. It says the document could not
# have been produced by following the protocol - a signature that does not verify, a
# key nobody enrolled, a challenge for a step the session has not reached. There is
# no honest client path to any of them, so a review queue is the right destination
# and a silent "not verified" is not.
FORGERY_SHAPED = frozenset({
    proof.BAD_SIGNATURE,
    proof.KEY_MISMATCH,
    proof.SESSION_MISMATCH,
    challenge.WRONG_SESSION,
    challenge.UNKNOWN_KEY,
    challenge.BAD_SIGNATURE,
    challenge.FORGED,
    challenge.LINK_BROKEN,
    challenge.FUTURE_STEP,
    replay.NONCE_REUSED,
    replay.STEP_REGRESSION,
    replay.STEP_NOT_YET_ISSUED,
    gates.UNKNOWN_DEVICE,
    gates.DEVICE_REVOKED,
    gates.OBSERVATION_NOT_COMMITTED,
})

# UNRESOLVED covers everything a working client can hit by being late, being on a
# slow clock, or being pointed at a session that has moved on. A stale step lives
# here and not above, even though a forwarded screenshot is exactly what produces
# one, because a slow scan from the back of a crowded room produces the same code
# and the humane default is a review rather than an accusation. `accept_window_steps`
# is where that tolerance is tuned; this is only where its overflow is named.
UNRESOLVED = frozenset({
    proof.MALFORMED,
    challenge.MALFORMED,
    challenge.EXPIRED,
    challenge.NOT_YET_VALID,
    challenge.TIMING_INCONSISTENT,
    challenge.STALE_STEP,
    replay.MALFORMED,
    replay.TOO_OLD,
    replay.DUPLICATE_PROOF,
    gates.DEVICE_NOT_ENROLLED,
    gates.SESSION_NOT_OPEN,
})

_UNCLASSIFIED = gates.REASON_CODES - FORGERY_SHAPED - UNRESOLVED
_DOUBLE_CLASSIFIED = FORGERY_SHAPED & UNRESOLVED
if _UNCLASSIFIED or _DOUBLE_CLASSIFIED:  # pragma: no cover - import-time guard
    raise DecisionError(
        "the refusal classification does not partition gates.REASON_CODES: "
        "unclassified %s, classified twice %s. Every reason code must have exactly "
        "one shape, or a refusal has no defined status."
        % (sorted(_UNCLASSIFIED), sorted(_DOUBLE_CLASSIFIED))
    )


# --- Which signals are a document disagreeing with itself -------------------
#
# `gates` reports signals rather than refusing on them, because none of them is
# proof of anything on its own. This is where the few that are self-contradictory
# get separated from the ones that are merely worth writing down.
#
# The asymmetry between the two origin claims is intentional. A handset whose clock
# runs slow reports observing a frame earlier than the counter allows, which is the
# commonest misconfiguration in the world; a handset reporting a frame from ahead of
# the counter has to have been set forward. The artifact already encodes that same
# asymmetry - `proof.max_future_skew_seconds` bounds one direction and nothing
# bounds the other - so following it here keeps one judgement in one place.
CONTRADICTION_SIGNALS = frozenset({
    replay.SIGNAL_FUTURE_CLAIM,
    replay.SIGNAL_CLAIM_PREDATES_CHALLENGE,
    origin.CLAIM_AHEAD,
    chain.CLAIM_NON_MONOTONIC,
})

# Recorded on the decision, never routed on. A capability bit this build does not
# know is a newer client, not a liar; a chain sitting exactly at the hop limit is a
# boundary worth seeing in the audit trail and nothing more.
NOTED_SIGNALS = gates.SIGNALS - CONTRADICTION_SIGNALS

# The one refusal a caller should not record as a fresh verdict. `replay` says it in
# as many words: a repeated digest is normally a client retrying a sync it could not
# confirm, so the endpoint should answer with the verdict already stored rather than
# overwriting a PRESENT with the NOT VERIFIED this module has no choice but to return
# for it. Exposed as a set so that logic lives at the boundary, once, instead of
# being rediscovered by whoever writes the next caller.
IDEMPOTENT = frozenset({replay.DUPLICATE_PROOF})


@dataclass(frozen=True)
class Policy:
    """The operating points in force, read from the artifact and never inlined."""

    present_millinats: int
    secondary_millinats: int
    min_coverage_pct: int
    min_supplied_pct: int
    config_version: str
    calibration: str = config.UNCALIBRATED

    @classmethod
    def load(cls, artifact: Optional[config.Artifact] = None) -> "Policy":
        """The operating points from one artifact, defaulting to the active one.

        The parameter exists so a caller judging an old proof can pass the artifact
        that proof's session was opened under. `fusion.Weights.load` takes the same
        argument for the same reason, and `decide` refuses a score and a threshold
        that came from different versions - so passing one here and forgetting it
        there fails loudly instead of quietly mixing two configurations.

        `calibration` travels with the points rather than being read separately,
        because a refusal has no score to carry it and would otherwise report
        today's calibration state against an old artifact's version.
        """
        artifact = artifact if artifact is not None else config.active()
        return cls(
            present_millinats=artifact[PARAMETER_PREFIX + "present_millinats"],
            secondary_millinats=artifact[PARAMETER_PREFIX + "secondary_millinats"],
            min_coverage_pct=artifact[PARAMETER_PREFIX + "min_coverage_pct"],
            min_supplied_pct=artifact[PARAMETER_PREFIX + "min_supplied_pct"],
            config_version=artifact.version,
            calibration=artifact.calibration,
        )

    def describe(self) -> Dict[str, Any]:
        return {
            "present_millinats": self.present_millinats,
            "secondary_millinats": self.secondary_millinats,
            "min_coverage_pct": self.min_coverage_pct,
            "min_supplied_pct": self.min_supplied_pct,
            "config_version": self.config_version,
            "calibration": self.calibration,
        }


@dataclass(frozen=True)
class Decision:
    """A verdict, and everything a person would need to argue with it.

    Deliberately not a number with a label attached. `reasons` says why this is not
    a better verdict, `evidence_present` and `evidence_missing` say what the score
    was built from and what was never there to build with, and `policy` and
    `config_version` say under which rules - so a decision from last term can be
    re-argued with the parameters that were actually in force.

    `confidence_milli` is None whenever the artifact is not field-validated, and
    that absence is the honest answer rather than a gap: a score under uncalibrated
    weights orders candidates and is not a probability, so there is no percentage to
    show a student. `millinats` remains available for ordering a review queue.
    """

    status: int
    millinats: int
    reasons: Tuple[str, ...]
    evidence_present: Tuple[str, ...]
    evidence_missing: Mapping[str, str]
    empty_blocks: Tuple[str, ...]
    signals: Tuple[str, ...]
    contradictions: Tuple[str, ...]
    adverse: Tuple[str, ...]
    policy: Policy
    calibration: str
    config_version: str
    coverage_pct: Optional[float] = None
    supplied_pct: Optional[float] = None
    confidence_milli: Optional[int] = None
    ordering_only: bool = True
    ordering_reason: str = ""
    gate_code: Optional[str] = None
    fused: Optional[fusion.Fused] = None

    def __post_init__(self) -> None:
        if self.status not in proof.STATUS_NAMES or self.status == proof.STATUS_UNKNOWN:
            raise DecisionError(
                "%r is not one of the four verdicts. There is no fifth outcome and "
                "no unknown one: a proof this layer has seen has been ruled on."
                % (self.status,)
            )
        undeclared = set(self.reasons) - REASON_CODES - gates.REASON_CODES
        if undeclared:
            raise DecisionError(
                "undeclared reason code(s) %s. A reason a person reads must be one "
                "this package declares, or the vocabulary drifts and the audit trail "
                "stops being comparable across versions." % (sorted(undeclared),)
            )
        if self.ordering_only != (self.confidence_milli is None):
            raise DecisionError(
                "ordering_only and confidence_milli disagree. A verdict either "
                "carries a calibrated probability or it carries an ordering; there "
                "is no third state for a caller to interpret."
            )
        if (self.gate_code is None) == (self.fused is None):
            raise DecisionError(
                "a decision rests on exactly one of a refusal and a score. This one "
                "carries %s, which means the two paths have been mixed and a reader "
                "could not tell whether the proof was weighed or rejected."
                % ("both" if self.gate_code is not None else "neither",)
            )

    @property
    def status_name(self) -> str:
        return proof.STATUS_NAMES[self.status]

    @property
    def refused(self) -> bool:
        """Whether this verdict came from a gate rather than from arithmetic."""
        return self.gate_code is not None

    @property
    def idempotent_retry(self) -> bool:
        """Whether the caller should answer with a stored verdict instead of this."""
        return self.gate_code in IDEMPOTENT

    def describe(self) -> Dict[str, Any]:
        """The audit row. JSON-safe, and it records what was weighed, not who.

        The same discipline `Fused.describe` keeps: no identifier, no nonce, no
        observation digest and no signal strength reaches this dictionary, because
        it is written to a durable table and read by a teacher.
        """
        return {
            "status": self.status,
            "status_name": self.status_name,
            "millinats": self.millinats,
            "coverage_pct": self.coverage_pct,
            "supplied_pct": self.supplied_pct,
            "confidence_milli": self.confidence_milli,
            "ordering_only": self.ordering_only,
            "ordering_reason": self.ordering_reason,
            "reasons": list(self.reasons),
            "evidence_present": list(self.evidence_present),
            "evidence_missing": dict(self.evidence_missing),
            "empty_blocks": list(self.empty_blocks),
            "signals": list(self.signals),
            "contradictions": list(self.contradictions),
            "adverse": list(self.adverse),
            "gate_code": self.gate_code,
            "refused": self.refused,
            "calibration": self.calibration,
            "config_version": self.config_version,
            "policy": self.policy.describe(),
            "fused": self.fused.describe() if self.fused is not None else None,
        }


def _meets(fraction: Optional[float], minimum: int) -> bool:
    """Whether a fraction clears a floor, treating an absent fraction as failing.

    A fraction is absent only when its denominator was zero - for `supplied_pct`,
    a handset on which nothing at all was obtainable. Reading that as a pass would
    make the emptiest possible evidence base clear a coverage floor, so it reads as
    a failure; it is never the only reason, because such a vector scores nothing and
    fails on score first.
    """
    return fraction is not None and fraction >= minimum


def _evidence(fused: fusion.Fused) -> Tuple[Tuple[str, ...], Mapping[str, str]]:
    """What was weighed and what was not, taken from the contributions themselves.

    Derived rather than listed, so a feature added to the vector appears here the
    moment it is priced and cannot be forgotten in a second hand-maintained table.
    """
    supplied = []
    absent = {}
    for block in fused.blocks:
        for contribution in block.contributions:
            if contribution.present:
                supplied.append(contribution.feature)
            else:
                absent[contribution.feature] = contribution.absent
    return tuple(supplied), MappingProxyType(absent)


def decide(
    fused: fusion.Fused,
    *,
    biometric: int,
    policy: Optional[Policy] = None,
) -> Decision:
    """Rule on a score. The argument list is the security property.

    A `fusion.Fused` and one recorded outcome come in, so the client's own claimed
    status, confidence and hop count are not merely ignored - they are unreachable
    from here. That is the never-trust-the-client rule expressed as a signature
    rather than as a comment somebody could delete.

    `biometric` is one of `proof.BIOMETRIC_*`, taken from the body `gates` has
    already verified the signature over. It is a keyword with no default on purpose:
    a caller that forgets it gets a `TypeError` rather than a silent PRESENT for a
    check that came back negative. It is a recorded fact and not a claim about the
    verdict, which is the line this module draws - `Cleared.claims` stays out of
    reach, a signed outcome does not.
    """
    if not isinstance(fused, fusion.Fused):
        raise DecisionError(
            "decide takes a fusion.Fused and nothing else. A gates.Cleared carries "
            "the client's own claimed verdict, and a policy layer that could read "
            "one would eventually read it."
        )
    if isinstance(biometric, bool) or biometric not in proof.BIOMETRIC_NAMES:
        raise DecisionError(
            "%r is not a biometric outcome this build has a name for. An outcome "
            "nobody can name cannot be routed on, and guessing which side of the "
            "line it falls is how an unknown becomes an acceptance. A bool is "
            "refused for the same reason it looks harmless: False would read as "
            "BIOMETRIC_ABSENT, quietly turning a check that answered no into a "
            "check that never ran and dropping the reason code with it."
            % (biometric,)
        )
    policy = policy if policy is not None else Policy.load()
    if fused.config_version != policy.config_version:
        raise DecisionError(
            "the score was computed under artifact %r and the operating points come "
            "from %r. Judging one artifact's arithmetic by another's thresholds is "
            "how a rollout produces verdicts that cannot be reproduced."
            % (fused.config_version, policy.config_version)
        )

    contradictions = tuple(s for s in fused.signals if s in CONTRADICTION_SIGNALS)

    # Every way this proof falls short of PRESENT, gathered before any status is
    # chosen, so the same list explains a SECONDARY and qualifies a SUSPICIOUS.
    shortfalls = []
    if fused.millinats < policy.present_millinats:
        shortfalls.append(BELOW_PRESENT)
    if not _meets(fused.coverage_pct, policy.min_coverage_pct):
        shortfalls.append(COVERAGE_TOO_THIN)
    if not _meets(fused.supplied_pct, policy.min_supplied_pct):
        shortfalls.append(SUPPLIED_TOO_THIN)
    if fused.adverse:
        shortfalls.append(ADVERSE_EVIDENCE)
    # ABSENT is deliberately not here. A check that never ran is already answered by
    # the score - the weight simply is not credited - and calling it adverse as well
    # would charge a handset without the hardware twice for the same missing thing.
    if biometric != proof.BIOMETRIC_ABSENT and biometric not in AFFIRMATIVE_BIOMETRIC:
        shortfalls.append(BIOMETRIC_NOT_AFFIRMATIVE)

    if contradictions:
        status = SUSPICIOUS
        reasons = (SELF_CONTRADICTION,) + tuple(shortfalls)
    elif not shortfalls:
        status = PRESENT
        reasons = ()
    elif fused.millinats >= policy.secondary_millinats:
        status = SECONDARY
        reasons = tuple(shortfalls)
    else:
        # BELOW_SECONDARY implies BELOW_PRESENT, and reporting both would pad the
        # list a person reads with an inference they can make themselves.
        status = NOT_VERIFIED
        reasons = (BELOW_SECONDARY,) + tuple(
            reason for reason in shortfalls if reason != BELOW_PRESENT
        )

    supplied, absent = _evidence(fused)
    return Decision(
        status=status,
        millinats=fused.millinats,
        reasons=reasons,
        evidence_present=supplied,
        evidence_missing=absent,
        empty_blocks=fused.empty_blocks,
        signals=fused.signals,
        contradictions=contradictions,
        adverse=fused.adverse,
        policy=policy,
        calibration=fused.calibration,
        config_version=fused.config_version,
        coverage_pct=fused.coverage_pct,
        supplied_pct=fused.supplied_pct,
        confidence_milli=fused.posterior_milli,
        ordering_only=fused.ordering_only,
        ordering_reason=fused.ordering_reason,
        fused=fused,
    )


def refuse(error: gates.GateError, *, policy: Optional[Policy] = None) -> Decision:
    """Turn a gate refusal into a verdict, with no arithmetic anywhere in it.

    A refused proof has no score to fall short of a threshold, so nothing here is
    compared to anything. The status comes from the shape of the reason code, and the
    reason reported is the gate's own code unaltered: one event, one name.
    """
    if not isinstance(error, gates.GateError):
        raise DecisionError(
            "refuse takes a gates.GateError. Any other exception on the proof path "
            "is a defect in this server, and answering a defect with a verdict about "
            "a student would put our bug in their attendance record."
        )
    policy = policy if policy is not None else Policy.load()
    code = error.code
    if code in FORGERY_SHAPED:
        status = SUSPICIOUS
    elif code in UNRESOLVED:
        status = NOT_VERIFIED
    else:  # pragma: no cover - the import-time partition guard forbids this
        raise DecisionError(
            "reason code %r has no classified shape, so its verdict is undefined. "
            "Classify it in FORGERY_SHAPED or UNRESOLVED." % (code,)
        )
    return Decision(
        status=status,
        millinats=0,
        reasons=(code,),
        evidence_present=(),
        evidence_missing=MappingProxyType({}),
        empty_blocks=(),
        signals=(),
        contradictions=(),
        adverse=(),
        policy=policy,
        calibration=policy.calibration,
        config_version=policy.config_version,
        ordering_reason=(
            "the proof was refused before it was weighed, so there is no score here "
            "to order by and no confidence to state"
        ),
        gate_code=code,
    )
