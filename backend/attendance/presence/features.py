"""One cleared proof, sorted into the evidence a decision can be made from.

This module counts, converts and labels. It computes no score, compares nothing
to a threshold, and reaches no verdict - `fusion` weighs and `decide` concludes.
Keeping those apart is what stops a tuned number appearing here, where it would
be invisible: a threshold inside a feature extractor looks like data cleaning.

**Four blocks, because the features inside one are not independent of each
other.** §21 forbids multiplying evidence as though it were independent, and the
correlations are not subtle: a valid challenge is nearly a function of a valid
session, and a relay hop is nearly a function of an origin sighting. So features
arrive grouped - `authentication`, `network`, `spatial`, `temporal` - and `fusion`
accumulates *across* blocks with an explicit dependency treatment *within* each.
The grouping is declared here, next to the features, rather than left for the
fusion layer to remember.

**Four kinds of absence, never one.** This is the module's main content and the
reason it is a module rather than a dict comprehension. A feature that is not
present says which of these it is:

`UNSUPPORTED` - the handset declared it cannot do this. A student holding a phone
with no BLE peripheral mode has done nothing wrong, and decision 3 of the plan is
explicit that missing evidence lowers confidence toward SECONDARY and is never
negative evidence. Charging it to them would make attendance a function of
hardware budget.

`NOT_OBSERVED` - the handset can do this and produced nothing. Weakly informative
at most: a phone in a bag hears no advertisement, and on the current scope most
handsets cannot scan at all, so silence is close to uninformative.

`FAILED` - evidence arrived and did not verify. The only absence carrying adverse
information, and even here the chain argument from `gates` applies: a rogue relay
can poison anyone's chain, so this degrades toward SECONDARY and never toward
SUSPICIOUS on its own.

`RESERVED` - this build has no mechanism for the feature at all. The whole spatial
block is RESERVED on the current scope, because Phase 5's anchors are not bought
and not built. Distinct from `UNSUPPORTED` on purpose: one is a fact about the
deployment and the other a fact about the handset, and collapsing them would let a
future build's genuine capability gap read as today's deliberate gap.

**No value is invented.** A `Feature` holds a value or an absence, never both and
never a default that reads as a measurement. `Feature.__post_init__` enforces it,
so the invariant cannot be forgotten by a later caller. The analytics engine's own
markers (`metrics.safe_pct` returning None, `context.insufficient`) answer a
different question - *is the sample big enough* - which is a calibration concern
rather than a per-proof one, so they are not borrowed here. The departure is
deliberate and it is stated rather than assumed.

**Every value names where it came from.** `Feature.derived_from` is non-empty
whenever a value is present, and it names observations rather than modules, so an
audit row can be read back to the bytes that produced it. That is the analytics
layer's second invariant, carried over verbatim.

**Nothing here decides that a signal is bad.** RSSI readings are carried as the
tuple that was recorded, unreduced: no mean, no minimum, no comparison. §16
forbids `RSSI > threshold = present`, and a single averaged number is one step
away from exactly that, so the averaging does not happen - not here and not
downstream of here without a room profile that does not yet exist.
"""
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from types import MappingProxyType

from . import codec, gates, proof

# --- Blocks -----------------------------------------------------------------

AUTHENTICATION = "authentication"
NETWORK = "network"
SPATIAL = "spatial"
TEMPORAL = "temporal"

BLOCKS = (AUTHENTICATION, NETWORK, SPATIAL, TEMPORAL)

# --- Why a feature is not present -------------------------------------------

UNSUPPORTED = "unsupported"
NOT_OBSERVED = "not_observed"
FAILED = "failed"
RESERVED = "reserved"

ABSENCE_REASONS = frozenset({UNSUPPORTED, NOT_OBSERVED, FAILED, RESERVED})

# Which absences a fusion layer may treat as bearing on the student at all. Named
# here, as a set, so that "missing evidence is not negative evidence" is something
# a test can assert rather than a sentence in a document.
ADVERSE_ABSENCES = frozenset({FAILED})
BENIGN_ABSENCES = ABSENCE_REASONS - ADVERSE_ABSENCES

# --- The features -----------------------------------------------------------

IDENTITY = "identity_authenticated"
DEVICE = "device_bound"
CHALLENGE = "challenge_committed"
BIOMETRIC = "biometric_outcome"
PLATFORM = "platform_declared"

ORIGIN_DIRECT = "origin_direct"
RELAY_DEPTH = "relay_depth"
RELAY_INTEGRITY = "relay_integrity"

ANCHOR_FINGERPRINT = "anchor_fingerprint"
SPATIAL_STABILITY = "spatial_stability"

QUEUE_AGE = "queue_age"
CLOCK_CONSISTENCY = "clock_consistency"

# The vector, in the order a reader should meet it, with each feature's block.
# One table rather than four lists: a feature that belongs to no block, or to two,
# is then a syntax error rather than a discrepancy nobody notices.
FEATURES: Mapping[str, str] = MappingProxyType({
    IDENTITY: AUTHENTICATION,
    DEVICE: AUTHENTICATION,
    CHALLENGE: AUTHENTICATION,
    BIOMETRIC: AUTHENTICATION,
    PLATFORM: AUTHENTICATION,
    ORIGIN_DIRECT: NETWORK,
    RELAY_DEPTH: NETWORK,
    RELAY_INTEGRITY: NETWORK,
    ANCHOR_FINGERPRINT: SPATIAL,
    SPATIAL_STABILITY: SPATIAL,
    QUEUE_AGE: TEMPORAL,
    CLOCK_CONSISTENCY: TEMPORAL,
})

# The spatial block, as a fact about this build rather than about any handset.
# Phase 5 replaces this constant with two extractors; until it does, a decision
# that reads the spatial block gets an explicit RESERVED and cannot mistake the
# absence of a mechanism for the absence of a student.
RESERVED_FEATURES = frozenset({ANCHOR_FINGERPRINT, SPATIAL_STABILITY})

# What the handset must have declared for an absence to mean anything other than
# UNSUPPORTED. A feature with no entry here is one no capability bit gates.
GATING_CAPABILITY: Mapping[str, int] = MappingProxyType({
    BIOMETRIC: proof.CAP_BIOMETRIC,
    ORIGIN_DIRECT: proof.CAP_BLE_SCAN,
    RELAY_DEPTH: proof.CAP_RELAY,
    RELAY_INTEGRITY: proof.CAP_RELAY,
})


# --- Where a value came from -------------------------------------------------
#
# Attached evidence is named by the digest the signed proof committed to, not by
# its position in a list. Position is an accident of transmission and two proofs
# with the same evidence in a different order would produce different audit rows;
# the digest is the thing the signature actually covers, so a row naming it can be
# read back to the bytes by anyone holding the observation, and cannot be read back
# to anything else.

SOURCE_PROOF = "proof"
SOURCE_RECEIPT = "receipt"

FIXED_SOURCES = frozenset({SOURCE_PROOF, SOURCE_RECEIPT})

# The observation kinds that may name themselves as a source. Phase 5's anchor
# readings are listed now because the codec already declares the schema; nothing
# produces one yet, which is what `RESERVED` is for.
SOURCE_KINDS = frozenset({
    codec.ORIGIN_SIGHTING.name,
    codec.RELAY_HOP.name,
    codec.ANCHOR_READING.name,
})


def evidence_source(kind: str, digest: bytes) -> str:
    """Name one attached observation by the digest its proof committed to."""
    if kind not in SOURCE_KINDS:
        raise FeatureError("no observation kind %r may name itself a source" % (kind,))
    return "%s:%s" % (kind, digest.hex())


def is_source(name: str) -> bool:
    """Whether a `derived_from` entry names something that can be looked up.

    Enforced rather than documented. "Every value traces back to an observation"
    is the analytics layer's second invariant, and an invariant that only a docstring
    holds is one a busy afternoon removes.
    """
    if name in FIXED_SOURCES:
        return True
    kind, _, rest = name.partition(":")
    if kind not in SOURCE_KINDS or not rest:
        return False
    try:
        bytes.fromhex(rest)
    except ValueError:
        return False
    return True


class FeatureError(Exception):
    """A vector was built from something that is not a cleared proof."""


@dataclass(frozen=True)
class Feature:
    """One observation, or one labelled reason there isn't one.

    `value` is whatever the feature measures and is never a score. `absent` is one
    of `ABSENCE_REASONS`. Exactly one of the two is set, which is the invariant the
    whole module exists to hold: a caller cannot read a zero and a caller cannot
    read a None without being told which kind of nothing it is.
    """

    name: str
    block: str
    value: Optional[Any] = None
    absent: Optional[str] = None
    derived_from: Tuple[str, ...] = ()
    detail: str = ""

    def __post_init__(self):
        if self.name not in FEATURES:
            raise FeatureError("undeclared feature %r" % (self.name,))
        if FEATURES[self.name] != self.block:
            raise FeatureError(
                "feature %r belongs to block %r, not %r"
                % (self.name, FEATURES[self.name], self.block)
            )
        if (self.value is None) == (self.absent is None):
            raise FeatureError(
                "feature %r must carry exactly one of a value and an absence"
                % (self.name,)
            )
        if self.absent is not None and self.absent not in ABSENCE_REASONS:
            raise FeatureError("undeclared absence reason %r" % (self.absent,))
        if self.value is not None and not self.derived_from:
            raise FeatureError(
                "feature %r has a value and names nothing it was derived from"
                % (self.name,)
            )
        for source in self.derived_from:
            if not is_source(source):
                raise FeatureError(
                    "feature %r names %r, which nothing can be looked up from"
                    % (self.name, source)
                )

    @property
    def present(self) -> bool:
        return self.value is not None

    @property
    def adverse(self) -> bool:
        """Whether this absence bears on the student. Only `FAILED` ever does."""
        return self.absent in ADVERSE_ABSENCES

    def describe(self) -> Dict[str, Any]:
        summary: Dict[str, Any] = {"name": self.name, "block": self.block}
        if self.present:
            summary["value"] = self.value
            summary["derived_from"] = list(self.derived_from)
        else:
            summary["absent"] = self.absent
        if self.detail:
            summary["detail"] = self.detail
        return summary


@dataclass(frozen=True)
class Evidence:
    """The sparse vector for one proof, complete in names and sparse in values.

    Complete in names is the point. Every feature in `FEATURES` appears, so a
    downstream layer iterates a fixed vocabulary and can never silently skip a
    block because nothing populated it - which is how a spatial claim would end up
    resting on an empty block.
    """

    features: Mapping[str, Feature]
    config_version: str = ""
    signals: Tuple[str, ...] = ()

    def __post_init__(self):
        missing = sorted(set(FEATURES) - set(self.features))
        if missing:
            raise FeatureError(
                "vector is missing %s; every feature must be named even when it "
                "has no value" % (", ".join(missing),)
            )
        for signal in self.signals:
            if signal not in gates.SIGNALS:
                raise FeatureError("undeclared signal %r" % (signal,))

    def __getitem__(self, name: str) -> Feature:
        return self.features[name]

    def block(self, name: str) -> Tuple[Feature, ...]:
        if name not in BLOCKS:
            raise FeatureError("undeclared block %r" % (name,))
        return tuple(f for f in self.features.values() if f.block == name)

    def present(self) -> Tuple[str, ...]:
        return tuple(n for n, f in self.features.items() if f.present)

    def absent(self, reason: Optional[str] = None) -> Tuple[str, ...]:
        return tuple(
            n
            for n, f in self.features.items()
            if not f.present and (reason is None or f.absent == reason)
        )

    def block_is_empty(self, name: str) -> bool:
        """Whether a whole block contributed nothing. Asked by `fusion` per block.

        A block with no values must not be allowed to look like a block whose
        values happened to be unremarkable, because the difference between them is
        the difference between "no spatial evidence exists" and "the student was in
        the room".
        """
        return not any(f.present for f in self.block(name))

    def describe(self) -> Dict[str, Any]:
        """For an audit row. No key material, no student, no raw observation."""
        return {
            "features": [f.describe() for f in self.features.values()],
            "present": list(self.present()),
            "absent": {
                reason: list(self.absent(reason))
                for reason in sorted(ABSENCE_REASONS)
                if self.absent(reason)
            },
            "empty_blocks": [b for b in BLOCKS if self.block_is_empty(b)],
            "signals": list(self.signals),
            "config_version": self.config_version,
        }


# --- Choosing which absence applies -----------------------------------------

def absence(feature: str, *, capabilities: int, failed: bool) -> str:
    """Which of the four kinds of nothing this is. The order is the argument.

    `RESERVED` first, because a mechanism this build does not have cannot have
    failed and cannot be a handset's shortcoming. Reading a missing anchor as
    `UNSUPPORTED` would quietly blame every phone in the room for a decision about
    procurement.

    `FAILED` next, ahead of the capability check, because evidence that arrived and
    did not verify says something whatever the handset claims about itself. A
    handset that declares no relay capability and then submits a chain that does
    not verify is more interesting than one that stayed quiet, not less, and
    letting the capability bit suppress that would hand an attacker a way to file
    failures under "old phone".

    `UNSUPPORTED` before `NOT_OBSERVED`, because a declared incapacity explains
    silence completely and silence from a capable handset does not.
    """
    if feature not in FEATURES:
        raise FeatureError("undeclared feature %r" % (feature,))
    if feature in RESERVED_FEATURES:
        return RESERVED
    if failed:
        return FAILED
    flag = GATING_CAPABILITY.get(feature)
    if flag is not None and not capabilities & flag:
        return UNSUPPORTED
    return NOT_OBSERVED


def _kinds_dropped(cleared: gates.Cleared) -> frozenset:
    """The observation kinds that arrived and did not survive.

    Read from `Cleared.dropped` rather than reconstructed, because the gate is the
    only thing that knows the difference between evidence that failed and evidence
    that never came. Deriving it here from counts would collapse exactly the
    distinction `Dropped` exists to preserve.
    """
    return frozenset(d.kind for d in cleared.dropped)


# --- The four blocks --------------------------------------------------------

def _authentication(cleared: gates.Cleared) -> Tuple[Feature, ...]:
    """The block whose features are near-functions of one another.

    Identity, device binding and the committed challenge are all `True` on any
    proof that reached here, because each is a hard gate and a proof that failed
    one never became a `Cleared`. That is not a padded vector: it is the honest
    shape of the evidence, and it is precisely why these five sit in one block
    rather than five. A fusion layer multiplying them as independent findings
    would count one signature three times.

    What actually varies inside the block is the biometric outcome and the
    platform, and those are the two the fusion weights will end up resting on.
    """
    body = cleared.signed.proof
    features = [
        Feature(
            IDENTITY,
            AUTHENTICATION,
            value=True,
            derived_from=(SOURCE_PROOF,),
            detail="the signature verified under a key this institution has bound "
                   "to a student on this session's roster",
        ),
        Feature(
            DEVICE,
            AUTHENTICATION,
            value=True,
            derived_from=(SOURCE_PROOF,),
            detail="the proof named the key it was checked against, and that key "
                   "is registered, unrevoked and enrolled here",
        ),
        Feature(
            CHALLENGE,
            AUTHENTICATION,
            value=(body.challenge_epoch, body.challenge_seq),
            derived_from=(SOURCE_PROOF,),
            detail="the epoch and step the proof committed to, re-derived from this "
                   "session's own key rather than taken from the submission",
        ),
    ]
    features.extend(_biometric(body))
    features.append(_platform(body))
    return tuple(features)


def _biometric(body: proof.Proof) -> Tuple[Feature, ...]:
    """The outcome as recorded, including the negative one.

    A failed fingerprint is a value, not an absence. This is the distinction the
    module's four reasons are easiest to get wrong on: `FAILED` here means evidence
    that arrived and did not verify - a signature that did not check, a chain that
    did not root - whereas a biometric that verified perfectly and returned "no
    match" is a measurement with an unwelcome result. Filing it as an absence would
    lose the difference between a wet thumb and a forged proof, and the student with
    the wet thumb is the one who pays for that.

    Nothing here refuses anything on a biometric, and `gates` has a test asserting
    no reason code in its whole vocabulary mentions one. `fusion` weighs the outcome.
    """
    if body.biometric == proof.BIOMETRIC_ABSENT:
        return (
            Feature(
                BIOMETRIC,
                AUTHENTICATION,
                absent=absence(
                    BIOMETRIC,
                    capabilities=body.capabilities,
                    failed=False,
                ),
                detail="no biometric outcome was submitted",
            ),
        )
    return (
        Feature(
            BIOMETRIC,
            AUTHENTICATION,
            value=body.biometric_name,
            derived_from=(SOURCE_PROOF,),
            detail="the platform's own verdict, carried as a verdict; no template, "
                   "image or score is submitted or stored",
        ),
    )


def _platform(body: proof.Proof) -> Feature:
    """Which degraded mode applies, and what the handset says it can do.

    An unrecognised platform is a value rather than a refusal, matching the open
    half of the asymmetry `proof` already argues: an older server that rejected a
    newer handset outright would punish a student who has done nothing wrong.
    """
    declared = ", ".join(body.capability_names()) or "none declared"
    if body.platform == proof.PLATFORM_UNKNOWN:
        return Feature(
            PLATFORM,
            AUTHENTICATION,
            absent=absence(PLATFORM, capabilities=body.capabilities, failed=False),
            detail="the handset declared no platform; capabilities: %s" % (declared,),
        )
    return Feature(
        PLATFORM,
        AUTHENTICATION,
        value=body.platform_name,
        derived_from=(SOURCE_PROOF,),
        detail="capabilities: %s" % (declared,),
    )


def _network(cleared: gates.Cleared) -> Tuple[Feature, ...]:
    """Origin sightings and relay custody. Empty on this build, and legibly so.

    No handset in the current scope scans or relays, so all three features here are
    absent on every real proof - `UNSUPPORTED` where the capability bit is clear,
    which is everywhere. The extraction is written out in full anyway: the gate can
    already verify sightings and chains, the tests exercise both, and a block that
    only appears once the hardware does is a block nobody has ever run.
    """
    body = cleared.signed.proof
    dropped = _kinds_dropped(cleared)
    sighting_failed = codec.ORIGIN_SIGHTING.name in dropped
    relay_failed = codec.RELAY_HOP.name in dropped

    if cleared.sightings:
        origin_feature = Feature(
            ORIGIN_DIRECT,
            NETWORK,
            value=tuple(s.rssi for s in cleared.sightings),
            derived_from=tuple(
                evidence_source(codec.ORIGIN_SIGHTING.name, s.digest())
                for s in cleared.sightings
            ),
            detail="received signal strength in dBm for each verified sighting, in "
                   "the order recorded and deliberately unreduced: no mean, no "
                   "minimum, and no comparison to a distance",
        )
    else:
        origin_feature = Feature(
            ORIGIN_DIRECT,
            NETWORK,
            absent=absence(
                ORIGIN_DIRECT,
                capabilities=body.capabilities,
                failed=sighting_failed,
            ),
            detail="a sighting arrived and did not verify"
            if sighting_failed
            else "no sighting of the teacher's origin frame was submitted",
        )
    return (origin_feature,) + _relay(cleared, failed=relay_failed)


def _relay(cleared: gates.Cleared, *, failed: bool) -> Tuple[Feature, ...]:
    """Depth and integrity, which move together on purpose.

    They are two readings of one thing, which is why both sit in the network block
    and neither is fused as independent evidence. Depth is a magnitude and integrity
    is a validity, and keeping them separate matters in one place: when a chain
    arrives and does not verify, depth is `FAILED` rather than zero. A zero would
    read as a measured absence of relaying, which is the ordinary case for almost
    every proof this build will see, and a poisoned chain is not the ordinary case.
    """
    body = cleared.signed.proof
    if not cleared.hops:
        detail = (
            "relay evidence arrived and did not verify"
            if failed
            else "no relay chain was submitted"
        )
        return tuple(
            Feature(
                name,
                NETWORK,
                absent=absence(name, capabilities=body.capabilities, failed=failed),
                detail=detail,
            )
            for name in (RELAY_DEPTH, RELAY_INTEGRITY)
        )

    sources = tuple(
        evidence_source(codec.RELAY_HOP.name, h.digest()) for h in cleared.hops
    )
    return (
        Feature(
            RELAY_DEPTH,
            NETWORK,
            value=len(cleared.hops),
            derived_from=sources,
            detail="hops of custody that verified; taken only when there are hops, "
                   "so a depth of zero can never be read here as a measurement",
        ),
        Feature(
            RELAY_INTEGRITY,
            NETWORK,
            value=True,
            derived_from=sources,
            detail="every hop signature verified against a cohort key, every link "
                   "matched its predecessor, and the chain rooted in a sighting "
                   "that had already verified for this session",
        ),
    )


def _spatial() -> Tuple[Feature, ...]:
    """The block that would answer the question this build cannot answer.

    Both features are `RESERVED`, which is a statement about the deployment: the
    anchors are neither bought nor built. It is kept distinct from `UNSUPPORTED`
    so that when Phase 5 exists, a handset that genuinely cannot hear an anchor is
    not recorded the same way as today's deliberate gap - otherwise a real
    capability limit would be indistinguishable from a procurement decision, and
    the residual risk would stop being visible in the audit trail.

    This is also the block that would defeat the window attack, and the reason the
    plan records that attack as accepted and unmitigated. A vector that quietly
    omitted the block would let a decision rest on an empty spatial claim; naming
    it and marking it reserved is what makes the gap countable.
    """
    return tuple(
        Feature(
            name,
            SPATIAL,
            absent=RESERVED,
            detail="this build has no anchor mechanism; spatial evidence is "
                   "specified and unbuilt, not merely unobserved",
        )
        for name in (ANCHOR_FINGERPRINT, SPATIAL_STABILITY)
    )


def _temporal(cleared: gates.Cleared) -> Tuple[Feature, ...]:
    """Two server-derived numbers, neither of them compared to anything.

    Both are always present, so the temporal block is the only one that is never
    empty on this scope. Neither carries a verdict about lateness: the single
    offline boundary lives in `replay`, was already enforced before this module
    ran, and duplicating it here as a comparison is how a threshold ends up in two
    places that drift apart.
    """
    body = cleared.signed.proof
    return (
        Feature(
            QUEUE_AGE,
            TEMPORAL,
            value=cleared.receipt.queued_seconds,
            derived_from=(SOURCE_RECEIPT,),
            detail="seconds between the step the committed challenge belongs to and "
                   "the moment the server received the proof; derived here, never "
                   "claimed by the handset",
        ),
        Feature(
            CLOCK_CONSISTENCY,
            TEMPORAL,
            value=body.captured_at - cleared.step_bounds[0],
            derived_from=(SOURCE_PROOF, SOURCE_RECEIPT),
            detail="the handset's claimed capture instant minus the start of the "
                   "step it answered, in seconds; positive means the handset's "
                   "clock ran ahead of that step",
        ),
    )


# --- The extractor ----------------------------------------------------------

def extract(cleared: gates.Cleared) -> Evidence:
    """Sort one cleared proof into the vector a decision is made from.

    Takes a `gates.Cleared` and nothing else. That signature is the module's main
    safeguard: there is no vector for a refused proof, because a refusal is a
    decision already taken and manufacturing evidence for it would invite a fusion
    layer to weigh it back up into an admission. A rejected proof travels as its
    reason code, not as a weak vector.

    Reads no configuration. No artifact is loaded, no timing is consulted and no
    number is compared, so there is nowhere in here for a tuned value to hide - the
    reason `config_version` is copied through from the gate rather than resolved
    again.
    """
    body = cleared.signed.proof
    if body.biometric not in proof.BIOMETRIC_NAMES:
        raise FeatureError(
            "biometric outcome %r is not one this build names, so this did not come "
            "through the gates" % (body.biometric,)
        )
    if body.claims.status not in proof.STATUS_NAMES:
        raise FeatureError(
            "claimed status %r is not a declared outcome, so this did not come "
            "through the gates" % (body.claims.status,)
        )

    built: Dict[str, Feature] = {}
    for feature in (
        _authentication(cleared) + _network(cleared) + _spatial() + _temporal(cleared)
    ):
        if feature.name in built:
            raise FeatureError("feature %r was built twice" % (feature.name,))
        built[feature.name] = feature

    ordered = MappingProxyType({name: built[name] for name in FEATURES})
    return Evidence(
        features=ordered,
        config_version=cleared.config_version,
        signals=cleared.signals,
    )
