"""Accumulating evidence into one number, without pretending it is a probability.

This module answers one question - *how much does the admitted evidence favour the
claim that this student was inside the classroom presence environment* - and
deliberately does not answer *and therefore what?* That belongs to `decide`,
because a layer that both scores and rules is a layer where a threshold can hide
inside an arithmetic decision.

**The hypothesis is presence, not identity.** Every weight in the artifact is a
statement about how much a feature moves the odds of *being in the room*, which is
why the authentication weights are modest even though the cryptography behind them
is not. A genuine student standing outside the window presents a valid signature, a
bound device, a fresh challenge and a real fingerprint. Weighted as evidence of
identity those features are overwhelming; weighted as evidence of presence they are
suggestive. §02 asks for the second question and this module is where refusing to
answer the first one instead becomes arithmetic.

**Blocks are the unit of independence, features are not** (§21). Within a block the
features are functions of one another to an unmeasured degree: a committed
challenge nearly implies a valid session, and a relay sighting is the origin
sighting seen a second time. So a block credits its strongest feature in full and
the rest at `fusion.correlated_credit_pct`, then caps the total. Across blocks the
sum is taken, because the block decomposition is exactly the claim that
authentication, network presence, spatial position and temporal consistency rest on
different mechanisms. Naive multiplication of correlated likelihood ratios is the
error §21 names, and a single conservative fraction is the honest stand-in for a
correlation structure nobody has measured - a matrix would look like a measurement.

**Nothing is ever subtracted.** There is no negative weight anywhere, and the
artifact's bounds make one unloadable. Adverse evidence - a chain that arrived and
did not verify, a biometric the platform rejected - is reported and credited
nothing, and it lowers `supplied_pct` because it counted as obtainable. That is
deliberate: the likelihood ratio of a failed fingerprint given proxying versus
given a wet thumb is not known here, and inventing one would be exactly the
decorative Bayesianism §22 forbids. A failed check is a routing condition for
`decide`, not a subtraction.

**Three numbers, because one would mislead** (decision 3). `millinats` is what the
evidence came to. `ceiling_millinats` is what the designed evidence base is worth
when every block is available, so `coverage_pct` says how much of the design a
verdict actually rests on. `obtainable_millinats` is what *this* handset in *this*
build could have produced, so `supplied_pct` distinguishes an old phone that did
everything it could from a capable one that supplied nothing. Missing evidence
lowers the first figure by arriving as less evidence, never as a penalty; the ratio
is what says whether anyone is at fault for the gap.

On the current scope the arithmetic states the residual risk instead of caveating
it. The largest single weight in the table is the anchor fingerprint and it is
RESERVED; the two reserved spatial weights together outweigh every feature this
build can collect, and the network block needs a radio this build does not use. So
coverage sits near a quarter however perfectly a student behaves, and a system
reporting high confidence here would be lying about what it measured.

**A confidence is not a probability until it is calibrated** (§23). `fuse` emits a
posterior only when the artifact is `field-validated` *and* a prior derived from
observed data was supplied. Under anything else `posterior_milli` is `None`,
`ordering_only` is `True` and `ordering_reason` says which condition failed. The
honesty is structural: there is no code path that turns an uncalibrated score into
a percentage, so nobody has to remember not to.

**The prior comes from data or it is declared absent** (§22). `Prior.from_base_rate`
takes observed attendance for the cohort. There is no default, no 0.5, and no
fallback: a base rate of exactly zero or one is refused too, because its log odds
are infinite and a clamped stand-in would be an assertion dressed as an estimate.
"""
import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Tuple

from . import config, features
from ..analytics import metrics


class FusionError(Exception):
    """A weight is missing, or a vector is not one this module can weigh."""


# The prefix under which every weight lives in the artifact. A feature counts as
# evidence exactly when `fusion.weight.<name>` is declared, which puts the list of
# what may move a score in the artifact rather than in this module - so adding
# evidence is a reviewable configuration change and not a code change.
WEIGHT_PREFIX = "fusion.weight."

# Recorded, never scored. `platform_declared` is a fact about the handset rather
# than evidence about the room, and `queue_age` says when a proof was offered
# rather than what it showed. Both belong in the audit trail and in `decide`'s
# routing; neither may be worth anything, because a phone cannot improve its
# evidence by declaring what kind of phone it is.
NON_EVIDENTIAL = frozenset({features.PLATFORM, features.QUEUE_AGE})

# Features credited per unit rather than once, and the parameter bounding how many
# units may be credited. The bound is the same one the protocol enforces, so a
# chain cannot be worth more here than it was allowed to be there.
PER_UNIT: Mapping[str, str] = MappingProxyType({
    features.RELAY_DEPTH: "relay.max_hops",
})

# Absences no handset in this build could have converted into evidence: UNSUPPORTED
# is the platform's limit, RESERVED is the roadmap's. Excluded from
# `obtainable_millinats`, because `supplied_pct` asks what this device withheld and
# neither of these was ever on offer.
UNOBTAINABLE = frozenset({features.UNSUPPORTED, features.RESERVED})

# Scales, not tuned values. Percent is what `correlated_credit_pct` is quoted in
# and per-mille is the resolution the rest of the codebase already reports
# confidence at (`proof.CONFIDENCE_MILLI_MAX`). Changing either would change what
# a field means rather than how strictly it is read, so neither is configuration.
PCT = 100
MILLI = 1000


@dataclass(frozen=True)
class Weights:
    """One artifact's weight table, resolved against the declared feature set.

    Loading is where a missing weight becomes an error instead of a silent zero.
    A feature that `features.extract` admits as evidence and that no artifact
    prices is a weight of nothing chosen by omission, which is the same mistake as
    a hardcoded threshold and harder to notice.
    """

    millinats: Mapping[str, int]
    units: Mapping[str, int]
    correlated_credit_pct: int
    block_cap_millinats: int
    calibration: str
    config_version: str

    @classmethod
    def load(cls, artifact: Optional[config.Artifact] = None) -> "Weights":
        current = artifact or config.active()
        millinats: Dict[str, int] = {}
        units: Dict[str, int] = {}
        for name in sorted(features.FEATURES):
            if name in NON_EVIDENTIAL:
                continue
            try:
                millinats[name] = current[WEIGHT_PREFIX + name]
            except config.ConfigError:
                raise FusionError(
                    "artifact %s prices no feature %r. Declare %s%s with bounds and "
                    "a reason, or stop extracting the feature as evidence - scoring "
                    "it at nothing by omission is a tuned value of zero hiding "
                    "outside the registry."
                    % (current.version, name, WEIGHT_PREFIX, name)
                )
            units[name] = current[PER_UNIT[name]] if name in PER_UNIT else 1
        return cls(
            millinats=MappingProxyType(millinats),
            units=MappingProxyType(units),
            correlated_credit_pct=current["fusion.correlated_credit_pct"],
            block_cap_millinats=current["fusion.block_cap_millinats"],
            calibration=current.calibration,
            config_version=current.version,
        )

    def gross(self, name: str) -> int:
        """The most this feature can be worth: its weight across its unit bound."""
        return self.millinats[name] * self.units[name]


@dataclass(frozen=True)
class Contribution:
    """What one feature was worth, and the arithmetic that got there.

    Kept per feature rather than summed away, because a confidence figure that
    cannot be taken apart again is not auditable. `leading` records which feature
    the block credited in full, which is the only place the correlation discount
    shows up as something a reader can check.
    """

    feature: str
    block: str
    weight_millinats: int
    units: int
    unit_bound: int
    gross_millinats: int
    credited_millinats: int
    leading: bool = False
    absent: Optional[str] = None
    obtainable: bool = True

    @property
    def present(self) -> bool:
        return self.absent is None

    def describe(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "block": self.block,
            "weight_millinats": self.weight_millinats,
            "units": self.units,
            "unit_bound": self.unit_bound,
            "gross_millinats": self.gross_millinats,
            "credited_millinats": self.credited_millinats,
            "leading": self.leading,
            "absent": self.absent,
            "obtainable": self.obtainable,
        }


@dataclass(frozen=True)
class BlockScore:
    """One block's total, with the cap and the discount both visible."""

    block: str
    millinats: int
    uncapped_millinats: int
    capped: bool
    empty: bool
    contributions: Tuple[Contribution, ...]

    def describe(self) -> Dict[str, Any]:
        return {
            "block": self.block,
            "millinats": self.millinats,
            "uncapped_millinats": self.uncapped_millinats,
            "capped": self.capped,
            "empty": self.empty,
            "contributions": [c.describe() for c in self.contributions],
        }


def _units_of(feature: features.Feature, bound: int) -> int:
    """How many units of its weight a present feature earns.

    Everything earns one unit unless the artifact bounds it per unit, and then the
    count comes from the observation and is clipped to the bound the protocol
    already enforced. A chain deeper than `relay.max_hops` cannot be worth more
    here than it was allowed to be in `chain`, and a count this module cannot read
    as a whole number is a bug upstream rather than something to guess at.
    """
    if bound == 1:
        return 1
    value = feature.value
    if isinstance(value, bool) or not isinstance(value, int):
        raise FusionError(
            "%s is priced per unit, so its value must be a count; got %r"
            % (feature.name, value)
        )
    if value < 0:
        raise FusionError("%s reported a negative count %d" % (feature.name, value))
    return min(value, bound)


# What a scoring pass assumes about the features that did not arrive. The same
# arithmetic runs three times over the same vector, which is the point: the ceiling
# and the obtainable figure are what this evidence base *would* have come to under
# the identical discount and cap, so the three numbers are comparable.
ATTAINED = "attained"      # absent features are worth nothing
OBTAINABLE = "obtainable"  # absences this handset could have filled, at full worth
CEILING = "ceiling"        # every feature at full worth, whatever actually arrived

ASSUMPTIONS = (ATTAINED, OBTAINABLE, CEILING)

_Row = Tuple[features.Feature, int, int, int, int, bool]


def _rows(
    block: str, vector: features.Evidence, weights: Weights, assume: str
) -> List[_Row]:
    rows: List[_Row] = []
    for feature in vector.block(block):
        if feature.name in NON_EVIDENTIAL:
            continue
        bound = weights.units[feature.name]
        weight = weights.millinats[feature.name]
        # An absence nobody could have prevented is not a withheld observation.
        obtainable = feature.absent not in UNOBTAINABLE
        if assume == CEILING:
            units = bound
        elif feature.present:
            units = _units_of(feature, bound)
        elif assume == OBTAINABLE and obtainable:
            units = bound
        else:
            units = 0
        rows.append((feature, weight, bound, units, weight * units, obtainable))
    return rows


def _score_block(
    block: str, vector: features.Evidence, weights: Weights, assume: str = ATTAINED
) -> BlockScore:
    """One block's arithmetic: strongest feature in full, the rest discounted, capped.

    The discount is §21 made concrete. Within a block the features are functions of
    one another to a degree nobody here has measured - a committed challenge nearly
    implies a valid session, a verified hop is the origin sighting seen again - so
    crediting each in full would multiply likelihood ratios that share most of
    their evidence. One conservative fraction is the honest stand-in; a correlation
    matrix would read as a measurement that was never taken.

    Ties break on the alphabetically first name, so the same vector always credits
    the same feature in full. An unstable leader would make a recorded figure
    irreproducible for no gain in accuracy.
    """
    rows = _rows(block, vector, weights, assume)

    leader = ""
    best = 0
    for feature, _weight, _bound, _units, gross, _obtainable in rows:
        if gross > best or (gross == best and gross > 0 and feature.name < leader):
            best, leader = gross, feature.name

    contributions: List[Contribution] = []
    uncapped = 0
    for feature, weight, bound, units, gross, obtainable in rows:
        leading = gross > 0 and feature.name == leader
        credited = gross if leading else gross * weights.correlated_credit_pct // PCT
        uncapped += credited
        contributions.append(
            Contribution(
                feature=feature.name,
                block=block,
                weight_millinats=weight,
                units=units,
                unit_bound=bound,
                gross_millinats=gross,
                credited_millinats=credited,
                leading=leading,
                absent=feature.absent,
                obtainable=obtainable,
            )
        )

    millinats = min(uncapped, weights.block_cap_millinats)
    return BlockScore(
        block=block,
        millinats=millinats,
        uncapped_millinats=uncapped,
        capped=millinats < uncapped,
        empty=vector.block_is_empty(block),
        contributions=tuple(contributions),
    )


def _total(vector: features.Evidence, weights: Weights, assume: str) -> int:
    return sum(
        _score_block(block, vector, weights, assume).millinats
        for block in features.BLOCKS
    )


@dataclass(frozen=True)
class Prior:
    """An observed base rate expressed as log odds, or a refusal to invent one.

    §22 in one class. There is no default prior, because the only defensible
    starting point for *this cohort attends* is what this cohort has been observed
    to do, and 0.5 is not a measurement of anything - it is the number that makes
    the arithmetic run. When the observation is missing or degenerate the class says
    so, `fuse` withholds the posterior, and the score remains an ordering.
    """

    log_odds_milli: int
    observed_present: int
    observed_expected: int
    determined: bool
    base_rate_pct: Optional[float] = None
    reason: str = ""

    @classmethod
    def from_base_rate(cls, present_sessions: int, expected_sessions: int) -> "Prior":
        """Log odds from observed attendance, or an explicitly undetermined prior.

        The two degenerate rates are refused rather than clamped. A cohort observed
        at 0% or 100% has infinite log odds, and a large finite stand-in would be an
        assertion about how certain the base rate is, dressed as an estimate and
        invisible in the output.
        """
        if present_sessions < 0 or expected_sessions < 0:
            raise FusionError(
                "a base rate cannot come from negative counts (%d of %d)"
                % (present_sessions, expected_sessions)
            )
        if present_sessions > expected_sessions:
            raise FusionError(
                "%d present of %d expected is not a rate; the counts disagree about "
                "the same cohort" % (present_sessions, expected_sessions)
            )
        rate = metrics.safe_pct(present_sessions, expected_sessions)
        if rate is None:
            return cls(
                log_odds_milli=0,
                observed_present=present_sessions,
                observed_expected=expected_sessions,
                determined=False,
                reason="no sessions were expected for this cohort, so there is no "
                "observed rate to start from",
            )
        if present_sessions == 0 or present_sessions == expected_sessions:
            return cls(
                log_odds_milli=0,
                observed_present=present_sessions,
                observed_expected=expected_sessions,
                determined=False,
                base_rate_pct=rate,
                reason="an observed rate of %.1f%% has no finite log odds, and a "
                "clamped stand-in would be an assertion rather than an estimate"
                % (rate,),
            )
        odds = present_sessions / (expected_sessions - present_sessions)
        return cls(
            log_odds_milli=int(round(math.log(odds) * MILLI)),
            observed_present=present_sessions,
            observed_expected=expected_sessions,
            determined=True,
            base_rate_pct=rate,
        )

    def describe(self) -> Dict[str, Any]:
        return {
            "determined": self.determined,
            "log_odds_milli": self.log_odds_milli if self.determined else None,
            "base_rate_pct": self.base_rate_pct,
            "observed_present": self.observed_present,
            "observed_expected": self.observed_expected,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Fused:
    """What the admitted evidence came to, and what it did not come to.

    No status, no threshold, no verdict. `decide` reads this; a layer that both
    scored and ruled would be a layer where a threshold could hide inside the
    arithmetic, and then no reviewer could tell a scoring change from a policy one.
    """

    millinats: int
    ceiling_millinats: int
    obtainable_millinats: int
    blocks: Tuple[BlockScore, ...]
    calibration: str
    config_version: str
    prior: Optional[Prior] = None
    posterior_milli: Optional[int] = None
    ordering_only: bool = True
    ordering_reason: str = ""
    empty_blocks: Tuple[str, ...] = ()
    adverse: Tuple[str, ...] = ()
    signals: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        ordered = 0 <= self.millinats <= self.obtainable_millinats
        if not (ordered and self.obtainable_millinats <= self.ceiling_millinats):
            raise FusionError(
                "the three figures are out of order (%d attained, %d obtainable, %d "
                "ceiling). Attained can only fall short of obtainable, and nothing "
                "can exceed the designed ceiling; an inversion means a weight was "
                "credited under one assumption and not another."
                % (self.millinats, self.obtainable_millinats, self.ceiling_millinats)
            )
        if self.ordering_only != (self.posterior_milli is None):
            raise FusionError(
                "ordering_only and posterior_milli disagree. A score is either "
                "calibrated enough to state as a probability or it is an ordering; "
                "there is no third state for a caller to interpret."
            )

    @property
    def coverage_pct(self) -> Optional[float]:
        """How much of the designed evidence base this figure rests on.

        Not a confidence. On this build the two spatial weights are the largest in
        the table and both are RESERVED, so coverage sits near a quarter however
        perfectly a student behaves - the accepted residual risk stated as
        arithmetic rather than as a caveat somebody has to remember to repeat.
        """
        return metrics.safe_pct(self.millinats, self.ceiling_millinats)

    @property
    def supplied_pct(self) -> Optional[float]:
        """How much of what *this* handset could have shown it actually showed.

        The figure that separates an old phone which did everything available to it
        from a capable one that supplied nothing. Adverse evidence lowers it,
        because a check that ran and failed was obtainable and was not supplied.
        """
        return metrics.safe_pct(self.millinats, self.obtainable_millinats)

    def describe(self) -> Dict[str, Any]:
        return {
            "millinats": self.millinats,
            "obtainable_millinats": self.obtainable_millinats,
            "ceiling_millinats": self.ceiling_millinats,
            "coverage_pct": self.coverage_pct,
            "supplied_pct": self.supplied_pct,
            "posterior_milli": self.posterior_milli,
            "ordering_only": self.ordering_only,
            "ordering_reason": self.ordering_reason,
            "calibration": self.calibration,
            "config_version": self.config_version,
            "prior": self.prior.describe() if self.prior is not None else None,
            "empty_blocks": list(self.empty_blocks),
            "adverse": list(self.adverse),
            "signals": list(self.signals),
            "blocks": [block.describe() for block in self.blocks],
        }


def _logistic_milli(log_odds_milli: int) -> int:
    """Total log odds to a per-mille probability, without overflowing either tail."""
    exponent = log_odds_milli / MILLI
    if exponent >= 0:
        probability = 1 / (1 + math.exp(-exponent))
    else:
        odds = math.exp(exponent)
        probability = odds / (1 + odds)
    return int(round(probability * MILLI))


def fuse(
    evidence: features.Evidence,
    *,
    prior: Optional[Prior] = None,
    weights: Optional[Weights] = None,
) -> Fused:
    """Weigh one admitted evidence vector. Reaches no verdict.

    Only a vector `features.extract` produced can be weighed, and only under the
    artifact it was extracted against. `Evidence` already refuses to exist with a
    feature left out, so the completeness check below is guarding against a
    stand-in rather than a real `Evidence` - Python enforces no interface, and a
    partial vector would score as a modest one instead of failing.

    `decide` is what reads the result, and it inherits one obligation this module
    deliberately does not discharge: `posterior_milli` is a probability under the
    artifact's own weights, and it says nothing about how much of the evidence base
    was available. A high posterior over a low `coverage_pct` is a confident
    statement about a quarter of the design, and only a policy layer can say
    whether that is enough.
    """
    table = weights or Weights.load()

    declared = set(features.FEATURES)
    supplied = set(evidence.features)
    if supplied != declared:
        raise FusionError(
            "this is not a complete evidence vector (missing: %s; unknown: %s). A "
            "vector with features left out would score as a modest one instead of "
            "failing, so it is refused rather than weighed."
            % (
                ", ".join(sorted(declared - supplied)) or "none",
                ", ".join(sorted(supplied - declared)) or "none",
            )
        )

    if evidence.config_version and evidence.config_version != table.config_version:
        raise FusionError(
            "the vector was extracted under artifact %r and these weights come from "
            "%r. A decision that cannot name one configuration cannot later be "
            "explained with the parameters that produced it."
            % (evidence.config_version, table.config_version)
        )

    blocks = tuple(
        _score_block(block, evidence, table, ATTAINED) for block in features.BLOCKS
    )
    millinats = sum(block.millinats for block in blocks)

    # Nothing adverse is subtracted here. A biometric the platform rejected and a
    # chain that arrived and did not verify are both credited zero and both counted
    # as obtainable, so they show up as a shortfall in `supplied_pct` and as reason
    # codes for `decide` to route on. Turning a failure into a negative weight would
    # need a likelihood ratio for *failed given proxying* that nobody has measured.
    adverse: List[str] = []
    for reason in sorted(features.ADVERSE_ABSENCES):
        adverse.extend(evidence.absent(reason))

    posterior: Optional[int] = None
    if table.calibration != config.FIELD_VALIDATED:
        ordering_reason = (
            "artifact %s is %s, so this figure orders candidates and is not a "
            "probability" % (table.config_version, table.calibration)
        )
    elif prior is None:
        ordering_reason = (
            "no prior was supplied and there is no default base rate to fall back "
            "on, so a posterior here would be an artifact of the assumption rather "
            "than a statement about this cohort"
        )
    elif not prior.determined:
        ordering_reason = "the prior is undetermined: %s" % (prior.reason,)
    else:
        ordering_reason = ""
        posterior = _logistic_milli(prior.log_odds_milli + millinats)

    return Fused(
        millinats=millinats,
        obtainable_millinats=_total(evidence, table, OBTAINABLE),
        ceiling_millinats=_total(evidence, table, CEILING),
        blocks=blocks,
        calibration=table.calibration,
        config_version=table.config_version,
        prior=prior,
        posterior_milli=posterior,
        ordering_only=posterior is None,
        ordering_reason=ordering_reason,
        empty_blocks=tuple(block.block for block in blocks if block.empty),
        adverse=tuple(sorted(adverse)),
        signals=tuple(evidence.signals),
    )
