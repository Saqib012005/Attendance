"""Every tuned number the presence layer uses, in one versioned place.

Two rules, and the whole module exists to enforce them.

**A tuned value lives here or nowhere.** A timing window inlined in a view, a
threshold hardcoded in a widget and a tolerance buried in a helper cannot be
reviewed together, cannot be changed together, and cannot be recorded against a
decision. Every parameter below is declared with its type, its bounds, its unit
and the reason it exists; a value outside the declaration fails to load.

**A decision records the configuration that produced it.** `active().version`
goes into every `PresenceDecision`, so a verdict from last term can be explained
with the parameters that were actually in force, not with today's. Artifacts are
files, added rather than edited: changing a threshold means a new version.

`calibration` is a required field on every artifact and it is not decorative. A
confidence figure produced under `uncalibrated` or `simulator-fitted` parameters
must never be presented as a probability - the artifact says which it is, so the
honesty is structural rather than a matter of remembering.
"""
import json
import os
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Optional, Tuple

HERE = Path(__file__).resolve().parent

# The artifact used when nothing else is named. Provisional: the timing windows
# are engineering choices, and no fusion parameter is calibrated at all yet.
DEFAULT_VERSION = "2026.09-provisional"

ENV_VERSION = "PRESENCE_CONFIG_VERSION"

UNCALIBRATED = "uncalibrated"
SIMULATOR_FITTED = "simulator-fitted"
FIELD_VALIDATED = "field-validated"
CALIBRATION_STATES = (UNCALIBRATED, SIMULATOR_FITTED, FIELD_VALIDATED)


class ConfigError(Exception):
    """An artifact is missing, malformed, or outside a declared bound."""


@dataclass(frozen=True)
class Parameter:
    kind: type
    minimum: Any
    maximum: Any
    unit: str
    why: str

    def check(self, name: str, value: Any) -> Any:
        # bool is an int subclass; a boolean where a count belongs is a mistake
        # worth failing on rather than coercing.
        if isinstance(value, bool) is not (self.kind is bool):
            raise ConfigError(
                "%s: expected %s, got %r" % (name, self.kind.__name__, value)
            )
        if self.kind is float and isinstance(value, int):
            value = float(value)
        if not isinstance(value, self.kind):
            raise ConfigError(
                "%s: expected %s, got %s"
                % (name, self.kind.__name__, type(value).__name__)
            )
        if self.minimum is not None and value < self.minimum:
            raise ConfigError(
                "%s: %r is below the declared minimum %r" % (name, value, self.minimum)
            )
        if self.maximum is not None and value > self.maximum:
            raise ConfigError(
                "%s: %r is above the declared maximum %r" % (name, value, self.maximum)
            )
        return value


# Declared once. A parameter that is not here cannot be loaded, and a parameter
# that is here must appear in every artifact - so adding one is a deliberate act
# that fails loudly until every artifact supplies it.
PARAMETERS: Mapping[str, Parameter] = MappingProxyType({
    "challenge.step_seconds": Parameter(
        int, 5, 300, "seconds",
        "How long one rolling challenge is current. Short enough that a "
        "screenshot forwarded to somebody outside the room is stale before it "
        "arrives; long enough that a slow scan from the back of a classroom "
        "still lands inside the step it started in.",
    ),
    "challenge.steps_per_epoch": Parameter(
        int, 2, 1000, "steps",
        "Steps before a fresh epoch key is derived. This bounds what a leaked "
        "epoch key is worth: the challenges of that epoch, in both directions, "
        "and of no other.",
    ),
    "challenge.lifetime_seconds": Parameter(
        int, 5, 600, "seconds",
        "How long after issue a challenge remains acceptable. Deliberately a "
        "little longer than one step, so a scan that straddles a rotation is "
        "not punished for the timing of the rotation.",
    ),
    "challenge.clock_skew_seconds": Parameter(
        int, 0, 300, "seconds",
        "Tolerance applied when a handset clock disagrees with the server, in "
        "both directions. A device clock is attacker-controlled, so this is a "
        "usability allowance and never a source of authority.",
    ),
    "challenge.accept_window_steps": Parameter(
        int, 0, 20, "steps",
        "How far behind the server's current step a submitted challenge may "
        "be. Covers capture-then-submit latency. Offline queueing is bounded "
        "by proof.max_offline_hours instead, which is a different question.",
    ),
    "proof.max_offline_hours": Parameter(
        int, 1, 168, "hours",
        "How long a signed proof may sit on a handset before the server stops "
        "accepting it. The challenge inside it is long expired either way; "
        "this bounds how far back the audit trail has to stay open.",
    ),
    "proof.nonce_retention_hours": Parameter(
        int, 1, 336, "hours",
        "How long a seen-nonce is remembered. Must exceed "
        "proof.max_offline_hours, or a proof could be replayed after its "
        "nonce was forgotten.",
    ),
    "relay.max_hops": Parameter(
        int, 1, 8, "hops",
        "How deep a relay chain of custody may run. Bounded by the geometry of a "
        "classroom rather than by the range of a radio: across a 15x20 ft room "
        "the diagonal is under eight metres, so one or two hops is enough to "
        "route around bodies and bags, and a chain much deeper than that is more "
        "plausibly one that has left the room than one solving a shadowing "
        "problem. Depth is also where the module's known weakness accumulates - "
        "a relay cannot verify the chain it extends, so every extra hop is "
        "another place an injected one can cost a genuine student their relay "
        "evidence.",
    ),
    "proof.max_future_skew_seconds": Parameter(
        int, 0, 3600, "seconds",
        "How far ahead of server time a client's claimed capture time may be "
        "before the claim itself is treated as a signal. The claim never sets "
        "the recorded time regardless.",
    ),

    # --- Fusion weights ---------------------------------------------------
    #
    # Millinats: thousandths of a natural log-odds unit, so 1000 is a likelihood
    # ratio of e and the arithmetic downstream stays in integers. No weight may
    # be zero. A zero would mean "declared and worthless", which is better said
    # by not declaring the feature as evidence at all, and a zero in an artifact
    # would also leave the hygiene sweep unable to tell a tuned value from the
    # integer zero.
    #
    # The hypothesis every weight is about is that the student was inside the
    # classroom presence environment - not that the student is who they say they
    # are. Read that way the table is uncomfortable on purpose: the largest weight
    # in it is RESERVED, and the two reserved weights together outweigh every
    # feature this build can collect, because they are the only two that bear on
    # location and this build has neither.
    "fusion.weight.identity_authenticated": Parameter(
        int, 1, 10000, "millinats",
        "The proof carried a valid signature from a key this institution has "
        "bound to an enrolled student. Strong evidence about identity and "
        "deliberately modest evidence about presence: a genuine student standing "
        "outside the window satisfies this feature completely.",
    ),
    "fusion.weight.device_bound": Parameter(
        int, 1, 10000, "millinats",
        "The signing key was one already registered to this student rather than "
        "one seen for the first time. Raises the cost of the lend-your-account "
        "attack from sharing a password to surrendering a phone, which is a real "
        "increase and not a decisive one.",
    ),
    "fusion.weight.challenge_committed": Parameter(
        int, 1, 10000, "millinats",
        "The proof committed to a rolling challenge the server can re-derive for "
        "the step it names. The most discriminating evidence available on a build "
        "with no radio, because it is the only one a forwarded screenshot cannot "
        "survive: the challenge is stale before it can be carried out of the room.",
    ),
    "fusion.weight.biometric_outcome": Parameter(
        int, 1, 10000, "millinats",
        "The platform ran its own biometric check and reported an outcome. "
        "Weighted as a second independent mechanism beside the signature - the "
        "handset attests that a person, not merely a process, answered - and not "
        "more, because the server never sees the check and cannot audit it.",
    ),
    "fusion.weight.origin_direct": Parameter(
        int, 1, 10000, "millinats",
        "At least one authenticated teacher origin frame verified. The largest "
        "weight among the features that can actually be collected, because it is "
        "the only one requiring the handset to have been within radio range of a "
        "device the teacher physically controls. Never a function of signal "
        "strength: the recorded RSSI values are carried for room calibration and "
        "are not read during fusion, so no setting of this weight can turn into "
        "a signal-strength threshold.",
    ),
    "fusion.weight.relay_depth": Parameter(
        int, 1, 10000, "millinats",
        "Credited once per verified hop, up to relay.max_hops. Per hop rather "
        "than per chain because each hop is a further authenticated device "
        "attesting to the same origin; small per hop because a chain of custody "
        "is not a location, and each extra hop is another place an injected one "
        "can cost a genuine student their relay evidence.",
    ),
    "fusion.weight.relay_integrity": Parameter(
        int, 1, 10000, "millinats",
        "Every hop in the submitted chain verified against its predecessor and "
        "resolved to a device enrolled in this session. Kept separate from depth "
        "so a one-hop chain that verifies completely is not scored below a longer "
        "one that only just held together.",
    ),
    "fusion.weight.anchor_fingerprint": Parameter(
        int, 1, 10000, "millinats",
        "RESERVED for Phase 5. The observed multi-anchor pattern matched the room "
        "profile for a position inside the room. The largest weight in the table, "
        "because it is the only feature in the vector that bears on location at "
        "all - which is the same fact as this build being unable to tell a student "
        "at a desk from a student at the window. Declared now so the ceiling "
        "reports honestly how much of the evidence base is missing.",
    ),
    "fusion.weight.spatial_stability": Parameter(
        int, 1, 10000, "millinats",
        "RESERVED for Phase 5. The observations held a consistent position across "
        "the window rather than arriving as one lucky sample. Weighted below the "
        "fingerprint itself, because stability qualifies a spatial claim and "
        "cannot substitute for one.",
    ),
    "fusion.weight.clock_consistency": Parameter(
        int, 1, 10000, "millinats",
        "The handset's claimed capture instant was derivable against the step it "
        "answered. The smallest weight in the table and correctly so: a device "
        "clock is attacker-controlled, so agreement is mildly reassuring while "
        "disagreement is already handled as a signal by the replay bounds.",
    ),
    "fusion.correlated_credit_pct": Parameter(
        int, 1, 99, "percent",
        "How much of a secondary feature's weight is credited inside its own "
        "block. Within a block the features are not independent - a valid "
        "challenge nearly implies a valid session, and a relay sighting is the "
        "same radio observation as the origin sighting seen once more - so adding "
        "their weights would multiply likelihood ratios that share most of their "
        "evidence. The strongest feature in a block is credited in full and the "
        "rest at this fraction. Bounded strictly below 100, because 100 is exactly "
        "the naive independence assumption, and strictly above 0, because 0 would "
        "discard genuinely additional mechanisms - a biometric outcome is not a "
        "restatement of a signature. It is one conservative fraction standing in "
        "for a correlation structure nobody has measured, which is why it is not "
        "a matrix that would look like a measurement.",
    ),
    "fusion.block_cap_millinats": Parameter(
        int, 100, 20000, "millinats",
        "The most any one block may contribute. A cap and not a target: it exists "
        "so no single block can carry a decision on its own however many features "
        "it accumulates, which is the arithmetic form of the rule that no one "
        "signal is allowed to mean present.",
    ),

    # --- Operating points -------------------------------------------------
    #
    # Where a score becomes a verdict. These are the only parameters in the file
    # that a policy owner rather than an engineer should be asked to sign off,
    # which is why they carry a prefix of their own and live nowhere near the
    # weights: a weight says what evidence is worth and an operating point says
    # what the institution will accept, and confusing the two is how a scoring
    # change ships as though it were a tuning change.
    #
    # Every one of them is compared against the attained millinat score and never
    # against the posterior. On an uncalibrated artifact there is no posterior at
    # all, so a threshold defined against one would silently stop existing.
    "decide.present_millinats": Parameter(
        int, 100, 20000, "millinats",
        "The score at or above which a proof may be called PRESENT. Set on this "
        "artifact so that PRESENT requires the complete authentication block - "
        "identity, device binding, a live challenge and a biometric outcome - "
        "because those four are the entire evidence base a build with no radio "
        "can collect, and accepting three of four would make the missing one "
        "optional in practice. The honest cost is stated where it belongs, in "
        "decide.py: a handset with no platform biometric cannot reach this line "
        "and lands in review instead.",
    ),
    "decide.secondary_millinats": Parameter(
        int, 1, 20000, "millinats",
        "The score at or above which a proof is worth a human looking at it. "
        "Below this there is nothing to review: a valid signature and no live "
        "challenge is an authenticated student who has not demonstrated "
        "participation in this session, which is a NOT VERIFIED and not a "
        "borderline case. Must sit strictly below decide.present_millinats.",
    ),
    "decide.min_coverage_pct": Parameter(
        int, 1, 100, "percent",
        "How much of the designed evidence base a PRESENT must rest on. This is "
        "the accepted residual risk expressed as a number a reviewer can move: "
        "the two spatial weights are the largest in the table and both are "
        "RESERVED, so a flawless handset on this build reaches roughly a quarter "
        "of the ceiling and no setting above that could ever pass. Kept "
        "deliberately below it, so the gate is armed and documented rather than "
        "pretending the missing quarter is present.",
    ),
    "decide.min_supplied_pct": Parameter(
        int, 1, 100, "percent",
        "How much of what this particular handset could have shown it must "
        "actually have shown to be called PRESENT. The check that separates an "
        "old phone which did everything available to it - a full fraction of a "
        "small obtainable total - from a capable one that declared a biometric "
        "and then produced no outcome. Never a penalty for missing hardware: an "
        "unsupported feature leaves the obtainable total, so it cannot lower this "
        "fraction.",
    ),
})


@dataclass(frozen=True)
class Artifact:
    """One loaded, validated configuration version."""

    version: str
    calibration: str
    notes: str
    values: Mapping[str, Any]

    def __getitem__(self, name: str) -> Any:
        try:
            return self.values[name]
        except KeyError:
            raise ConfigError("%r is not a declared parameter" % (name,))

    @property
    def is_calibrated(self) -> bool:
        """Whether a confidence from this artifact may be called a probability."""
        return self.calibration == FIELD_VALIDATED


def artifact_path(version: str) -> Path:
    return HERE / ("presence-%s.json" % version)


def available_versions() -> Tuple[str, ...]:
    prefix, suffix = "presence-", ".json"
    return tuple(
        sorted(p.name[len(prefix):-len(suffix)] for p in HERE.glob("presence-*.json"))
    )


def load(version: str) -> Artifact:
    path = artifact_path(version)
    if not path.exists():
        raise ConfigError(
            "no configuration artifact for version %r (available: %s)"
            % (version, ", ".join(available_versions()) or "none")
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigError("%s is not readable JSON: %s" % (path.name, exc))
    return _validate(version, raw, path.name)


def _validate(version: str, raw: Any, where: str) -> Artifact:
    if not isinstance(raw, dict):
        raise ConfigError("%s: expected a JSON object" % where)

    declared = raw.get("version")
    if declared != version:
        raise ConfigError(
            "%s: declares version %r but is filed as %r. Filename and contents "
            "must agree, or a decision cannot be traced back to parameters."
            % (where, declared, version)
        )

    calibration = raw.get("calibration")
    if calibration not in CALIBRATION_STATES:
        raise ConfigError(
            "%s: calibration must be one of %s, got %r"
            % (where, ", ".join(CALIBRATION_STATES), calibration)
        )

    values = raw.get("parameters")
    if not isinstance(values, dict):
        raise ConfigError("%s: 'parameters' must be a JSON object" % where)

    unknown = set(values) - set(PARAMETERS)
    if unknown:
        raise ConfigError(
            "%s: undeclared parameter(s) %s. Declare them in PARAMETERS with "
            "bounds and a reason, or remove them."
            % (where, ", ".join(sorted(unknown)))
        )
    missing = set(PARAMETERS) - set(values)
    if missing:
        raise ConfigError(
            "%s: missing parameter(s) %s" % (where, ", ".join(sorted(missing)))
        )

    checked = {
        name: PARAMETERS[name].check(name, values[name]) for name in sorted(values)
    }
    return Artifact(
        version=version,
        calibration=calibration,
        notes=str(raw.get("notes", "")),
        values=MappingProxyType(checked),
    )


# --- The active artifact --------------------------------------------------

_active: Optional[Artifact] = None


def active() -> Artifact:
    """The artifact in force, loaded once.

    Which version that is comes from the environment, so a deployment can be
    moved onto a new artifact without a code change and, more importantly, two
    deployments can be run on different versions deliberately - which is what a
    staged rollout of a threshold change looks like.
    """
    global _active
    if _active is None:
        _active = load(os.getenv(ENV_VERSION) or DEFAULT_VERSION)
    return _active


def set_active(artifact: Optional[Artifact]) -> None:
    """Install an artifact, or clear the cache with None. For tests and rollouts."""
    global _active
    _active = artifact


def get(name: str) -> Any:
    """One parameter from the active artifact."""
    return active()[name]


def cross_check() -> Tuple[str, ...]:
    """Relationships between parameters that no single bound can express.

    Returned rather than raised so a caller can decide: the config registry
    treats a non-empty result as an activation gate failure, while a test can
    report all of them at once.
    """
    a = active()
    problems = []
    if a["challenge.lifetime_seconds"] < a["challenge.step_seconds"]:
        problems.append(
            "challenge.lifetime_seconds (%d) is shorter than one step (%d): every "
            "challenge would expire before the next one is issued, leaving gaps "
            "in which nothing can be scanned"
            % (a["challenge.lifetime_seconds"], a["challenge.step_seconds"])
        )
    if a["proof.nonce_retention_hours"] <= a["proof.max_offline_hours"]:
        problems.append(
            "proof.nonce_retention_hours (%d) does not exceed "
            "proof.max_offline_hours (%d): a proof could be accepted after its "
            "nonce had been forgotten, which is a replay"
            % (a["proof.nonce_retention_hours"], a["proof.max_offline_hours"])
        )
    present = a["decide.present_millinats"]
    secondary = a["decide.secondary_millinats"]
    if secondary >= present:
        problems.append(
            "decide.secondary_millinats (%d) is not below decide.present_millinats "
            "(%d): the review band would be empty or inverted, so a proof could "
            "clear the bar for review only by clearing the bar for acceptance"
            % (secondary, present)
        )
    # The naive sum of every weight, which is an upper bound on any real score: the
    # correlation discount and the per-block cap can only reduce it. Checking against
    # the bound rather than the true ceiling keeps this function from importing the
    # fusion layer that imports this one, and it still catches the mistake that
    # matters - an operating point set where nothing can reach it.
    reachable = sum(
        value for name, value in a.values.items() if name.startswith("fusion.weight.")
    )
    if present > reachable:
        problems.append(
            "decide.present_millinats (%d) exceeds the sum of every declared weight "
            "(%d), so no evidence permitted by this artifact could ever be called "
            "present" % (present, reachable)
        )
    return tuple(problems)
