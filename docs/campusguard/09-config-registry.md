# 09 — Configuration registry

Two rules, and this document is about the machinery that enforces them rather than
about the numbers themselves.

1. **A tuned value lives in a versioned artifact or nowhere.** Not in a view, not in
   a widget, not in `settings.py`, not in a helper default argument.
2. **A decision records the configuration that produced it**, and is re-decided by
   that configuration and not by the one deployed the day it happened to sync.

Both are enforced by tests and by a deploy-time check, not by convention. The first
rule exists because a threshold inlined in three files cannot be reviewed, changed
or attributed as one thing. The second exists because an offline proof can arrive
days after the lesson, and a verdict that a newly-activated threshold silently
re-decided is a verdict nobody can explain to the student it was about.

Everything below is in `backend/attendance/presence/config/`.

## The artifact

One version is one file: `presence-<version>.json`. Four top-level keys, and the
loader rejects anything that fails any of them.

```json
{
  "version": "2026.09-provisional",
  "calibration": "uncalibrated",
  "notes": "…what the numbers are and are not…",
  "parameters": { "challenge.step_seconds": 15 }
}
```

- **`version`** must equal the version in the filename. A file that disagrees with
  its own name is refused, because a decision that names a version has to be able
  to find the bytes that produced it.
- **`calibration`** is one of `uncalibrated`, `simulator-fitted`, `field-validated`.
  Required, closed set, no default. It is the field that decides whether a
  confidence figure may be called a probability — see *Calibration* below.
- **`notes`** is prose, and on the shipping artifact it says in as many words that
  the fusion weights are an ordering and not a measurement.
- **`parameters`** must contain **exactly** the declared set: an undeclared key is
  refused by name, and a missing one is refused by name.

**Artifacts are added, never edited.** Changing a threshold means shipping a new
version, which is what makes rule 2 mean anything: if a file could be edited in
place, `PresenceDecision.config_version` would name a moving target. The one
artifact on disk carries an explicit note about the single time it was edited —
before it had ever been deployed, while the package was untracked and no decision
could yet exist against it. That note is there so the exception is visible rather
than assumed.

The directory is held to that shape by tests: `test_the_artifact_directory_holds_only_artifacts`
fails on any file that is neither `__init__.py` nor a versioned JSON, and
`test_each_artifact_file_is_pretty_printed_json` keeps a diff between two versions
readable.

## The declaration

`PARAMETERS` is a mapping of name to `Parameter(kind, minimum, maximum, unit, why)`
and it is the single source of what may exist. Twenty-five parameters in five
groups: `challenge.*` timing, `proof.*` windows, `relay.*` structure, `fusion.*`
weights, and `decide.*` operating points.

`why` is not documentation garnish — `test_every_parameter_declares_a_unit_and_a_reason`
fails on an empty one. A value without a stated reason is a value nobody can review,
and the reasons are where the uncomfortable facts about this build are written down:
that the two largest weights in the table are `RESERVED` for unbuilt spatial
evidence, and that `decide.min_coverage_pct` is the accepted residual risk expressed
as a number a reviewer can move.

`Parameter.check` refuses a value outside its bounds, and refuses a type mismatch
with one deliberate sharp edge: **a boolean is not a count.** `bool` is an `int`
subclass in Python, so `"challenge.step_seconds": true` would otherwise load as 1
and quietly retune the layer. The check compares `isinstance(value, bool)` against
whether the declared kind *is* `bool`, so a bool in an int slot and an int in a bool
slot both fail. An integer in a `float` slot is widened, because JSON writes `1`
where it means `1.0`.

Adding a parameter is deliberately disruptive: because every artifact must supply
every declared name, a new declaration fails to load every existing artifact until
each one is given a value. That is the intended cost — a parameter that appeared
with a silent default would be a tuned number with no review attached.

## How an artifact fails to load

`ConfigError`, with the reason, in every one of these cases:

| Failure | Message names |
|---|---|
| No file for that version | the version, and every version that does exist |
| Unreadable JSON | the filename and the parse error |
| Not a JSON object | the filename |
| `version` disagrees with the filename | both values |
| `calibration` missing or not in the closed set | the permitted set |
| `parameters` not an object | the filename |
| Undeclared parameter | each offending name, with the instruction to declare it |
| Missing parameter | each missing name |
| Value out of bounds or wrong type | the name, the value and the bound |

Unknown *top-level* keys are ignored rather than fatal, so a future field can be
added without breaking older readers. Unknown *parameters* are fatal, because an
unrecognised parameter is either a typo silently doing nothing or a tuning knob
nobody declared.

## Relationships no single bound can express

`cross_check()` returns a tuple of problem strings — returned, not raised, so a
caller can decide whether to refuse or to report all of them at once. Four
relations:

1. `challenge.lifetime_seconds` must be at least one `step_seconds`, or every
   challenge expires before its successor is issued and there are gaps in which
   nothing can be scanned.
2. `proof.nonce_retention_hours` must **exceed** `proof.max_offline_hours`. A nonce
   forgotten while a proof carrying it is still acceptable is a replay window.
3. `decide.secondary_millinats` must sit strictly below `decide.present_millinats`,
   or the review band is empty or inverted and a proof could clear the bar for
   review only by clearing the bar for acceptance.
4. `decide.present_millinats` must not exceed the sum of every `fusion.weight.*`,
   or no evidence the artifact permits could ever be called present.

Relation 4 checks against the **naive sum** rather than the true attainable ceiling.
That is a deliberate approximation with a reason on both sides: the correlation
discount and the per-block cap can only reduce a real score, so the sum is a valid
upper bound; and using it keeps `config` from importing `fusion`, which imports
`config`. It catches the mistake that matters — an operating point set where nothing
can reach it — without an import cycle.

What makes each of these worth a check rather than a comment is that **all four fail
silently in production.** None raises anything at runtime. Each just quietly decides
wrong: accepting replays, making an outcome unreachable, refusing everyone.

## Activation, and running two versions on purpose

```python
config.active()          # the artifact in force, loaded once and cached
config.set_active(a)     # install one, or None to clear the cache
config.get(name)         # one parameter from the active artifact
```

Which version is active comes from the environment — `PRESENCE_CONFIG_VERSION`,
falling back to `DEFAULT_VERSION` (`2026.09-provisional`). Two consequences, and the
second is the point: a deployment can be moved onto a new artifact without a code
change, and **two deployments can deliberately run different versions at once**,
which is what a staged rollout of a threshold change looks like.

Sessions pin at open time. `PresenceSession.open` stores `config.active().version`
on the row, and `PresenceSession.artifact()` loads that version back. Everything
downstream of a session reads through it:

```python
artifact = presence.artifact()
timing  = challenge.Timing.from_artifact(artifact)
bounds  = replay.Bounds.from_artifact(artifact)
policy  = decide.Policy.load(artifact)
weights = fusion.Weights.load(artifact)
```

`submit_proof` resolves that artifact once and threads all four into `gates.clear`,
`fusion.fuse`, `decide.decide` and the refusal path, so a proof queued during a
lesson is judged by the parameters that were in force during the lesson.
`PinnedArtifactTests` in `tests_presence_wiring.py` proves it by making two
artifacts disagree about the same bytes: under a pinned `present_millinats` of 3000
a proof that is `present` under the shipped 2500 comes back `secondary`, and the
decision names the pinned version. The same file pins the offline window the same
way — a five-day-old proof is accepted under a pinned 168-hour allowance and
`not_verified` under the shipped 24.

**Challenge issuance reads the pinned artifact too**, which is less obvious than it
sounds. `step_seconds` and `steps_per_epoch` determine which challenge a given
moment maps to, so a teacher screen issuing under a newer artifact would display a
code the verifier — reading the pinned one — would correctly refuse to recognise.
`GET /api/v1/presence/sessions/<id>/challenge/` therefore builds its `Timing` from
`presence.artifact()` and returns the pinned `config_version` alongside the code.

**A pinned artifact that has gone missing is a server fault, not a verdict.** The
endpoint answers `503` and names the version it could not load. No decision row, no
refusal filed against the student, and no nonce burned — the ledger write is the
last step of `gates.clear` and the handler returns before it. The queued proof stays
queued and succeeds once the artifact is restored, which is the recoverable shape;
deciding under a substitute artifact would produce a verdict nobody could re-derive
from the version the record names.

### One read is not yet pinned

`chain.max_hops()` still reads `config.get("relay.max_hops")` from the active
artifact. It is dormant on this build — the endpoint passes `resolve_relay=None`, so
no chain is ever verified — and `chain.verify_chain` and `chain.signals` already
accept an optional `limit`, so pinning it is a one-line change when Phase 6 wires
relay. Doing it now would add untestable dead code. Recorded here rather than fixed
so it cannot be forgotten.

## Calibration

`calibration` is the field that keeps this layer honest about what its numbers mean,
and it is structural rather than a matter of anyone remembering:

- `uncalibrated` — the weights are an argued **ordering**. Nothing has been fitted
  against labelled data.
- `simulator-fitted` — fitted against generated adversarial scenarios. Still not a
  probability about real students.
- `field-validated` — fitted against a labelled field dataset. Only this state makes
  `Artifact.is_calibrated` true, and only then may a confidence figure be presented
  as a probability.

**The shipping artifact is `uncalibrated`**, and `decide` refuses to emit
`confidence_milli` at all under it — the decision carries `ordering_only: true`
instead of a number that would read like a probability. `CalibrationHonestyTests`
pins that: `test_the_shipped_artifact_is_not_calibrated` and
`test_simulator_fitted_is_not_calibrated` both have to be deliberately changed when
field data exists, which is the right amount of friction for a claim about accuracy.

`03-fusion-and-calibration.md` covers what the weights encode and why. The relevant
fact here is that the honesty lives in a required field on every artifact and is
recorded on every decision, so it travels with the verdict.

## The deploy gate

`backend/attendance/checks.py` registers two Django system checks, so they run in CI
and again as the first thing `runserver` and `migrate` do. Both are **errors**,
because both describe a deployment that cannot do its job.

| ID | Fires when | Consequence if it did not fire |
|---|---|---|
| `attendance.E001` | the active artifact will not load | every proof answers 503, and no new session can even be created — `PresenceSession.open` reads `active()` to pin |
| `attendance.E002` | the active artifact has no version string | a decision that cannot name its parameters cannot be re-derived |
| `attendance.E003` | one `cross_check()` relation fails — one error per problem | the silent wrong decisions listed above |

The `E001` hint names `PRESENCE_CONFIG_VERSION` and lists the versions that do
exist, because the overwhelmingly likely cause is a typo in a deployment variable.
The `E003` hint says artifacts are added and never edited, so the fix is a new
version rather than an amendment to the active one. When the artifact cannot load,
the consistency check returns nothing rather than raising: one misconfiguration must
not look like two problems.

**Deliberately not checked: whether the active artifact is calibrated.** Shipping
uncalibrated is the honest current state of this build. A check that failed on it
would either block every deploy or be permanently silenced, and a permanently
silenced check is noise. `test_being_uncalibrated_is_not_a_check_failure` pins that
decision so it cannot drift into a silenced check.

## The hygiene sweep, and its written-down blind spot

`HygieneTests` is what gives rule 1 teeth. It parses each scanned module with `ast`,
collects integer literals, and fails on any literal whose value coincides with a
value the active artifact declares — unless there is an entry in
`LITERAL_EXEMPTIONS` saying what it is.

**What it scans is part of the design.** The whole `presence/` package except
`config/` itself, *plus* the app-level `presence_*.py` modules — `presence_views.py`
and `presence_ledger.py` are Django-facing and therefore sit outside the package,
which for a while put them outside this check as well, which is exactly where a tuned
number would have gone to hide. An earlier draft of the endpoint did carry its own
observation cap of 32 while the wire schema carried 64. `models.py` is deliberately
*not* scanned: its integers are field widths and column lengths fixed by the
encodings they store, and scanning it would produce a page of exemptions that taught
a reader nothing. The test also asserts that it found modules to scan and values to
look for before it walks anything, because a hygiene test that scans nothing passes
forever while enforcing nothing.

It is a **proxy, not a proof.** It cannot distinguish a tuned 15 from a structural
15, and `LITERAL_EXEMPTIONS` is where that weakness is written down instead of
hidden. The current entries are all wire format: schema tags in `codec.py`, protocol
enumeration values in `proof.py` that happen to collide with a hop count, the
mandatory BLE AD-structure length in `origin.py`, and the `MILLI` denominator that
defines the unit every weight is quoted in.

Each exemption **pins the number of occurrences it covers**, and that count is why
the table can be trusted. A file-and-value exemption without one would also exempt
every future literal of that value in that file, so the blind spot would widen
quietly as the file grew. With the count pinned, an exemption covers exactly what
was reviewed when it was written: a new occurrence fails until the count is raised
deliberately, and a removed one fails until it is lowered
(`test_the_exemption_table_has_no_stale_entries`). The table cannot drift out of
step with the code in either direction.

Two companion tests close the obvious ways around the rule:
`test_no_presence_module_reads_tuning_from_django_settings` — because a tuned value
in `settings.py` satisfies the letter of rule 1 and defeats it — and the artifact
directory shape tests above.

The rule also reaches the client: `frontend/attendance_app` must not carry a copy of
a tuned number to know how to behave. That is why the challenge endpoint returns
`refresh_after` as an **instant** rather than returning `step_seconds` and letting
the screen do the arithmetic.

## `ConfigVersion`: the registry table, and what does not write it

`presence_config_versions` is the audit surface for activation: the artifact as
activated, its digest, its calibration state, the `cross_check()` results that let
it through, who activated it and when, and a unique constraint permitting exactly
one `is_active` row.

**Nothing writes it yet.** The runtime path reads artifacts from disk through
`config.active()`, and activation today is a deployment variable rather than a
recorded act with an actor attached. The expected state of the table on this build
is empty.

Stating that plainly matters more than the table does. An audit table that is
documented as the record of activation and is in fact never written is worse than no
table, because a reader assumes the record exists. The gap closes when there is an
admin activation path — the model, the digest field and the `activation_checks`
field exist so that path has somewhere to write, and the deploy checks already run
the gate that path would record.

## Current values

The shipping artifact is `2026.09-provisional`, `uncalibrated`. These are the values
the code reads at runtime; the reason for each is in `PARAMETERS`, and the fusion
argument is in `03-fusion-and-calibration.md`.

| Parameter | Value | Unit |
|---|---|---|
| `challenge.step_seconds` | 15 | seconds |
| `challenge.steps_per_epoch` | 20 | steps |
| `challenge.lifetime_seconds` | 30 | seconds |
| `challenge.clock_skew_seconds` | 10 | seconds |
| `challenge.accept_window_steps` | 2 | steps |
| `proof.max_offline_hours` | 24 | hours |
| `proof.nonce_retention_hours` | 48 | hours |
| `proof.max_future_skew_seconds` | 120 | seconds |
| `relay.max_hops` | 3 | hops |
| `fusion.weight.identity_authenticated` | 900 | millinats |
| `fusion.weight.device_bound` | 700 | millinats |
| `fusion.weight.challenge_committed` | 1400 | millinats |
| `fusion.weight.biometric_outcome` | 1100 | millinats |
| `fusion.weight.clock_consistency` | 250 | millinats |
| `fusion.weight.origin_direct` | 2300 | millinats — **reserved, Phase 4** |
| `fusion.weight.relay_depth` | 450 | millinats — **reserved, Phase 6** |
| `fusion.weight.relay_integrity` | 800 | millinats — **reserved, Phase 6** |
| `fusion.weight.anchor_fingerprint` | 3400 | millinats — **reserved, Phase 5** |
| `fusion.weight.spatial_stability` | 1700 | millinats — **reserved, Phase 5** |
| `fusion.correlated_credit_pct` | 35 | percent |
| `fusion.block_cap_millinats` | 4600 | millinats |
| `decide.present_millinats` | 2500 | millinats |
| `decide.secondary_millinats` | 1000 | millinats |
| `decide.min_coverage_pct` | 20 | percent |
| `decide.min_supplied_pct` | 90 | percent |

The five reserved weights sum to 8650 of a 13000 total. That is the number to keep in
view when reading any claim about this build: **two thirds of the designed evidence
base is unbuilt**, the largest weights in the table are the two that bear on
location, and `decide.min_coverage_pct` is set to 20 because a flawless handset on
this build reaches roughly a quarter of the ceiling. The artifact reports that
honestly rather than renormalising it away.

## Changing a value

1. Copy the active artifact to `presence-<new-version>.json`, change the value,
   update `version` inside the file to match the filename.
2. Set `calibration` truthfully. A hand-changed threshold does not become
   `field-validated`.
3. Say in `notes` what changed and why. This is the only place the reason for a
   specific value in a specific version lives.
4. Run the suite. `test_every_artifact_on_disk_loads` validates the new file,
   `HygieneTests` catches a value that also got inlined somewhere, and
   `manage.py check` runs the cross-check.
5. Roll it out with `PRESENCE_CONFIG_VERSION` — one deployment at a time if the
   change moves an operating point.

Sessions already open keep their pinned version, and their queued proofs keep being
judged by it. That is the rule working, not a caching bug.
