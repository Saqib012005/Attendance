# 10 — Validation plan

Every claim in this documentation is in one of three states, and this document exists
to keep them apart:

- **Verified** — a test that runs in CI fails if the claim stops being true.
- **Planned** — the check is designed, the gate is named, the code is not written.
- **Not done** — named here, with what it would take, and not softened.

**No accuracy figure appears anywhere in this document.** Not a percentage, not a
false-accept rate, not a target dressed as a result. The reason is in *Why there are
no rates yet* below, and it is a stronger reason than caution.

## What is verified today

962 tests, all passing, run by CI on every push and pull request before anything is
allowed to build or deploy.

| Suite | Tests | Covers |
|---|---|---|
| `tests.py` | 31 | the analytics engine (pre-existing) |
| `tests_marking.py` | 49 | the Phase 0a fixes on the old marking path |
| `tests_presence_keys.py` | 71 | key hierarchy, derivation, signing, rotation, MAC truncation |
| `tests_presence_codec.py` | 51 | canonical encoding, schema tags, round-trips, malformed input |
| `tests_presence_challenge.py` | 57 | rolling chain, epochs, expiry, skew, forgery |
| `tests_presence_origin.py` | 62 | origin frame build/verify, ephemeral ids, BLE frame budget |
| `tests_presence_chain.py` | 72 | relay chain of custody, hop verification, pseudonyms |
| `tests_presence_proof.py` | 48 | proof schema, signing, bounds, claim fields |
| `tests_presence_replay.py` | 51 | nonce ledger, windows, duplicates, concurrency |
| `tests_presence_gates.py` | 72 | the hard rejects, their order, and what each leaves behind |
| `tests_presence_features.py` | 82 | observation window to sparse evidence vector |
| `tests_presence_fusion.py` | 72 | block decomposition, correlation discount, caps |
| `tests_presence_decide.py` | 68 | verdicts, coverage, reason codes, refusals |
| `tests_presence_config.py` | 37 | artifact loading, bounds, cross-checks, hygiene sweep |
| `tests_presence_models.py` | 47 | the 14 presence models, constraints, purge behaviour |
| `tests_presence_endpoint.py` | 54 | submission end to end, idempotence, what reaches a student |
| `tests_presence_wiring.py` | 38 | session opening, artifact pinning, challenge issuance, deploy checks |

882 of those are presence tests: 11,086 lines of test against 6,760 lines of
presence code plus 888 lines of Django-facing views and ledger. The ratio is
deliberate for a layer whose output is evidence about a person.

Three properties of the suite worth naming, because they are what makes it more than
a count:

- **Refusals are asserted for their side effects, not just their status.** A forged
  proof must leave the nonce ledger untouched, write no decision row, and mark
  nobody — `test_a_forged_proof_leaves_the_ledger_untouched`,
  `test_every_refusal_before_the_ledger_leaves_it_empty`.
- **Damage is swept rather than sampled where the input space allows it.** A
  truncated signature is refused *at every length* including empty and over-long
  (`test_a_truncated_signature_is_refused_at_every_length`); every byte-taking entry
  point in `chain.py` is fed garbage and must refuse with a declared reason code
  rather than leaking a codec error (`test_every_byte_taking_entry_point_refuses_with_a_declared_code`);
  single-bit flips in messages, signatures and challenge payloads each have their own
  test.
- **The concurrency case is tested with real threads.** `tests_presence_replay.py`
  runs simultaneous submissions of one proof through a barrier and asserts exactly
  one admission, with every loser carrying a declared duplicate code.

## Attack coverage today

The attack numbering is `05-threat-model.md`'s, so the two documents cannot drift.
"How" says what kind of check it is, which matters more than that a check exists.

| # | Attack | State | How it is checked |
|---|---|---|---|
| 1 | QR screenshot forwarded out of the room | Verified | challenge expiry and step bounds, `tests_presence_challenge.py` + endpoint refusal |
| 2 | QR photographed, used later in the session | Verified | same, plus `test_a_challenge_the_session_has_not_reached_is_a_fabrication` |
| 3 | Video of the teacher's screen, replayed | Verified | as 1–2; the challenge is stale before the recording is useful |
| 4 | Session UUID submitted directly | Verified | proof signature + challenge commitment are required; `test_an_invented_challenge_value_does_not_pass_for_one` |
| 5 | Replaying a captured proof | Verified | nonce ledger, `test_an_admitted_proof_burns_its_nonce`, `test_a_reused_nonce_under_a_different_proof_is_refused`, plus the threaded concurrency test |
| 6 | Backdating an offline mark | Verified | `test_a_backdated_capture_claim_backdates_nothing`, `test_the_mark_is_timestamped_by_the_database_and_not_the_request`, and `tests_marking.py` for the old path |
| 7 | Late offline sync marking the class present | Verified | `test_a_late_sync_marks_unmarked_students_absent_not_present` |
| 8 | Credential sharing | Verified | device binding; `test_another_students_device_cannot_be_submitted_under_this_account` |
| 9 | Second device on the same account | Verified | `test_a_proof_from_an_unknown_key_is_recorded_against_the_submitter`, `test_a_revoked_device_is_told_to_register_the_current_one` |
| 10 | Self-granting an admin account | Verified | `test_admin_role_is_refused_and_creates_nothing`, `test_is_staff_in_the_payload_is_ignored` |
| 11 | Forging a challenge | Verified | HMAC verification; bit-flip and fabrication tests |
| 12 | Tampering with a proof in transit | Verified | `test_the_stored_body_is_the_bytes_the_signature_was_checked_over`, truncation sweep, bit flips |
| 13 | Claiming a favourable verdict | Verified | `test_a_claimed_verdict_does_not_become_the_verdict`, `test_a_claimed_hop_count_conjures_no_hops`, `test_a_claimed_present_cannot_rescue_a_forged_proof` |
| 14 | Denial of attendance by relaying garbage | Verified by design | relay evidence is a bonus and never a precondition: `test_a_reserved_absence_is_never_adverse`, `test_a_handset_without_the_capability_is_unsupported`, `test_the_reserved_features_never_count_as_withheld_on_any_vector` |
| 15 | **Marking present from outside the room** | **Not closed, not testable here** | needs spatial evidence; see below |

## Why there are no rates yet

This is the part of a validation plan that is usually padded with numbers, so it is
worth being precise about why there are none.

**Rows 1–13 are correctness properties, not rates.** A forged signature is refused
because Ed25519 verification fails, an expired challenge because arithmetic on the
step index says so, a replayed nonce because the ledger has a unique constraint. The
correct target for each is exactly zero accepts, the tests assert exactly that, and a
measured "false accept rate of 0.02%" for any of them would mean a bug rather than a
tuning opportunity. Reporting them as rates would make deterministic guarantees look
statistical, which reads as more rigorous and is less.

**Row 15 is the one that needs a rate, and it is the one no test on this build can
reach.** Distinguishing a student at a desk from a student at the window is a
statistical judgement about radio, made against a room profile, with a real
false-accept and false-reject trade-off. That is Phase 5. There is no spatial
evidence in this build, so there is nothing to measure, and any number quoted for it
would be fabricated.

Between those two sits the fusion layer, which *does* have tunable operating points
(`decide.present_millinats`, `min_coverage_pct`, `min_supplied_pct`). Its parameters
are currently an argued ordering, not a fit — the artifact says `uncalibrated` and
`decide` refuses to emit a confidence percentage at all. `03-fusion-and-calibration.md`
covers what that means; the consequence here is that there is no operating curve to
report because nothing has been fitted.

## What is not tested, named

Five gaps. Each says what it needs, so none of them can be mistaken for an oversight.

**1. The adversarial lab does not exist.** `presence/lab/` is an empty directory.
Phase 3 fills it: an RF propagation model for a 15×20 ft room with wall, window and
door attenuation; a relay-graph simulator at 10 / 30 / 50 / 100 / 200 students; and
scenario generators for all fifteen attacks. Its value on *this* build is not rate
measurement — see above — but scale: a generator can push thousands of variations of
rows 1–13 through the real `gates` and `fusion` code where a unit test builds one by
hand. For rows 14–15 and the relay rows it is the only way to reach the question at
all, and even then it measures a model rather than a classroom.

**2. There is no cross-language codec test**, because there is no second language
yet. `01-protocol-spec.md` and `02-crypto-spec.md` both depend on a Dart client
producing byte-identical canonical encodings, and a silent divergence there would
invalidate every proof in the field while every backend test still passed. The test
is specified — the same struct signed in Dart and verified in Python and the reverse,
compared byte for byte — and it is blocked on the Phase 2 client existing.

**3. There are no client tests for presence**, for the same reason: the client is
Phase 2. The Flutter project currently has one 16-line smoke test. When the
verification stepper and the teacher console land they need widget tests, and
`flutter analyze` needs to be in CI, which it is not.

**4. There is no device compatibility matrix.** `06-platform-matrix.md` documents the
platform constraints from vendor documentation, which is not the same as knowing which
handsets can actually advertise, hold a foreground scan past an OEM battery manager,
or reach `android.ranging`. That matrix is a Phase 4 deliverable and it needs real
devices.

**5. There is no field study.** This is the largest gap and the one that bounds every
claim. See below.

## The adversarial matrix, as a plan

Phase 3's lab command runs scenarios through the **real** gate and fusion pipeline —
not a copy of it — and asserts an outcome per row. The point of wiring it into CI is
regression: a change to a weight or a threshold that weakens a defence should fail
the build rather than ship.

| Rows | Scenario family | Assertion | Meaning of the assertion |
|---|---|---|---|
| 1–4 | stale, forwarded, recorded and fabricated challenges, generated across the whole timing space | zero accepts | fuzz-scale coverage of a deterministic property |
| 5 | replay under concurrency, duplicate nonces, reordered sequences | zero accepts, exactly one admission per proof | as above, plus a race |
| 6–7 | backdated captures, late syncs, clock-skew extremes | zero accepts; no unmarked student ever becomes present | as above |
| 8–9 | unknown, revoked and cross-account device keys | zero accepts | as above |
| 10 | privilege escalation through registration | zero accepts | as above |
| 11–13 | forged MACs, tampered bodies, fabricated claim fields | zero accepts | as above |
| 14 | garbage relayed at a victim, rogue relays injected into chains | **no genuine student loses a verdict they would otherwise have earned** | a fairness property, and the reason relay is a bonus |
| 15 | positions inside, at the window, at the door, in the corridor, in the adjacent room | a measured accept rate per position | **only meaningful from Phase 5, and only against the model** |
| relay | coverage, latency, loss, collision and dedup at 10–200 students | congestion holds at 100+ | gates whether Phase 6 is buildable at all |

Two honesty constraints on that table, both of which have to survive into anything
said about the lab:

- **A rate measured against a simulator is a statement about the simulator.** The
  propagation model is written by the same people as the thing it tests. Numbers from
  it are labelled `simulator-fitted` in the artifact that consumes them and are never
  reported as field results.
- **Zero accepts in a fuzz run is not a proof of impossibility.** It is a much wider
  net than a unit test and it is still a net. The cryptographic argument for why rows
  1–13 cannot be accepted is in `02-crypto-spec.md`; the lab checks the implementation
  against that argument rather than establishing it.

## Calibration, as a plan

`presence/calibrate.py` does not exist. What it has to do is fixed by the config
registry, which already has the machinery to accept its output:

1. **Take labelled observations** — proofs with a known ground truth of inside or
   outside the room — and fit the per-feature weights and the operating points.
2. **Report the diagnostics that make a confidence figure meaningful**: reliability
   diagram, Brier score, expected calibration error, and the FAR/FRR curve from which
   an operating point is *chosen* rather than picked.
3. **Emit a new artifact**, with `calibration` set to whatever is true —
   `simulator-fitted` from lab data, `field-validated` only from field data.
4. **Never edit an existing artifact.** A refit is a new version, so every decision
   already recorded keeps naming the parameters that actually produced it.

The state transition is the honest part. `Artifact.is_calibrated` is true only for
`field-validated`, and `decide` gates `confidence_milli` on it, so a confidence
percentage cannot appear until a field dataset exists. Two tests have to be
deliberately changed to make that happen —
`test_the_shipped_artifact_is_not_calibrated` and
`test_simulator_fitted_is_not_calibrated` — which is the right amount of friction for
a claim about accuracy.

Reuse rather than a second statistics layer: `analytics/metrics.py` is already
dependency-free stdlib and already carries percentiles, MAD-based z-scores, the
`math.erf` normal CDF, CUSUM, EWMA and OLS slope. Calibration imports from there.

## The field study, which has not happened

This is what would let anything in this documentation be called validated, and it is
the one thing no amount of code substitutes for.

**What it needs, and none of it exists yet:**

- A pilot room with anchors installed and surveyed — roughly four beacons, which is a
  procurement decision nobody has made.
- A room profile calibrated at every position that matters: front, middle, back, all
  four corners, beside the door, beside the window, **and the negatives** — the
  corridor outside, immediately outside the window, the adjacent room, and a
  different floor. The negatives are the entire point; a profile fitted only on
  interior positions cannot discriminate.
- Multiple handset models, because RSSI is device-specific and per-device
  normalisation is exactly the sort of correction that looks fine on the phone it was
  written on.
- Real densities. A model that holds for 10 students and collapses at 60 has not been
  validated for a classroom.
- Repetition across times of day and room occupancy, because bodies attenuate 2.4 GHz.
- Ground-truth labels collected independently of the system being tested.

**The one test that would settle row 15**, from the delivery plan and still the right
shape: two physical phones and the pilot room's anchors; mark attendance from inside
the room, then from outside the window, outside the door, in the corridor and in the
adjacent room; confirm the decision and the reason codes match what
`05-threat-model.md` predicts for each position. It cannot run on this build, and
that is precisely why row 15 stays listed as an open residual risk rather than as a
mitigated one.

Until it runs: **the correct statement is that this build produces an unforgeable,
non-replayable, non-backdatable, device-bound, biometric-gated, offline-capable
attendance proof that the server re-derives — and that it is not proof of physical
presence in the room.** Both halves, every time, including in a demo.

## Gates that run today

CI, `.github/workflows/main_presence.yml`, on every push and pull request. `test`
gates `build`, which gates `deploy`, and nothing deploys from a pull request or from
a branch other than `main`.

| Gate | What it catches |
|---|---|
| `manage.py check` | a configuration artifact that will not load, or whose parameters are mutually contradictory — `attendance.E001/E002/E003` |
| `manage.py makemigrations --check --dry-run` | a model edited without its migration, which passes every test and then fails on deploy |
| `manage.py test attendance -v 2` | the 962 tests above |

Two of those catch a class of failure that testing alone does not. The system check
fires on a deployment variable typo that would otherwise surface as a run of 503s;
the migration check fires on a schema drift that the test runner cannot see, because
it builds its database from the models rather than from the migrations.

CI pins Python 3.11 to match `backend/Dockerfile`, and supplies a junk `SECRET_KEY`
as a literal rather than a repository secret — `settings.py` refuses to boot without
one, and handing a test run the deployment's key would put a production signing
secret inside every run including one triggered from a fork.

**Not in CI yet:** `flutter test`, `flutter analyze`, and the Phase 3 lab command.

## Running it locally

```bash
cd backend
PYTHONPATH= SECRET_KEY=probe python manage.py test attendance -v 1
PYTHONPATH= SECRET_KEY=probe python manage.py check
PYTHONPATH= SECRET_KEY=probe python manage.py makemigrations --check --dry-run
```

`PYTHONPATH=` is not decoration: it shadows a conflicting global Django install on
the development machine, which is what `dev.ps1` exists to do on PowerShell. A
`SECRET_KEY` must be present in the environment because `settings.py` no longer
carries a fallback — that was one of the Phase 0b hardening changes. The
`UserWarning: No directory at: …staticfiles\` line is expected noise from a
development tree with no collected static files.

One suite at a time, by module:

```bash
PYTHONPATH= SECRET_KEY=probe python manage.py test attendance.tests_presence_gates -v 2
```
