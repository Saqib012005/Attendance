# 00 — Architecture

## What problem the layer solves

The question the presence layer answers is deliberately not *"did a request
arrive claiming this student is here?"* It is:

> Does this authenticated device exhibit sufficient authenticated evidence of
> participation inside the active classroom trust domain?

The distinction matters because the previous primitive answered the first
question. `AttendanceSession.qr_code_data` was plain unsigned JSON containing
`session_id` and a `pattern_code` drawn from `random.randint(10, 99)` — ninety
possible values, shareable by screenshot. The offline path wrote a
client-supplied `timestamp` straight into `marked_at`, so a client could backdate
its own attendance, and a session synced more than 24 hours late marked every
unmarked enrolled student **present**. Proxy attendance was caught after the fact
and statistically, by the analytics integrity module. That is good forensics on a
weak primitive.

## Where presence stops and analytics starts

They are separate packages with separate jobs, and the boundary is load-bearing.

| | `attendance.presence` | `attendance.analytics` |
|---|---|---|
| Question | Is *this one* mark evidenced? | What do *all* the marks mean? |
| Input | One signed proof plus its observation window | Records already committed |
| Output | `PRESENT` / `SECONDARY` / `NOT VERIFIED` / `SUSPICIOUS` + reason codes | Rates, forecasts, risk bands, integrity flags |
| Timing | At submission, before a record exists | After the fact, over history |
| Determinism | Integer arithmetic; same verdict on every machine | Float statistics |

Presence does not compute percentages and analytics does not adjudicate proofs.
Where the two meet, presence reason codes flow into the existing
`AttendanceFlag` table by extending `FLAG_TYPE_CHOICES`, rather than growing a
parallel flag system.

Two invariants are inherited from `analytics/__init__.py` verbatim, and two more
are specific to handling evidence:

1. **No value is invented.** Absent evidence is reported as absent, never
   substituted with a plausible-looking number.
2. **Every derived figure traces back** to the observations that produced it.
3. **Absent evidence is not negative evidence.** A platform that cannot supply a
   signal moves the verdict toward `SECONDARY`; it never moves it toward
   `SUSPICIOUS`, and it never makes a compliant student unverifiable.
4. **Nothing the client asserts is trusted.** Client status, confidence and hop
   count are recorded as signed claims — attributable, and re-derived server side
   before any decision is taken.

Presence reuses `analytics/metrics.py` rather than forking a second statistics
layer, and reuses its honesty machinery: `metrics.safe_pct` returns `None` on a
zero denominator, and `context.insufficient(actual, required)` is the existing
insufficient-data marker.

## Layering

`backend/attendance/presence/`. Each module depends only on those above it, and
that ordering is enforced by the import graph, not by convention.

```
codec       canonical deterministic encoding for everything that gets signed
keys        key hierarchy, rotation, Ed25519 sign/verify, HKDF derivation
challenge   session root key -> epoch keys -> linked rolling challenge chain
replay      nonce, sequence, epoch and duplicate-proof windows
origin      teacher BLE origin payload            (schema reserved; unbuilt)
chain       relay chain of custody                (schema reserved; unbuilt)
proof       the signed attendance proof: build, verify, canonical hash
gates       mandatory hard rejects, run to completion before any scoring
features    observation window -> sparse evidence vector
fusion      dependency-aware accumulation over independent evidence blocks
calibrate   fit likelihoods and thresholds from labelled data   (Phase 3; unbuilt)
decide      gates + fusion -> Decision with reason codes and versions
config/     versioned parameter artifacts + loader + schema validation
lab/        adversarial simulator                               (Phase 3; empty)
```

Sizes, as a rough map of where the work is: `challenge` 689 lines, `features`
679, `fusion` 606, `chain` 579, `keys` 554, `decide` 542, `gates` 528, `codec`
531, `proof` 521, `origin` 509, `replay` 460, `config` 482.

Three of those modules are placeholders of different kinds, and the difference
matters when reading the code:

- **`origin` and `chain` are fully implemented and fully tested, but nothing
  calls them with real data.** They exist because the wire schemas they own had
  to be declared before the proof schema froze — see *Reserved space* below.
- **`calibrate` and `lab` do not exist yet.** They are Phase 3. Until they do,
  the active configuration is an ordering argument, not a measurement, and
  `03-fusion-and-calibration.md` says so at length.

## The decision pipeline

One path, no branches that skip a stage:

```
    submitted bytes
        |
        v
  gates.clear(...)  ------ GateError ------>  decide.refuse(...)
        |                                          |
        v                                          v
  features.extract(cleared)                     Decision
        |                                    (NOT VERIFIED or
        v                                     SUSPICIOUS, with
  fusion.fuse(vector, ...)                     the gate's reason)
        |
        v
  decide.decide(fused, biometric=..., policy=...)
        |
        v
     Decision
```

Gates are hard rejects and are **not** probabilistic inputs. An invalid session,
an expired or replayed challenge, a bad signature, an unknown device, a duplicate
proof: each ends the pipeline. Folding those into a score is how scoring systems
get talked past — a sufficiently high score on everything else should never buy
its way past a forged signature, and the only way to guarantee that is to refuse
before scoring exists.

### Gate order, and why the last position is load-bearing

`gates.clear()` runs its checks in a fixed order: cheapest and most specific
first, so the reason code that gets recorded is the informative one rather than
whichever check happened to run first.

1. **Shape** — decode the submitted bytes against the frozen schema.
2. **Registration** — resolve `device_key_id` to a `RegisteredDevice`; refuse
   unknown, revoked and not-enrolled separately, because those are three
   different problems for whoever reads the flag.
3. **Signature and session binding** — `proof.verify` against that device's
   public key.
4. **Committed challenge** — `challenge.verify_committed` re-derives the
   challenge from the session root key and confirms the proof committed to a
   challenge the server itself could have issued.
5. **Session open** — refuse a step whose window begins after the session ended.
6. **Attached observations** — admit the observation bodies, *dropping*
   unverifiable ones rather than refusing the proof (see below).
7. **Uniqueness — last, and only last.** `replay.admit` writes. Burning a nonce
   on a proof that was going to be refused anyway would let anyone who can replay
   one malformed copy of a submission stop the genuine one from ever being
   accepted.

### Two deliberate asymmetries

**A bad observation drops; a bad proof refuses.** A rogue device within radio
range can append a hop to anyone's chain. If a proof whose chain failed to verify
were refused, that rogue could deny attendance to every student in range by
relaying garbage at them. Dropping the unverifiable body costs the student
evidence, which is recoverable; refusing costs them the lesson, which is not.

**Liveness is not gated, and cannot be.** A challenge is a function of the
session and the step, so a proof built from step *n* is byte-identical whether it
was scanned during step *n* or copied from a screenshot of it later. Nothing in
the proof distinguishes those. What the server can do, and does: bound how late a
proof may arrive, refuse a step the session has not reached, refuse a device
already counted further into the session, and record a server-derived
`queued_seconds` so fusion can weigh lateness. The remaining gap — a code carried
out of the room and used later on a bound device — is closed by spatial evidence,
not by arithmetic, and is recorded as residual risk rather than papered over.

### No database in the decision path

`gates`, `features`, `fusion` and `decide` touch no ORM. Every fact they cannot
compute arrives as an argument: the session's keys, when it opened and closed, a
resolver for device registrations, a resolver for relay pseudonyms, and a ledger
interface. That is what lets the identical code path run inside a request, inside
a test, and inside the Phase 3 adversarial lab and reach the same verdict — and
it is why a verdict can be re-derived from the proof that produced it, which is
the whole value proposition of an evidence system.

## Reserved space, and why it was declared before it was needed

The proof schema is signed. Adding a field to it later would change what a
signature covers, which would invalidate every proof already in the field. So the
schemas for evidence this build cannot gather were declared **now**, and the
proof carries a fixed-width array of 32-byte canonical hashes of observation
bodies rather than the bodies themselves.

Two consequences fall out of that shape, both intended:

- An observation body can be gathered, hashed into the proof, and **synced
  separately later** — still bound by the original signature, because the hash
  was signed.
- A body whose schema tag this build does not recognise is set aside as unusable
  rather than causing the submission carrying it to be refused. A newer client
  talking to an older server degrades; it does not fail.

The registry as declared in this build, with the CBOR tag each struct carries:

| Tag | Schema | Purpose | State |
|---|---|---|---|
| 1 | `qr_challenge` | What the teacher's screen displays and the student scans | **Live** |
| 2 | `attendance_proof` | The signed proof the student submits | **Live** |
| 3 | `origin_sighting` | A student's sighting of the teacher's BLE origin frame | Reserved (Phase 4) |
| 4 | `relay_hop` | One authenticated hop of the relay chain of custody | Reserved (Phase 6) |
| 5 | `anchor_reading` | One RSSI reading of one room anchor | Reserved (Phase 5) |
| 6 | `device_registration` | Device binding enrolment | **Live** |

`codec.schema_fingerprint()` is a SHA-256 over a canonical text rendering of the
entire registry. In this build it is:

```
087177288b4c3f4eaa91203feafe8b57de5028f59ccd99980be6bc42c0078109
```

The fingerprint exists so a Dart implementation and a Python implementation can
prove they agree on every field of every struct. `codec.schema_text()` renders
the registry as text rather than only hashing it, because the moment two
fingerprints disagree is exactly the moment you want a diff naming which field
moved.

### The spatial evidence contract

`04-spatial-evidence.md` is deferred with Phase 5 — writing it now would document
a system nobody can run. What cannot be deferred is the *shape* the data model
must already accept, because getting that wrong means a migration rewrite later.
That contract is:

- **Anchors are identified ephemerally.** `anchor_reading.anchor_ref` is 4 bytes
  derived per session, not a permanent beacon MAC. A passive listener collecting
  refs across two sessions learns nothing that links them.
- **RSSI crosses the wire as an unsigned offset.** `rssi_offset = dBm + 128`, so
  the codec never needs a signed integer — one fewer cross-language encoding
  decision to get wrong. Round-tripped by `origin.to_offset` / `origin.rssi_dbm`.
- **A reading carries its sample count.** A single sample and a median of twenty
  are not the same evidence, and the fingerprint comparison needs to know which
  it got.
- **Comparison is per-room and per-device.** `RoomProfile` is versioned and holds
  the per-position distributions; `RegisteredDevice` holds the normalisation
  profile. There is no universal RSSI threshold anywhere, and there must never be
  one: the same -70 dBm means different distances in different rooms on different
  handsets.
- **Two evidence features are reserved, not merely absent.**
  `anchor_fingerprint` and `spatial_stability` report `reserved` on every proof
  this build produces, which is a different thing from `unsupported`.

## Data model

Fourteen models in `backend/attendance/models.py`, migrations `0014`–`0016`.
Every one carries a `presence_`-prefixed `db_table`, and that prefix is not
cosmetic — see *Why the prefix* below.

| Model | `db_table` | Holds |
|---|---|---|
| `Room` | `presence_rooms` | The missing spatial entity: code, name, dimensions, building, floor |
| `RoomProfile` | `presence_room_profiles` | Versioned per-room calibration: anchor map, per-position distributions, tolerance |
| `Anchor` | `presence_anchors` | A fixed BLE beacon: room, position, ephemeral-ID key, battery, last seen |
| `RegisteredDevice` | `presence_registered_devices` | Device binding: student, public key, platform, capability flags |
| `PresenceSession` | `presence_sessions` | The presence-layer state attached to an `AttendanceSession` |
| `SessionEpoch` | `presence_session_epochs` | Rolling challenge chain state: epoch, sequence, expiry |
| `PresenceObservation` | `presence_observations` | Raw per-observation evidence inside the window; **purged on session close** |
| `ReplayEntry` | `presence_replay_entries` | The nonce / digest ledger that makes a proof usable once |
| `StepHighWater` | `presence_step_high_water` | Furthest step each device has been counted at, per session |
| `AttendanceProof` | `presence_proofs` | The signed proof, its re-validation verdict, and sync state |
| `RelayChainRecord` | `presence_relay_chains` | The chain as submitted, retained for audit |
| `PresenceDecision` | `presence_decisions` | Decision, reason codes, evidence present/missing, and every version used |
| `ManualOverride` | `presence_manual_overrides` | Teacher override: actor, timestamp, reason, original decision, new decision |
| `ConfigVersion` | `presence_config_versions` | Registry row per activated config artifact, with activation gate results |

Four things about this table are decisions rather than defaults:

**`PresenceObservation` is purged on session close.** Raw RF observations are the
input to a verdict, not a record to keep. Retaining them across sessions would
accumulate exactly the permanent student RF tracking database that
`08-privacy.md` forbids.

**`PresenceDecision` records the versions, not just the verdict.** Config
version, calibration state, protocol version, codec fingerprint and room-profile
version. A verdict without them cannot be re-derived, and a verdict that cannot
be re-derived is an assertion rather than evidence.

**`ManualOverride` never erases the original.** Both decisions are stored, with
the actor, the time and the stated reason. A teacher correcting a machine verdict
is a normal and necessary operation; losing what the machine said is not.

**`AttendanceProof` is 1:1 with `AttendanceRecord`, and the existing
`unique_together (session, student)` stays** as the duplicate-attendance
backstop. `marked_at` remains `auto_now_add`, which is what makes a backdated
offline mark impossible to *write* through any code path rather than merely
rejected by one of them.

### Why the prefix

`backend/db.sqlite3` on the original development machine records **two divergent
migration lineages both as applied** — HEAD's `0008_remove_attendancesession_board_type`
through `0013_academicterm_…`, and an abandoned branch's `0008_enrollment_status`,
`0009_attendanceauditevent_registereddevice_and_more`,
`0011_attendancesession_boundary_unit_and_more`, `0012_remove_enrollment_status`.
Django keys `django_migrations` on `(app, name)`, so both sets coexist silently.

That dev database therefore physically contains three tables with **no model in
HEAD**: `attendance_audit_events`, `attendance_verifications` and
`registered_devices`. They are reachable only from the `teacher`,
`origin/teacher` and `backup-main-before-upstream-pull` branches, traced to
commits `bec7805` and `aed5a86`.

A new `RegisteredDevice` model whose `db_table` was `registered_devices` would
fail with *table already exists* on that one machine and succeed everywhere else
— the worst possible failure shape. Namespacing every presence table avoids it
without writing a migration that drops tables holding somebody's rows.

## HTTP surface

One route. Deliberately.

```
POST /api/v1/presence/proofs/
```

The proof carries its own authentication — an Ed25519 signature over a canonical
CBOR struct, verified against the public key of a registered device. The endpoint
re-derives everything: challenge validity from the session root key, session
window, device registration, uniqueness, and then the decision itself. The
client's `claimed_status`, `claimed_confidence_milli` and `claimed_hop_count` are
stored as signed claims and are **never** inputs to the verdict.

There is no `GET` on this path, and there is no second route that accepts a
verdict. A single ingress point is what makes "the server re-derives rather than
trusts" a checkable property rather than an aspiration: there is exactly one place
to audit.

The scan endpoint that already existed is likewise `POST` and not `GET`, because
it persists `AttendanceFlag` rows and a `GET` that writes evidence rows turns a
page refresh into a finding.

## Client architecture (Phase 2, not yet built)

`frontend/attendance_app/lib/presence/`, mirroring the backend layering so the
two canonical encoders can be diffed field by field:

```
presence/
  crypto/        Ed25519 keypair in the platform keystore via flutter_secure_storage
                 plus the same canonical codec as the backend, cross-tested
  challenge.dart verify the rolling challenge locally, offline
  ble/           capability probe, origin advertiser, scanner, relay state machine
                 (all Phase 4+; the capability probe is what Phase 2 needs)
  biometric.dart local_auth gate; the result is SUCCESS / FAILED / CANCELLED only
  evidence.dart  observation-window collector
  proof.dart     build and sign the proof locally, offline
  store.dart     sqflite proof queue, extending the existing sync_service schema
```

Two inherited facts shape this rather than being worked around. `pubspec.yaml`
carries **both** `provider` and `flutter_riverpod`; new presence code uses
Riverpod, the newer of the two, rather than deepening the split. And
`lib/config/api_config.dart` hardcodes `isProduction = true`, so any local
development run needs `--dart-define=API_BASE_URL=http://<host>:8000/api/v1` —
the override replaces the whole base, suffix included.

The biometric result is three states and no more. No fingerprint, no face
template and no raw biometric image is stored, transmitted or hashed. What crosses
the wire is one small integer in a signed struct.
