# 08 — Privacy

Two rules bind everything in this document, and neither is a preference:

1. **This system must not become a permanent record of where students have been.**
2. **Students are not monitored outside an active attendance session.**

Presence verification needs radio observations, and radio observations are movement
data. The design's answer is not to promise restraint; it is to make the data
short-lived, to broadcast pseudonyms rather than identities, and to keep the
retention rule enforced by code that runs rather than by a paragraph like this one.

## What crosses the air

The teacher's origin frame is **17 bytes** and contains no person:

```
[version:1][session_ref:4][counter:4][ephemeral_id:8]
```

`session_ref` is a 4-byte reference derived for this session, not the session UUID.
`ephemeral_id` rotates. Two frames captured in two different lessons cannot be
linked to each other, and neither can be linked to a teacher, a class or a room by
anyone who was not given the session key.

The three ephemeral identifier families all come from the same HKDF hierarchy with
distinct purpose labels — `origin-ephemeral`, `relay-pseudonym`, `anchor-ephemeral`
— so a value from one context cannot be replayed as a value from another and none of
them is a durable identifier:

| Broadcast identifier | Scope | What a passive listener learns |
|---|---|---|
| Teacher `ephemeral_id` | one session, rotating | nothing that survives the lesson |
| Relay pseudonym | one session, one relay context | that *some* device relayed; not which student |
| `anchor_ref` (4 bytes) | one session | nothing that links two sessions |

That last row is the reason `anchor_reading.anchor_ref` is a derived per-session
value and **not a beacon MAC address**. A permanent beacon identifier would let
anyone with a scanner build a map of which rooms a phone visits, from outside the
system entirely.

**Never broadcast, and there is no field wide enough to carry it:** student names,
usernames, email addresses, student IDs, the permanent student identity, biometric
data of any kind, private keys, or analytics. The widest byte string any schema
declares is 32 bytes and every one of them is named in `01-protocol-spec.md`.

The relay chain deserves its own sentence, because a chain of custody is exactly the
sort of structure that leaks a roster by accident. **Pseudonyms only.** A chain
carrying permanent identities would broadcast a class list to anyone with a scanner.
The pseudonyms in `RelayChainRecord.hop_pseudonyms` resolve to people only through
this session, in this database. (No chains exist on this scope — the relay layer is
unbuilt — so the expected state of that table is empty.)

## Biometrics: four integers, and nothing else

The only biometric fact that crosses the wire is which of four things happened:

| Value | Meaning |
|---|---|
| 0 | `absent` — no biometric was attempted |
| 1 | `success` |
| 2 | `failed` |
| 3 | `cancelled` |

**Not stored, not transmitted, not hashed, not derived:** fingerprints, face
templates, raw biometric images, match scores, sensor data, retry counts per
modality. The platform biometric API returns a local outcome and that outcome
becomes one small integer inside a signed struct.

A `failed` outcome is the one adverse absence in the whole evidence model — see
`03-fusion-and-calibration.md`. A `cancelled` outcome is *not* adverse: a student
who dismissed a prompt has not done anything suspicious.

## Retention

| Data | Kept | Removed by |
|---|---|---|
| `PresenceObservation` — raw radio observations | until the session closes | `PresenceSession.close()`, at end-of-session |
| `ReplayEntry` — the nonce/digest ledger | `proof.nonce_retention_hours` (48 h) | pruned at each session close |
| `StepHighWater` | life of the session row | never pruned — deliberately |
| `AttendanceProof.proof_bytes` | with the attendance record | cascade from the session |
| `PresenceDecision` | with the attendance record | cascade from the session |
| `RelayChainRecord` | with the proof | cascade |
| `RegisteredDevice` | until revoked or the student is deleted | revocation, cascade |
| `AttendanceRecord`, `AttendanceFlag` | institutional register data | existing retention rules |

Three of those rows need justifying rather than merely listing.

**Observations are purged at close, and that purge is now actually wired.** The
guarantee was documented in three places and called from none: `end_session` did not
touch the presence row at all. Two properties were untrue as a result — the raw
observations outlived their lesson, and `closed_at` was never set, which left the
session-open gate unable to fire in production. `PresenceSession.close()` now does
both halves in one idempotent call, `views.end_session` invokes it on both of its
exit paths, and `EndSessionPresenceCloseTests` pins it. Recording this rather than
quietly fixing it is the point: a privacy property with no caller is a claim, not a
control.

**The replay ledger is pruned at session close.** Nothing pruned it either, so
entries accumulated for the life of the deployment — a permanent record of every
submission, which these rules do not allow. The horizon comes from
`replay.retention_horizon`, which is longer than the offline acceptance window by a
cross-check the config registry enforces, so pruning can never forget a nonce that a
still-acceptable proof could reuse. Session close is the moment because it is
infrequent and already inside a write; putting a delete on the proof endpoint would
have put it on the hot path.

**`StepHighWater` is never pruned, and that is the privacy-costly choice made
deliberately.** It is one small integer per device per session. Deriving it from the
ledger instead would mean the first prune forgot how far a device had got and
re-opened the step regression it exists to refuse. The cost is a row that says "this
device reached step 11 in this session" outliving the observations; the benefit is a
defence that does not evaporate 48 hours in. Both halves are stated in the model
docstring.

**What survives a purge is the decision, not the evidence.** A `PresenceDecision`
keeps its verdict, reason codes, which evidence was present and which was missing,
and every version used to reach it. That is what makes a verdict re-derivable and
challengeable months later. What it does not keep is what the room's radio looked
like at 10:15 on a Tuesday.

## What is identifying, and stays so

Pseudonymity is for the air, not for the register. Attendance is by its nature a
record about a named person, and pretending otherwise would be theatre. These are
identifying and are meant to be:

- `RegisteredDevice` binds a student account to one handset's public key. That
  binding is the point of device binding.
- `AttendanceProof.student`, `PresenceDecision`, `AttendanceFlag` and
  `AttendanceRecord` all name a student.
- `ManualOverride` names the teacher who overrode a verdict, when, and why.

The distinction that matters: these are **register data about attendance events**,
not **movement data about a person's location over time**. The first is what a
school already keeps. The second is what the purge rules exist to prevent
accumulating.

## Leaving mid-session: three policies, and which one is in force

A student marked present at 10:05 who leaves at 10:15 is a real institutional
question, and the honest answer is that it is a policy question rather than a
technical one. Three options, with what each costs:

**Policy A — mark on arrival, and stop.** Presence is evidenced once, at the moment
of marking. Departure is not detected and not looked for. *Privacy cost: none
beyond the marking itself. Integrity cost: a student can leave immediately after
being marked.*

**Policy B — sample within the session window.** Additional observation windows at
unpredictable points during the lesson, each producing evidence bound to the same
session. *Privacy cost: the system now observes students at moments they did not
initiate. Integrity cost: much lower. Requires the spatial or network evidence that
does not exist on this build.*

**Policy C — continuous monitoring for the session's duration.** *Privacy cost:
unacceptable, and it is the rule this document opens with. Not offered.*

**Policy A is what this build does**, and it is the only one it *can* do: there is
no BLE evidence, no anchors and no continuous collection anywhere in the code. That
is a consequence of the scope, not a considered institutional choice, and it should
not be presented as one.

If an institution later wants Policy B, the constraint it inherits from this document
is that sampling must remain **inside an active session, initiated by the session,
and purged at its close** — the same three conditions that govern the observation
window today. Policy C stays refused whatever anyone asks for, because a system that
watches students between lessons is a different product with different consent
requirements.

## Secrets, and what a compromise reaches

Stated rather than left implied, because a privacy document that omits its own worst
case is not much use:

**A database compromise lets an attacker mint challenges** for any session, since
`PresenceSession` holds the challenge root secret and signing seed at rest — it must,
because the teacher's handset generates challenges offline.

**It does not let them sign a proof as any student.** Device private keys are
generated on the handset, live in the platform keystore, and never leave it. There is
no escrow and no recovery path, which is a deliberate trade: a lost handset means
re-registration, not key recovery.

**It does not reveal a biometric**, because none was ever stored anywhere.

`PresenceSession.__repr__` is written out by hand and prints
`root_secret=<redacted> signing_seed=<redacted>`, because the default repr of a model
with secret columns is one careless log line away from printing them. Mitigations
beyond that are operational: encrypt at rest, restrict production database access,
and treat `PRESENCE_SIGNING_KEY` as a production secret with its own rotation
procedure — see `02-crypto-spec.md`.

## Who can see what

| Audience | Sees | Never sees |
|---|---|---|
| Student | their own verdict, the evidence *categories* used and unavailable, one plain sentence per outcome | reason-code vocabulary, relay topology, hop counts, anchor identities, other students' evidence |
| Teacher | per-student verdicts for their own sessions, reason *category*, evidence summary, the override action | raw observations (purged), any other teacher's sessions |
| Administrator | aggregate integrity signals, decision records with reason codes | biometric data (none exists), raw observations after close |

The student-facing restriction is not paternalism. A complete refusal vocabulary
returned to whoever is probing the system is a map of its checks, which is why
`presence_views.ACTIONABLE` contains exactly four entries — the refusals a student
can actually do something about — and everything else answers with the generic
sentence for its outcome.

## Deletion and data-subject requests

Deleting a `User` cascades to their `AttendanceRecord`s, `AttendanceProof`s,
`PresenceObservation`s and `PresenceDecision`s. `RegisteredDevice` goes with them, so
the student-to-public-key binding disappears; the key itself was never held here.
`ReplayEntry` rows carry no student foreign key — they hold a device key id and a
digest — and expire on the retention schedule.

Two honest limitations:

- **A deleted student's `ManualOverride` rows name the teacher, not the student**, so
  an override survives the student's deletion as a record of a teacher action. Whether
  that is correct depends on the institution's own retention rules and is not
  something this layer should decide.
- **No automated export exists.** A subject access request is served by querying the
  database. Building an export endpoint is a real deliverable and it is not in this
  scope.

## Open items

- **The purge runs at session close, and a session that is never ended never
  purges.** Sessions do expire, but expiry is not the same code path as
  `end_session`. A periodic sweep over presence sessions whose parent session ended
  long ago is the missing belt-and-braces, and it needs the management-command
  package that Phase 3 creates.
- **No retention sweep for `AttendanceProof.proof_bytes`.** Proofs live as long as
  the attendance record they support, which is the institution's register retention.
  That is defensible and it is also an unbounded default nobody has explicitly
  chosen.
- **Consent and notice copy does not exist.** Students should be told, in the app,
  what is collected during a session and what is discarded at its end. The
  capability-disclosure surface in Phase 2 is where that belongs.
