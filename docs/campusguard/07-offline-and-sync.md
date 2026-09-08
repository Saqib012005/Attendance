# 07 — Offline operation and sync

The design premise is that the classroom has no usable internet. Not "intermittent
as a degraded mode" — **absent as the normal case.** A teacher starts a session, a
student is marked, and the network may not reappear until either of them leaves the
building.

Two properties follow, and everything in this document is a consequence of one of
them:

1. **Nothing on the marking path may require a round trip.** A challenge must be
   generated, displayed, scanned, verified and turned into a signed proof with both
   devices offline.
2. **A proof that arrives late must be judged on evidence, not on trust.** The
   server was not present when the mark happened, so its only route to a verdict is
   re-derivation from things it independently knows.

## What is offline by construction

The rolling challenge is a **pure function** of the session root key and the step
number. Neither device needs to ask anything of the server:

- The teacher's device derives epoch keys from the session root key by HKDF and the
  challenge for step *n* by HMAC. It can do this for every step of a 50-minute
  lesson at the moment the session is created.
- The student's device verifies the challenge locally — `verify_public` for the
  cheap shape check, `verify_authoritative` when it holds the session key.
- The proof is built and signed on the handset by a key that never leaves it.

The one thing the student's device cannot do offline is *find out whether the mark
was accepted*. That is not a gap in the protocol; it is the definition of being
offline, and it is why the response to a sync is a verdict rather than an
acknowledgement.

## What the server refuses to take from the client

The old marking path wrote a **client-supplied `timestamp` straight into
`marked_at`**, behind a 24-hour window check. A client could therefore choose when
it had attended. Worse, a session synced more than 24 hours late ran
`default_status = 'present' if is_expired else 'absent'`, so a late sync marked every
unmarked enrolled student **present**. Both are gone.

What the server derives for itself, on every submission:

| Fact | Source | Never |
|---|---|---|
| `received_at` | the server's clock | a client field |
| `queued_seconds` | receipt time minus the step's own window, from the challenge chain | a client timestamp difference |
| `marked_at` on the resulting record | `auto_now_add` | settable through any code path |
| the verdict | re-run gates, re-extract features, re-fuse | `claimed_status` |
| confidence | re-fused | `claimed_confidence_milli` |
| hop count | re-verified chain | `claimed_hop_count` |

`queued_seconds` is the interesting one. It is a *measurement of lateness* rather
than an assertion about it, because the step a challenge belongs to is fixed by the
chain and cannot be chosen by the handset. That is what lets fusion weigh lateness
without giving the client a lever on it.

The device's own timestamp claim is still recorded — `captured_at_claim` — and two
signals are raised from comparing it with facts the server owns:
`signal_capture_claim_ahead_of_server` and
`signal_capture_claim_predates_challenge`. A lie is evidence too. It is just not
input to arithmetic.

## The three time windows, and why two of them differ

Read from the active config artifact, not written into code:

| Parameter | Value | What it bounds |
|---|---|---|
| `proof.max_offline_hours` | 24 | How long a queued proof may wait and still be accepted |
| `proof.nonce_retention_hours` | 48 | How long the replay ledger remembers a burnt nonce |
| `proof.max_future_skew_seconds` | 120 | How far ahead of the server a capture claim may be |

**Retention is deliberately longer than acceptance.** If the ledger forgot a nonce
at the same moment the proof carrying it became too old, there would be a window in
which a replayed proof was neither remembered nor rejected for age — and the order
of those two expiries would decide the outcome. Making retention outlast acceptance
means every proof still inside the acceptance window is checked against a ledger
that still remembers it, and every proof outside it is refused on age before
uniqueness is consulted at all.

A proof past 24 hours is refused with `replay_too_old`. That is one of only four
refusals a student is told the reason for, because it is the one they can act on:
*"This attendance was recorded too long ago to be accepted now."* Every other
refusal answers with a generic sentence, since a complete refusal vocabulary
returned to whoever is probing it is a map of the checks.

## A retry is not a second attempt

This is the part of an offline system that goes wrong quietly. A queue whose
acknowledgement was lost on a train will send the same proof again, and that is the
**ordinary case**, not an attack. Getting it wrong in the safe-looking direction —
refusing every resubmission — marks an attending student absent with no route back
but a teacher override.

The rules, in the order they matter:

**A resubmission of a proof this same student already had accepted is answered with
the stored verdict.** Nothing new is recorded and no fresh refusal is invented. The
response carries `duplicate: true` so a client can tell an acknowledgement from a
first acceptance, and the verdict is byte-for-byte the one that was reached the
first time.

**A refused submission burns no nonce.** `replay.admit` is the *last* gate for
exactly this reason: if a malformed copy of a submission consumed the nonce, anyone
able to replay one corrupted copy could stop the genuine one from ever being
accepted.

**Attempts are rows.** `AttendanceProof.digest` is unique only among rows whose
`validation_state` is `accepted`:

```python
models.UniqueConstraint(
    fields=['digest'],
    condition=models.Q(validation_state='accepted'),
    name='presence_proof_digest_accepted_once',
)
```

A plain unique index here was a real bug, and the model docstring records it: the
first *refused* row made every later attempt at the same body collide, so one
corrupted signature on a flaky link would answer the student's own honest retry with
the refusal forever. The partial constraint keeps saying the thing that actually
matters — **one body is marked present at most once** — while letting a student
retry. The replay ledger says the same thing from the other side, against a
different table.

**A mark may have more than one proof.** `AttendanceProof.record` is a ForeignKey,
not a OneToOne, and the model docstring names this as a corrected modelling slip. A
student recorded for review who later submits a proof that clears outright has two
proofs bearing on one mark; so does anyone whose queue drains twice with a fresh
nonce each time. Under a unique index the second was an `IntegrityError` on an
ordinary action.

The four states a submission can end in:

| `validation_state` | Meaning |
|---|---|
| `received` | Stored, not yet judged |
| `accepted` | Re-derived and judged — this is the one the unique constraint covers |
| `refused` | Refused before scoring; no nonce burnt |
| `duplicate` | An idempotent retry of something already decided |

## Out-of-order arrival, and the mark that is never pruned

A queue does not drain in the order it filled. Proofs from steps 4, 11 and 7 may
arrive in that sequence, and the protocol has to distinguish *late* from
*regressive*.

`StepHighWater` holds one small integer per device per session: the furthest step
that device has had accepted. A proof for an earlier step than the mark is refused
with `replay_step_regression`; one for a step the session has not reached yet is
refused with `replay_step_not_yet_issued`.

**The high-water mark is never pruned, and is deliberately not derived from the
replay ledger.** Ledger entries expire on the retention schedule. If the mark were
computed from them, the first prune would forget how far a device had got and
re-open the regression the mark exists to refuse — a defence that works in every
test and fails in the field 48 hours in. The in-memory ledger used by tests and by
the Phase 3 lab makes the identical choice, because an adapter that diverged here
would pass its own suite and fail only after the first prune.

## Evidence can arrive after the proof it belongs to

The proof carries a fixed-width array of 32-byte canonical hashes of observation
bodies, not the bodies. Two consequences, both intended:

- An observation body can be gathered, hashed into the proof, and **synced
  separately later**, still bound by the original signature — because the hash was
  signed.
- A body whose schema tag this build does not recognise is set aside as unusable
  rather than refusing the submission carrying it. A newer client talking to an
  older server degrades; it does not fail.

The same asymmetry applies to bodies that fail verification: `gates` **drops** an
unverifiable observation and continues, rather than refusing the proof. See
`00-architecture.md` and `05-threat-model.md` T14 — refusing would let a rogue
device in radio range deny attendance to everyone around it.

## What a verdict does to the register

Only `PRESENT` asserts attendance. The mapping is small and each row is a decision:

| Verdict | `AttendanceRecord` |
|---|---|
| `PRESENT` | `present` |
| `SECONDARY` | `pending_review` — the existing status, reused rather than joined by a fourth spelling of the same idea |
| `NOT VERIFIED` | **no record at all** |
| `SUSPICIOUS` | **no record at all** |

The two negative outcomes write nothing, and that is the important line. An `absent`
row reads as a finding that the student was elsewhere; what actually happened is that
this proof did not establish anything. The attempt survives as a `PresenceDecision`
and an `AttendanceFlag`, and the teacher's audited override exists for the case where
the student was in fact there.

## The client queue

**What exists today** (`frontend/attendance_app/lib/services/sync_service.dart`):
three sqflite tables — `offline_queue` for pattern images, `offline_sessions` for
teacher-created sessions, `offline_qr_queue` for scans — a 30-second drain timer, a
24-hour TTL, and three statuses: `pending`, `synced`, `failed_file_missing`. On web
the same shapes are kept in `SharedPreferences` as JSON lists.

**What Phase 2 adds** is a fourth table for signed proofs, alongside the existing
three rather than replacing them, with states that distinguish outcomes the current
three cannot express:

| State | Meaning |
|---|---|
| `queued` | Signed, waiting for a network |
| `sending` | In flight; a crash here must not lose the row |
| `accepted` | Server returned a verdict of `PRESENT` |
| `review` | Server returned `SECONDARY` |
| `rejected` | Server refused; the reason it is willing to state is stored |
| `expired` | Past `max_offline_hours` before a network appeared — never silently dropped |
| `conflict` | The server answered with a verdict for a *different* proof covering this session |

The distinction that matters: `expired` and `rejected` are **kept and shown**, not
deleted. A student whose proof died in the queue needs to know that, and their
teacher needs to be able to see it, because the override path is the only remedy and
it cannot be exercised on a row that was quietly removed.

`sending` exists because at-least-once delivery is the only achievable guarantee
offline. The server's idempotence — a resubmitted accepted proof returns the stored
verdict — is what makes at-least-once safe. Those two designs are a pair; neither
works alone.

## Failure modes, and what happens

| Situation | Outcome |
|---|---|
| Acknowledgement lost, client retries | Stored verdict returned, `duplicate: true`, nothing re-recorded |
| Session ended before the student synced | Accepted if the step's window began before the session closed; a step that begins after close is refused as session-closed |
| Handset clock hours wrong | The verdict does not depend on it. `captured_at_claim` is compared against server facts and raises a signal; a claim more than `max_future_skew_seconds` ahead is refused |
| Network reappears after 24 hours | Refused `replay_too_old`, and the student is told so in plain words |
| Queue drains out of order | Judged per step against `StepHighWater` |
| Two students share one handset offline | Second proof is signed by a device bound to the first student. Submitting under the other account is a **403**, not a verdict |
| Observation bodies lost, proof survives | Proof stands; the features those bodies would have supplied report `not_observed`, which is not adverse |

## What offline operation does not solve

**A courier.** A student leaving a room with no signal cannot carry a peer's proof
out for them. A proof submitted under an account that does not own the signing device
answers **403 and records nothing** — deliberately, because that is an authorization
failure of the *request* and not a verdict about a *student*, and writing a refusal
row would make one person's misuse look like another person's failed attendance. An
authenticated courier envelope is the relay design's business and does not exist.

**A device with no clock at all** still works, since the verdict never depends on the
handset's clock. What it loses is the ability to have its capture claim corroborated,
so it supplies one fewer temporal signal.

**Liveness.** A proof built from step *n* is byte-identical whether it was scanned
during step *n* or copied from a screenshot of it seconds later. Offline operation
neither causes nor worsens that; see `05-threat-model.md` T1 and T15.
