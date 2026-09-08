# 05 — Threat model

Every attack is recorded in five parts: **ATTACK** (what the adversary does),
**EXPECTED SIGNAL** (what it should look like from inside the system),
**DETECTION** (the mechanism that sees it), **MITIGATION** (what happens then) and
**RESIDUAL RISK** (what is still open). The last part is the one that matters; a
threat model without it is a marketing document.

## Adversary model

Three adversaries, with different capabilities, treated differently:

**A1 — the cooperating student.** A student who wants to be marked present while
elsewhere, and a friend inside the room who will help. Ordinary phones, no special
equipment, no code. This is the overwhelmingly common case and the one the design
is aimed at.

**A2 — the technical student.** Can read this repository — it is public — install
tools, script an HTTP client, decompile the APK, root a handset, and run a BLE
sniffer. Cannot break Ed25519 or extract a key from a hardware keystore.

**A3 — the insider.** Has database access, or is the teacher. Explicitly *not*
defended against for challenge minting: see A3 below, stated rather than hidden.

Out of scope, and stated so: breaking Ed25519, HMAC-SHA256, HKDF or SHA-256;
compromising a hardware keystore; physical coercion; and an institution that
chooses not to look at its own flags.

## What this build actually closes

| # | Attack | Closed |
|---|---|---|
| 1 | QR screenshot forwarded to a student outside | **Yes** |
| 2 | QR photographed and used later in the session | **Yes** |
| 3 | Video of the teacher's screen, replayed | **Yes** |
| 4 | Session UUID obtained and submitted directly | **Yes** |
| 5 | Replaying a captured proof | **Yes** |
| 6 | Backdating an offline mark | **Yes** |
| 7 | Late offline sync marking the whole class present | **Yes** |
| 8 | Sharing credentials so a friend marks you present | **Yes** |
| 9 | Marking from a second device on the same account | **Yes** |
| 10 | Self-granting an admin account through registration | **Yes** |
| 11 | Forging a challenge without the session key | **Yes** |
| 12 | Tampering with a proof in transit | **Yes** |
| 13 | Claiming a favourable verdict in the proof body | **Yes** |
| 14 | Denial of attendance by relaying garbage at a victim | **Yes** (by design) |
| 15 | **Marking present from outside the room** | **NO — see RESIDUAL RISK** |

Rows 1–14 are closed by cryptography and protocol design and need no hardware.
Row 15 needs spatial evidence, which needs beacons nobody has bought.

## T1 — QR screenshot forwarded out of the room

**ATTACK.** A student inside photographs the projected QR and sends it to a friend
in the corridor, who scans the image from their screen.

**EXPECTED SIGNAL.** The forwarded challenge belongs to a step that has passed by
the time it is used. Messaging latency, screen-capture time and the recipient's
reaction are each seconds; the step is 15.

**DETECTION.** `challenge.verify_committed` recomputes the step window from
`session_start` and `challenge_seq`. A challenge outside `lifetime_seconds` plus
`clock_skew_seconds` fails with `challenge_expired`; one behind the acceptance
window fails with `challenge_stale_step`.

**MITIGATION.** Hard gate. `NOT VERIFIED`, reason `challenge_expired`, no score
computed.

**RESIDUAL RISK.** A recipient who is *already waiting*, on a fast connection,
with the app open, has a window of `lifetime_seconds + clock_skew_seconds` — 40
seconds under the active timing, spanning up to two steps. This is closed by
distance, not by time: the recipient still needs their own account, their own
registered device and their own biometric, so the attack degenerates into T15 —
the student being outside the room. Shortening `step_seconds` narrows the window
and raises the failure rate for slow cameras and poor lighting; the current value
is a stated engineering trade, not a measurement.

## T2 — QR photographed and used later in the same session

**ATTACK.** As T1, but the student keeps the image and scans it half an hour later.

**EXPECTED SIGNAL.** The step is far behind the session's current step.

**DETECTION.** `challenge_stale_step` from the acceptance window
(`accept_window_steps` = 2), and independently `replay_step_regression` from the
per-device step high-water mark if that device has already been counted further
into the session.

**MITIGATION.** Hard gate, `NOT VERIFIED`.

**RESIDUAL RISK.** None specific to this attack beyond T1's window.

## T3 — Video of the teacher's screen, replayed

**ATTACK.** A student records the projector for the whole lesson and replays it
later, giving them every challenge in sequence.

**EXPECTED SIGNAL.** Whichever step is chosen is stale by exactly the amount of
time between recording and replay.

**DETECTION.** As T1 and T2 — the recording does not make any individual step
fresher. Additionally, an epoch key covers only 20 steps, so a recording of one
epoch yields nothing about any other.

**MITIGATION.** Hard gate, `NOT VERIFIED`.

**RESIDUAL RISK.** A recording replayed *in real time* to a student outside the
room — a live video call pointed at the projector — defeats the freshness check
entirely, because the challenge really is current. This is T15. It is not closed by
this build. It is the single most practical attack remaining, requires no technical
skill beyond a video call, and it is closed only by spatial evidence.

## T4 — Session UUID obtained and submitted directly

**ATTACK.** The pre-presence attack: learn the `session_id` and POST a mark. Under
the old primitive this was sufficient — possession of the UUID *was* the
authentication.

**EXPECTED SIGNAL.** A submission with no challenge, or with a fabricated one.

**DETECTION.** There is no endpoint that accepts a mark without a signed proof. The
proof must carry a challenge the server can re-derive from the session root key,
and a signature from a registered device over the whole struct.

**MITIGATION.** The attack has no route. The old `qr_code_data` no longer contains
a usable secret: it carries no `pattern_code` and its challenge expires.

**RESIDUAL RISK.** None. This is the primitive the layer was built to replace.

## T5 — Replaying a captured proof

**ATTACK.** Intercept or copy a valid proof — from a network capture, a rooted
handset's queue, or a shared debug log — and submit it again, perhaps from a
different device.

**EXPECTED SIGNAL.** Byte-identical, or identical but for fields the attacker
cannot re-sign.

**DETECTION.** Three independent mechanisms, any one of which suffices:
`replay_duplicate_proof` from the SHA-256 digest ledger; `replay_nonce_reused`
from the per-session nonce ledger; and a signature failure the moment any field is
altered.

**MITIGATION.** A byte-identical resubmission is **idempotent** and returns the
original decision, because a phone that lost the network mid-submission has done
nothing wrong. A *modified* copy fails signature verification. A different proof
from the same device at the same step is a second attempt and a finding.

**RESIDUAL RISK.** The proof is a bearer credential for its own single use. An
attacker who captures one before the genuine device submits it can spend it — and
in doing so **denies the genuine student their mark**, because the digest is then
burned. This is why the nonce ledger runs last in the gate order, and it is why
`replay_duplicate_proof` returning the original decision matters: the genuine
student's resubmission gets the verdict the attacker's submission produced, against
their own device key, so the outcome is correct even though the attacker triggered
it. Transport confidentiality (HTTPS, enforced) is what actually prevents the
capture.

## T6 — Backdating an offline mark

**ATTACK.** Edit the client's clock, or the queued record, so a mark appears to
have happened during a session that has ended.

**EXPECTED SIGNAL.** A `captured_at` inconsistent with the challenge the proof
committed to.

**DETECTION.** `marked_at` is `auto_now_add` at the database level, so the client's
timestamp has no path to it through any code. `replay.claim_signals` raises
`signal_capture_claim_ahead_of_server` and
`signal_capture_claim_predates_challenge` when the claim is impossible relative to
the challenge.

**MITIGATION.** The claim is recorded and attributable — it is inside a signed
struct — and it is not the time of record. The signals feed fusion and the
integrity engine rather than gating, because an unsynchronised device clock is
common and mostly innocent.

**RESIDUAL RISK.** A device whose clock is merely *wrong* produces the same signals
as one lying deliberately. The system does not distinguish them and should not
pretend to; what it does is record the discrepancy so a pattern across sessions is
visible to the integrity engine.

The replaced primitive wrote the client's `timestamp` directly into `marked_at`
behind a 24-hour window check. That is now impossible rather than merely
discouraged.

## T7 — Late offline sync marking the whole class present

**ATTACK.** Not really an attack — a defect severe enough to belong here. The
pre-presence offline-sync path computed
`default_status = 'present' if is_expired else 'absent'`. Syncing a session more
than 24 hours late marked **every unmarked enrolled student present.**

**EXPECTED SIGNAL.** A sync arriving after the session's expiry window.

**DETECTION AND MITIGATION.** The fail-open default is removed. Absent evidence
produces no mark, never a favourable one. A regression test asserts that a late
sync does not mark unmarked students present.

**RESIDUAL RISK.** None for the presence path. This is listed because it was by
some distance the largest hole in the system it replaced — larger than the
client-supplied timestamp — and because "the default when we do not know" is worth
checking in any code that touches attendance.

## T8 — Credential sharing

**ATTACK.** A student gives their password to a friend inside the room, who logs in
and marks them present.

**EXPECTED SIGNAL.** A successful login and a proof from a device that is not the
student's registered one.

**DETECTION.** `gate_unknown_device` — the friend's handset holds no device key
bound to that student. `gate_device_not_enrolled` if a key exists but is not
enrolled for the class.

**MITIGATION.** Hard gate. Before this layer, **nothing bound a login to a device
at all**, so this attack simply worked.

**RESIDUAL RISK.** The student can hand over the *handset*, unlocked. Then the
biometric gate is the only remaining obstacle, and a student who has shared their
password will share a finger. Device binding raises the cost from "send a text
message" to "give someone your phone for the hour", which is a real deterrent and
not a proof. Enrolment fraud is the deeper version: a student who registers a
friend's device as their own has bound the wrong device from the start. Enrolment
should be supervised; this build does not enforce that.

## T9 — Second device on the same account

**ATTACK.** A student registers a spare handset, leaves it in the classroom, and
marks themselves present remotely.

**EXPECTED SIGNAL.** Two device keys for one student, one of which is never in the
same place as the student.

**DETECTION.** `RegisteredDevice` records a device per student with platform and
capability flags, and each key has its own id. A second registration is visible as
a second row rather than as an indistinguishable login.

**MITIGATION.** Partial, and honestly partial. Policy on how many devices a student
may bind is an institutional decision the model supports and does not make.
`gate_device_revoked` exists so a device can be withdrawn.

**RESIDUAL RISK.** **Substantially open.** A spare phone left on a desk, with the
biometric supplied at enrolment time and a session that does not re-prompt, is a
working proxy. Two things narrow it and neither closes it: the biometric gate must
be satisfied at the time of the proof, and the phone must be *in* the room for the
spatial evidence of Phase 5. On this build, only the first applies. Restricting
enrolment to one device per student would help and is not implemented.

## T10 — Self-granting an admin account

**ATTACK.** POST to the public registration endpoint with `role: "admin"`. Under the
pre-presence serializer this set `is_staff = True`, minting a Django-admin account
against a publicly routed `/admin/`.

**EXPECTED SIGNAL.** A registration body asking for a privilege it should not be
able to request.

**DETECTION AND MITIGATION.** Two independent belts. `validate_role` refuses any
role outside `{student, teacher}` with a 400, and `create()` forces `is_staff` and
`is_superuser` to false regardless of what the body asked for. Both are deliberate:
one stops the role, the other stops the privilege, and a future serializer change
that loosens either one still has to get past the other.

**RESIDUAL RISK.** None for this route. Note that this was **remotely exploitable
against the live deployment** and is the reason Phase 0a was the first commit of the
work rather than a cleanup at the end.

## T11 — Forging a challenge

**ATTACK.** Construct a plausible `qr_challenge` — correct session id, a future
step, a made-up 8-byte challenge value — and build a proof committing to it.

**EXPECTED SIGNAL.** A challenge value that does not re-derive.

**DETECTION.** `challenge.verify_committed` recomputes
`mac_truncated(epoch_key, session_id || epoch || seq)` from the session root secret.
A mismatch is `challenge_forged`, distinct from `challenge_bad_signature` and from
`challenge_expired`.

**MITIGATION.** Hard gate, classified `FORGERY_SHAPED`, so the verdict is
`SUSPICIOUS` rather than `NOT VERIFIED`. Something asserted what it could not have
known.

**RESIDUAL RISK.** The challenge is truncated to 8 bytes, so a blind guess succeeds
with probability 2^-64 per attempt. That is not the concern; the concern is an
attacker with a *rate*. Submission rate limiting and the per-device step high-water
mark bound attempts, and each failure is recorded as a `SUSPICIOUS` finding rather
than a silent 400 — so a grinding attack is loud. Rate limiting on
`/api/v1/presence/proofs/` is a deployment configuration item and should be
verified in the environment rather than assumed from this document.

## T12 — Tampering with a proof in transit

**ATTACK.** Modify a field — `biometric` from `cancelled` to `success`, say — on a
proof captured in flight.

**EXPECTED SIGNAL.** A signature that no longer covers the bytes presented.

**DETECTION.** `proof.verify` against the registered device's public key. The
signature covers every field including the observation hashes, so an attacker cannot
add, remove or alter an observation either.

**MITIGATION.** Hard gate, `proof_bad_signature`, classified `FORGERY_SHAPED` →
`SUSPICIOUS`.

**RESIDUAL RISK.** None cryptographically. Operationally: a device whose private key
is *not* in a hardware keystore (`CAP_HARDWARE_KEYSTORE` unset) can have its key
extracted from a rooted handset, after which the attacker signs whatever they like
as that student. The capability bit records which devices are in that position; this
build does not refuse them, because refusing would make cheaper handsets
unverifiable. That is a policy lever the institution can set and this document
flags rather than decides.

## T13 — Claiming a favourable verdict

**ATTACK.** Set `claimed_status = PRESENT` and `claimed_confidence_milli = 1000` in
the proof and sign it. The claim is genuinely signed by a genuine device key.

**EXPECTED SIGNAL.** A signed claim that disagrees with what the server derives.

**DETECTION.** The claim is never an input. `decide.decide` computes the verdict from
the evidence vector; the claim is stored alongside. `decide_self_contradiction`
fires when a signed claim contradicts the proof's own other signed fields.

**MITIGATION.** The claim is inert and attributable. A client that lies is on
record as having lied.

**RESIDUAL RISK.** None to the verdict. The claim fields are retained deliberately
rather than dropped, because a device that repeatedly claims more than it can
support is a signal worth having.

## T14 — Denial of attendance

**ATTACK.** A malicious device in radio range appends garbage relay hops to other
students' chains, or floods the room with invalid origin frames, so that everyone's
proof fails to verify and nobody is marked present.

**EXPECTED SIGNAL.** Observation bodies that fail verification, attached to
otherwise valid proofs from many different students.

**DETECTION.** `gates._admit_observations` verifies each body independently of the
proof carrying it.

**MITIGATION.** **An unverifiable observation is dropped; the proof is not
refused.** This asymmetry is the entire defence. Dropping costs that student
evidence, which is recoverable — they fall to `SECONDARY` and get a second check.
Refusing would cost them the lesson, which is not recoverable, and would hand any
attacker with a phone the ability to fail a whole classroom.

**RESIDUAL RISK.** An attacker can still degrade a room from `PRESENT` to
`SECONDARY` en masse, which is a nuisance amounting to "everyone gets checked
manually today". Detecting the flood itself — many dropped bodies of the same shape
across many students in one session — is an integrity-engine pattern and is not
implemented; it is noted in `10-validation-plan.md` as a gap. Note also that this
attack requires the relay layer to exist, so it is not reachable on this build.

## T15 — RESIDUAL RISK: marking present from outside the room

**This is not closed. It is accepted, and it must survive into anything said about
this feature — including a demo.**

**ATTACK.** A student stands outside the window, or in the corridor, or in the
adjacent room, or on the pavement below. They have:

- a valid account and a successful login,
- their own registered device with its key in a hardware keystore,
- a fresh challenge — obtained from a live video call pointed at the projector, or
  simply by standing close enough to read the screen through the glass,
- a real biometric, supplied by the real finger of the real student.

They submit. Every gate passes. Every available evidence feature is present.
`supplied_pct` is 100%.

**They are marked `PRESENT`.**

**EXPECTED SIGNAL.** Nothing this build can observe. Every signal it has is
satisfied, honestly, by a student who is three metres away through a wall.

**DETECTION.** None available. The evidence that would discriminate is spatial:
multi-anchor RSSI fingerprinting compared against a per-room, per-device calibrated
profile that includes explicit *negative* positions — corridor, outside-window,
adjacent-room, different-floor. Those are `anchor_fingerprint` and
`spatial_stability`, they are the **two largest weights in the fusion table**, and
both report `reserved` on every proof this build produces.

**MITIGATION.** None in this scope. What exists instead:

- The `coverage_pct` figure sits near 26% on a perfect proof, and that number is
  reported rather than hidden. The system says out loud that three quarters of its
  designed evidence base is missing.
- The evidence vector, wire schemas and data model reserve the space, so Phase 5 is
  an addition rather than a rewrite.
- The honest-limits disclosure is a Phase 2 UI requirement, not a Phase 4 one,
  precisely because *every* platform is in this degraded mode today.

**RESIDUAL RISK — stated in full.** Physical presence in the room is **not
established** by this build. What is established is that an authenticated student,
on a device bound to them, holding a challenge that was live within the last few
tens of seconds, with a fresh biometric, produced a proof that cannot be forged,
replayed, backdated or transferred. That is a large improvement over a system where
possessing a session UUID was sufficient. It is not proof of presence.

Anyone told otherwise is being misled.

## A3 — The insider, stated rather than hidden

**Database access mints challenges.** `SessionKeys` holds the challenge root secret
and the challenge signing key, and both are at rest in the database, because the
teacher's device must generate challenges with no connectivity. An attacker with
database read access can therefore mint valid challenges for any session.

They **cannot** sign a proof as any student: device private keys are generated on
the handset and never leave it. There is no escrow and no recovery path.

That asymmetry is why the two key hierarchies are separate, and it is the reason
this section exists rather than the property being left implied. Mitigations are
operational rather than cryptographic: encrypt the database at rest, restrict
production database access, and treat `PRESENCE_SIGNING_KEY` as a production secret
with its own rotation procedure.

**The teacher is trusted, and audited.** A teacher can override any machine verdict.
`ManualOverride` records actor, timestamp, stated reason, the original decision and
the new one, and **never erases the original**. The defence against teacher fraud is
the audit trail, not prevention — a teacher who can end a session and mark a
register can always mark whoever they like, and pretending otherwise would be
theatre.
