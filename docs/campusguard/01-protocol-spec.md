# 01 — Protocol specification, v1

**Protocol version 1. Codec version 1. Schema registry fingerprint
`087177288b4c3f4eaa91203feafe8b57de5028f59ccd99980be6bc42c0078109`.**

This document specifies the wire formats and the rules for accepting them. It is
the contract between the Python implementation in
`backend/attendance/presence/` and the Dart implementation in
`frontend/attendance_app/lib/presence/`. Where the two disagree, the schema
fingerprint test fails and neither is trusted until they agree again.

> **This is not Bluetooth Mesh.** Nothing here claims conformance to any
> Bluetooth SIG specification beyond the use of ordinary BLE GATT and
> advertising as a transport. The relay protocol is a CampusGuard
> application-layer protocol. See `06-platform-matrix.md` for why Bluetooth Mesh
> was considered and rejected, and §*Standards* below for the split between what
> is standard and what is ours.

## Canonical encoding

Every struct that is signed, hashed or compared is encoded the same way:

```
cbor2.dumps([tag, version, field_0, field_1, ..., field_n], canonical=True)
```

A flat CBOR array, not a map. The first two elements are the schema tag and the
schema version; the rest are the declared fields in declaration order.

Five rules make the encoding deterministic enough to sign:

1. **Canonical CBOR** (`canonical=True`): definite-length items, shortest-form
   integers, deterministic ordering. Two implementations that both follow RFC
   8949's canonical rules produce identical bytes.
2. **Array, not map.** Field order is positional and fixed by the schema, so
   there is no key-ordering question to get wrong across languages.
3. **Every declared field must be present.** There are no optional-by-omission
   fields in a signed struct. A missing field is an error, not a default.
4. **An undeclared key is an error.** A mistyped field name would otherwise
   silently sign a value the caller never supplied.
5. **Fixed-size byte fields are length-checked on encode**, not merely on decode.
   A 15-byte session id does not become a valid 16-byte one by padding.

`codec.digest(schema, values)` is SHA-256 over those bytes and is a struct's
stable identity. `codec.digest_bytes(raw)` is the same over bytes already
encoded, for when a verifier holds the wire form and must not risk re-encoding
producing something different.

### Cross-implementation agreement

`codec.schema_text()` renders the entire registry as canonical text:

```
codec=1
anchor_reading tag=5 v=1 anchor_ref:bytes:4:0,ephemeral_id:bytes:8:0,...
attendance_proof tag=2 v=1 session_id:bytes:16:0,device_key_id:bytes:8:0,...
...
```

`codec.schema_fingerprint()` is SHA-256 over that text. Each implementation
produces the text from its own declarations and a cross-language test compares
them. Text rather than a bare hash, because when two fingerprints disagree the
thing you want is a diff naming which field moved — not the knowledge that
something, somewhere, differs.

## Schema registry

Six schemas, tagged 1–6. Tags are permanent: a tag is never reused for a
different struct, and an unrecognised tag is set aside rather than refused.

### Tag 1 — `qr_challenge`

What the teacher's screen displays and the student's camera scans.

| Field | Type | Size | Notes |
|---|---|---|---|
| `session_id` | bytes | 16 | The session this challenge belongs to |
| `key_id` | bytes | 8 | Which server signing key issued it |
| `epoch` | uint | — | Which epoch key derived it |
| `seq` | uint | — | Step index within the session |
| `challenge` | bytes | 8 | `HMAC-SHA256(epoch_key, …)` truncated |
| `prev_link` | bytes | 8 | The previous challenge in the chain |
| `issued_at` | uint | — | Server time, seconds |
| `expires_at` | uint | — | Server time, seconds |

It carries **no `pattern_code`**, and never will again. The replaced primitive's
freshness value was `str(random.randint(10, 99))` — ninety possible values, which
a student could guess in a few tries or simply read out to somebody in the
corridor.

`prev_link` is what makes the sequence a chain rather than a series. A verifier
that has seen step `seq - 1` can confirm linkage; one that has not can still
check the HMAC independently. At step 0 the link field carries a sentinel
(`(1 << 64) - 1`) standing in for "no previous step", so the genesis case has an
explicit encoding rather than a special case in every verifier.

### Tag 2 — `attendance_proof`

What the student signs and submits. Sixteen fields.

| Field | Type | Size | Notes |
|---|---|---|---|
| `session_id` | bytes | 16 | |
| `device_key_id` | bytes | 8 | **Who this is comes from here, not from a name field** |
| `challenge` | bytes | 8 | The challenge value committed to |
| `challenge_epoch` | uint | — | |
| `challenge_seq` | uint | — | |
| `nonce` | bytes | 16 | Fresh per proof; makes replay detectable |
| `captured_at` | uint | — | **Client clock. Signed, therefore attributable. Never the time the mark happened.** |
| `biometric` | uint | — | `0` absent, `1` success, `2` failed, `3` cancelled |
| `platform` | uint | — | `0` unknown, `1` Android, `2` iOS, `3` web |
| `capabilities` | uint | — | Bit field; see below |
| `claimed_status` | uint | — | The client's own view. Recorded, never trusted |
| `claimed_confidence_milli` | uint | — | Likewise |
| `claimed_hop_count` | uint | — | Likewise |
| `observations` | array | ≤64 | 32-byte canonical hashes of tags 3–5 |

There is no student identifier field anywhere in a proof. The server resolves
`device_key_id` → `RegisteredDevice` → student, which means a proof intercepted in
transit does not disclose whose it is to anyone without database access.

The three `claimed_*` fields exist because a client that lies should be **on
record** as having lied. They are signed, so the lie is attributable; they are
re-derived server side, so the lie is inert.

Capability bits, as declared in `proof.py`:

| Bit | Constant | Meaning |
|---|---|---|
| `1 << 0` | `CAP_BLE_SCAN` | Can scan for BLE advertisements |
| `1 << 1` | `CAP_BLE_ADVERTISE` | Can act as a BLE peripheral |
| `1 << 2` | `CAP_RELAY` | Can participate as a relay node |
| `1 << 3` | `CAP_RANGING` | Has the Android 16 ranging module |
| `1 << 4` | `CAP_BIOMETRIC` | Has a usable platform biometric |
| `1 << 5` | `CAP_HARDWARE_KEYSTORE` | Private key is hardware-backed |
| `1 << 6` | `CAP_BACKGROUND_SERVICE` | Can hold a typed foreground service |

Capabilities are how "this handset genuinely cannot do that" is distinguished
from "this handset chose not to". A bit the server does not recognise raises a
signal (`gate_unknown_capability_bit`) and is otherwise ignored — a newer client
is not punished for knowing more than the server.

### Tag 3 — `origin_sighting` *(reserved, Phase 4)*

A student's sighting of the teacher's BLE origin frame: `session_ref` (4),
`counter` (uint), `ephemeral_id` (8), `rssi_offset` (uint), `observed_at` (uint).

The frame that actually goes on air is not the CBOR struct — it is 17 packed
bytes, because BLE advertising has no room for CBOR:

```
[version:1][session_ref:4][counter:4][ephemeral_id:8] = 17 bytes
```

A legacy `ADV_IND` PDU carries 31 octets of AD data. Three go to the Flags AD
structure, two to the AD header, two to a 16-bit company identifier — leaving a
**24-octet budget** for manufacturer-specific data. The 17-byte frame fits with
room to spare, and `origin.ADVERTISEMENT_BUDGET` records the arithmetic so a
future field addition has to confront the limit rather than discover it on a
device.

`session_ref` is derived per session and is not the session UUID. `ephemeral_id`
is a truncated MAC under a per-counter derived key, so the advertisement is
unlinkable across sessions and carries no teacher identity.

### Tag 4 — `relay_hop` *(reserved, Phase 6)*

One authenticated hop: `hop_index` (uint), `prev_proof_hash` (32),
`relay_pseudonym` (16), `signature` (64), `observed_at` (uint).

Each hop signs a 98-byte preimage:

```
b"relay-hop" || hop_index(8, big-endian) || prev_proof_hash(32)
             || relay_pseudonym(16) || observed_at(8) || ...
```

`chain.PREIMAGE_LEN == 98` and `chain.LABEL == b"relay-hop"`. The domain label is
there so a relay signature can never be replayed as a signature over anything
else — a signing key used for two purposes with no domain separation is one
purpose away from a forgery.

`relay_pseudonym` is `HKDF(session_id, device_public_key)` truncated to 16 bytes.
It is stable within a session — so a repeated relay is detectable — and
meaningless outside it, so nothing links a student's relay activity across two
lessons. **No permanent student identity is ever exposed through the chain.**

`relay.max_hops` is 3 in the active configuration. A chain deeper than that is
refused with `chain_too_deep` rather than merely discounted.

### Tag 5 — `anchor_reading` *(reserved, Phase 5)*

`anchor_ref` (4), `ephemeral_id` (8), `rssi_offset` (uint), `sample_count`
(uint), `observed_at` (uint). See `00-architecture.md`, *The spatial evidence
contract*.

### Tag 6 — `device_registration`

`student_ref` (uint), `public_key` (32), `platform` (uint), `capabilities`
(uint), `created_at` (uint), `nonce` (16). Enrolment of a device key. Currently
**nothing in the pre-presence system bound a login to a device at all.**

## The rolling challenge chain

### Derivation

```
session root key                    (per session; see 02-crypto-spec.md)
    |
    |  HKDF, purpose "epoch", epoch index
    v
epoch key
    |
    |  HMAC-SHA256, truncated to 8 bytes
    v
challenge(epoch, seq) = mac_truncated(epoch_key, session_id || epoch || seq)
```

The MAC input is a hand-rolled 32 bytes — `session_id` (16) followed by `epoch`
(8, big-endian) followed by `seq` (8, big-endian) — rather than a codec schema.
That is a considered exception to "everything signed goes through the codec": all
three fields are fixed-width, so there is no length prefix to disagree about, no
ordering question and no encoding ambiguity. The properties the codec exists to
guarantee are free here. A schema would also spend one of the permanent tags and
change the pinned fingerprint for a structure that is never transmitted, only
recomputed on both sides. Big-endian because it is the order every standard
library agrees on without a flag.

Truncation to 8 bytes is safe here in a way it would not be for a long-lived
authenticator: the value is worthless outside its step, the server rejects a step
outside its acceptance window, and a wrong guess yields a rejected scan rather
than an oracle to grind against.

### Linkage

Step `seq` carries `prev_link = challenge(epoch_of(seq-1), seq-1)`.

Step 0 carries a **genesis link**: `challenge(epoch_key(0), SENTINEL, SENTINEL)`
where `SENTINEL = 2**64 - 1`. A sentinel rather than eight zero bytes, for two
reasons — zeros are a value an attacker can write by hand, whereas this requires
the epoch key; and no real step can reach `2**64 - 1`, so the genesis link can
never collide with a genuine step's challenge.

### Timing

Five parameters, read as **one snapshot** per operation rather than
parameter-by-parameter. A staged configuration rollout can legitimately swap the
active artifact between two requests; it must not be able to swap it between two
reads *inside* one verification, which is how a challenge ends up checked against
a step length and a lifetime that never coexisted. `Timing.version` travels with
the result so `PresenceDecision.config_version` records the parameters that
actually produced the verdict.

Active values under `2026.09-provisional`:

| Parameter | Value | Why |
|---|---|---|
| `challenge.step_seconds` | 15 | A forwarded screenshot is stale before it can be used |
| `challenge.steps_per_epoch` | 20 | 5 minutes per epoch key |
| `challenge.lifetime_seconds` | 30 | Exceeds one step, so a scan straddling a rotation still succeeds |
| `challenge.clock_skew_seconds` | 10 | Tolerance for an unsynchronised device clock |
| `challenge.accept_window_steps` | 2 | How far back a step may be and still be accepted |

These are engineering choices with stated reasons, **not measurements.** They are
in `presence/config/` because they are tunable, and they carry no claim to being
optimal.

### Verification, three depths

`challenge.py` exposes three verification entry points, and which one a caller
uses is itself a security decision:

- **`verify_public`** — structure, signature and freshness only. For a verifier
  holding the server's public key but not the session root key. Cannot confirm
  the challenge was one the server would have issued.
- **`verify_authoritative`** — adds re-derivation from the session root key. This
  is what proves the value was not fabricated by anyone who did not hold the key.
- **`verify_committed`** — what the gate calls. Confirms a *proof* committed to a
  challenge the server itself could have issued at that step, and returns the
  step's time bounds so later gates can compare the session window against them.

Eleven reason codes, each naming one specific failure:
`challenge_malformed`, `challenge_wrong_session`, `challenge_unknown_key`,
`challenge_bad_signature`, `challenge_expired`, `challenge_not_yet_valid`,
`challenge_timing_inconsistent`, `challenge_forged`, `challenge_link_broken`,
`challenge_stale_step`, `challenge_future_step`.

Separate codes rather than one `invalid`, because "your clock is 40 seconds fast"
and "you presented a value nobody could have issued" are the same HTTP status and
completely different events. One is a support ticket; the other is an incident.

## Replay, uniqueness and time windows

`replay.py` owns four separate questions that are easy to conflate:

| Question | Mechanism | Reason code |
|---|---|---|
| Have I seen this exact proof? | SHA-256 digest ledger | `replay_duplicate_proof` |
| Has this nonce been used? | Nonce ledger, per session | `replay_nonce_reused` |
| Did this arrive too late to mean anything? | `proof.max_offline_hours` | `replay_too_old` |
| Is this device going backwards? | Per-device step high-water mark | `replay_step_regression` |
| Is this a step the session has not reached? | Session start plus step arithmetic | `replay_step_not_yet_issued` |

Active bounds: `proof.max_offline_hours` 24, `proof.nonce_retention_hours` 48,
`proof.max_future_skew_seconds` 120.

Retention is deliberately **longer than acceptance**. A nonce is kept for 48 hours
while a proof is only accepted for 24, so a replay attempted just after the
acceptance window closes is still recognised as a replay rather than merely
rejected as late. Those are different findings and the second one loses
information.

### Duplicate submission is idempotent, not an attack

`decide.IDEMPOTENT` contains `replay_duplicate_proof`, and that single set
membership is the difference between a usable client and a broken one. A phone
that submits, loses the network before reading the response, and retries has done
nothing wrong. Resubmitting a byte-identical proof returns the original decision.

What is *not* idempotent: two **different** proofs from the same device at the
same step. Those are two attempts, and the second is a finding. A test named
`test_two_forged_attempts_at_one_body_are_two_attempts` pins this, because the
natural implementation of "be nice about retries" quietly makes forgery attempts
free.

### The client clock is never the time of record

`captured_at` is a client timestamp inside a signed struct. It is stored, and it
is attributable — a device that lies about its clock has signed the lie. It is
never written to `marked_at`, which is `auto_now_add` at the database level.

Two signals come out of comparing the claim to server-derived time, and both are
*signals* rather than gates:

- `signal_capture_claim_ahead_of_server` — the device claims to have captured the
  proof in the future.
- `signal_capture_claim_predates_challenge` — the device claims to have captured
  it before the challenge it committed to existed.

Neither refuses the proof. A device with a badly-set clock is common and mostly
innocent; a device whose clock claim is impossible relative to the challenge it
holds is more interesting, and the right response is to record it and let fusion
and the integrity engine weigh it, not to lock a student out of a lesson over an
unsynchronised NTP.

The replaced primitive did the opposite: it wrote the client's `timestamp`
directly into `marked_at` behind a 24-hour window check, so a client could
backdate its own attendance to any point in the previous day.

## Standards, and what is ours

Per the requirement not to overclaim conformance, stated explicitly:

**Standard, used as specified by its own specification:**

- Ed25519 signatures — RFC 8032.
- HMAC-SHA256 — RFC 2104, FIPS 180-4.
- HKDF — RFC 5869.
- CBOR and its canonical/deterministic encoding rules — RFC 8949.
- SHA-256 — FIPS 180-4.
- BLE GATT and BLE advertising, as a transport only — Bluetooth Core
  Specification. *(Phase 4+; nothing in this build touches radio.)*
- Android Ranging (`android.ranging`) — a platform API, not a protocol we define.
  *(Phase 8.)*

**CampusGuard application-layer protocol, ours and not standardised anywhere:**

- The rolling challenge chain: epoch derivation, step linkage, the genesis
  sentinel, the three verification depths.
- The attendance proof struct and its claim/re-derivation split.
- The relay chain-of-custody preimage, its domain label, and relay-scoped
  pseudonyms.
- The origin frame layout and its ephemeral identifiers.
- The evidence vector, block decomposition and millinat fusion arithmetic.
- The gate ordering and the drop-versus-refuse asymmetry.

**Explicitly not claimed:** Bluetooth Mesh conformance, any Bluetooth SIG
profile, any FIDO/WebAuthn conformance, and any certification of any kind. The
relay layer is not Bluetooth Mesh and must never be described as such — see
`06-platform-matrix.md` for the reasoning.
