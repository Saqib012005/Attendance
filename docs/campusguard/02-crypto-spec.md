# 02 — Cryptography

## Primitives

Three, all from the `cryptography` package (pinned `cryptography==50.0.0`), all
used as their own specifications describe:

| Primitive | Standard | Used for |
|---|---|---|
| Ed25519 | RFC 8032 | Signing challenges, proofs, relay hops, device registrations |
| HMAC-SHA256 | RFC 2104 | Challenge values, ephemeral identifiers |
| HKDF-SHA256 | RFC 5869 | Every derived key |
| SHA-256 | FIPS 180-4 | Canonical struct digests, key ids |

**No primitive is invented, and no construction is used that could not be
described to a reviewer in terms of those four.** That is a hard constraint, not
a preference. There is no custom cipher, no home-made KDF, no novel signature
scheme, no "hardened" hash, and no place where a security property rests on
something not in the list above.

Sizes: seeds 32 bytes, public keys 32, signatures 64, key ids 8, MACs 32 (full)
or 8 (truncated, challenge only).

### Where truncation happens, and why it is defensible there

`keys.mac_truncated` exists for exactly one caller: the challenge value, cut to 8
bytes so it fits in a QR code a phone camera can read across a classroom.

Truncation is a real reduction in strength. It is acceptable here because the
value is worthless outside its 15-second step, is single-use, and is checked
against a server-side sequence window — so a forgery attempt is bounded by rate
limiting and window arithmetic rather than by the MAC length alone, and a wrong
guess produces a rejected scan rather than an oracle to grind against.

The docstring on that function says *"do not reuse this for anything
long-lived"*, and that warning is the load-bearing part.

## Key hierarchy

Two hierarchies, deliberately separate, meeting nowhere.

```
SERVER / TEACHER SIDE                      STUDENT DEVICE SIDE
=====================                      ===================

PRESENCE_SIGNING_KEY  (env, 32-byte seed)  device seed (generated on device,
    |                                       never leaves the hardware keystore)
    | Keyring: one active + retired             |
    v                                           v
server signing key (Ed25519)               device signing key (Ed25519)
    | signs challenges                          | signs proofs, relay hops
    |
    v
SessionKeys(session_id, root_secret, signing)
    |
    | HKDF, purpose "epoch", salt=session_id, context=epoch
    v
epoch key  --HMAC-->  challenge(epoch, seq)
```

### Domain separation

Every derivation goes through `keys.derive`, which builds its HKDF `info` as:

```
info = b"campusguard/presence/v1/" || purpose || 0x00 || context
```

`purpose` must be one of five declared strings — `epoch`,
`origin-ephemeral`, `relay-pseudonym`, `device-binding`, `anchor-ephemeral` — and
an unrecognised string is an error rather than a valid derivation. That check
exists because an unrecognised purpose would otherwise derive a perfectly valid
key that simply is not the one the other side derived, and the resulting failure
looks exactly like tampering rather than like the typo it is.

`salt` carries the per-session value (the session id) and `context` the per-item
value (an epoch number, an anchor reference). They go into **distinct HKDF
inputs** rather than being concatenated by the caller, so no pair of different
`(salt, context)` values can collide into the same derivation.

The version string `v1` is inside the domain constant, so a future protocol
version derives entirely different keys from the same root secret without any
migration step.

### Per-epoch keys

`SessionKeys.epoch_key(epoch)` derives a fresh key every 20 steps — five minutes
under the active timing.

The reason is containment in both directions. A leaked epoch key — a compromised
teacher handset mid-lesson, a challenge chain recovered from a screen recording —
yields the challenges of that epoch and **no other**, neither earlier nor later.
A single session-long challenge key would turn one screen recording into the whole
lesson.

### What a database compromise gets an attacker, stated plainly

`SessionKeys` holds both the challenge root secret and the challenge signing key,
and both are at rest in the database. Both halves must be available to the
teacher's device, because the teacher generates challenges with **no
connectivity** — that is the whole offline requirement.

So a database compromise lets an attacker mint valid challenges for a session.

It does **not** let them sign a proof as any student, because device private keys
are generated on the handset and never leave its keystore. There is no key escrow,
no server-side copy, and no recovery path that reconstructs a device key.

That asymmetry is the reason the two hierarchies are kept separate, and it belongs
in the threat model rather than being left implied. See `05-threat-model.md`.

### The SECRET_KEY coupling, and the check that refuses it

An ancestor commit in this repository derived presence signing material from
Django's `SECRET_KEY`. That coupling is worse than it looks: it ties presence
signing to session cookies and password-reset tokens, so one rotation silently
rotates the other and one leak is two leaks.

`keys._reject_secret_key_material` refuses a signing seed that is any of the four
obvious derivations of `settings.SECRET_KEY` — the raw prefix, the zero-padded
prefix, `sha256(secret)`, and `sha256(DOMAIN || secret)` — compared in constant
time.

The check is by value rather than by policy because **the failure mode of the
coupling is that everything appears to work.** Nothing breaks, nothing warns, and
the two secrets are one secret until the day one of them leaks.

## Key management

### Environment

| Variable | Holds |
|---|---|
| `PRESENCE_SIGNING_KEY` | The active signing seed, 32 bytes, unpadded base64url |
| `PRESENCE_RETIRED_SIGNING_KEYS` | Comma-separated retired **public** keys, still valid for verification |

A key id is derived from the key itself (first 8 bytes of a SHA-256 over the
public key), not assigned. That means a key id cannot be forged onto a different
key, and two deployments that load the same seed agree on its id without
coordinating.

Generate a seed with:

```bash
python -c "from attendance.presence.keys import SigningKey; print(SigningKey.generate().seed_b64url())"
```

### Rotation without a flag day

`Keyring` holds one active signing key and every key still valid for
verification. Only the active key signs; retired keys verify.

That shape exists because signatures made minutes before a rotation must keep
verifying until they expire. The procedure:

1. Generate a new seed.
2. Move the current **public** key into `PRESENCE_RETIRED_SIGNING_KEYS`.
3. Set `PRESENCE_SIGNING_KEY` to the new seed.
4. Restart.

Dropping a retired key is a separate, later decision — made when nothing it
signed is still inside its validity window. With `proof.max_offline_hours` at 24
and `nonce_retention_hours` at 48, a retired key can be dropped after 48 hours
with nothing outstanding.

### Ephemeral keyrings, and the guard on them

`Keyring.ephemeral()` generates a fresh in-memory keyring for tests and local
development. `Keyring.from_environment()` **fails** rather than falling back to an
ephemeral keyring when the environment is not configured, and the fallback path
is gated on `DEBUG`.

A silent ephemeral fallback in production would produce a system that signs and
verifies perfectly, loses every key on restart, and invalidates every proof in
every offline queue — while reporting no error at any point.

## What gets signed, and by whom

| Struct | Signer | Verifier | Covers |
|---|---|---|---|
| `qr_challenge` | Server session signing key | Student device, offline, with the session public key | Session, epoch, step, challenge, link, validity window |
| `attendance_proof` | Student device key | Server, on submission | Every field of the proof, including the observation hashes |
| `relay_hop` | Relaying student's device key | Server, on submission | Domain label, hop index, previous proof hash, pseudonym, time |
| `device_registration` | Student device key | Server, at enrolment | Public key, platform, capabilities, nonce |

The observation-hash indirection is what makes the proof extensible without
breaking signatures. The proof signs 32-byte canonical hashes of observation
bodies, so a body can be gathered now, hashed into the proof, and **synced
later** — still bound by the original signature, because the hash was signed at
the time.

## Constant-time comparison

`keys.equal` is `hmac.compare_digest`. It is used for every comparison an
attacker can iterate against: challenge values, MACs, key material, digests.

Ordinary `==` on bytes short-circuits on the first differing byte, which leaks a
prefix-match length through timing. For an 8-byte challenge that an attacker can
submit repeatedly, that is the difference between 2^64 guesses and 8 × 256.

## What a proof does not contain

Worth stating as a property of the cryptography rather than only as a privacy
policy, because it is enforced by the schema rather than by a rule someone has to
remember:

- **No student name, email, id number or any permanent identifier.** Identity is
  resolved server side from `device_key_id`.
- **No biometric data of any kind.** Not a fingerprint, not a face template, not a
  hash of either. One integer with four possible values: absent, success, failed,
  cancelled.
- **No private key material.** Device private keys never leave the handset.
- **No location, no coordinates, no geofence result.** RSSI offsets and anchor
  references are all the spatial evidence the schemas can carry, and both are
  session-scoped and ephemeral.

The relay pseudonym deserves its own line: it is `HKDF(session_id,
device_public_key)` truncated to 16 bytes, so it is stable **within** a session —
which is what makes a repeated relay detectable — and unlinkable **across**
sessions. A passive listener who records every pseudonym in one lesson learns
nothing that identifies anybody, and nothing that lets them recognise the same
student next week.

## Cross-language verification

The Dart implementation must produce byte-identical canonical encodings. Two
tests enforce it:

1. **Schema agreement.** Both sides render `codec.schema_text()` from their own
   declarations; the fingerprints must match. In this build:
   `087177288b4c3f4eaa91203feafe8b57de5028f59ccd99980be6bc42c0078109`.
2. **Round-trip signing.** The same struct signed in Dart verifies in Python and
   vice versa, over a fixed set of vectors including boundary cases: zero-valued
   uints, maximum uints, empty observation arrays, and the 64-element maximum.

A silent encoding divergence — one implementation emitting a definite-length array
where the other emits indefinite, say — would break every proof in the field with
a `proof_bad_signature` that looks like an attack. This is the test that stops a
protocol bug from being diagnosed as a security incident.
