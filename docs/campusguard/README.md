# CampusGuard presence layer — engineering documentation

This directory documents the **presence layer**: the part of CampusGuard that
produces a cryptographically checkable record that an authenticated student took
part in an active, teacher-controlled session, offline, on a proof the server
re-derives rather than trusts.

It replaces a primitive in which possessing a session UUID was sufficient to be
marked present.

## Read this first

Two sentences bound everything in here, and both halves of each need to survive
into anything said about this feature — including a demo.

1. What is built is an **unforgeable, non-replayable, non-backdatable,
   device-bound, biometric-gated, offline-capable attendance proof that the
   server re-derives**. That is a large improvement on what it replaced.
2. It is **not proof that the student was physically in the room.** A student
   outside the window with a valid account, their own registered device, a fresh
   challenge and a real fingerprint is marked `PRESENT`. Closing that gap needs
   the deferred spatial evidence of Phase 5, which needs hardware nobody has
   bought. See [05-threat-model.md](05-threat-model.md), *Residual risk*.

No accuracy figure is claimed anywhere in this documentation. Not 99%, not any
number. The active fusion configuration is labelled `uncalibrated` and the code
refuses to emit a probability rather than relying on a reader to remember that.

## Documents

| Document | Covers | State |
|---|---|---|
| [00-architecture.md](00-architecture.md) | Layering, module responsibilities, data model, where presence stops and analytics starts | Current |
| [01-protocol-spec.md](01-protocol-spec.md) | Wire formats, rolling challenge chain, TTL, replay windows, dedup | Current |
| [02-crypto-spec.md](02-crypto-spec.md) | Key hierarchy, primitives, derivation labels, proof signing, rotation | Current |
| [03-fusion-and-calibration.md](03-fusion-and-calibration.md) | Gates, evidence vector, block fusion, thresholds, what "confidence" means | Current, **simulator-free and unfitted** |
| 04-spatial-evidence.md | Anchors, RF fingerprint, room calibration, device normalisation | **Deferred with Phase 5.** Its data-model contract is in `00-architecture.md` |
| [05-threat-model.md](05-threat-model.md) | Attack → expected signal → detection → mitigation → **residual risk** | Current |
| [06-platform-matrix.md](06-platform-matrix.md) | Verified platform constraints; why Android is the relay platform | Current; device compatibility matrix arrives with Phase 4 |
| [07-offline-and-sync.md](07-offline-and-sync.md) | Offline capture, queue states, submission, idempotence, clock handling | Current |
| [08-privacy.md](08-privacy.md) | What is never broadcast or stored, ephemeral identifiers, retention, departure policy | Current |
| [09-config-registry.md](09-config-registry.md) | Versioned parameters, activation, the no-tuned-numbers-in-code rule | Current |
| [10-validation-plan.md](10-validation-plan.md) | What is tested today, the adversarial matrix, the field study that is not done | Current |
| [11-ip-analysis.md](11-ip-analysis.md) | Prior-art territory, mechanism analysis, questions for counsel | **Public stub only — see the file** |
| [12-roadmap.md](12-roadmap.md) | Phases 0–8, what each needs, what each unlocks | Current |

## Scope of this build

Phases 0–3 of the delivery plan. Phases 4–8 are **designed but not built**: the
data model, the wire schemas and the evidence vector reserve space for BLE
origin, relay chain of custody, multi-anchor RF fingerprinting and precision
ranging so that adding them later is not a rewrite. Nothing in this build emits
or consumes a single BLE packet.

The practical consequence is that **every platform currently runs in the
degraded mode** described in `06-platform-matrix.md`: QR challenge, biometric
gate, device binding and server-side re-derivation. The evidence vector's
`network` and `spatial` blocks are empty on every proof this build produces.

## Conventions

- `unsupported` means this handset cannot supply the signal. `reserved` means no
  build can, because the mechanism is unbuilt. Neither is negative evidence.
- A parameter that was tuned lives in `backend/attendance/presence/config/` and
  nowhere else. A test fails the build if a tuned number appears in code.
- Where a document states a number, it is the number the code reads at runtime,
  and the probe that produced it is named so it can be re-run.
