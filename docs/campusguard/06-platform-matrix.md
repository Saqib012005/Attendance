# 06 — Platform matrix

This is the *platform* matrix: what each operating system and browser is capable
of, and what this build therefore uses. It is not the *device* compatibility
matrix — which handsets actually manage a stable advertise-plus-scan-plus-
foreground-service combination — because that requires running the relay layer on
shipping hardware, and the relay layer is unbuilt. That document arrives with
Phase 4 and is a deliverable rather than a footnote.

The vendor-documented constraints below were checked against current official
documentation in September 2026, not recalled. Platform capability is the one part
of this design most likely to have moved by the time you read it: re-check before
building on any single line of it, particularly the Web Bluetooth status and the
Android 16 ranging caveats.

## The fact that dominates every row

**On this build, no platform supplies BLE evidence, because nothing gathers it.**
Phases 4 through 6 are designed and unbuilt. Every platform — Android included —
runs in the degraded mode described below, and the honest-disclosure UI is
therefore a Phase 2 requirement rather than a Phase 4 one.

That is why the table has two distinct columns. Confusing them is how a design
document becomes a marketing document.

| | Platform *could* | This build *does* |
|---|---|---|
| QR rolling challenge | all | **all** |
| Device-bound Ed25519 keypair | all | **all** |
| Biometric gate | Android, iOS | **Android, iOS** |
| Hardware-backed key storage | Android, iOS | **Android, iOS** |
| BLE central (scan) | Android, iOS, Chrome-behind-a-flag | *nothing* |
| BLE peripheral (advertise) | Android, iOS (foreground only) | *nothing* |
| Multi-hop relay | **Android only** | *nothing* |
| Anchor RF fingerprint | Android, iOS | *nothing — and no anchors exist* |
| Precision ranging | Android 16+, capability-gated | *nothing* |

Read the right-hand column as the truthful description of the system, and the
left-hand one as the reason the wire schemas reserve space.

## Web: central-only, and permanently outside the mesh

The Flutter web build **can never participate in a relay mesh**, and this is a
standards fact rather than an implementation gap:

- Web Bluetooth is **central-role only**. There is no peripheral or advertising
  API at all — not behind a flag, not proposed for one. A browser cannot be a
  relay node or a teacher origin.
- Advertisement *scanning* (`requestLEScan`) sits behind
  `chrome://flags/#enable-experimental-web-platform-features` with an open
  Chromium issue, so even the central role is not dependably available.
- Mozilla and Apple have both declined to implement Web Bluetooth. There is no
  iOS browser path at all, since every iOS browser uses WebKit.

`frontend/attendance_app/lib/config/api_config.dart` hardcodes
`isProduction = true` and CI ships a `flutter build web` target, so the web build
is a real deployment target and not a curiosity. It therefore **degrades
explicitly**: QR challenge, device-bound key, server-side re-derivation, and a UI
that names what is unavailable. What it must never do is produce a weaker proof
that looks identical to a stronger one.

Web also has no platform biometric behind `local_auth`. WebAuthn is the nearest
equivalent and is not the same thing: it authenticates a credential rather than
returning a local liveness outcome. Web proofs therefore carry no `CAP_BIOMETRIC`,
and `biometric_outcome` is absent as `unsupported` — which lowers confidence
toward `SECONDARY` and never counts against the student.

## This is not Bluetooth Mesh, and the claim would be wrong twice

Bluetooth Mesh is a real Bluetooth SIG specification. CampusGuard's relay is
**not** an implementation of it, and no document, README, slide or demo may imply
that it is.

Two independent reasons, either sufficient on its own:

**There is no platform stack.** Android ships no Bluetooth Mesh implementation.
Using the standard would mean carrying a third-party library — Nordic's is the
usual choice — with its own provisioning model, its own persistence and its own
lifecycle, none of which the platform maintains.

**The lifecycle is wrong by an order of magnitude.** Mesh assumes a *provisioned
network*: a provisioner assigns addresses, distributes network and application
keys, and nodes persist that configuration. CampusGuard's trust domain is created
when a teacher starts a session and destroyed when they end it — roughly 50
minutes. Provisioning a network per lesson, for a membership that changes every
lesson, is the wrong shape at a cost nobody would pay.

What this actually is: **a custom application-layer protocol over BLE GATT and
advertising.** The standards it does use are named in `02-crypto-spec.md`, they are
cryptographic RFCs, and they are used unmodified. The protocol built on top of them
is ours and is specified in `01-protocol-spec.md`. Keeping those two categories
apart is the whole point of saying it this way.

## iOS: relay is infeasible, so Android is the relay platform

CoreBluetooth gives iOS a real central role and a real peripheral role, and neither
carries a classroom relay:

- **Background peripheral advertising is heavily restricted.** The advertising rate
  drops, the local name is dropped from the advertisement, and only the overflow
  area carries service UUIDs — readable in practice only by another iOS device.
- **Manufacturer-specific data is not available** to CoreBluetooth for
  iBeacon-style frames, which is exactly where the 17-byte origin frame lives.
- A relay must advertise and scan **while the student is doing something else**,
  which is the case iOS restricts hardest.

So the design decision is stated plainly rather than discovered later: **Android is
the relay platform. iOS gets QR challenge, biometric, hardware-backed device
binding, and — when Phase 4 lands — direct origin *scanning*, which the foreground
central role supports fine.** iOS never relays.

This is a capability statement, not a ranking of students. An iOS student supplies
fewer evidence features, so their `coverage_pct` is lower and their verdict trends
toward `SECONDARY` rather than `PRESENT` on a marginal case. They never trend
toward `SUSPICIOUS`, because `unsupported` is not an adverse absence reason — see
`03-fusion-and-calibration.md`.

## Android: capable, and full of sharp edges

Android can do all of it. Whether a *particular* Android device does it reliably is
a different question, and the answer is often no.

| Constraint | Since | What it does to the design |
|---|---|---|
| `BLUETOOTH_SCAN`, `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` are runtime permissions | API 31 | Three prompts, each refusable. A refusal must degrade, not fail |
| `neverForLocation` on the scan permission | API 31 | Claim it where honest — it avoids a location prompt for a feature that is not locating anyone |
| Foreground services must declare a **type** | API 34 | The relay service needs `connectedDevice`, declared in the manifest and matched at start |
| Tightened background start rules | Android 15 | The relay cannot be started from the background; it starts from the student's own tap |
| `ADVERTISE_FAILED_TOO_MANY_ADVERTISERS` | all | Advertiser slots are finite and shared with every other app. Must be handled as an expected outcome with backoff, not an error |
| Peripheral mode is not universal | all | `BluetoothAdapter.isMultipleAdvertisementSupported()` is false on real shipping devices. Those handsets scan but never relay |
| OEM battery managers | all | Samsung, Xiaomi and OnePlus kill scans and services despite a compliant foreground service. No API defeats this; documentation and per-OEM guidance is the only honest answer |

Two consequences that the code already encodes:

**`CAP_RELAY` is a separate bit and is not implied by scan plus advertise.**
`proof.py` says so in a comment at the constant, because relaying needs both radio
roles *and* a foreground service the OEM will leave running, and that combination
fails on hardware where each part individually works.

**Relay is an opportunistic bonus, never a precondition for `PRESENT`.** If it were
a precondition, every student with a handset lacking peripheral mode — or an
aggressive battery manager, or one refused permission — would be permanently
unverifiable. The fusion weights make this concrete: `relay_depth` is 450 and
`relay_integrity` 800, against `anchor_fingerprint` 3400. Relay is the *least*
weighted evidence in the network block for exactly this reason.

## Android 16 ranging: real, and narrow

Android 16 introduced a unified ranging module — `android.ranging.RangingManager` —
behind a single `android.permission.RANGING` permission, with
`registerCapabilitiesCallback` for runtime discovery. It puts four very different
technologies behind one API: BLE Channel Sounding, BLE RSSI ranging, UWB, and
Wi-Fi NAN RTT.

It is genuinely the right primitive for high-assurance distance, and it is
available to almost nobody:

- **Every participant needs Android 16+.** A teacher on 16 and a student on 14 get
  nothing.
- **Background ranging is UWB-only**, so on BLE-backed ranging the app must be in
  the foreground.
- **A responder answers one initiator at a time.** In a room of forty students that
  is a scheduling problem, not a measurement.
- **Concurrent sessions are capped per device**, which caps how much of a class can
  be ranged inside one observation window.

So ranging is what the design has always called it: **optional high-assurance
evidence with graceful degradation.** `CAP_RANGING` exists in the capability bit set
so a handset can declare it and a future extractor can read it. Nothing produces a
ranging observation today, no evidence feature consumes one, and no verdict depends
on one.

## How a capability bit reaches a decision

The path is short and deliberately so. A capability bit is a *claim by the handset*
about what it can do, and its only job is to distinguish "this evidence is missing
because the platform cannot supply it" from "this evidence is missing and the
platform said it could".

`features.GATING_CAPABILITY` is the whole mapping, and it has four entries:

| Feature | Gating bit | Absent with the bit set | Absent without it |
|---|---|---|---|
| `biometric_outcome` | `CAP_BIOMETRIC` | `not_observed` | `unsupported` |
| `origin_direct` | `CAP_BLE_SCAN` | `not_observed` | `unsupported` |
| `relay_depth` | `CAP_RELAY` | `not_observed` | `unsupported` |
| `relay_integrity` | `CAP_RELAY` | `not_observed` | `unsupported` |

Everything else is ungated. `identity_authenticated`, `device_bound`,
`challenge_committed`, `queue_age` and `clock_consistency` need no radio and no
platform feature, which is why they are the five features a bare authenticated proof
supplies on every platform. `anchor_fingerprint` and `spatial_stability` report
`reserved` regardless of what any handset claims, because the mechanism does not
exist server-side — `features.RESERVED_FEATURES` is a fact about this build, not
about the device.

**Neither `unsupported` nor `reserved` nor `not_observed` is adverse.** Only `failed`
is. A handset cannot lower its own verdict by declaring fewer capabilities, and it
cannot raise it by declaring more — declaring `CAP_BLE_SCAN` and then supplying no
origin sighting converts an `unsupported` into a `not_observed`, which is
*informative* rather than favourable.

`CAP_HARDWARE_KEYSTORE` gates nothing today. It is recorded because a proof signed by
a key in a hardware keystore is materially stronger evidence than one signed by a key
in application storage, and the policy question — whether to require it, and thereby
make cheaper handsets unverifiable — is named in `05-threat-model.md` T12 as a lever
that has not been pulled.

## What the UI must say, on every platform, today

Because Phases 4–6 are unbuilt, the disclosure below is not a corner case for
unusual handsets. It is the state of every student on every platform:

- Name the evidence categories that were used, and the ones that were not available.
- Never present a `SECONDARY` outcome as a failure or an accusation. It means *check
  this one by another route*, and on this build it will frequently mean *this platform
  cannot supply what the model wants*.
- Never show relay topology, hop counts or anchor identities to a student
  (`03-fusion-and-calibration.md` and the privacy document explain why).
- Never imply room-level certainty. `05-threat-model.md` T15 is the reason.

## Not in this document

- **The per-device compatibility matrix** — advertise, scan, peripheral mode,
  advertiser slots and battery-manager survival, per handset model. Phase 4.
- **The BLE plugin decision.** `universal_ble` covers both radio roles across
  platforms; `flutter_blue_plus` plus `flutter_ble_peripheral` is the fallback
  pairing. Neither is in `pubspec.yaml` and neither should be added before Phase 4
  needs it.
- **Anchor hardware.** No beacon has been bought. See `00-architecture.md` for the
  data-model contract that keeps buying them later from becoming a migration
  rewrite.
