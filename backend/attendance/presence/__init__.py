"""
Presence layer: cryptographic evidence that an authenticated student took part
in an active, teacher-controlled session.

This package replaces a primitive in which possessing a session UUID was enough
to be marked present. It does not replace the analytics engine, which still owns
percentages, forecasts and after-the-fact anomaly detection.

Layering (each module depends only on those above it):

    codec     - canonical deterministic encoding for everything that gets signed
    keys      - key hierarchy, rotation, Ed25519 sign/verify, HKDF derivation
    challenge - session root key -> epoch keys -> linked rolling challenge chain
    replay    - nonce, sequence, epoch and duplicate-proof windows
    origin    - teacher BLE origin payload (implemented; nothing gathers it yet)
    chain     - relay chain of custody (implemented; nothing gathers it yet)
    proof     - the signed attendance proof: build, verify, canonical hash
    gates     - mandatory hard rejects, run to completion before any scoring
    features  - observation window -> sparse evidence vector
    fusion    - dependency-aware accumulation over independent evidence blocks
    calibrate - fit likelihoods and thresholds from labelled data (Phase 3;
                not written - this is where it will sit, not where it is)
    decide    - gates + fusion -> Decision with reason codes and versions

Four invariants hold throughout. The first two are inherited verbatim from
`attendance.analytics`; the second two are specific to evidence handling.

1. No value is invented. Where evidence is absent the layer says so explicitly
   instead of substituting a plausible-looking number.
2. Every derived figure can be traced back to the observations that produced it.
3. Absent evidence is not negative evidence. A platform that cannot supply a
   signal lowers confidence toward SECONDARY; it never pushes toward SUSPICIOUS,
   and it never makes a compliant student unverifiable.
4. Nothing the client asserts is trusted. Client-side status, confidence and hop
   counts are recorded as signed claims - attributable, and re-derived server
   side before any decision is taken.

Cryptography here is assembled from established primitives only: Ed25519,
HMAC-SHA256 and HKDF from the `cryptography` package. No primitive is invented,
and no construction is used that could not be described to a reviewer in terms
of those three.
"""
