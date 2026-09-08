"""The signed attendance proof, and the parts of it the server refuses to believe.

A proof is what a handset can produce with no connectivity: it names a session, a
device key, the challenge it saw, a nonce, and a handful of facts about itself. The
device signs the canonical bytes, and that signature is the whole of its
authority - it makes the proof unforgeable and non-repudiable, and it makes every
claim inside it *attributable*, which is a different and smaller thing than making
the claim true.

The distinction runs through this module. Four fields - `captured_at`,
`claimed_status`, `claimed_confidence_milli`, `claimed_hop_count` - are the
client's account of itself. They are signed, so a device that lies is on record
and can be measured over time, and they are never inputs to a decision (§39).
`biometric` sits in the same category and it is worth being blunt about: the
server sees an outcome the handset asserts, not a biometric check it performed.
Its value is that a compromised handset must forge it under a key held in that
handset's secure element, and that a pattern of failures is visible; its value is
not proof that a face was present.

What this module can settle on its own is narrow, and it is deliberately all it
does: are these bytes a canonical proof of the declared shape, was the signature
made by the key the body names, and is it a proof for the session it was
submitted to. Whether the challenge inside was real belongs to `challenge`,
whether it has been seen before to `replay`, and whether the result is presence
to `gates` and `fusion`. Composing those is `decide`'s job, not this one's.

There is no envelope schema. A signature travels beside the body in whatever
transport is carrying it, because signing an envelope that contains a signature
is a circular definition, and because the tag and version inside the signed bytes
already stop a proof being reinterpreted as any other struct.
"""
import secrets
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from . import codec, keys

SCHEMA = codec.ATTENDANCE_PROOF

# Shapes, measured from the schema rather than restated. A wire format change
# must not be able to leave a stale constant behind in here.
SESSION_ID_LEN = SCHEMA.fields[SCHEMA.index("session_id")].size
DEVICE_KEY_ID_LEN = SCHEMA.fields[SCHEMA.index("device_key_id")].size
CHALLENGE_LEN = SCHEMA.fields[SCHEMA.index("challenge")].size
NONCE_LEN = SCHEMA.fields[SCHEMA.index("nonce")].size
MAX_OBSERVATIONS = SCHEMA.fields[SCHEMA.index("observations")].size
OBSERVATION_LEN = SCHEMA.fields[SCHEMA.index("observations")].item.size


# --- Wire enumerations -------------------------------------------------------
#
# Fixed by the schema version in exactly the way the schema tag is: a value here
# can be added to in a new version and can never be retuned, so none of these is
# a parameter and none belongs in a config artifact. Because they are small
# integers, some of them coincide with declared parameter values, and the
# config-hygiene test's exemption table records that this file is allowed to say
# them.

BIOMETRIC_ABSENT = 0
BIOMETRIC_SUCCESS = 1
BIOMETRIC_FAILED = 2
BIOMETRIC_CANCELLED = 3

# §09 in one line: the only biometric fact that crosses the wire is which of
# these four happened. No template, no image, no score, and no field in the
# schema wide enough to smuggle one - the widest byte string a proof carries is
# 32 bytes and every one of them is named.
BIOMETRIC_NAMES: Mapping[int, str] = MappingProxyType({
    BIOMETRIC_ABSENT: "absent",
    BIOMETRIC_SUCCESS: "success",
    BIOMETRIC_FAILED: "failed",
    BIOMETRIC_CANCELLED: "cancelled",
})

PLATFORM_UNKNOWN = 0
PLATFORM_ANDROID = 1
PLATFORM_IOS = 2
PLATFORM_WEB = 3

PLATFORM_NAMES: Mapping[int, str] = MappingProxyType({
    PLATFORM_UNKNOWN: "unknown",
    PLATFORM_ANDROID: "android",
    PLATFORM_IOS: "ios",
    PLATFORM_WEB: "web",
})

# The four outcomes, as they travel on the wire. `decide` produces the same
# vocabulary from the server's own re-derivation; a proof's copy is a claim.
STATUS_UNKNOWN = 0
STATUS_PRESENT = 1
STATUS_SECONDARY = 2
STATUS_NOT_VERIFIED = 3
STATUS_SUSPICIOUS = 4

STATUS_NAMES: Mapping[int, str] = MappingProxyType({
    STATUS_UNKNOWN: "unknown",
    STATUS_PRESENT: "present",
    STATUS_SECONDARY: "secondary",
    STATUS_NOT_VERIFIED: "not_verified",
    STATUS_SUSPICIOUS: "suspicious",
})

# Confidence travels as thousandths because floats are never encoded.
CONFIDENCE_MILLI_MAX = 1000

# What the handset says it can do, as a bit set. Written as shifts so the wire
# value of each flag is visible and so adding one cannot renumber another.
CAP_BLE_SCAN = 1 << 0
CAP_BLE_ADVERTISE = 1 << 1
# Not implied by the two above it. Relaying needs advertise and scan together,
# plus a foreground service that the OEM's battery manager will actually leave
# running, and the platform matrix is a record of how often that combination
# fails on shipping hardware.
CAP_RELAY = 1 << 2
CAP_RANGING = 1 << 3
CAP_BIOMETRIC = 1 << 4
CAP_HARDWARE_KEYSTORE = 1 << 5
CAP_BACKGROUND_SERVICE = 1 << 6

CAPABILITY_NAMES: Mapping[int, str] = MappingProxyType({
    CAP_BLE_SCAN: "ble_scan",
    CAP_BLE_ADVERTISE: "ble_advertise",
    CAP_RELAY: "relay",
    CAP_RANGING: "ranging",
    CAP_BIOMETRIC: "biometric",
    CAP_HARDWARE_KEYSTORE: "hardware_keystore",
    CAP_BACKGROUND_SERVICE: "background_service",
})

KNOWN_CAPABILITIES = 0
for _flag in CAPABILITY_NAMES:
    KNOWN_CAPABILITIES |= _flag
del _flag


# --- Reason codes ------------------------------------------------------------
#
# What this module alone can decide. Everything about freshness, uniqueness and
# presence belongs to `challenge`, `replay` and `gates`, and their codes live
# there so that a verdict names the layer that reached it.

MALFORMED = "proof_malformed"
BAD_SIGNATURE = "proof_bad_signature"
KEY_MISMATCH = "proof_key_mismatch"
SESSION_MISMATCH = "proof_session_mismatch"

REASON_CODES = frozenset({MALFORMED, BAD_SIGNATURE, KEY_MISMATCH, SESSION_MISMATCH})


class ProofError(Exception):
    """A proof that cannot be taken as evidence, and which layer said so."""

    def __init__(self, code: str, message: str):
        if code not in REASON_CODES:
            raise AssertionError("undeclared proof reason code %r" % (code,))
        super().__init__(message)
        self.code = code


def new_nonce() -> bytes:
    """A fresh proof nonce. Random, not a counter: a counter leaks how many
    proofs a device has made, and a device that is reset must not repeat."""
    return secrets.token_bytes(NONCE_LEN)


@dataclass(frozen=True)
class Claims:
    """The device's account of its own outcome.

    Kept in one object, and named for what it is, so that no caller can pass a
    claim to something expecting a finding. `decide` produces the real verdict;
    these exist to be compared against it, because a device whose claims
    disagree with the server's re-derivation is interesting whichever way the
    disagreement runs.
    """

    status: int = STATUS_UNKNOWN
    confidence_milli: int = 0
    hop_count: int = 0

    def describe(self) -> Dict[str, Any]:
        return {
            "claimed_status": STATUS_NAMES.get(self.status, "unrecognised"),
            "claimed_confidence_milli": self.confidence_milli,
            "claimed_hop_count": self.hop_count,
        }


@dataclass(frozen=True)
class Proof:
    """One parsed, shape-checked proof. Says nothing about whether it is valid."""

    session_id: bytes
    device_key_id: bytes
    challenge: bytes
    challenge_epoch: int
    challenge_seq: int
    nonce: bytes
    captured_at: int
    biometric: int
    platform: int
    capabilities: int
    claims: Claims
    observations: Tuple[bytes, ...] = ()

    def values(self) -> Dict[str, Any]:
        """The schema dict, in the schema's own vocabulary."""
        return {
            "session_id": self.session_id,
            "device_key_id": self.device_key_id,
            "challenge": self.challenge,
            "challenge_epoch": self.challenge_epoch,
            "challenge_seq": self.challenge_seq,
            "nonce": self.nonce,
            "captured_at": self.captured_at,
            "biometric": self.biometric,
            "platform": self.platform,
            "capabilities": self.capabilities,
            "claimed_status": self.claims.status,
            "claimed_confidence_milli": self.claims.confidence_milli,
            "claimed_hop_count": self.claims.hop_count,
            "observations": list(self.observations),
        }

    def encode(self) -> bytes:
        return codec.encode(SCHEMA.name, self.values())

    def digest(self) -> bytes:
        """The proof's identity, and what `replay` remembers it by."""
        return codec.digest(SCHEMA.name, self.values())

    @property
    def biometric_name(self) -> str:
        return BIOMETRIC_NAMES.get(self.biometric, "unrecognised")

    @property
    def platform_name(self) -> str:
        return PLATFORM_NAMES.get(self.platform, "unrecognised")

    def has_capability(self, flag: int) -> bool:
        return bool(self.capabilities & flag)

    def capability_names(self) -> Tuple[str, ...]:
        """Declared capabilities, known ones only.

        An unknown bit from a newer client is dropped here rather than named,
        and `unknown_capabilities` is where it stays visible. Silently dropping
        it would be worse: the point of a capability set is that missing evidence
        can be explained by the handset instead of counted against the student.
        """
        return tuple(
            name for flag, name in CAPABILITY_NAMES.items() if self.capabilities & flag
        )

    @property
    def unknown_capabilities(self) -> int:
        return self.capabilities & ~KNOWN_CAPABILITIES

    def describe(self) -> Dict[str, Any]:
        """An audit summary. No key material, no student identity, no PII.

        `device_key_id` is in here because it is a key id, not a person: resolving
        it to a student is the server's job and happens against a table this
        module cannot see.
        """
        summary = {
            "session_id": self.session_id.hex(),
            "device_key_id": self.device_key_id.hex(),
            "challenge_epoch": self.challenge_epoch,
            "challenge_seq": self.challenge_seq,
            "biometric": self.biometric_name,
            "platform": self.platform_name,
            "capabilities": list(self.capability_names()),
            "observation_count": len(self.observations),
            "schema_version": SCHEMA.version,
        }
        summary.update(self.claims.describe())
        if self.unknown_capabilities:
            summary["unknown_capability_bits"] = self.unknown_capabilities
        return summary


@dataclass(frozen=True)
class Signed:
    """A proof, the exact bytes that were signed, and the signature over them.

    The bytes are kept rather than re-encoded on demand. A signature is only
    meaningful over the octets that were actually received, and re-deriving them
    would quietly substitute this build's encoder for the one that signed.
    """

    proof: Proof
    body: bytes
    signature: bytes

    @property
    def digest(self) -> bytes:
        return codec.digest_bytes(self.body)


# --- Shape and semantics -----------------------------------------------------

def _uint(name: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProofError(MALFORMED, "%s is %r, not an unsigned integer" % (name, value))
    return value


def _check_semantics(proof: Proof) -> Proof:
    """The rules the codec cannot express, applied identically on both paths.

    `build` and `parse` share this so a proof a client can construct is exactly a
    proof this server will parse. A divergence there is the kind of bug that only
    shows up in the field, on one platform, after a release.

    Two vocabularies are closed and two are open, and the asymmetry is on purpose.
    `biometric` and `claimed_status` carry meaning that is load-bearing enough
    that an unrecognised value must not be silently folded into a neighbouring
    one, so an unknown value is refused. `platform` and unused capability bits
    are left open, because an older server refusing a newer handset outright is a
    worse failure than one that records what it does not recognise: the student
    holding that handset has done nothing wrong.
    """
    if proof.biometric not in BIOMETRIC_NAMES:
        raise ProofError(
            MALFORMED,
            "biometric outcome %r is not one of %s"
            % (proof.biometric, ", ".join(sorted(BIOMETRIC_NAMES.values()))),
        )
    if proof.claims.status not in STATUS_NAMES:
        raise ProofError(
            MALFORMED, "claimed status %r is not a declared outcome" % (proof.claims.status,)
        )
    if proof.claims.confidence_milli > CONFIDENCE_MILLI_MAX:
        raise ProofError(
            MALFORMED,
            "claimed confidence %d exceeds %d thousandths"
            % (proof.claims.confidence_milli, CONFIDENCE_MILLI_MAX),
        )
    if len(set(proof.observations)) != len(proof.observations):
        raise ProofError(
            MALFORMED,
            "observations contain a repeated digest: one observation submitted "
            "twice must not be able to look like two",
        )
    return proof


def build(
    *,
    session_id: bytes,
    device_key_id: bytes,
    challenge: bytes,
    challenge_epoch: int,
    challenge_seq: int,
    captured_at: int,
    biometric: int,
    platform: int,
    capabilities: int = 0,
    nonce: Optional[bytes] = None,
    claims: Optional[Claims] = None,
    observations: Sequence[bytes] = (),
) -> Proof:
    """Assemble a proof. Every length is checked by the codec at encode time; the
    vocabularies are checked here, so an unbuildable proof fails at the caller
    rather than at the verifier."""
    proof = Proof(
        session_id=bytes(session_id),
        device_key_id=bytes(device_key_id),
        challenge=bytes(challenge),
        challenge_epoch=_uint("challenge_epoch", challenge_epoch),
        challenge_seq=_uint("challenge_seq", challenge_seq),
        nonce=new_nonce() if nonce is None else bytes(nonce),
        captured_at=_uint("captured_at", captured_at),
        biometric=_uint("biometric", biometric),
        platform=_uint("platform", platform),
        capabilities=_uint("capabilities", capabilities),
        claims=claims or Claims(),
        observations=tuple(bytes(o) for o in observations),
    )
    return _check_semantics(proof)


def parse(body: bytes) -> Proof:
    """Bytes to proof, with no signature involved.

    Strict by way of `codec.decode`: the values are re-encoded and compared
    against the input, so one proof has exactly one encoding. Without that, the
    same evidence could be resubmitted under a second set of bytes and a
    digest-keyed ledger would see two proofs.
    """
    try:
        values = codec.decode(body, SCHEMA.name, strict=True)
    except codec.CodecError as exc:
        raise ProofError(MALFORMED, "not a canonical attendance proof: %s" % (exc,))
    return _check_semantics(Proof(
        session_id=values["session_id"],
        device_key_id=values["device_key_id"],
        challenge=values["challenge"],
        challenge_epoch=values["challenge_epoch"],
        challenge_seq=values["challenge_seq"],
        nonce=values["nonce"],
        captured_at=values["captured_at"],
        biometric=values["biometric"],
        platform=values["platform"],
        capabilities=values["capabilities"],
        claims=Claims(
            status=values["claimed_status"],
            confidence_milli=values["claimed_confidence_milli"],
            hop_count=values["claimed_hop_count"],
        ),
        observations=tuple(values["observations"]),
    ))


# --- Signing and verification ------------------------------------------------

def sign(proof: Proof, signing_key: keys.SigningKey) -> Signed:
    """Sign a proof with the device key it names.

    Refusing to sign a proof that names another device is not defence against an
    attacker - an attacker edits this function out - but it turns a whole class of
    client bug into an immediate, local failure instead of a signature that every
    server on earth will reject for reasons the handset cannot see.
    """
    expected = keys.key_id_for(signing_key.public().public_bytes)
    if not keys.equal(proof.device_key_id, expected):
        raise ProofError(
            KEY_MISMATCH,
            "proof names device %s but is being signed by %s"
            % (proof.device_key_id.hex(), expected.hex()),
        )
    body = proof.encode()
    return Signed(proof=proof, body=body, signature=signing_key.sign(body))


def verify(
    body: bytes,
    signature: bytes,
    device_key: keys.VerifyKey,
    *,
    session_id: Optional[bytes] = None,
) -> Signed:
    """Bytes and a signature to a proof, or raise.

    Ordered so that each failure is reported by the thing that can actually
    explain it. Shape first, because a malformed body reported as a bad signature
    sends an integrator hunting the wrong bug. Then the binding between the key
    the body names and the key being verified against - checked explicitly,
    because a caller that resolved the key from some outer transport field would
    otherwise accept a genuine signature by device A over a body claiming device
    B. Then the signature. Only then anything that reads a field, because before
    the signature verifies, every field in here is just bytes somebody sent.

    The caller supplies the key. This module never looks up a device, so it can
    be run against a proof in a test, in the lab, or on a handset, and the same
    code path decides.
    """
    proof = parse(body)

    if not keys.equal(proof.device_key_id, device_key.key_id):
        raise ProofError(
            KEY_MISMATCH,
            "proof names device %s but was verified against %s"
            % (proof.device_key_id.hex(), device_key.key_id.hex()),
        )

    try:
        device_key.verify(bytes(body), bytes(signature))
    except keys.SignatureError as exc:
        raise ProofError(BAD_SIGNATURE, "proof signature is not valid: %s" % (exc,))

    if session_id is not None and not keys.equal(proof.session_id, bytes(session_id)):
        raise ProofError(
            SESSION_MISMATCH,
            "proof is for session %s, submitted against %s"
            % (proof.session_id.hex(), bytes(session_id).hex()),
        )

    return Signed(proof=proof, body=bytes(body), signature=bytes(signature))


def observation_digests(*encoded: bytes) -> Tuple[bytes, ...]:
    """Hash observation structs for inclusion in a proof.

    A proof commits to its evidence by digest and carries none of it: the bodies
    travel beside the proof, and the server re-hashes them to find out whether
    they are the ones that were signed. So a relay hop or an anchor reading can be
    dropped in transit without invalidating the proof, and cannot be added to it
    afterwards. The array is empty on this scope, because nothing generates
    observations yet.
    """
    digests = []
    for raw in encoded:
        digest = codec.digest_bytes(raw)
        if len(digest) != OBSERVATION_LEN:
            raise ProofError(
                MALFORMED,
                "observation digest is %d bytes, expected %d" % (len(digest), OBSERVATION_LEN),
            )
        digests.append(digest)
    if len(digests) > MAX_OBSERVATIONS:
        raise ProofError(
            MALFORMED,
            "%d observations exceeds the schema's maximum of %d"
            % (len(digests), MAX_OBSERVATIONS),
        )
    return tuple(digests)


def committed_to(proof: Proof, encoded: Iterable[bytes]) -> bool:
    """Whether every supplied observation body appears in the proof's commitment.

    Deliberately not "the sets are equal": a proof may commit to an observation
    whose body was lost on the way, and that is a missing-evidence problem for
    fusion rather than a validity problem here. What must never pass is the
    reverse - a body that the signed proof does not account for.
    """
    committed = set(proof.observations)
    return all(codec.digest_bytes(raw) in committed for raw in encoded)
