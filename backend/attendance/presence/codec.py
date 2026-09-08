"""
Canonical encoding for everything the presence layer signs.

A signature is only meaningful if both sides agree, byte for byte, on what was
signed. Two independent implementations - Python here, Dart on the handset - have
to produce identical bytes from identical values, offline, across library
versions. That rules out a few things that look convenient:

* JSON. Key order, whitespace, integer-vs-float and Unicode escaping are all
  implementation choices. `json.dumps(sort_keys=True)` fixes some of that in
  Python and says nothing about Dart.
* CBOR maps. Canonical map key ordering changed between RFC 7049 (length first,
  then bytewise) and RFC 8949 (bytewise only). Libraries disagree about which
  they implement, and the disagreement is silent.
* Floats. Encoding width, subnormals and NaN payloads are portability traps, and
  nothing that gets signed here actually needs a real number. Confidence travels
  as an integer in thousandths.

So every signable struct is a CBOR **array** with a fixed, declared field order,
prefixed by a small integer schema tag and a schema version. Position replaces
key ordering, which removes the ambiguity rather than papering over it, and the
tag plus version inside the signed bytes give domain separation between struct
types: a signature over an `attendance_proof` cannot be reinterpreted as a
signature over a `qr_challenge`.

Only four value kinds are permitted: unsigned integers, byte strings, text
strings and booleans, plus fixed-shape arrays of those and an explicit null for
declared-optional fields. Anything else raises rather than encoding.
"""
import hashlib
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Optional, Tuple

import cbor2

# Bumped when the encoding rules themselves change - not when a schema changes,
# which is what each schema's own version is for.
CODEC_VERSION = 1

# cbor2 emits shortest-form integers and definite-length containers under
# canonical=True. With arrays rather than maps that is all the determinism the
# format has to supply.
_CBOR_KWARGS = {"canonical": True}


class CodecError(Exception):
    """Base class: something could not be encoded or decoded as declared."""


class SchemaError(CodecError):
    """The schema itself is unknown or malformed."""


class FieldError(CodecError):
    """A value does not match its declared field."""


UINT = "uint"
BYTES = "bytes"
TEXT = "text"
BOOL = "bool"
ARRAY = "array"

_KINDS = (UINT, BYTES, TEXT, BOOL, ARRAY)

# An unsigned 64-bit ceiling, stated once. Timestamps, epochs and sequence
# numbers all live under it, and a value above it is a bug or an attack rather
# than a large number.
UINT_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class Field:
    """One position in a schema.

    `size` is an exact length for BYTES and a maximum length for TEXT; it is a
    maximum element count for ARRAY. `optional` permits CBOR null in this
    position and nothing else - it does not permit the field to be omitted from
    the array, because that would change the arity and therefore the meaning of
    every position after it.
    """

    name: str
    kind: str
    size: Optional[int] = None
    optional: bool = False
    item: Optional["Field"] = None

    def __post_init__(self):
        if self.kind not in _KINDS:
            raise SchemaError("field %s: unknown kind %r" % (self.name, self.kind))
        if self.kind == BYTES and not self.size:
            raise SchemaError("field %s: BYTES needs an exact size" % self.name)
        if self.kind == ARRAY and self.item is None:
            raise SchemaError("field %s: ARRAY needs an item field" % self.name)
        if self.kind == ARRAY and self.size is None:
            raise SchemaError("field %s: ARRAY needs a maximum length" % self.name)


@dataclass(frozen=True)
class Schema:
    """A signable struct: a stable tag, a version, and an ordered field list.

    The tag is small and permanent. Reusing a retired tag for a different struct
    would let an old signature be replayed against the new meaning, so tags are
    only ever added.
    """

    name: str
    tag: int
    version: int
    fields: Tuple[Field, ...]

    def index(self, name: str) -> int:
        for i, f in enumerate(self.fields):
            if f.name == name:
                return i
        raise SchemaError("schema %s has no field %r" % (self.name, name))


# --- Schema registry ------------------------------------------------------
#
# Tags are permanent. A retired tag is never reused for a different struct,
# because an old signature over the retired meaning would then verify against
# the new one.
#
# Tags 3-5 are declared but unbuilt on the current scope. They exist now so that
# the proof schema below does not have to change when the evidence they describe
# becomes available: the proof commits to a list of observation *hashes*, so an
# observation body can be added later, synced separately, and still be bound by
# the original signature. Declaring the shape early is the difference between
# reserving space and rewriting the wire format.

QR_CHALLENGE = Schema(
    name="qr_challenge",
    tag=1,
    version=1,
    fields=(
        Field("session_id", BYTES, 16),
        Field("key_id", BYTES, 8),
        Field("epoch", UINT),
        Field("seq", UINT),
        Field("challenge", BYTES, 8),
        # The previous challenge in the chain. A verifier that has seen step
        # seq-1 can confirm linkage; one that has not can still check the HMAC.
        Field("prev_link", BYTES, 8),
        Field("issued_at", UINT),
        Field("expires_at", UINT),
    ),
)

ATTENDANCE_PROOF = Schema(
    name="attendance_proof",
    tag=2,
    version=1,
    fields=(
        Field("session_id", BYTES, 16),
        # Who this is comes from the device key, not from a field. The server
        # resolves device_key_id -> RegisteredDevice -> student, so no permanent
        # student identity is ever carried in a proof.
        Field("device_key_id", BYTES, 8),
        Field("challenge", BYTES, 8),
        Field("challenge_epoch", UINT),
        Field("challenge_seq", UINT),
        Field("nonce", BYTES, 16),
        # Client clock. Recorded, signed, and therefore attributable; never
        # treated as the time the mark happened.
        Field("captured_at", UINT),
        Field("biometric", UINT),
        Field("platform", UINT),
        Field("capabilities", UINT),
        # The client's own view of its own outcome. Signed, so a client that
        # lies is on record; re-derived server side regardless.
        Field("claimed_status", UINT),
        Field("claimed_confidence_milli", UINT),
        Field("claimed_hop_count", UINT),
        # Canonical hashes of observation structs (tags 3-5). Empty while the
        # network-presence and spatial evidence blocks are unbuilt.
        Field("observations", ARRAY, 64, item=Field("observation", BYTES, 32)),
    ),
)

ORIGIN_SIGHTING = Schema(
    name="origin_sighting",
    tag=3,
    version=1,
    fields=(
        Field("session_ref", BYTES, 4),
        Field("counter", UINT),
        Field("ephemeral_id", BYTES, 8),
        # RSSI is negative dBm. Stored as dBm + 128 so the codec never needs a
        # signed integer, which is one less cross-language encoding decision.
        Field("rssi_offset", UINT),
        Field("observed_at", UINT),
    ),
)

RELAY_HOP = Schema(
    name="relay_hop",
    tag=4,
    version=1,
    fields=(
        Field("hop_index", UINT),
        Field("prev_proof_hash", BYTES, 32),
        # Relay-scoped pseudonym, not a student identifier: meaningless outside
        # this session and not linkable across sessions.
        Field("relay_pseudonym", BYTES, 16),
        Field("signature", BYTES, 64),
        Field("observed_at", UINT),
    ),
)

ANCHOR_READING = Schema(
    name="anchor_reading",
    tag=5,
    version=1,
    fields=(
        Field("anchor_ref", BYTES, 4),
        Field("ephemeral_id", BYTES, 8),
        Field("rssi_offset", UINT),
        Field("sample_count", UINT),
        Field("observed_at", UINT),
    ),
)

DEVICE_REGISTRATION = Schema(
    name="device_registration",
    tag=6,
    version=1,
    fields=(
        Field("student_ref", UINT),
        Field("public_key", BYTES, 32),
        Field("platform", UINT),
        Field("capabilities", UINT),
        Field("created_at", UINT),
        Field("nonce", BYTES, 16),
    ),
)

_SCHEMAS = {
    s.name: s
    for s in (
        QR_CHALLENGE,
        ATTENDANCE_PROOF,
        ORIGIN_SIGHTING,
        RELAY_HOP,
        ANCHOR_READING,
        DEVICE_REGISTRATION,
    )
}

_BY_TAG = {s.tag: s for s in _SCHEMAS.values()}
if len(_BY_TAG) != len(_SCHEMAS):
    raise SchemaError("duplicate schema tag in registry")


# --- Validation -----------------------------------------------------------

def get_schema(name: str) -> Schema:
    try:
        return _SCHEMAS[name]
    except KeyError:
        raise SchemaError("unknown schema %r" % (name,))


def all_schemas() -> Tuple[Schema, ...]:
    """Every registered schema, ordered by tag.

    Exposed so that callers which have to walk the whole registry - the
    cross-language agreement check, the round-trip tests, tooling that renders
    the wire format - do not have to reach into module internals. A schema added
    to the registry is therefore covered by those walks without anyone
    remembering to list it.
    """
    return tuple(sorted(_SCHEMAS.values(), key=lambda s: s.tag))


def _check_uint(f: Field, value: Any) -> int:
    # bool subclasses int in Python. A boolean in a UINT position would encode
    # as 0 or 1 without complaint, which hides a caller mistake, so reject it.
    if isinstance(value, bool) or not isinstance(value, int):
        raise FieldError(
            "field %s: expected an unsigned integer, got %s"
            % (f.name, type(value).__name__)
        )
    if value < 0 or value > UINT_MAX:
        raise FieldError("field %s: %d is outside 0..2**64-1" % (f.name, value))
    return value


def _check_bytes(f: Field, value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise FieldError(
            "field %s: expected bytes, got %s" % (f.name, type(value).__name__)
        )
    raw = bytes(value)
    if len(raw) != f.size:
        raise FieldError(
            "field %s: expected exactly %d bytes, got %d" % (f.name, f.size, len(raw))
        )
    return raw


def _check_text(f: Field, value: Any) -> str:
    if not isinstance(value, str):
        raise FieldError(
            "field %s: expected text, got %s" % (f.name, type(value).__name__)
        )
    if f.size is not None and len(value) > f.size:
        raise FieldError(
            "field %s: %d characters exceeds the %d permitted"
            % (f.name, len(value), f.size)
        )
    return value


def _check_bool(f: Field, value: Any) -> bool:
    if not isinstance(value, bool):
        raise FieldError(
            "field %s: expected a bool, got %s" % (f.name, type(value).__name__)
        )
    return value


def _check_array(f: Field, value: Any) -> list:
    if not isinstance(value, (list, tuple)):
        raise FieldError(
            "field %s: expected a list, got %s" % (f.name, type(value).__name__)
        )
    if len(value) > f.size:
        raise FieldError(
            "field %s: %d elements exceeds the %d permitted"
            % (f.name, len(value), f.size)
        )
    return [_coerce(f.item, v) for v in value]


_CHECKS = {
    UINT: _check_uint,
    BYTES: _check_bytes,
    TEXT: _check_text,
    BOOL: _check_bool,
    ARRAY: _check_array,
}


def _coerce(f: Field, value: Any) -> Any:
    if value is None:
        if f.optional:
            return None
        raise FieldError("field %s: null is not permitted here" % f.name)
    if isinstance(value, float):
        raise FieldError(
            "field %s: floats are never encoded - carry a real number as an "
            "integer in thousandths instead" % f.name
        )
    return _CHECKS[f.kind](f, value)


# --- Encode / decode ------------------------------------------------------

_MISSING = object()


def encode(schema_name: str, values: dict) -> bytes:
    """Canonical bytes for one struct.

    Every declared field must be present. An undeclared key is an error rather
    than something to ignore, because a mistyped field name would otherwise sign
    a value the caller never supplied.
    """
    schema = get_schema(schema_name)
    declared = {f.name for f in schema.fields}
    unknown = set(values) - declared
    if unknown:
        raise FieldError(
            "schema %s: unexpected field(s) %s"
            % (schema.name, ", ".join(sorted(unknown)))
        )
    body = [schema.tag, schema.version]
    for f in schema.fields:
        raw = values.get(f.name, _MISSING)
        if raw is _MISSING:
            raise FieldError("schema %s: field %s is missing" % (schema.name, f.name))
        body.append(_coerce(f, raw))
    return cbor2.dumps(body, **_CBOR_KWARGS)



def identify(raw: bytes) -> Optional[Schema]:
    """Which schema these bytes claim to be, or None.

    The tag only, and nothing else validated. It exists so a verifier holding a
    mixed bag of observation bodies can route each one to the code that knows how
    to check it, without that routing step having to pretend it validated
    anything. Every caller decodes again, strictly, naming the schema it expects.

    None covers both "not a canonical struct at all" and "a tag this build does
    not know", because the caller does the same thing with either: set the body
    aside as unusable rather than refuse the submission carrying it. A newer
    client attaching evidence an older server cannot read must degrade, not fail.
    """
    if not isinstance(raw, (bytes, bytearray)):
        return None
    try:
        body = cbor2.loads(bytes(raw))
    except Exception:
        return None
    if not isinstance(body, list) or not body:
        return None
    tag = body[0]
    if not isinstance(tag, int) or isinstance(tag, bool):
        return None
    return _BY_TAG.get(tag)


def decode(raw: bytes, schema_name: Optional[str] = None, strict: bool = True) -> dict:
    """Values from canonical bytes.

    The struct type is identified by the tag inside the bytes. Passing
    `schema_name` additionally asserts which struct the caller expected, which
    is what a verifier should always do.

    `strict` re-encodes the decoded values and requires the result to equal the
    input. A signature is checked over received bytes, so a non-canonical
    encoding would fail verification anyway - but rejecting it here means two
    different byte strings can never stand for the same proof, which is what
    would otherwise let one piece of evidence be submitted twice.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise CodecError("expected bytes to decode, got %s" % type(raw).__name__)
    try:
        body = cbor2.loads(bytes(raw))
    except Exception as exc:
        raise CodecError("not decodable as CBOR: %s" % (exc,))

    if not isinstance(body, list) or len(body) < 2:
        raise CodecError("expected a CBOR array beginning [tag, version]")
    tag, version = body[0], body[1]
    if not isinstance(tag, int) or isinstance(tag, bool):
        raise CodecError("schema tag is not an integer")
    schema = _BY_TAG.get(tag)
    if schema is None:
        raise SchemaError("unknown schema tag %r" % (tag,))
    if schema_name is not None and schema.name != schema_name:
        raise SchemaError(
            "expected schema %s, these bytes carry %s" % (schema_name, schema.name)
        )
    if version != schema.version:
        raise SchemaError(
            "schema %s: this build understands version %d, received %r"
            % (schema.name, schema.version, version)
        )
    if len(body) != len(schema.fields) + 2:
        raise CodecError(
            "schema %s: expected %d elements, got %d"
            % (schema.name, len(schema.fields) + 2, len(body))
        )

    values = {}
    for f, element in zip(schema.fields, body[2:]):
        values[f.name] = _coerce(f, element)

    if strict:
        recoded = encode(schema.name, values)
        if recoded != bytes(raw):
            raise CodecError(
                "schema %s: input is not canonical - it decodes cleanly but "
                "re-encodes to different bytes" % schema.name
            )
    return values


def digest(schema_name: str, values: dict) -> bytes:
    """SHA-256 over the canonical bytes. This is a struct's stable identity."""
    return hashlib.sha256(encode(schema_name, values)).digest()


def digest_bytes(raw: bytes) -> bytes:
    """SHA-256 over already-encoded bytes."""
    return hashlib.sha256(bytes(raw)).digest()


# --- Cross-implementation agreement --------------------------------------

def _render_field(f: Field) -> str:
    parts = [
        f.name,
        f.kind,
        "" if f.size is None else str(f.size),
        "1" if f.optional else "0",
    ]
    if f.item is not None:
        parts.append("(" + _render_field(f.item) + ")")
    return ":".join(parts)


def schema_text() -> str:
    """A canonical text rendering of the whole registry.

    Each implementation produces this from its own declarations and a
    cross-language test compares the two. Text rather than a bare hash, because
    the moment the fingerprints disagree is exactly the moment you want a diff
    that says which field moved.
    """
    lines = ["codec=%d" % CODEC_VERSION]
    for name in sorted(_SCHEMAS):
        s = _SCHEMAS[name]
        lines.append(
            "%s tag=%d v=%d %s"
            % (
                s.name,
                s.tag,
                s.version,
                ",".join(_render_field(f) for f in s.fields),
            )
        )
    return "\n".join(lines) + "\n"


def schema_fingerprint() -> str:
    """Short stable identifier for the registry as declared in this build."""
    return hashlib.sha256(schema_text().encode("utf-8")).hexdigest()








