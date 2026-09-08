"""Tests for the canonical encoding the presence layer signs over.

Two things are being defended here, and they are not the same thing.

The first is *agreement*: Python here and Dart on the handset must produce
identical bytes from identical values, or every signature fails in the field
after the app has shipped. `schema_fingerprint` is pinned below for exactly that
reason - a change to it is a wire-format change, and the Dart side has to move in
the same commit.

The second is *uniqueness*: one proof must have exactly one valid encoding. If
two different byte strings can decode to the same values, the same piece of
evidence can be submitted twice under two different hashes, and a duplicate-proof
cache stops working. The `strict` re-encode in `decode` is what closes that, so
several tests below assert the ugly cases it catches - and one asserts what
`strict=False` lets through, because that is a loaded gun and a test is the right
place to document it.
"""
import hashlib
from contextlib import contextmanager

import cbor2
from django.test import SimpleTestCase

from .presence import codec
from .presence.codec import (
    ARRAY,
    BOOL,
    BYTES,
    TEXT,
    UINT,
    UINT_MAX,
    CodecError,
    Field,
    FieldError,
    Schema,
    SchemaError,
)

# Real tags are small and permanent. These two sit in a band no real schema may
# use, so a test schema can never squat on a tag a future struct wants, and
# `test_the_test_only_tag_band_is_free` fails if that assumption ever stops
# holding.
TEST_TAG = 0x7FFF
TEST_TAG_TWIN = 0x7FFE
TEST_TAG_FLOOR = 0x7F00


@contextmanager
def registered(*schemas):
    """Temporarily add schemas to the registry.

    The registry is deliberately module-level and closed: tags are permanent, so
    there is no public way to add one at runtime and there should not be. Tests
    that need a shape the real registry does not contain - TEXT, BOOL, a
    declared-optional field - reach in here rather than have the production API
    grow a hole for their benefit.
    """
    for s in schemas:
        assert s.name not in codec._SCHEMAS, s.name
        assert s.tag not in codec._BY_TAG, s.tag
        codec._SCHEMAS[s.name] = s
        codec._BY_TAG[s.tag] = s
    try:
        yield
    finally:
        for s in schemas:
            codec._SCHEMAS.pop(s.name, None)
            codec._BY_TAG.pop(s.tag, None)


def sample_value(f, seed=0):
    """A valid value for one declared field.

    Driven off the declaration rather than hand-written per schema, so a schema
    added to the registry is round-tripped by the tests below without anyone
    remembering to extend a fixture.
    """
    if f.kind == UINT:
        return 1000 + seed
    if f.kind == BYTES:
        return bytes((seed + i) % 256 for i in range(f.size))
    if f.kind == TEXT:
        return "value-%d" % seed
    if f.kind == BOOL:
        return seed % 2 == 0
    if f.kind == ARRAY:
        return [sample_value(f.item, seed + i) for i in range(min(2, f.size))]
    raise AssertionError("no sample for kind %r" % (f.kind,))


def sample(schema):
    return {f.name: sample_value(f, i) for i, f in enumerate(schema.fields)}


QR = codec.QR_CHALLENGE
PROOF = codec.ATTENDANCE_PROOF


class RegistryTests(SimpleTestCase):
    def test_tags_are_unique(self):
        tags = [s.tag for s in codec.all_schemas()]
        self.assertEqual(len(tags), len(set(tags)))

    def test_the_test_only_tag_band_is_free(self):
        """The helper above assumes nothing real lives at 0x7F00 or above."""
        for s in codec.all_schemas():
            self.assertLess(s.tag, TEST_TAG_FLOOR, s.name)

    def test_schema_fingerprint_is_pinned(self):
        """A wire-format change must be a deliberate, visible one.

        If this fails because a field was added, moved, resized or renamed, the
        Dart implementation has to change in the same commit and every proof
        signed by an older build stops verifying. Update the constant only
        together with the client and a protocol version bump.
        """
        self.assertEqual(
            codec.schema_fingerprint(),
            "087177288b4c3f4eaa91203feafe8b57de5028f59ccd99980be6bc42c0078109",
        )

    def test_schema_text_is_a_diffable_rendering(self):
        text = codec.schema_text()
        self.assertEqual(text, codec.schema_text())
        self.assertIn("codec=%d" % codec.CODEC_VERSION, text)
        for s in codec.all_schemas():
            self.assertIn("%s tag=%d v=%d" % (s.name, s.tag, s.version), text)
            for f in s.fields:
                self.assertIn(f.name, text)

    def test_schema_text_records_nesting_and_sizes(self):
        """The rendering has to name the *shape*, not just the field.

        A hash that ignored an item type or a length cap would let the two
        implementations disagree while both reported the same fingerprint.
        """
        line = [
            ln for ln in codec.schema_text().splitlines()
            if ln.startswith("attendance_proof ")
        ][0]
        self.assertIn("observations:array:64:0:(observation:bytes:32:0)", line)

    def test_get_schema_rejects_an_unknown_name(self):
        with self.assertRaises(SchemaError):
            codec.get_schema("no_such_struct")


class RoundTripTests(SimpleTestCase):
    def test_every_registered_schema_round_trips(self):
        for s in codec.all_schemas():
            with self.subTest(schema=s.name):
                values = sample(s)
                raw = codec.encode(s.name, values)
                self.assertEqual(codec.decode(raw, s.name), values)

    def test_the_tag_identifies_the_struct_without_being_told(self):
        for s in codec.all_schemas():
            with self.subTest(schema=s.name):
                raw = codec.encode(s.name, sample(s))
                # No schema_name: a verifier that does not yet know what it has
                # still gets the right struct back.
                self.assertEqual(codec.decode(raw), sample(s))

    def test_encoding_is_deterministic(self):
        values = sample(QR)
        self.assertEqual(codec.encode(QR.name, values), codec.encode(QR.name, values))

    def test_dict_order_does_not_reach_the_bytes(self):
        """Field order comes from the schema. It must not come from the caller."""
        values = sample(QR)
        reversed_order = {k: values[k] for k in reversed(list(values))}
        self.assertNotEqual(list(values), list(reversed_order))
        self.assertEqual(
            codec.encode(QR.name, values), codec.encode(QR.name, reversed_order)
        )

    def test_the_first_two_elements_are_tag_and_version(self):
        for s in codec.all_schemas():
            with self.subTest(schema=s.name):
                body = cbor2.loads(codec.encode(s.name, sample(s)))
                self.assertEqual(body[0], s.tag)
                self.assertEqual(body[1], s.version)
                self.assertEqual(len(body), len(s.fields) + 2)

    def test_an_empty_observation_list_round_trips(self):
        """The state this ships in: no BLE evidence, so no observations."""
        values = sample(PROOF)
        values["observations"] = []
        raw = codec.encode(PROOF.name, values)
        self.assertEqual(codec.decode(raw, PROOF.name)["observations"], [])

    def test_a_full_observation_list_round_trips(self):
        values = sample(PROOF)
        values["observations"] = [bytes([i]) * 32 for i in range(64)]
        raw = codec.encode(PROOF.name, values)
        self.assertEqual(
            codec.decode(raw, PROOF.name)["observations"], values["observations"]
        )


class DomainSeparationTests(SimpleTestCase):
    """A signature over one struct must not verify as another."""

    def test_identical_values_under_two_schemas_encode_differently(self):
        shape = (Field("a", UINT), Field("b", BYTES, 4))
        one = Schema(name="tmp_one", tag=TEST_TAG, version=1, fields=shape)
        two = Schema(name="tmp_two", tag=TEST_TAG_TWIN, version=1, fields=shape)
        with registered(one, two):
            values = {"a": 7, "b": b"abcd"}
            self.assertNotEqual(
                codec.encode("tmp_one", values), codec.encode("tmp_two", values)
            )

    def test_decode_rejects_a_struct_the_caller_did_not_expect(self):
        raw = codec.encode(QR.name, sample(QR))
        with self.assertRaises(SchemaError):
            codec.decode(raw, PROOF.name)

    def test_an_unknown_tag_is_rejected(self):
        body = cbor2.loads(codec.encode(QR.name, sample(QR)))
        body[0] = 0x6FFF
        with self.assertRaises(SchemaError):
            codec.decode(cbor2.dumps(body, canonical=True))

    def test_a_version_this_build_does_not_understand_is_rejected(self):
        body = cbor2.loads(codec.encode(QR.name, sample(QR)))
        body[1] = QR.version + 1
        with self.assertRaises(SchemaError):
            codec.decode(cbor2.dumps(body, canonical=True), QR.name)

    def test_a_tag_that_is_not_an_integer_is_rejected(self):
        body = cbor2.loads(codec.encode(QR.name, sample(QR)))
        body[0] = "qr_challenge"
        with self.assertRaises(CodecError):
            codec.decode(cbor2.dumps(body, canonical=True))


class CanonicalFormTests(SimpleTestCase):
    """One proof, one encoding. Anything else lets evidence be double-counted."""

    def setUp(self):
        self.values = sample(QR)
        self.raw = codec.encode(QR.name, self.values)

    def test_trailing_bytes_are_rejected(self):
        # cbor2 decodes the first item and ignores whatever follows, so this is
        # not caught by parsing - only by re-encoding and comparing.
        with self.assertRaises(CodecError):
            codec.decode(self.raw + b"\xff\xff", QR.name)

    def test_strict_is_what_catches_it(self):
        """Documenting the sharp edge: strict=False accepts padded bytes.

        The values come back correct, but the hash of the input does not equal
        the hash of the canonical form - so a replay cache keyed on the received
        bytes would see two distinct proofs. Verifiers use the default.
        """
        loose = codec.decode(self.raw + b"\xff\xff", QR.name, strict=False)
        self.assertEqual(loose, self.values)
        self.assertNotEqual(
            hashlib.sha256(self.raw + b"\xff\xff").digest(),
            hashlib.sha256(self.raw).digest(),
        )

    def test_an_indefinite_length_array_is_rejected(self):
        self.assertEqual(self.raw[0], 0x8A)  # definite-length array of 10
        indefinite = b"\x9f" + self.raw[1:] + b"\xff"
        self.assertEqual(cbor2.loads(indefinite), cbor2.loads(self.raw))
        with self.assertRaises(CodecError):
            codec.decode(indefinite, QR.name)

    def test_a_non_shortest_integer_is_rejected(self):
        # Byte 2 is the version, encoded as a single byte because it is 1. The
        # same value written as a uint8 header plus a byte is valid CBOR and not
        # canonical. The assertion above the surgery keeps the surgery honest.
        self.assertEqual(self.raw[2], 0x01)
        padded = self.raw[:2] + b"\x18\x01" + self.raw[3:]
        self.assertEqual(cbor2.loads(padded), cbor2.loads(self.raw))
        with self.assertRaises(CodecError):
            codec.decode(padded, QR.name)

    def test_a_map_is_not_a_struct(self):
        with self.assertRaises(CodecError):
            codec.decode(cbor2.dumps({"session_id": b"S" * 16}, canonical=True))

    def test_the_wrong_number_of_elements_is_rejected(self):
        body = cbor2.loads(self.raw)
        with self.assertRaises(CodecError):
            codec.decode(cbor2.dumps(body[:-1], canonical=True), QR.name)
        with self.assertRaises(CodecError):
            codec.decode(cbor2.dumps(body + [1], canonical=True), QR.name)

    def test_a_bare_scalar_is_rejected(self):
        with self.assertRaises(CodecError):
            codec.decode(cbor2.dumps(1, canonical=True))

    def test_bytes_that_are_not_cbor_are_rejected(self):
        for bad in (b"", b"not cbor at all", b"\xff\xff\xff"):
            with self.subTest(raw=bad):
                with self.assertRaises(CodecError):
                    codec.decode(bad)

    def test_decode_requires_bytes(self):
        for bad in ("8a0101", None, 17, ["8a"]):
            with self.subTest(value=bad):
                with self.assertRaises(CodecError):
                    codec.decode(bad)


class FieldValidationTests(SimpleTestCase):
    def encode_qr(self, **overrides):
        values = sample(QR)
        values.update(overrides)
        return codec.encode(QR.name, values)

    def test_floats_are_never_encoded(self):
        with self.assertRaises(FieldError) as caught:
            self.encode_qr(epoch=1.0)
        self.assertIn("thousandths", str(caught.exception))

    def test_a_float_inside_an_array_is_rejected_too(self):
        values = sample(PROOF)
        values["observations"] = [1.5]
        with self.assertRaises(FieldError):
            codec.encode(PROOF.name, values)

    def test_a_bool_is_not_an_unsigned_integer(self):
        """bool subclasses int, so this would otherwise encode as 0 or 1."""
        with self.assertRaises(FieldError):
            self.encode_qr(epoch=True)

    def test_a_negative_integer_is_rejected(self):
        with self.assertRaises(FieldError):
            self.encode_qr(epoch=-1)

    def test_the_unsigned_ceiling_holds(self):
        codec.encode(QR.name, dict(sample(QR), epoch=UINT_MAX))
        with self.assertRaises(FieldError):
            self.encode_qr(epoch=UINT_MAX + 1)

    def test_a_string_in_an_integer_position_is_rejected(self):
        with self.assertRaises(FieldError):
            self.encode_qr(epoch="3")

    def test_byte_strings_must_be_exactly_the_declared_length(self):
        for wrong in (b"S" * 15, b"S" * 17, b""):
            with self.subTest(length=len(wrong)):
                with self.assertRaises(FieldError):
                    self.encode_qr(session_id=wrong)

    def test_text_in_a_bytes_position_is_rejected(self):
        with self.assertRaises(FieldError):
            self.encode_qr(session_id="S" * 16)

    def test_an_undeclared_field_is_rejected(self):
        """A mistyped name would otherwise sign a value nobody supplied."""
        with self.assertRaises(FieldError) as caught:
            self.encode_qr(sesion_id=b"S" * 16)
        self.assertIn("sesion_id", str(caught.exception))

    def test_a_missing_field_is_rejected(self):
        values = sample(QR)
        del values["expires_at"]
        with self.assertRaises(FieldError) as caught:
            codec.encode(QR.name, values)
        self.assertIn("expires_at", str(caught.exception))

    def test_an_over_long_array_is_rejected(self):
        values = sample(PROOF)
        values["observations"] = [b"o" * 32] * 65
        with self.assertRaises(FieldError):
            codec.encode(PROOF.name, values)

    def test_array_elements_are_length_checked(self):
        values = sample(PROOF)
        values["observations"] = [b"o" * 31]
        with self.assertRaises(FieldError):
            codec.encode(PROOF.name, values)

    def test_a_bare_value_where_an_array_is_declared_is_rejected(self):
        values = sample(PROOF)
        values["observations"] = b"o" * 32
        with self.assertRaises(FieldError):
            codec.encode(PROOF.name, values)

    def test_null_is_rejected_unless_the_field_declares_it(self):
        with self.assertRaises(FieldError):
            self.encode_qr(epoch=None)

    def test_text_bool_and_optional_fields(self):
        """Exercised through a temporary schema: the registry has none yet.

        These kinds are declared by the codec, so they are tested by the codec.
        Leaving them until some future struct uses them is how an encoding bug
        ships inside the first schema that needs one.
        """
        mixed = Schema(
            name="tmp_mixed",
            tag=TEST_TAG,
            version=1,
            fields=(
                Field("label", TEXT, 8),
                Field("flag", BOOL),
                Field("maybe", BYTES, 4, optional=True),
            ),
        )
        with registered(mixed):
            values = {"label": "abc", "flag": False, "maybe": None}
            raw = codec.encode("tmp_mixed", values)
            self.assertEqual(codec.decode(raw, "tmp_mixed"), values)

            present = {"label": "abc", "flag": True, "maybe": b"wxyz"}
            self.assertEqual(
                codec.decode(codec.encode("tmp_mixed", present), "tmp_mixed"), present
            )

            with self.assertRaises(FieldError):
                codec.encode("tmp_mixed", dict(values, label="too long for eight"))
            with self.assertRaises(FieldError):
                codec.encode("tmp_mixed", dict(values, flag=1))
            with self.assertRaises(FieldError):
                codec.encode("tmp_mixed", dict(values, label=b"abc"))

    def test_an_optional_field_still_occupies_its_position(self):
        """Null, not omitted: dropping it would shift every later field."""
        mixed = Schema(
            name="tmp_arity",
            tag=TEST_TAG,
            version=1,
            fields=(Field("maybe", BYTES, 4, optional=True), Field("after", UINT)),
        )
        with registered(mixed):
            raw = codec.encode("tmp_arity", {"maybe": None, "after": 9})
            body = cbor2.loads(raw)
            self.assertEqual(len(body), 4)
            self.assertIsNone(body[2])
            self.assertEqual(body[3], 9)

class SchemaDeclarationTests(SimpleTestCase):
    """A malformed declaration must fail at import, not at signing time."""

    def test_bytes_needs_an_exact_size(self):
        with self.assertRaises(SchemaError):
            Field("k", BYTES)

    def test_an_array_needs_an_item_and_a_cap(self):
        with self.assertRaises(SchemaError):
            Field("k", ARRAY, 4)
        with self.assertRaises(SchemaError):
            Field("k", ARRAY, item=Field("i", UINT))

    def test_an_unknown_kind_is_rejected(self):
        with self.assertRaises(SchemaError):
            Field("k", "float64")

    def test_index_locates_a_field_and_says_so_when_it_cannot(self):
        self.assertEqual(QR.index("session_id"), 0)
        self.assertEqual(QR.index("expires_at"), len(QR.fields) - 1)
        with self.assertRaises(SchemaError):
            QR.index("nope")


class DigestTests(SimpleTestCase):
    """A struct's identity is the hash of its canonical bytes, nothing else."""

    def test_digest_is_sha256_over_the_canonical_encoding(self):
        values = sample(PROOF)
        self.assertEqual(
            codec.digest(PROOF.name, values),
            hashlib.sha256(codec.encode(PROOF.name, values)).digest(),
        )

    def test_digest_bytes_agrees_with_digest(self):
        values = sample(PROOF)
        raw = codec.encode(PROOF.name, values)
        self.assertEqual(codec.digest_bytes(raw), codec.digest(PROOF.name, values))

    def test_one_changed_byte_changes_the_digest(self):
        values = sample(PROOF)
        other = dict(values, session_id=bytes([values["session_id"][0] ^ 1]) + values["session_id"][1:])
        self.assertNotEqual(
            codec.digest(PROOF.name, values), codec.digest(PROOF.name, other)
        )

    def test_the_digest_is_32_bytes(self):
        self.assertEqual(len(codec.digest(QR.name, sample(QR))), 32)
