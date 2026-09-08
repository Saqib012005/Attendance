"""Tests for the signed attendance proof.

The module's whole claim is a separation, and these tests are what hold it: a
signature makes every field inside a proof *attributable*, and it makes none of
them *true*. So the tests are organised around who decides what.

`SignatureTests` pin the unforgeable part, including the rule that a proof has
exactly one encoding - a valid signature over non-canonical bytes is still
refused, because otherwise the same evidence could be resubmitted under a second
byte string and a digest-keyed ledger would count two proofs.

`ClaimTests` pin the opposite, and are the reason the module exists in this shape:
a proof claiming `present` at full confidence and one claiming `suspicious` travel
the identical code path and reach the identical result. Nothing here reads a claim
to decide anything, and the test is a behavioural assertion of that rather than a
comment saying so.

`PrivacyTests` check the schema itself for room to smuggle what §09 forbids. The
widest byte string a proof can carry is 32 bytes and every position is named, so
there is nowhere to put a face template - a structural guarantee rather than a
policy anyone has to remember.
"""
import cbor2
from django.test import SimpleTestCase

from .presence import codec, keys
from .presence import proof as proof_mod
from .presence.proof import (
    BAD_SIGNATURE,
    KEY_MISMATCH,
    MALFORMED,
    SESSION_MISMATCH,
    Claims,
    Proof,
    ProofError,
)

SESSION_ID = bytes(range(16))
OTHER_SESSION_ID = bytes(range(16, 32))
CHALLENGE = b"\xc0" * 8
CAPTURED_AT = 1_757_000_045


class Case(SimpleTestCase):
    def setUp(self):
        self.key = keys.SigningKey.generate()
        self.device_key = self.key.public()
        self.other = keys.SigningKey.generate()

    def build(self, **overrides):
        kwargs = {
            "session_id": SESSION_ID,
            "device_key_id": self.device_key.key_id,
            "challenge": CHALLENGE,
            "challenge_epoch": 0,
            "challenge_seq": 3,
            "captured_at": CAPTURED_AT,
            "biometric": proof_mod.BIOMETRIC_SUCCESS,
            "platform": proof_mod.PLATFORM_ANDROID,
            "capabilities": proof_mod.CAP_BIOMETRIC | proof_mod.CAP_HARDWARE_KEYSTORE,
            "nonce": b"\xa0" * 16,
        }
        kwargs.update(overrides)
        return proof_mod.build(**kwargs)

    def signed(self, **overrides):
        return proof_mod.sign(self.build(**overrides), self.key)

    def refused(self, code, callable_, *args, **kwargs):
        with self.assertRaises(ProofError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception


class ShapeTests(Case):
    def test_every_length_is_taken_from_the_schema(self):
        """Restating one would let the wire format and this module drift apart."""
        fields = {f.name: f for f in proof_mod.SCHEMA.fields}
        self.assertEqual(proof_mod.SESSION_ID_LEN, fields["session_id"].size)
        self.assertEqual(proof_mod.DEVICE_KEY_ID_LEN, fields["device_key_id"].size)
        self.assertEqual(proof_mod.CHALLENGE_LEN, fields["challenge"].size)
        self.assertEqual(proof_mod.NONCE_LEN, fields["nonce"].size)
        self.assertEqual(proof_mod.MAX_OBSERVATIONS, fields["observations"].size)
        self.assertEqual(proof_mod.OBSERVATION_LEN, fields["observations"].item.size)

    def test_a_nonce_is_generated_when_none_is_supplied(self):
        first, second = self.build(nonce=None), self.build(nonce=None)
        self.assertEqual(len(first.nonce), proof_mod.NONCE_LEN)
        self.assertNotEqual(first.nonce, second.nonce)

    def test_a_negative_or_non_integer_field_is_refused(self):
        for name in ("challenge_epoch", "challenge_seq", "captured_at", "capabilities"):
            for bad in (-1, True, 1.5, "3", None):
                with self.subTest(field=name, value=repr(bad)):
                    self.refused(MALFORMED, self.build, **{name: bad})

    def test_a_wrong_length_field_is_refused_by_the_codec(self):
        for name, value in (
            ("session_id", SESSION_ID[:-1]),
            ("challenge", CHALLENGE + b"\x01"),
            ("nonce", b"\xa0" * 15),
        ):
            with self.subTest(field=name):
                with self.assertRaises(codec.CodecError):
                    self.build(**{name: value}).encode()

    def test_the_digest_is_the_hash_of_the_signed_bytes(self):
        """The ledger keys on this, so the two definitions must not diverge."""
        signed = self.signed()
        self.assertEqual(signed.digest, codec.digest_bytes(signed.body))
        self.assertEqual(signed.digest, signed.proof.digest())

    def test_a_proof_survives_a_round_trip_unchanged(self):
        signed = self.signed()
        self.assertEqual(proof_mod.parse(signed.body), signed.proof)
        self.assertEqual(proof_mod.parse(signed.body).encode(), signed.body)

    def test_another_struct_cannot_be_read_as_a_proof(self):
        """The tag inside the signed bytes is what makes this structural."""
        other = codec.encode(codec.QR_CHALLENGE.name, {
            "session_id": SESSION_ID, "key_id": b"\x01" * 8, "epoch": 0, "seq": 1,
            "challenge": CHALLENGE, "prev_link": b"\x02" * 8,
            "issued_at": CAPTURED_AT, "expires_at": CAPTURED_AT + 30,
        })
        self.refused(MALFORMED, proof_mod.parse, other)

    def test_arbitrary_bytes_are_refused(self):
        for bad in (b"", b"\x00", b"not cbor at all", cbor2.dumps({"a": 1})):
            with self.subTest(body=bad[:12]):
                self.refused(MALFORMED, proof_mod.parse, bad)


class VocabularyTests(Case):
    def test_an_unrecognised_biometric_outcome_is_refused(self):
        """A closed vocabulary: folding an unknown value into a neighbouring one
        would quietly turn a failure into an absence, or the reverse."""
        for bad in (4, 99, 255):
            with self.subTest(biometric=bad):
                self.refused(MALFORMED, self.build, biometric=bad)

    def test_the_four_biometric_outcomes_are_the_only_ones(self):
        """§09: an outcome, never a template, a score or an image."""
        self.assertEqual(
            set(proof_mod.BIOMETRIC_NAMES.values()),
            {"absent", "success", "failed", "cancelled"},
        )

    def test_an_absent_biometric_is_not_a_failed_one(self):
        """A platform that offers none must not look like a student who failed."""
        absent = self.build(biometric=proof_mod.BIOMETRIC_ABSENT)
        failed = self.build(biometric=proof_mod.BIOMETRIC_FAILED)
        self.assertEqual(absent.biometric_name, "absent")
        self.assertEqual(failed.biometric_name, "failed")
        self.assertNotEqual(absent.biometric, failed.biometric)

    def test_an_unrecognised_claimed_status_is_refused(self):
        self.refused(MALFORMED, self.build, claims=Claims(status=9))

    def test_a_confidence_above_one_is_refused(self):
        self.build(claims=Claims(confidence_milli=proof_mod.CONFIDENCE_MILLI_MAX))
        self.refused(
            MALFORMED, self.build,
            claims=Claims(confidence_milli=proof_mod.CONFIDENCE_MILLI_MAX + 1),
        )

    def test_an_unknown_platform_is_tolerated_and_named_honestly(self):
        """An older server refusing a newer handset punishes the wrong person."""
        built = self.build(platform=77)
        self.assertEqual(built.platform_name, "unrecognised")
        self.assertEqual(proof_mod.parse(proof_mod.sign(built, self.key).body), built)

    def test_an_unknown_capability_bit_is_kept_visible_rather_than_dropped(self):
        spare = 1 << 20
        built = self.build(capabilities=proof_mod.CAP_BIOMETRIC | spare)
        self.assertEqual(built.unknown_capabilities, spare)
        self.assertNotIn("unrecognised", built.capability_names())
        self.assertEqual(built.describe()["unknown_capability_bits"], spare)

    def test_a_known_capability_set_reads_back_by_name(self):
        built = self.build(capabilities=proof_mod.CAP_BLE_SCAN | proof_mod.CAP_RELAY)
        self.assertEqual(set(built.capability_names()), {"ble_scan", "relay"})
        self.assertTrue(built.has_capability(proof_mod.CAP_RELAY))
        self.assertFalse(built.has_capability(proof_mod.CAP_RANGING))
        self.assertEqual(built.unknown_capabilities, 0)

    def test_relaying_is_its_own_capability(self):
        """Advertise and scan together do not imply it: a foreground service the
        OEM battery manager leaves alone is the part that actually fails."""
        both = self.build(
            capabilities=proof_mod.CAP_BLE_SCAN | proof_mod.CAP_BLE_ADVERTISE
        )
        self.assertFalse(both.has_capability(proof_mod.CAP_RELAY))

    def test_every_capability_flag_is_a_distinct_single_bit(self):
        seen = 0
        for flag in proof_mod.CAPABILITY_NAMES:
            with self.subTest(flag=flag):
                self.assertEqual(flag & (flag - 1), 0, "not a single bit")
                self.assertEqual(seen & flag, 0, "two capabilities share a bit")
            seen |= flag
        self.assertEqual(seen, proof_mod.KNOWN_CAPABILITIES)

    def test_every_reason_code_is_declared_and_namespaced(self):
        self.assertEqual(
            proof_mod.REASON_CODES,
            {MALFORMED, BAD_SIGNATURE, KEY_MISMATCH, SESSION_MISMATCH},
        )
        for code in proof_mod.REASON_CODES:
            with self.subTest(code=code):
                self.assertTrue(code.startswith("proof_"))

    def test_an_undeclared_reason_code_cannot_be_raised(self):
        with self.assertRaises(AssertionError):
            raise ProofError("proof_invented_here", "message")


class SignatureTests(Case):
    def test_a_signed_proof_verifies(self):
        signed = self.signed()
        back = proof_mod.verify(
            signed.body, signed.signature, self.device_key, session_id=SESSION_ID
        )
        self.assertEqual(back.proof, signed.proof)
        self.assertEqual(back.body, signed.body)

    def test_the_signature_is_over_the_raw_canonical_bytes(self):
        """Checked against the primitive, not against our own verifier, which
        would agree with any wrapper we invented. The Dart client signs the same
        bytes, so a helpful prefix added here would break every proof in the
        field rather than fail a test."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        signed = self.signed()
        raw = Ed25519PublicKey.from_public_bytes(self.device_key.public_bytes)
        raw.verify(signed.signature, signed.body)
        self.assertEqual(len(signed.signature), keys.SIGNATURE_LEN)

    def test_signing_refuses_a_proof_that_names_another_device(self):
        """Not defence - an attacker deletes this check - but it turns a client
        bug into a local failure instead of a signature nothing will accept."""
        self.refused(
            KEY_MISMATCH, proof_mod.sign,
            self.build(device_key_id=keys.key_id_for(self.other.public().public_bytes)),
            self.key,
        )

    def test_an_edited_field_breaks_the_signature(self):
        signed = self.signed()
        body = bytearray(signed.body)
        position = body.index(SESSION_ID)
        body[position] ^= 0x01
        self.assertEqual(len(body), len(signed.body))
        self.refused(
            BAD_SIGNATURE, proof_mod.verify, bytes(body), signed.signature,
            self.device_key,
        )

    def test_a_truncated_signature_fails_closed(self):
        signed = self.signed()
        for length in (0, 32, keys.SIGNATURE_LEN - 1):
            with self.subTest(length=length):
                self.refused(
                    BAD_SIGNATURE, proof_mod.verify, signed.body,
                    signed.signature[:length], self.device_key,
                )

    def test_a_signature_from_another_device_fails_closed(self):
        signed = self.signed()
        forged = self.other.sign(signed.body)
        self.refused(
            BAD_SIGNATURE, proof_mod.verify, signed.body, forged, self.device_key
        )

    def test_a_valid_signature_over_non_canonical_bytes_is_still_refused(self):
        """One proof, one encoding.

        The bytes below decode to the same values under an indefinite-length CBOR
        array, and the signature over them is genuine. Accepting it would let the
        same evidence be resubmitted as a second, differently-digested proof, and
        a ledger keyed on digests would count two.
        """
        signed = self.signed()
        items = cbor2.loads(signed.body)
        loose = b"\x9f" + b"".join(cbor2.dumps(i) for i in items) + b"\xff"
        self.assertNotEqual(loose, signed.body)
        self.assertEqual(cbor2.loads(loose), items)
        signature = self.key.sign(loose)
        self.device_key.verify(loose, signature)
        self.refused(MALFORMED, proof_mod.verify, loose, signature, self.device_key)

    def test_the_returned_bytes_are_the_ones_received(self):
        """Not re-encoded: a signature is only meaningful over the octets that
        arrived, and re-deriving them would substitute this build's encoder."""
        signed = self.signed()
        back = proof_mod.verify(signed.body, signed.signature, self.device_key)
        self.assertIs(type(back.body), bytes)
        self.assertEqual(back.body, signed.body)


class OrderingTests(Case):
    """Each failure reported by the layer that can explain it."""

    def test_shape_is_checked_before_the_signature(self):
        """A malformed body reported as a bad signature sends an integrator
        hunting the wrong bug."""
        self.refused(
            MALFORMED, proof_mod.verify, b"not a proof", b"\x00" * keys.SIGNATURE_LEN,
            self.device_key,
        )

    def test_the_key_binding_is_checked_before_the_signature(self):
        """A caller that resolved the key from an outer transport field would
        otherwise accept a genuine signature by device A over a body naming B."""
        signed = self.signed()
        self.refused(
            KEY_MISMATCH, proof_mod.verify, signed.body, signed.signature,
            self.other.public(),
        )

    def test_the_session_is_only_checked_once_the_signature_holds(self):
        """Before it verifies, every field in a proof is just bytes somebody sent."""
        signed = self.signed()
        self.refused(
            BAD_SIGNATURE, proof_mod.verify, signed.body, self.other.sign(signed.body),
            self.device_key, session_id=OTHER_SESSION_ID,
        )
        self.refused(
            SESSION_MISMATCH, proof_mod.verify, signed.body, signed.signature,
            self.device_key, session_id=OTHER_SESSION_ID,
        )

    def test_omitting_the_session_skips_that_check(self):
        """The endpoint always passes it; the lab and offline tooling need not."""
        signed = self.signed()
        proof_mod.verify(signed.body, signed.signature, self.device_key)


class ClaimTests(Case):
    """§39, asserted behaviourally rather than promised in a comment."""

    def test_a_claim_of_present_and_a_claim_of_suspicious_travel_identically(self):
        """Nothing in this module reads a claim to decide anything. If something
        ever did, these two would stop agreeing."""
        outcomes = []
        for status in (proof_mod.STATUS_PRESENT, proof_mod.STATUS_SUSPICIOUS):
            signed = self.signed(claims=Claims(status=status, confidence_milli=1000))
            back = proof_mod.verify(
                signed.body, signed.signature, self.device_key, session_id=SESSION_ID
            )
            outcomes.append((back.proof.claims.status, back.body == signed.body))
        self.assertEqual([o[1] for o in outcomes], [True, True])
        self.assertEqual(
            [o[0] for o in outcomes],
            [proof_mod.STATUS_PRESENT, proof_mod.STATUS_SUSPICIOUS],
        )

    def test_a_maximal_claim_earns_nothing(self):
        """Full confidence, present, and nine hops: all recorded, none believed."""
        signed = self.signed(claims=Claims(proof_mod.STATUS_PRESENT, 1000, 9))
        back = proof_mod.verify(signed.body, signed.signature, self.device_key)
        self.assertEqual(back.proof.claims, Claims(proof_mod.STATUS_PRESENT, 1000, 9))

    def test_claims_default_to_saying_nothing(self):
        built = self.build()
        self.assertEqual(built.claims, Claims(proof_mod.STATUS_UNKNOWN, 0, 0))

    def test_the_claims_are_signed_so_a_lie_is_attributable(self):
        """The point of carrying them at all: a device whose claims disagree with
        the server's re-derivation is on record under its own key."""
        signed = self.signed(claims=Claims(proof_mod.STATUS_PRESENT, 1000, 0))
        body = bytearray(signed.body)
        position = body.index(bytes([proof_mod.STATUS_PRESENT]) + b"\x19\x03\xe8")
        body[position] = proof_mod.STATUS_NOT_VERIFIED
        self.refused(
            BAD_SIGNATURE, proof_mod.verify, bytes(body), signed.signature,
            self.device_key,
        )

    def test_a_claim_is_named_as_a_claim_wherever_it_is_reported(self):
        """So no downstream reader can mistake one for a finding."""
        described = self.signed().proof.describe()
        for key in ("claimed_status", "claimed_confidence_milli", "claimed_hop_count"):
            with self.subTest(key=key):
                self.assertIn(key, described)
        self.assertNotIn("status", described)
        self.assertNotIn("confidence", described)


class ObservationTests(Case):
    def encoded_reading(self, counter=1):
        return codec.encode(codec.ORIGIN_SIGHTING.name, {
            "session_ref": b"\x01\x02\x03\x04", "counter": counter,
            "ephemeral_id": b"\xe0" * 8, "rssi_offset": 40,
            "observed_at": CAPTURED_AT,
        })

    def test_a_proof_commits_to_evidence_by_digest_and_carries_none_of_it(self):
        body = self.encoded_reading()
        digests = proof_mod.observation_digests(body)
        self.assertEqual([len(d) for d in digests], [proof_mod.OBSERVATION_LEN])
        built = self.build(observations=digests)
        self.assertNotIn(body, built.encode())
        self.assertTrue(proof_mod.committed_to(built, [body]))

    def test_a_body_the_proof_does_not_account_for_is_refused(self):
        built = self.build(observations=proof_mod.observation_digests(
            self.encoded_reading(1)
        ))
        self.assertFalse(proof_mod.committed_to(built, [self.encoded_reading(2)]))

    def test_a_committed_body_lost_in_transit_is_not_a_validity_problem(self):
        """It is missing evidence for fusion to weigh, which is a different
        question from whether the proof is genuine."""
        built = self.build(observations=proof_mod.observation_digests(
            self.encoded_reading(1), self.encoded_reading(2)
        ))
        self.assertTrue(proof_mod.committed_to(built, [self.encoded_reading(1)]))
        self.assertTrue(proof_mod.committed_to(built, []))

    def test_evidence_cannot_be_added_after_signing(self):
        signed = self.signed()
        extended = Proof(**{
            **{f: getattr(signed.proof, f) for f in (
                "session_id", "device_key_id", "challenge", "challenge_epoch",
                "challenge_seq", "nonce", "captured_at", "biometric", "platform",
                "capabilities", "claims",
            )},
            "observations": proof_mod.observation_digests(self.encoded_reading()),
        })
        self.refused(
            BAD_SIGNATURE, proof_mod.verify, extended.encode(), signed.signature,
            self.device_key,
        )

    def test_a_repeated_observation_digest_is_refused(self):
        """One observation submitted twice must not be able to look like two."""
        digest = codec.digest_bytes(self.encoded_reading())
        self.refused(MALFORMED, self.build, observations=(digest, digest))

    def test_more_observations_than_the_schema_allows_are_refused(self):
        too_many = [self.encoded_reading(i) for i in range(proof_mod.MAX_OBSERVATIONS + 1)]
        self.refused(MALFORMED, proof_mod.observation_digests, *too_many)

    def test_the_observation_array_is_empty_on_this_scope(self):
        """Nothing generates observations yet: the network-presence and spatial
        blocks are designed and unbuilt, and an empty array is the honest record
        of that rather than a placeholder value."""
        self.assertEqual(self.build().observations, ())
        self.assertEqual(self.build().describe()["observation_count"], 0)


class PrivacyTests(Case):
    def test_no_field_is_wide_enough_to_carry_a_biometric_template(self):
        """Structural, not a policy anyone has to remember: every byte string in
        the schema has an exact declared size, and the widest is 32."""
        for f in proof_mod.SCHEMA.fields:
            if f.kind == codec.BYTES:
                with self.subTest(field=f.name):
                    self.assertLessEqual(f.size, 32)
            self.assertNotEqual(f.kind, codec.TEXT, "a proof carries no free text")

    def test_a_proof_carries_no_permanent_student_identity(self):
        """Who this is comes from the device key, resolved against a table this
        module cannot see."""
        names = {f.name for f in proof_mod.SCHEMA.fields}
        for forbidden in ("student", "student_id", "email", "name", "roll_number"):
            with self.subTest(field=forbidden):
                self.assertNotIn(forbidden, names)

    def test_describing_a_proof_leaks_no_key_material(self):
        described = self.signed().proof.describe()
        serialised = repr(described)
        self.assertNotIn(self.key.seed_b64url(), serialised)
        self.assertNotIn(self.device_key.public_bytes.hex(), serialised)
        self.assertIn(self.device_key.key_id.hex(), serialised)

    def test_the_biometric_field_holds_an_outcome_and_nothing_else(self):
        field = proof_mod.SCHEMA.fields[proof_mod.SCHEMA.index("biometric")]
        self.assertEqual(field.kind, codec.UINT)
        self.assertEqual(len(proof_mod.BIOMETRIC_NAMES), 4)
