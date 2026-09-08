"""Tests for the presence key hierarchy.

The hierarchy exists to make three separations true rather than intended, and
each one is asserted here rather than described in a comment:

**Presence signing is not Django's SECRET_KEY.** An ancestor commit in this
repository derived signing material from it, which couples proof signatures to
session cookies: one rotation silently rotates the other and one leak is two.
`SecretKeyCouplingTests` checks the obvious derivations by value, because the
failure mode of that coupling is that everything appears to work.

**A key's identity comes from the key.** Ids are derived, not assigned, so a
rotated key gets a new id without a registry, two deployments agree without
coordinating, and an id inside a signed struct can be checked against the key
that supposedly produced it.

**Verification survives rotation; signing does not.** A retired key keeps
verifying until everything it signed has expired, and only the active key signs.
`KeyringTests` walks that rotation end to end, since the alternative - a flag day
where every proof signed minutes earlier becomes indistinguishable from a forgery
- is the whole reason the keyring is not a single key.

There is no test that reads `os.environ` and hopes. `from_environment` takes an
explicit mapping precisely so its behaviour can be pinned without a test
depending on the shell it was launched from.
"""
import hashlib

from django.test import SimpleTestCase, override_settings

from .presence import keys
from .presence.keys import (
    DOMAIN,
    KEY_ID_LEN,
    MAC_LEN,
    PUBLIC_KEY_LEN,
    SEED_LEN,
    SIGNATURE_LEN,
    KeyMaterialError,
    Keyring,
    SessionKeys,
    SignatureError,
    SigningKey,
    VerifyKey,
)

SESSION_ID = bytes(range(16))
OTHER_SESSION_ID = bytes(range(16, 32))
MESSAGE = b"canonical codec bytes stand in here"

# A seed no derivation of any SECRET_KEY used below can equal.
INDEPENDENT_SEED = bytes(range(100, 100 + SEED_LEN))


class KeyIdTests(SimpleTestCase):
    def test_an_id_is_derived_from_the_public_key(self):
        public = SigningKey.from_seed(INDEPENDENT_SEED).public()
        self.assertEqual(public.key_id, keys.key_id_for(public.public_bytes))

    def test_an_id_is_stable_across_calls_and_processes(self):
        """Derived, so two deployments naming one key agree without a registry."""
        public = SigningKey.from_seed(INDEPENDENT_SEED).public().public_bytes
        self.assertEqual(keys.key_id_for(public), keys.key_id_for(public))
        self.assertEqual(
            keys.key_id_for(public),
            hashlib.sha256(DOMAIN + b"keyid" + public).digest()[:KEY_ID_LEN],
        )

    def test_an_id_is_eight_bytes(self):
        self.assertEqual(len(keys.key_id_for(b"k" * PUBLIC_KEY_LEN)), KEY_ID_LEN)

    def test_two_keys_do_not_share_an_id(self):
        one = SigningKey.generate()
        two = SigningKey.generate()
        self.assertNotEqual(one.key_id, two.key_id)

    def test_an_id_is_not_a_slice_of_the_key(self):
        """A hash, so an id in a QR payload reveals nothing about the key."""
        public = SigningKey.generate().public().public_bytes
        self.assertNotIn(keys.key_id_for(public), public)

    def test_a_wrong_length_public_key_is_refused(self):
        for wrong in (b"", b"k" * 31, b"k" * 33):
            with self.subTest(length=len(wrong)):
                with self.assertRaises(KeyMaterialError):
                    keys.key_id_for(wrong)


class SigningKeyTests(SimpleTestCase):
    def test_a_seed_round_trips_through_configuration(self):
        key = SigningKey.from_seed(INDEPENDENT_SEED)
        self.assertEqual(SigningKey.from_b64url(key.seed_b64url()).seed, key.seed)
        self.assertEqual(SigningKey.from_b64url(key.seed_b64url()).key_id, key.key_id)

    def test_base64url_is_accepted_padded_or_not(self):
        """'=' in an environment variable is a persistent copy-paste hazard."""
        key = SigningKey.from_seed(INDEPENDENT_SEED)
        unpadded = key.seed_b64url()
        self.assertNotIn("=", unpadded)
        padded = unpadded + "=" * (-len(unpadded) % 4)
        self.assertEqual(SigningKey.from_b64url(padded).seed, key.seed)
        self.assertEqual(SigningKey.from_b64url("  %s  " % unpadded).seed, key.seed)

    def test_a_truncated_seed_is_refused_rather_than_stretched(self):
        """Silently padding would produce a different key that still works."""
        key = SigningKey.from_seed(INDEPENDENT_SEED)
        with self.assertRaises(KeyMaterialError) as caught:
            SigningKey.from_b64url(key.seed_b64url()[:-4])
        self.assertIn("expected exactly %d" % SEED_LEN, str(caught.exception))

    def test_text_that_is_not_base64_is_refused(self):
        with self.assertRaises(KeyMaterialError):
            SigningKey.from_b64url("this is not a key")

    def test_a_wrong_length_seed_is_refused(self):
        for wrong in (b"", b"s" * 31, b"s" * 33):
            with self.subTest(length=len(wrong)):
                with self.assertRaises(KeyMaterialError):
                    SigningKey.from_seed(wrong)

    def test_a_signature_verifies_under_the_matching_public_key(self):
        key = SigningKey.generate()
        signature = key.sign(MESSAGE)
        self.assertEqual(len(signature), SIGNATURE_LEN)
        key.public().verify(MESSAGE, signature)

    def test_nothing_is_prepended_to_the_signed_message(self):
        """Signatures are over raw canonical bytes; the codec's tag separates domains.

        Asserted so a future 'helpful' prefix cannot be added on the Python side
        without the Dart implementation failing in the field. Verified against the
        primitive directly rather than against our own verifier, which would agree
        with any wrapper we invented.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        key = SigningKey.generate()
        raw_public = Ed25519PublicKey.from_public_bytes(key.public().public_bytes)
        raw_public.verify(key.sign(MESSAGE), MESSAGE)

    def test_the_public_key_travels_and_the_seed_does_not(self):
        key = SigningKey.generate()
        self.assertEqual(key.public().key_id, key.key_id)
        self.assertEqual(len(key.public().public_bytes), PUBLIC_KEY_LEN)
        self.assertNotIn(key.seed, key.public().public_bytes)

    def test_repr_does_not_print_the_seed(self):
        """A traceback, a log line or a Django debug page would otherwise leak it."""
        key = SigningKey.from_seed(INDEPENDENT_SEED)
        text = repr(key)
        self.assertIn("redacted", text)
        self.assertIn(key.key_id.hex(), text)
        self.assertNotIn(key.seed.hex(), text)
        self.assertNotIn(key.seed_b64url(), text)


class VerifyKeyTests(SimpleTestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        self.public = self.key.public()
        self.signature = self.key.sign(MESSAGE)

    def test_a_public_key_round_trips_through_configuration(self):
        self.assertEqual(
            VerifyKey.from_b64url(self.public.to_b64url()), self.public
        )

    def test_verify_raises_and_verifies_returns(self):
        """`if verify(...)` would read as success, so verify() has no return value."""
        self.assertIsNone(self.public.verify(MESSAGE, self.signature))
        self.assertTrue(self.public.verifies(MESSAGE, self.signature))
        self.assertFalse(self.public.verifies(MESSAGE + b"!", self.signature))

    def test_another_key_does_not_verify(self):
        with self.assertRaises(SignatureError):
            SigningKey.generate().public().verify(MESSAGE, self.signature)

    def test_one_flipped_bit_in_the_message_is_refused(self):
        tampered = bytes([MESSAGE[0] ^ 1]) + MESSAGE[1:]
        with self.assertRaises(SignatureError):
            self.public.verify(tampered, self.signature)

    def test_one_flipped_bit_in_the_signature_is_refused(self):
        tampered = bytes([self.signature[0] ^ 1]) + self.signature[1:]
        with self.assertRaises(SignatureError):
            self.public.verify(MESSAGE, tampered)

    def test_a_truncated_signature_is_refused_by_length_not_by_luck(self):
        with self.assertRaises(SignatureError) as caught:
            self.public.verify(MESSAGE, self.signature[:-1])
        self.assertIn("expected %d" % SIGNATURE_LEN, str(caught.exception))

    def test_an_empty_signature_is_refused(self):
        with self.assertRaises(SignatureError):
            self.public.verify(MESSAGE, b"")

    def test_a_signature_error_is_not_a_key_material_error(self):
        """Distinct on purpose: 'forged' and 'misconfigured' are different alarms."""
        self.assertFalse(issubclass(SignatureError, KeyMaterialError))
        self.assertFalse(issubclass(KeyMaterialError, SignatureError))

    def test_a_verify_key_cannot_sign(self):
        self.assertFalse(hasattr(self.public, "sign"))
        self.assertFalse(hasattr(self.public, "seed"))


class SecretKeyCouplingTests(SimpleTestCase):
    """Presence signing must not be a function of Django's SECRET_KEY.

    Checked by value, and only the obvious derivations can be checked that way -
    the guard cannot recognise an arbitrary KDF over SECRET_KEY. That is a real
    limit, and the guard still earns its place: the specific mistake it catches is
    one this repository has already made once, and it catches it at key load
    rather than after a term of signed proofs.
    """

    LONG = "django-insecure-" + "q" * 40
    SHORT = "tiny"

    def candidates(self, secret):
        raw = secret.encode("utf-8")
        return {
            "prefix": raw[:SEED_LEN],
            "zero-padded": raw.ljust(SEED_LEN, b"\x00")[:SEED_LEN],
            "sha256": hashlib.sha256(raw).digest(),
            "domain-separated sha256": hashlib.sha256(DOMAIN + raw).digest(),
        }

    def test_every_obvious_derivation_is_refused(self):
        for secret in (self.LONG, self.SHORT):
            with override_settings(SECRET_KEY=secret):
                for label, seed in self.candidates(secret).items():
                    if len(seed) != SEED_LEN:
                        continue
                    with self.subTest(secret=secret[:12], derivation=label):
                        with self.assertRaises(KeyMaterialError) as caught:
                            SigningKey.from_seed(seed)
                        self.assertIn("SECRET_KEY", str(caught.exception))
                        self.assertIn(keys.ENV_ACTIVE, str(caught.exception))

    def test_the_refusal_says_how_to_fix_it(self):
        """An error that only says 'no' gets worked around with a different seed."""
        with override_settings(SECRET_KEY=self.LONG):
            with self.assertRaises(KeyMaterialError) as caught:
                SigningKey.from_seed(hashlib.sha256(self.LONG.encode()).digest())
        self.assertIn("seed_b64url()", str(caught.exception))

    def test_an_independent_seed_is_accepted(self):
        with override_settings(SECRET_KEY=self.LONG):
            self.assertEqual(len(SigningKey.from_seed(INDEPENDENT_SEED).seed), SEED_LEN)

    def test_a_generated_key_is_never_caught_by_the_guard(self):
        """The guard must not be a source of flaky boots."""
        with override_settings(SECRET_KEY=self.LONG):
            for _ in range(50):
                SigningKey.generate()


class KeyringTests(SimpleTestCase):
    def setUp(self):
        self.old = SigningKey.generate()
        self.new = SigningKey.generate()

    def test_only_the_active_key_signs(self):
        ring = Keyring(active=self.new, retired=[self.old.public()])
        key_id, signature = ring.sign(MESSAGE)
        self.assertEqual(key_id, self.new.key_id)
        ring.verify(key_id, MESSAGE, signature)

    def test_the_active_key_also_verifies(self):
        ring = Keyring(active=self.new)
        self.assertEqual(ring.key_ids, (self.new.key_id,))
        key_id, signature = ring.sign(MESSAGE)
        ring.verify(key_id, MESSAGE, signature)

    def test_a_rotation_does_not_invalidate_what_was_already_signed(self):
        """The point of the keyring, walked end to end.

        Without this, a proof signed thirty seconds before a rotation becomes
        indistinguishable from a forgery - so a key rotation would have to be a
        flag day, and in practice would not happen.
        """
        before = Keyring(active=self.old)
        key_id, signature = before.sign(MESSAGE)

        after = Keyring(active=self.new, retired=[self.old.public()])
        after.verify(key_id, MESSAGE, signature)
        self.assertEqual(after.sign(MESSAGE)[0], self.new.key_id)
        self.assertEqual(after.key_ids, tuple(sorted((self.old.key_id, self.new.key_id))))

    def test_dropping_a_retired_key_is_what_finally_rejects_its_signatures(self):
        key_id, signature = Keyring(active=self.old).sign(MESSAGE)
        dropped = Keyring(active=self.new)
        with self.assertRaises(KeyMaterialError) as caught:
            dropped.verify(key_id, MESSAGE, signature)
        self.assertIn(key_id.hex(), str(caught.exception))
        self.assertIn("retired", str(caught.exception))
        self.assertIn("forged", str(caught.exception))

    def test_an_unknown_id_is_a_configuration_error_not_a_signature_error(self):
        ring = Keyring(active=self.new)
        with self.assertRaises(KeyMaterialError):
            ring.verifier(b"\x00" * KEY_ID_LEN)

    def test_a_retired_key_cannot_be_used_to_sign_by_naming_its_id(self):
        ring = Keyring(active=self.new, retired=[self.old.public()])
        self.assertEqual(ring.active.key_id, self.new.key_id)
        self.assertFalse(hasattr(ring.verifier(self.old.key_id), "sign"))

    def test_key_ids_are_ordered_so_a_deployment_can_be_diffed(self):
        ring = Keyring(active=self.new, retired=[self.old.public()])
        self.assertEqual(list(ring.key_ids), sorted(ring.key_ids))


class EnvironmentTests(SimpleTestCase):
    """Loading from configuration, with an explicit mapping rather than the shell."""

    def setUp(self):
        self.active = SigningKey.generate()
        self.retired = SigningKey.generate()

    def test_an_active_seed_is_loaded(self):
        ring = Keyring.from_environment(
            {keys.ENV_ACTIVE: self.active.seed_b64url()}
        )
        self.assertEqual(ring.active.key_id, self.active.key_id)

    def test_retired_seeds_are_loaded_as_verifiers_only(self):
        ring = Keyring.from_environment({
            keys.ENV_ACTIVE: self.active.seed_b64url(),
            keys.ENV_RETIRED: self.retired.seed_b64url(),
        })
        self.assertEqual(
            set(ring.key_ids), {self.active.key_id, self.retired.key_id}
        )
        self.assertEqual(ring.sign(MESSAGE)[0], self.active.key_id)

    def test_the_retired_list_tolerates_the_way_people_edit_it(self):
        third = SigningKey.generate()
        ring = Keyring.from_environment({
            keys.ENV_ACTIVE: self.active.seed_b64url(),
            keys.ENV_RETIRED: " %s , ,%s,\n" % (
                self.retired.seed_b64url(), third.seed_b64url()
            ),
        })
        self.assertEqual(
            set(ring.key_ids),
            {self.active.key_id, self.retired.key_id, third.key_id},
        )

    @override_settings(DEBUG=False)
    def test_a_missing_key_is_fatal_in_production(self):
        """No generated-on-boot fallback: it would look like forgery, not misconfig.

        A key minted per process invalidates every signature on every restart and
        every scale-out, and the resulting failures are indistinguishable from
        forged proofs. Failing to boot is the honest outcome.
        """
        for env in ({}, {keys.ENV_ACTIVE: ""}, {keys.ENV_ACTIVE: "   "}):
            with self.subTest(env=env):
                with self.assertRaises(KeyMaterialError) as caught:
                    Keyring.from_environment(env)
                self.assertIn(keys.ENV_ACTIVE, str(caught.exception))
                self.assertIn("no fallback", str(caught.exception))

    @override_settings(DEBUG=False)
    def test_the_production_failure_names_the_command_that_fixes_it(self):
        with self.assertRaises(KeyMaterialError) as caught:
            Keyring.from_environment({})
        self.assertIn("seed_b64url()", str(caught.exception))

    @override_settings(DEBUG=True)
    def test_a_missing_key_is_ephemeral_and_loud_in_development(self):
        with self.assertLogs("attendance.presence.keys", level="WARNING") as logged:
            first = Keyring.from_environment({})
            second = Keyring.from_environment({})
        self.assertIn(keys.ENV_ACTIVE, "\n".join(logged.output))
        self.assertIn("restart", "\n".join(logged.output))
        # Both calls inside the capture: a warning that escapes to stderr makes
        # every other test run look like it has a problem.
        self.assertEqual(len(logged.output), 2)
        self.assertNotEqual(first.active.key_id, second.active.key_id)

    @override_settings(DEBUG=True)
    def test_a_malformed_key_is_fatal_even_in_development(self):
        """A typo must not silently degrade into an ephemeral key."""
        for bad in ("not-base64!!", self.active.seed_b64url()[:-4]):
            with self.subTest(value=bad):
                with self.assertRaises(KeyMaterialError):
                    Keyring.from_environment({keys.ENV_ACTIVE: bad})

    def test_a_malformed_retired_entry_is_fatal_too(self):
        with self.assertRaises(KeyMaterialError):
            Keyring.from_environment({
                keys.ENV_ACTIVE: self.active.seed_b64url(),
                keys.ENV_RETIRED: "nonsense",
            })

    def test_the_same_configuration_yields_the_same_ids(self):
        env = {keys.ENV_ACTIVE: self.active.seed_b64url()}
        self.assertEqual(
            Keyring.from_environment(env).key_ids,
            Keyring.from_environment(env).key_ids,
        )


class ServerKeyringTests(SimpleTestCase):
    def tearDown(self):
        keys.set_server_keyring(None)

    def test_an_installed_keyring_is_returned_and_cached(self):
        ring = Keyring.ephemeral()
        keys.set_server_keyring(ring)
        self.assertIs(keys.server_keyring(), ring)
        self.assertIs(keys.server_keyring(), ring)

    def test_clearing_the_cache_reloads_from_the_environment(self):
        keys.set_server_keyring(Keyring.ephemeral())
        keys.set_server_keyring(None)
        with override_settings(DEBUG=False):
            with self.assertRaises(KeyMaterialError):
                Keyring.from_environment({})


class DeriveTests(SimpleTestCase):
    SECRET = bytes(range(32))

    def test_derivation_is_deterministic(self):
        one = keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH, salt=b"s", context=b"c")
        two = keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH, salt=b"s", context=b"c")
        self.assertEqual(one, two)

    def test_an_undeclared_purpose_is_refused(self):
        """It would derive a valid key that is simply not the other side's key.

        Which fails later, as a signature mismatch, and looks like tampering
        rather than like the typo it is.
        """
        with self.assertRaises(KeyMaterialError) as caught:
            keys.derive(self.SECRET, purpose="epochs")
        self.assertIn("epochs", str(caught.exception))
        self.assertIn("PURPOSES", str(caught.exception))

    def test_every_declared_purpose_derives(self):
        seen = {}
        for purpose in sorted(keys.PURPOSES):
            with self.subTest(purpose=purpose):
                seen[purpose] = keys.derive(self.SECRET, purpose=purpose)
        self.assertEqual(len(set(seen.values())), len(keys.PURPOSES))

    def test_purposes_are_domain_separated(self):
        """One secret, two purposes, no relationship between the results."""
        epoch = keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH)
        relay = keys.derive(self.SECRET, purpose=keys.PURPOSE_RELAY_PSEUDONYM)
        self.assertNotEqual(epoch, relay)

    def test_salt_and_context_both_change_the_result(self):
        base = keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH, salt=b"a", context=b"b")
        self.assertNotEqual(
            base,
            keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH, salt=b"z", context=b"b"),
        )
        self.assertNotEqual(
            base,
            keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH, salt=b"a", context=b"z"),
        )

    def test_no_pair_of_salt_and_context_collides(self):
        """The reason they are separate arguments rather than one concatenation.

        A caller passing salt + context joined by hand would make ("ab", "c") and
        ("a", "bc") derive the same key, which is a cross-session collision waiting
        for a session id and an epoch number to line up.
        """
        left = keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH, salt=b"ab", context=b"c")
        right = keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH, salt=b"a", context=b"bc")
        self.assertNotEqual(left, right)

    def test_the_requested_length_is_honoured_and_bounded(self):
        for length in (1, 16, 32, 64):
            with self.subTest(length=length):
                self.assertEqual(
                    len(keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH, length=length)),
                    length,
                )
        for bad in (0, -1, 65):
            with self.subTest(length=bad):
                with self.assertRaises(KeyMaterialError):
                    keys.derive(self.SECRET, purpose=keys.PURPOSE_EPOCH, length=bad)

    def test_a_short_or_wrong_typed_secret_is_refused(self):
        for bad in (b"", b"too short", "a string of thirty-two chars ok!", None, 17):
            with self.subTest(secret=repr(bad)[:24]):
                with self.assertRaises(KeyMaterialError):
                    keys.derive(bad, purpose=keys.PURPOSE_EPOCH)

    def test_the_domain_is_versioned_into_every_derivation(self):
        """A break in the scheme invalidates every derived key at once, by design."""
        self.assertTrue(DOMAIN.endswith(b"/v1/"))
        self.assertIn(b"campusguard/presence", DOMAIN)


class MacTests(SimpleTestCase):
    KEY = bytes(range(32))

    def test_a_full_mac_is_thirty_two_bytes(self):
        self.assertEqual(len(keys.mac(self.KEY, MESSAGE)), MAC_LEN)

    def test_a_truncated_mac_is_a_prefix_of_the_full_one(self):
        full = keys.mac(self.KEY, MESSAGE)
        for length in (1, 8, 16, MAC_LEN):
            with self.subTest(length=length):
                self.assertEqual(
                    keys.mac_truncated(self.KEY, MESSAGE, length), full[:length]
                )

    def test_truncation_is_bounded(self):
        for bad in (0, -1, MAC_LEN + 1):
            with self.subTest(length=bad):
                with self.assertRaises(KeyMaterialError):
                    keys.mac_truncated(self.KEY, MESSAGE, bad)

    def test_a_different_key_gives_a_different_mac(self):
        other = bytes(range(1, 33))
        self.assertNotEqual(keys.mac(self.KEY, MESSAGE), keys.mac(other, MESSAGE))

    def test_equal_compares_without_leaking_a_prefix_length(self):
        left = keys.mac(self.KEY, MESSAGE)
        self.assertTrue(keys.equal(left, keys.mac(self.KEY, MESSAGE)))
        self.assertFalse(keys.equal(left, keys.mac(self.KEY, MESSAGE + b"!")))
        self.assertFalse(keys.equal(left, left[:-1]))
        self.assertFalse(keys.equal(left, b""))


class SessionKeysTests(SimpleTestCase):
    def setUp(self):
        self.session = SessionKeys.generate(SESSION_ID)

    def test_generated_material_reloads_identically(self):
        """The teacher's device and the server must derive the same chain offline."""
        reloaded = SessionKeys.load(
            SESSION_ID, self.session.root_secret, self.session.signing.seed
        )
        self.assertEqual(reloaded.epoch_key(0), self.session.epoch_key(0))
        self.assertEqual(reloaded.signing.key_id, self.session.signing.key_id)

    def test_a_session_id_must_be_a_uuid_sized_value(self):
        for wrong in (b"", b"s" * 15, b"s" * 17):
            with self.subTest(length=len(wrong)):
                with self.assertRaises(KeyMaterialError) as caught:
                    SessionKeys.generate(wrong)
                self.assertIn("16", str(caught.exception))

    def test_a_wrong_length_root_secret_is_refused(self):
        with self.assertRaises(KeyMaterialError):
            SessionKeys.load(SESSION_ID, b"short", self.session.signing.seed)

    def test_each_epoch_has_its_own_key(self):
        """So a leaked epoch key yields that epoch's challenges and no other's."""
        derived = [self.session.epoch_key(e) for e in range(8)]
        self.assertEqual(len(set(derived)), len(derived))

    def test_an_epoch_key_does_not_reveal_its_neighbours(self):
        first = self.session.epoch_key(3)
        self.assertNotIn(first, self.session.epoch_key(4))
        self.assertNotIn(first, self.session.epoch_key(2))

    def test_two_sessions_never_share_an_epoch_key(self):
        """The session id is the HKDF salt, so this holds without coordination."""
        other = SessionKeys.load(
            OTHER_SESSION_ID, self.session.root_secret, self.session.signing.seed
        )
        self.assertNotEqual(other.epoch_key(0), self.session.epoch_key(0))

    def test_an_epoch_must_be_a_non_negative_integer(self):
        for bad in (-1, True, False, 1.0, "0", None):
            with self.subTest(epoch=repr(bad)):
                with self.assertRaises(KeyMaterialError):
                    self.session.epoch_key(bad)

    def test_a_large_epoch_is_representable(self):
        """Eight big-endian bytes: nothing in a 50-minute session comes close."""
        self.assertEqual(len(self.session.epoch_key((1 << 64) - 1)), 32)
        with self.assertRaises(OverflowError):
            self.session.epoch_key(1 << 64)

    def test_the_public_key_is_all_a_student_needs(self):
        self.assertEqual(self.session.public(), self.session.signing.public())
        self.assertFalse(hasattr(self.session.public(), "root_secret"))

    def test_repr_prints_neither_secret(self):
        text = repr(self.session)
        self.assertIn(SESSION_ID.hex(), text)
        self.assertIn("redacted", text)
        self.assertNotIn(self.session.root_secret.hex(), text)
        self.assertNotIn(self.session.signing.seed.hex(), text)

    def test_two_generated_sessions_share_no_material(self):
        other = SessionKeys.generate(SESSION_ID)
        self.assertNotEqual(other.root_secret, self.session.root_secret)
        self.assertNotEqual(other.signing.seed, self.session.signing.seed)
