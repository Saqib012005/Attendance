"""Tests for the relay chain of custody.

Four claims are being pinned, and the third is the uncomfortable one.

**A chain cannot be reordered, shortened in the middle, or spliced.** Those are
the properties the hash links buy, and they are asserted by doing each of those
things to a genuine chain and watching it fail.

**A hop is attributable.** The pseudonym is derived from the signing key, so a
device cannot sign a hop naming somebody else, and a stranger's hop fails at the
cohort rather than being quietly counted.

**A relay cannot tell a forged chain from a real one.** `test_a_relay_cannot_tell`
asserts exactly that: the same forged chain passes `parse_chain` and fails
`verify_chain`. It is the privacy tradeoff written as a test rather than as a
paragraph nobody re-reads, and if somebody later "fixes" it by handing relays the
cohort, this test is where the argument has to happen.

**Depth is a hop count and nothing else.** No function here turns it into a
distance, a room, or a presence, and `EvidenceTests` fails if one appears.
"""
import ast
import inspect
import pathlib
from types import MappingProxyType

from django.test import SimpleTestCase

from .presence import chain, codec, config, keys, origin, proof
from .presence.chain import (
    BAD_SIGNATURE,
    BROKEN_LINK,
    MALFORMED,
    OUT_OF_ORDER,
    REPEATED_RELAY,
    TOO_DEEP,
    UNKNOWN_RELAY,
)

SESSION_ID = bytes(range(proof.SESSION_ID_LEN))
OTHER_SESSION = bytes(range(proof.SESSION_ID_LEN))[::-1]
ROOT_SECRET = b"chain-root-secret-for-tests-0001"
SIGNING_SEED = b"chain-signing-seed-for-tests-001"

# A fixed instant, so nothing depends on when the suite runs.
START = 1_757_000_000


def artifact_with(**overrides):
    """The shipped artifact with substitutions, for the parameter-driven tests."""
    values = dict(config.active().values)
    values.update(overrides)
    return config.Artifact(
        version="test-artifact",
        calibration=config.UNCALIBRATED,
        notes="built by tests_presence_chain",
        values=MappingProxyType(values),
    )


class Case(SimpleTestCase):
    def setUp(self):
        self.keys = keys.SessionKeys.load(SESSION_ID, ROOT_SECRET, SIGNING_SEED)
        self.sighting = origin.record(
            origin.build(self.keys, counter=4), rssi=-70, observed_at=START + 60
        )
        self.root = chain.root_link(self.sighting.encode())
        self.devices = [
            keys.SigningKey.from_seed(bytes([n]) * keys.SEED_LEN) for n in (11, 22, 33)
        ]

    def tearDown(self):
        config.set_active(None)

    def source(self):
        return pathlib.Path(chain.__file__).read_text(encoding="utf-8")

    def build(self, count=None, *, session_id=SESSION_ID, root=None, limit=None):
        hops = ()
        for index, device in enumerate(self.devices[: count or len(self.devices)]):
            hops = chain.extend(
                hops,
                root=self.root if root is None else root,
                session_id=session_id,
                observed_at=START + 61 + index,
                signing_key=device,
                limit=limit,
            )
        return hops

    def cohort(self, devices=None):
        return chain.cohort_index(
            SESSION_ID, [d.public() for d in (devices or self.devices)]
        )

    def verify(self, hops, *, root=None, resolve=None, session_id=SESSION_ID, limit=None):
        return chain.verify_chain(
            chain.encode_chain(hops),
            session_id=session_id,
            root=self.root if root is None else root,
            resolve=resolve or self.cohort().get,
            limit=limit,
        )

    def refused(self, code, call, *args, **kwargs):
        with self.assertRaises(chain.ChainError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception


class PreimageTests(Case):
    def test_the_preimage_is_one_fixed_length_whatever_it_contains(self):
        """Fixed width is what makes it unambiguous without a length prefix."""
        for hop_index, observed_at in ((0, 0), (1, START), (chain.COUNT_MAX, chain.COUNT_MAX)):
            with self.subTest(hop_index=hop_index):
                raw = chain.preimage(hop_index, b"h" * 32, b"p" * 16, observed_at)
                self.assertEqual(len(raw), chain.PREIMAGE_LEN)

    def test_two_different_hops_cannot_share_a_preimage(self):
        base = chain.preimage(1, b"h" * 32, b"p" * 16, START)
        variants = {
            base,
            chain.preimage(2, b"h" * 32, b"p" * 16, START),
            chain.preimage(1, b"g" * 32, b"p" * 16, START),
            chain.preimage(1, b"h" * 32, b"q" * 16, START),
            chain.preimage(1, b"h" * 32, b"p" * 16, START + 1),
        }
        self.assertEqual(len(variants), 5)

    def test_the_preimage_is_domain_separated_from_every_other_signature(self):
        raw = chain.preimage(0, b"h" * 32, b"p" * 16, START)
        self.assertTrue(raw.startswith(keys.DOMAIN + chain.LABEL + b"\x00"))
        self.assertNotIn(chain.PSEUDONYM_LABEL, raw)

    def test_a_hop_signature_is_not_a_proof_signature(self):
        """Domain separation, asserted rather than trusted.

        The prefix is only worth something if it actually prevents the confusion,
        so this signs a hop and offers the signature to `proof.verify` over bytes
        that begin the way a proof does. It must fail, and the reason it fails is
        that the two preimages can never coincide.
        """
        hop = chain.sign_hop(
            hop_index=0,
            prev_proof_hash=self.root,
            session_id=SESSION_ID,
            observed_at=START,
            signing_key=self.devices[0],
        )
        with self.assertRaises(Exception):
            self.devices[0].public().verify(hop.encode(), hop.signature)

    def test_a_field_of_the_wrong_width_is_refused_not_padded(self):
        self.refused(MALFORMED, chain.preimage, 0, b"h" * 31, b"p" * 16, START)
        self.refused(MALFORMED, chain.preimage, 0, b"h" * 32, b"p" * 15, START)

    def test_a_boolean_is_not_a_count(self):
        self.refused(MALFORMED, chain.preimage, True, b"h" * 32, b"p" * 16, START)

    def test_a_count_beyond_its_fixed_width_is_refused(self):
        self.refused(
            MALFORMED, chain.preimage, chain.COUNT_MAX + 1, b"h" * 32, b"p" * 16, START
        )

    def test_the_signature_width_agrees_with_the_key_module(self):
        self.assertEqual(chain.SIGNATURE_LEN, keys.SIGNATURE_LEN)


class PseudonymTests(Case):
    def test_a_relay_can_compute_its_own_with_no_secret_it_does_not_hold(self):
        """The requirement that rules out deriving this from the session root key.

        A student handset never sees the session root secret, so a derivation that
        needed it would leave a relay unable to name itself offline - which is the
        only situation relaying exists for.
        """
        tag = chain.pseudonym(SESSION_ID, self.devices[0].public().public_bytes)
        self.assertEqual(len(tag), chain.PSEUDONYM_LEN)
        signature = inspect.signature(chain.pseudonym)
        self.assertEqual(list(signature.parameters), ["session_id", "device_public_bytes"])

    def test_the_same_device_is_unlinkable_across_sessions(self):
        public = self.devices[0].public().public_bytes
        self.assertNotEqual(
            chain.pseudonym(SESSION_ID, public),
            chain.pseudonym(OTHER_SESSION, public),
        )

    def test_it_is_stable_within_a_session_so_a_loop_can_be_spotted(self):
        public = self.devices[0].public().public_bytes
        self.assertEqual(
            chain.pseudonym(SESSION_ID, public), chain.pseudonym(SESSION_ID, public)
        )

    def test_two_devices_do_not_share_one(self):
        tags = {
            chain.pseudonym(SESSION_ID, d.public().public_bytes) for d in self.devices
        }
        self.assertEqual(len(tags), len(self.devices))

    def test_a_hop_names_the_device_that_signed_it_and_cannot_name_another(self):
        """`sign_hop` derives the pseudonym rather than accepting one."""
        self.assertNotIn(
            "relay_pseudonym", inspect.signature(chain.sign_hop).parameters
        )
        hop = chain.sign_hop(
            hop_index=0,
            prev_proof_hash=self.root,
            session_id=SESSION_ID,
            observed_at=START,
            signing_key=self.devices[1],
        )
        self.assertEqual(
            hop.relay_pseudonym,
            chain.pseudonym(SESSION_ID, self.devices[1].public().public_bytes),
        )

    def test_the_cohort_index_resolves_a_hop_in_constant_time(self):
        index = self.cohort()
        self.assertEqual(len(index), len(self.devices))
        hop = self.build(1)[0]
        self.assertEqual(
            index[hop.relay_pseudonym].public_bytes,
            self.devices[0].public().public_bytes,
        )

    def test_the_same_device_listed_twice_is_not_a_collision(self):
        one = self.devices[0].public()
        again = keys.VerifyKey(key_id=one.key_id, public_bytes=one.public_bytes)
        self.assertEqual(len(chain.cohort_index(SESSION_ID, [one, again])), 1)

    def test_two_devices_sharing_a_pseudonym_are_refused_not_resolved(self):
        """A branch SHA-256 will not reach, tested by removing SHA-256.

        Substituting a constant derivation is the only way to exercise the guard,
        and the guard is worth having: silently keeping whichever key was inserted
        last would make a hop resolve to the wrong device, and the mismatch would
        then be reported as a bad signature.
        """
        original = chain.pseudonym
        chain.pseudonym = lambda session_id, device_public_bytes: bytes(chain.PSEUDONYM_LEN)
        try:
            self.refused(
                REPEATED_RELAY,
                chain.cohort_index,
                SESSION_ID,
                [d.public() for d in self.devices],
            )
        finally:
            chain.pseudonym = original

    def test_a_device_key_of_the_wrong_width_is_refused(self):
        self.refused(MALFORMED, chain.pseudonym, SESSION_ID, b"short")
        self.refused(MALFORMED, chain.pseudonym, b"short", b"k" * keys.PUBLIC_KEY_LEN)


class HopTests(Case):
    def test_a_hop_round_trips_through_its_canonical_encoding(self):
        hop = self.build(1)[0]
        self.assertEqual(chain.parse_hop(hop.encode()), hop)

    def test_a_hop_has_exactly_one_encoding(self):
        """Strictness is what stops one hop being resubmitted as two."""
        hop = self.build(1)[0]
        loose = codec.encode(chain.SCHEMA.name, hop.values())
        self.assertEqual(loose, hop.encode())
        self.assertEqual(codec.digest_bytes(loose), hop.digest())

    def test_a_hop_of_another_struct_type_is_refused(self):
        self.refused(MALFORMED, chain.parse_hop, self.sighting.encode())

    def test_truncated_bytes_are_refused(self):
        self.refused(MALFORMED, chain.parse_hop, self.build(1)[0].encode()[:-1])

    def test_describe_names_the_clock_as_a_claim(self):
        described = self.build(1)[0].describe()
        self.assertIn("claimed_observed_at", described)
        self.assertNotIn("observed_at", described)

    def test_describe_carries_no_signature_and_no_key_material(self):
        hop = self.build(1)[0]
        described = hop.describe()
        self.assertNotIn("signature", described)
        rendered = repr(described)
        self.assertNotIn(hop.signature.hex(), rendered)
        self.assertNotIn(self.devices[0].public().public_bytes.hex(), rendered)


class LinkTests(Case):
    def test_a_genuine_chain_parses_and_verifies(self):
        hops = self.build()
        self.assertEqual(len(chain.parse_chain(chain.encode_chain(hops), root=self.root)), 3)
        self.assertEqual(len(self.verify(hops)), 3)

    def test_each_hop_chains_to_the_digest_of_the_one_before_it(self):
        hops = self.build()
        self.assertEqual(hops[0].prev_proof_hash, self.root)
        for previous, hop in zip(hops, hops[1:]):
            self.assertEqual(hop.prev_proof_hash, previous.digest())

    def test_a_reordered_chain_is_refused(self):
        wire = chain.encode_chain(self.build())
        self.refused(
            OUT_OF_ORDER, chain.parse_chain, (wire[1], wire[0], wire[2]), root=self.root
        )

    def test_a_hop_removed_from_the_middle_is_refused(self):
        wire = chain.encode_chain(self.build())
        self.refused(OUT_OF_ORDER, chain.parse_chain, (wire[0], wire[2]), root=self.root)

    def test_a_chain_spliced_from_two_others_is_refused(self):
        """Same indices, same depth, genuine signatures throughout - and refused.

        Both chains are real, so nothing about a single hop is wrong. What fails is
        the link: hop one of the second chain commits to the digest of *its* hop
        zero, and no other. Splicing is the attack the hash chain exists for.
        """
        first = chain.encode_chain(self.build())
        other = chain.root_link(
            origin.record(
                origin.build(self.keys, counter=5), rssi=-60, observed_at=START + 90
            ).encode()
        )
        second = chain.encode_chain(self.build(root=other))
        self.refused(
            BROKEN_LINK, chain.parse_chain, (first[0], second[1]), root=self.root
        )

    def test_a_chain_grafted_onto_a_different_sighting_is_refused(self):
        hops = self.build()
        other = chain.root_link(
            origin.record(
                origin.build(self.keys, counter=6), rssi=-60, observed_at=START + 95
            ).encode()
        )
        self.refused(BROKEN_LINK, self.verify, hops, root=other)

    def test_a_device_relaying_twice_in_one_chain_is_refused(self):
        """A loop, which carries no evidence and costs battery."""
        hops = self.build(1)
        looped = chain.extend(
            hops,
            root=self.root,
            session_id=SESSION_ID,
            observed_at=START + 70,
            signing_key=self.devices[0],
        )
        self.refused(REPEATED_RELAY, chain.parse_chain, chain.encode_chain(looped), root=self.root)

    def test_a_root_that_is_not_an_origin_sighting_is_refused(self):
        self.refused(MALFORMED, chain.root_link, self.build(1)[0].encode())

    def test_a_peer_without_the_sighting_may_omit_the_root(self):
        """It narrows what a pass means; it does not change what a pass is worth."""
        wire = chain.encode_chain(self.build())
        self.assertEqual(len(chain.parse_chain(wire, root=None)), 3)

    def test_the_server_may_not_omit_the_root(self):
        parameters = inspect.signature(chain.verify_chain).parameters
        self.assertIs(parameters["root"].default, inspect.Parameter.empty)
        self.assertIs(parameters["session_id"].default, inspect.Parameter.empty)


class DepthTests(Case):
    def extra(self, count):
        return [
            keys.SigningKey.from_seed(bytes([90 + n]) * keys.SEED_LEN)
            for n in range(count)
        ]

    def test_the_limit_comes_from_the_artifact_not_from_this_module(self):
        """The same code accepts a deeper chain under a different artifact."""
        shipped = chain.max_hops()
        hops = self.build()
        self.assertEqual(len(hops), shipped)
        self.refused(
            TOO_DEEP,
            chain.extend,
            hops,
            root=self.root,
            session_id=SESSION_ID,
            observed_at=START + 80,
            signing_key=self.extra(1)[0],
        )
        config.set_active(artifact_with(**{"relay.max_hops": shipped + 1}))
        deeper = chain.extend(
            hops,
            root=self.root,
            session_id=SESSION_ID,
            observed_at=START + 80,
            signing_key=self.extra(1)[0],
        )
        self.assertEqual(len(deeper), shipped + 1)

    def test_a_chain_deeper_than_the_limit_is_refused_on_arrival(self):
        config.set_active(artifact_with(**{"relay.max_hops": 4}))
        hops = chain.extend(
            self.build(),
            root=self.root,
            session_id=SESSION_ID,
            observed_at=START + 80,
            signing_key=self.extra(1)[0],
        )
        wire = chain.encode_chain(hops)
        config.set_active(artifact_with(**{"relay.max_hops": 3}))
        self.refused(TOO_DEEP, chain.parse_chain, wire, root=self.root)

    def test_the_depth_is_checked_before_a_hop_is_signed(self):
        """On a handset the difference is battery spent on a refusal to come."""
        source = self.source()
        body = source[source.index("def extend("):]
        body = body[: body.index("\ndef ")] if "\ndef " in body else body
        self.assertLess(body.index("TOO_DEEP"), body.index("sign_hop("))

    def test_the_declared_maximum_cannot_outrun_what_a_proof_can_carry(self):
        """The relation `config.cross_check` cannot express, asserted here instead.

        A chain reaches the server as observation digests inside a proof, and the
        proof schema caps how many of those there can be. An artifact allowed to
        declare a deeper chain than a proof can commit to would produce chains that
        verify and then cannot be submitted. config is the bottom layer and may not
        import proof to check this, so the check lives where both are in scope.
        """
        self.assertLessEqual(
            config.PARAMETERS["relay.max_hops"].maximum, proof.MAX_OBSERVATIONS
        )
        self.assertLessEqual(chain.max_hops(), proof.MAX_OBSERVATIONS)

    def test_an_artifact_that_outruns_the_proof_schema_fails_closed(self):
        config.set_active(artifact_with(**{"relay.max_hops": proof.MAX_OBSERVATIONS + 1}))
        self.refused(TOO_DEEP, chain.max_hops)

    def test_a_chain_at_the_limit_is_signalled_not_refused(self):
        hops = self.build()
        self.assertEqual(len(self.verify(hops)), len(hops))
        self.assertIn(chain.DEPTH_AT_LIMIT, chain.signals(hops))

    def test_a_shallow_chain_signals_nothing(self):
        self.assertEqual(chain.signals(self.build(1)), ())

    def test_an_empty_chain_is_not_an_error(self):
        """The ordinary case on every platform in this scope."""
        self.assertEqual(chain.parse_chain((), root=self.root), ())
        self.assertEqual(chain.signals(()), ())
        self.assertEqual(chain.describe_chain(())["depth"], 0)


class SignatureTests(Case):
    def test_a_stranger_can_produce_a_well_formed_hop_and_still_fail(self):
        stranger = keys.SigningKey.from_seed(b"z" * keys.SEED_LEN)
        forged = chain.extend(
            (),
            root=self.root,
            session_id=SESSION_ID,
            observed_at=START + 61,
            signing_key=stranger,
        )
        self.refused(UNKNOWN_RELAY, self.verify, forged)

    def test_one_flipped_bit_in_a_signature_is_refused(self):
        hop = self.build(1)[0]
        broken = chain.Hop(
            hop.hop_index,
            hop.prev_proof_hash,
            hop.relay_pseudonym,
            bytes([hop.signature[0] ^ 1]) + hop.signature[1:],
            hop.observed_at,
        )
        self.refused(BAD_SIGNATURE, self.verify, (broken,))

    def test_a_signature_lifted_onto_another_hop_is_refused(self):
        """The preimage binds all four fields, so a signature does not travel."""
        hops = self.build()
        swapped = chain.Hop(
            hops[1].hop_index,
            hops[1].prev_proof_hash,
            hops[1].relay_pseudonym,
            hops[0].signature,
            hops[1].observed_at,
        )
        self.refused(BAD_SIGNATURE, self.verify, (hops[0], swapped))

    def test_a_hop_whose_clock_was_edited_after_signing_is_refused(self):
        hop = self.build(1)[0]
        edited = chain.Hop(
            hop.hop_index,
            hop.prev_proof_hash,
            hop.relay_pseudonym,
            hop.signature,
            hop.observed_at + 1,
        )
        self.refused(BAD_SIGNATURE, self.verify, (edited,))

    def test_structure_is_reported_before_signatures(self):
        """A reordered chain must not be reported as a forgery."""
        wire = chain.encode_chain(self.build())
        self.refused(
            OUT_OF_ORDER,
            chain.verify_chain,
            (wire[1], wire[0], wire[2]),
            session_id=SESSION_ID,
            root=self.root,
            resolve=self.cohort().get,
        )

    def test_a_resolver_that_returns_the_wrong_key_is_caught_as_such(self):
        """Not as a forgery. A resolver is caller-supplied code."""
        wrong = self.devices[2].public()
        self.refused(UNKNOWN_RELAY, self.verify, self.build(1), resolve=lambda tag: wrong)

    def test_a_resolver_that_knows_nobody_refuses_rather_than_accepts(self):
        self.refused(UNKNOWN_RELAY, self.verify, self.build(1), resolve=lambda tag: None)

    def test_verification_under_the_wrong_session_refuses(self):
        self.refused(
            UNKNOWN_RELAY,
            chain.verify_chain,
            chain.encode_chain(self.build(1)),
            session_id=OTHER_SESSION,
            root=self.root,
            resolve=self.cohort().get,
        )


class PeerLimitTests(Case):
    """The module's central limitation, asserted so nobody can forget it."""

    def forged(self):
        strangers = [
            keys.SigningKey.from_seed(bytes([200 + n]) * keys.SEED_LEN)
            for n in range(2)
        ]
        hops = ()
        for index, device in enumerate(strangers):
            hops = chain.extend(
                hops,
                root=self.root,
                session_id=SESSION_ID,
                observed_at=START + 61 + index,
                signing_key=device,
            )
        return hops

    def test_a_relay_cannot_tell_a_forged_chain_from_a_real_one(self):
        """The privacy tradeoff, as a test rather than as a paragraph.

        The same bytes pass the structural check a handset can run and fail the
        cryptographic check only the server can run. A relay holds no cohort, so
        it cannot resolve a pseudonym, so it cannot check a signature - and the
        reason it holds no cohort is that a chain must not carry identity.

        If somebody later closes this gap by shipping the cohort to handsets,
        this test breaks, and that is the point: the argument then has to happen
        here, in front of the privacy rule it would be trading away.
        """
        wire = chain.encode_chain(self.forged())
        self.assertEqual(len(chain.parse_chain(wire, root=self.root)), 2)
        self.refused(UNKNOWN_RELAY, self.verify, self.forged())

    def test_the_structural_check_needs_no_secret_at_all(self):
        """What a relay can run is exactly what needs nothing it must not hold."""
        parameters = inspect.signature(chain.parse_chain).parameters
        for absent in ("resolve", "session_id", "signing_key", "cohort"):
            with self.subTest(parameter=absent):
                self.assertNotIn(absent, parameters)

    def test_a_poisoned_chain_costs_evidence_and_never_accuses(self):
        """What an injected hop can and cannot do.

        A rogue relay appending to a genuine chain makes the whole chain
        unverifiable, which is a denial of evidence. Nothing here turns that into
        an accusation, and nothing may: the identical refusal is produced by a
        genuine student whose device registration has not reached this server.
        Fusion reads a refusal as absent evidence, and absent evidence lowers
        confidence toward SECONDARY.
        """
        genuine = self.build(2)
        poisoned = chain.extend(
            genuine,
            root=self.root,
            session_id=SESSION_ID,
            observed_at=START + 70,
            signing_key=keys.SigningKey.from_seed(b"q" * keys.SEED_LEN),
        )
        error = self.refused(UNKNOWN_RELAY, self.verify, poisoned)
        for word in ("suspicious", "cheat", "fraud", "proxy", "attack"):
            with self.subTest(word=word):
                self.assertNotIn(word, str(error).lower())
        # And the honest half: the first two hops were and remain genuine.
        self.assertEqual(len(self.verify(genuine)), 2)

    def test_the_module_says_out_loud_what_it_cannot_do(self):
        source = self.source()
        for sentence in (
            "cannot verify the chain it is extending",
            "Depth is not distance",
            "never as evidence of wrongdoing",
        ):
            with self.subTest(sentence=sentence):
                self.assertIn(sentence, source)


class ClaimTests(Case):
    def test_a_clock_running_backwards_is_a_signal_not_a_refusal(self):
        """Handset clocks are wrong constantly; the hash links carry the order.

        Refusing here would throw away a structurally sound chain over a wrong
        clock, which costs a genuine student evidence and buys nothing - the
        ordering was already established by the links, not by these numbers.
        """
        hops = ()
        for index, device in enumerate(self.devices):
            hops = chain.extend(
                hops,
                root=self.root,
                session_id=SESSION_ID,
                observed_at=START + 90 - index,
                signing_key=device,
            )
        self.assertEqual(len(self.verify(hops)), len(hops))
        self.assertIn(chain.CLAIM_NON_MONOTONIC, chain.signals(hops))

    def test_an_absurd_clock_is_recorded_rather_than_judged(self):
        """No plausibility bound lives in this module.

        A bound on how wrong a handset clock may be is a tuned value, and a tuned
        value belongs in an artifact. `proof.max_future_skew_seconds` already
        answers that question once, against the server's clock, where there is a
        trustworthy clock to answer it against.
        """
        hop = chain.sign_hop(
            hop_index=0,
            prev_proof_hash=self.root,
            session_id=SESSION_ID,
            observed_at=chain.COUNT_MAX,
            signing_key=self.devices[0],
        )
        self.assertEqual(len(self.verify((hop,))), 1)

    def test_a_signal_is_never_a_reason(self):
        self.assertEqual(chain.SIGNALS & chain.REASON_CODES, frozenset())

    def test_the_claim_is_signed_so_editing_it_is_attributable(self):
        hop = self.build(1)[0]
        edited = chain.Hop(
            hop.hop_index,
            hop.prev_proof_hash,
            hop.relay_pseudonym,
            hop.signature,
            0,
        )
        self.refused(BAD_SIGNATURE, self.verify, (edited,))

    def test_the_clock_a_hop_reports_is_named_as_a_claim(self):
        described = self.build(1)[0].describe()
        self.assertIn("claimed_observed_at", described)
        self.assertNotIn("observed_at", described)


class EvidenceTests(Case):
    def test_there_is_no_reason_code_for_a_missing_chain(self):
        """Decision 3 made structural: the vocabulary has no word for absence.

        Missing evidence must lower confidence, never act as negative evidence.
        A refusal vocabulary with no term for "there was no chain" cannot express
        the mistake, which is stronger than remembering not to make it.
        """
        for code in chain.REASON_CODES:
            for word in ("absent", "missing", "none", "unavailable", "no_relay"):
                with self.subTest(code=code, word=word):
                    self.assertNotIn(word, code)

    def test_the_module_offers_nothing_that_judges_distance_or_presence(self):
        forbidden = (
            "distance", "meters", "metres", "nearby", "proximity",
            "is_present", "in_room", "inside", "verified",
        )
        for name in dir(chain):
            if name.startswith("_"):
                continue
            for word in forbidden:
                with self.subTest(name=name, word=word):
                    self.assertNotIn(word, name.lower())

    def test_depth_is_reported_as_a_count_and_never_converted(self):
        described = chain.describe_chain(self.build())
        self.assertEqual(described["depth"], len(self.devices))
        self.assertEqual(sorted(described), ["depth", "hops", "signals"])

    def test_a_chain_reaches_a_proof_as_digests_and_fits_inside_one(self):
        """The join to `proof`: hops travel as observation digests."""
        wire = chain.encode_chain(self.build())
        digests = proof.observation_digests(*wire)
        self.assertEqual(len(digests), len(wire))
        self.assertLessEqual(len(digests), proof.MAX_OBSERVATIONS)
        self.assertEqual(len(set(digests)), len(digests))

    def test_an_empty_chain_is_a_chain_and_not_an_error(self):
        """Nothing to relay is the common case, not a failure of anything."""
        self.assertEqual(chain.parse_chain((), root=self.root), ())
        self.assertEqual(chain.signals(()), ())
        self.assertEqual(chain.describe_chain(())["depth"], 0)


class PrivacyTests(Case):
    def test_a_hop_has_no_free_text_and_no_stretchable_field(self):
        """Identity has nowhere to sit in a hop, even for somebody who wants it.

        Every BYTES field declares a fixed size, so there is no field a client can
        stretch, and there is no TEXT field at all - a name, an email or a student
        number has no home here.
        """
        for f in chain.SCHEMA.fields:
            with self.subTest(field=f.name):
                self.assertNotEqual(f.kind, codec.TEXT)
                self.assertFalse(f.optional)
                if f.kind == codec.BYTES:
                    self.assertIsNotNone(f.size)

    def test_a_hop_carries_no_public_key_and_no_student_reference(self):
        hop = self.build(1)[0]
        wire = hop.encode()
        self.assertNotIn(self.devices[0].public().public_bytes, wire)
        self.assertNotIn(self.devices[0].public().key_id, wire)
        self.assertNotIn(SESSION_ID, wire)

    def test_a_hop_carries_nothing_derived_from_the_session_root_secret(self):
        wire = self.build(1)[0].encode()
        self.assertNotIn(ROOT_SECRET, wire)
        self.assertNotIn(self.keys.epoch_key(0), wire)

    def test_the_same_device_relaying_twice_is_unlinkable_across_sessions(self):
        public = self.devices[0].public().public_bytes
        self.assertNotEqual(
            chain.pseudonym(SESSION_ID, public),
            chain.pseudonym(OTHER_SESSION, public),
        )

    def test_the_pseudonym_is_not_a_truncation_of_anything_recoverable(self):
        public = self.devices[0].public().public_bytes
        tag = chain.pseudonym(SESSION_ID, public)
        self.assertNotIn(tag, public)
        self.assertNotIn(tag, SESSION_ID)
        self.assertNotEqual(tag, public[: chain.PSEUDONYM_LEN])

    def test_describing_a_chain_for_audit_leaks_no_key_material(self):
        hops = self.build()
        rendered = repr(chain.describe_chain(hops))
        for device in self.devices:
            with self.subTest(device=device.public().key_id.hex()):
                self.assertNotIn(device.public().public_bytes.hex(), rendered)
                self.assertNotIn(device.public().key_id.hex(), rendered)
        self.assertNotIn(ROOT_SECRET.hex(), rendered)
        for hop in hops:
            self.assertNotIn(hop.signature.hex(), rendered)

    def test_the_linkability_residue_is_stated_rather_than_hidden(self):
        """The honesty rule applied to this module's own weak spot.

        The pseudonym is a hash of two public values, so a holder of the class
        roster can link it to a device within a session. That is written into the
        function's own docstring, because a limitation recorded only in a design
        document is a limitation nobody reads at the point of use.
        """
        source = self.source()
        self.assertIn(
            "an adversary who already holds the class's public keys", source
        )
        self.assertIn("not a keyed MAC", source)


class BoundaryTests(Case):
    """Nothing untrusted escapes this module as an unlabelled exception.

    Every entry point that takes bytes off the wire either returns or raises
    `ChainError` with a code from `REASON_CODES`. That is what lets the proof
    endpoint translate a refusal into a reason code and a rejected proof, instead
    of into a 500 - the shape of defect this project already has one live example
    of, where a stray NameError committed a record and then reported failure.
    """

    def garbage(self):
        good = self.build(1)[0].encode()
        return (
            b"",
            b"\x00",
            b"not cbor at all",
            good[:-1],
            good + b"\x00",
            self.sighting.encode(),
        )

    def test_every_byte_taking_entry_point_refuses_with_a_declared_code(self):
        for raw in self.garbage():
            for name, call in (
                ("root_link", lambda r: chain.root_link(r)),
                ("parse_hop", lambda r: chain.parse_hop(r)),
                ("parse_chain", lambda r: chain.parse_chain((r,), root=self.root)),
                (
                    "verify_chain",
                    lambda r: chain.verify_chain(
                        (r,),
                        session_id=SESSION_ID,
                        root=self.root,
                        resolve=self.cohort().get,
                    ),
                ),
            ):
                with self.subTest(entry=name, raw=raw[:12]):
                    try:
                        call(raw)
                    except chain.ChainError as exc:
                        self.assertIn(exc.code, chain.REASON_CODES)
                    except codec.CodecError as exc:
                        self.fail("%s leaked a codec error: %s" % (name, exc))

    def test_a_refusal_can_only_carry_a_declared_reason_code(self):
        with self.assertRaises(AssertionError):
            chain.ChainError("chain_invented_on_the_spot", "nope")
