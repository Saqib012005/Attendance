"""Tests for the evidence vector.

Seven claims, and most of them are claims about absence rather than about
measurement - which is the right emphasis, because on the current scope almost
every feature in the vector is absent and the whole question is what that means.

**The vector is complete in names and sparse in values.** Every feature appears on
every proof, so a fusion layer iterates a fixed vocabulary and cannot skip a block
because nothing populated it. `EvidenceTests` refuses a vector with a name missing.

**There are four kinds of nothing and exactly one of them is adverse.**
`AbsenceTests` pins the resolution order and the argument for it; `AdverseTests`
pins the consequence - a handset that declares no capabilities produces a vector
with no adverse feature at all, which is decision 3 of the plan stated as an
assertion instead of a paragraph.

**A failed biometric is a value.** `BiometricTests` separates "the platform checked
and said no" from "evidence arrived and did not verify". Collapsing them would make
a wet thumb indistinguishable from a forged proof.

**The spatial block is RESERVED and stays RESERVED.** However much a handset claims
it can do, this build has no anchors, and `SpatialTests` fails if that ever reads as
`UNSUPPORTED` - because then a procurement decision would be recorded as a fact
about somebody's phone.

**RSSI arrives unreduced.** `NetworkTests` asserts the tuple that was recorded, in
order, with no mean and no minimum. §16 forbids `RSSI > threshold = present`, and a
single averaged number is one step from it.

**Nothing here reads configuration.** `SourceTests` walks the module source and
fails if `config` is referenced at all, which is the only way to be sure a tuned
number is not hiding inside what looks like data cleaning.

**There is no vector for a refused proof.** `extract` takes a `gates.Cleared` and
nothing else. `BoundaryTests` builds a `Cleared` by hand around a body no honest
builder would produce, and asserts the extractor refuses rather than sorting it.
"""
import json
import pathlib
from dataclasses import replace

from django.test import SimpleTestCase

from .presence import (
    chain,
    challenge,
    codec,
    config,
    features,
    gates,
    keys,
    origin,
    proof,
    replay,
)

SESSION_ID = bytes(range(proof.SESSION_ID_LEN))
OTHER_SESSION = bytes(range(proof.SESSION_ID_LEN))[::-1]
ROOT_SECRET = b"feature-root-secret".ljust(keys.SEED_LEN, b".")
SIGNING_SEED = b"feature-signing-seed".ljust(keys.SEED_LEN, b".")

# A fixed instant and a fixed step, so nothing depends on when the suite runs.
START = 1_757_000_000
SEQ = 4

# A handset that admits to nothing. Used wherever the point is that a declared
# incapacity must never cost the student anything.
NO_CAPABILITY = 0


class Case(SimpleTestCase):
    """One session, one device, two relays, and helpers that build real proofs.

    Everything goes through `gates.clear`, because a vector built from anything else
    is a vector this module refuses to produce. The one exception is `by_hand`, and
    it exists to test that refusal.
    """

    def setUp(self):
        self.keys = keys.SessionKeys.load(SESSION_ID, ROOT_SECRET, SIGNING_SEED)
        self.timing = challenge.Timing.active()
        self.device = keys.SigningKey.from_seed(
            b"feature-device".ljust(keys.SEED_LEN, b".")
        )
        self.relays = [
            keys.SigningKey.from_seed(bytes([n]) * keys.SEED_LEN) for n in (81, 82)
        ]
        self.ledger = replay.MemoryLedger()
        self.context = gates.SessionContext(
            session_keys=self.keys, session_start=START
        )

    def tearDown(self):
        config.set_active(None)

    # --- fixture helpers ----------------------------------------------------

    def at(self, seq=SEQ):
        return START + seq * self.timing.step_seconds + 1

    def value_for(self, seq=SEQ):
        found = challenge.epoch_of(seq, self.timing)
        return challenge.challenge_value(
            self.keys.epoch_key(found), SESSION_ID, found, seq
        )

    def sighting(self, *, seq=SEQ, rssi=-65, session_keys=None):
        emitter = session_keys or self.keys
        frame = origin.build(emitter, counter=seq, timing=self.timing)
        return origin.record(frame, rssi=rssi, observed_at=self.at(seq))

    def hops(self, root, devices=None):
        built = ()
        chosen = self.relays if devices is None else devices
        for index, device in enumerate(chosen):
            built = chain.extend(
                built,
                root=root,
                session_id=SESSION_ID,
                observed_at=self.at() + index,
                signing_key=device,
            )
        return built

    def cohort(self, devices=None):
        chosen = self.relays if devices is None else devices
        return chain.cohort_index(SESSION_ID, [d.public() for d in chosen]).get

    def signed(
        self,
        *,
        observations=(),
        capabilities=None,
        biometric=None,
        platform=None,
        captured_at=None,
        claims=None,
        nonce=None,
    ):
        built = proof.build(
            session_id=SESSION_ID,
            device_key_id=self.device.public().key_id,
            challenge=self.value_for(),
            challenge_epoch=challenge.epoch_of(SEQ, self.timing),
            challenge_seq=SEQ,
            captured_at=self.at() if captured_at is None else captured_at,
            biometric=proof.BIOMETRIC_SUCCESS if biometric is None else biometric,
            platform=proof.PLATFORM_ANDROID if platform is None else platform,
            capabilities=(
                proof.CAP_BIOMETRIC if capabilities is None else capabilities
            ),
            nonce=nonce,
            claims=claims,
            observations=proof.observation_digests(*observations),
        )
        return proof.sign(built, self.device)

    def clear(self, signed, **over):
        settings = dict(
            context=self.context,
            resolve_device=lambda key_id: gates.Registration(
                verify_key=self.device.public()
            ),
            ledger=self.ledger,
            received_at=self.at() + 1,
            observations=(),
            resolve_relay=None,
            timing=self.timing,
        )
        settings.update(over)
        return gates.clear(signed.body, signed.signature, **settings)

    def vector(self, signed=None, **over):
        """The evidence for one proof, cleared through the real gate first."""
        return features.extract(self.clear(self.signed() if signed is None else signed, **over))

    def relayed(self, **over):
        """A verified sighting, a two-hop chain rooted in it, and the vector."""
        seen = self.sighting()
        bodies = (seen.encode(),) + chain.encode_chain(
            self.hops(chain.root_link(seen.encode()))
        )
        settings = dict(observations=bodies, resolve_relay=self.cohort())
        settings.update(over)
        capable = (
            proof.CAP_BIOMETRIC
            | proof.CAP_BLE_SCAN
            | proof.CAP_RELAY
        )
        return self.vector(
            self.signed(observations=bodies, capabilities=capable), **settings
        )

    def by_hand(self, **over):
        """A `Cleared` assembled without the gate, around a body it would refuse.

        `proof.build` and `proof.parse` share `_check_semantics`, so the only route
        to a body carrying an undeclared outcome is around the builder. The gate
        would refuse such a body; this constructs the `Cleared` the gate never
        would, so the extractor's own boundary check can be observed.
        """
        honest = proof.parse(self.signed().body)
        signed = proof.sign(replace(honest, **over), self.device)
        entry = replay.Entry(
            digest=signed.proof.digest(),
            session_id=SESSION_ID,
            device_key_id=self.device.public().key_id,
            nonce=signed.proof.nonce,
            step=SEQ,
            received_at=self.at() + 1,
        )
        return gates.Cleared(
            signed=signed,
            receipt=replay.Receipt(
                entry=entry, queued_seconds=1, signals=(), config_version="by-hand"
            ),
            step_bounds=challenge.step_bounds(START, SEQ, self.timing),
        )


class VocabularyTests(Case):
    """The declarations, checked against each other rather than against a list."""

    def test_every_feature_belongs_to_a_declared_block(self):
        for name, block in features.FEATURES.items():
            self.assertIn(block, features.BLOCKS, name)

    def test_every_block_owns_at_least_one_feature(self):
        owned = set(features.FEATURES.values())
        self.assertEqual(owned, set(features.BLOCKS))

    def test_only_a_failed_absence_is_adverse(self):
        """The plan's third invariant, as a set operation rather than a promise."""
        self.assertEqual(features.ADVERSE_ABSENCES, frozenset({features.FAILED}))
        self.assertEqual(
            features.ADVERSE_ABSENCES | features.BENIGN_ABSENCES,
            features.ABSENCE_REASONS,
        )
        self.assertEqual(features.ADVERSE_ABSENCES & features.BENIGN_ABSENCES, frozenset())

    def test_the_reserved_features_are_exactly_the_spatial_block(self):
        spatial = {n for n, b in features.FEATURES.items() if b == features.SPATIAL}
        self.assertEqual(features.RESERVED_FEATURES, frozenset(spatial))

    def test_every_gating_capability_is_a_bit_this_build_knows(self):
        for name, flag in features.GATING_CAPABILITY.items():
            self.assertIn(name, features.FEATURES, name)
            self.assertTrue(flag & proof.KNOWN_CAPABILITIES, name)

    def test_no_reserved_feature_is_also_gated_by_a_capability(self):
        """Both at once would be incoherent: a mechanism that does not exist cannot
        be one a handset lacks, and the absence would depend on which check ran
        first."""
        self.assertEqual(
            features.RESERVED_FEATURES & set(features.GATING_CAPABILITY), frozenset()
        )


class FeatureTests(Case):
    """One observation, or one labelled reason there isn't one. Never both."""

    def test_a_feature_carrying_both_a_value_and_an_absence_is_refused(self):
        with self.assertRaises(features.FeatureError) as caught:
            features.Feature(
                features.QUEUE_AGE,
                features.TEMPORAL,
                value=1,
                absent=features.NOT_OBSERVED,
                derived_from=(features.SOURCE_RECEIPT,),
            )
        self.assertIn("exactly one", str(caught.exception))

    def test_a_feature_carrying_neither_is_refused(self):
        with self.assertRaises(features.FeatureError):
            features.Feature(features.QUEUE_AGE, features.TEMPORAL)

    def test_an_undeclared_feature_name_is_refused(self):
        with self.assertRaises(features.FeatureError):
            features.Feature("wishful_thinking", features.TEMPORAL, value=1,
                             derived_from=(features.SOURCE_RECEIPT,))

    def test_a_feature_filed_under_the_wrong_block_is_refused(self):
        with self.assertRaises(features.FeatureError) as caught:
            features.Feature(features.QUEUE_AGE, features.NETWORK, value=1,
                             derived_from=(features.SOURCE_RECEIPT,))
        self.assertIn(features.TEMPORAL, str(caught.exception))

    def test_an_undeclared_absence_reason_is_refused(self):
        with self.assertRaises(features.FeatureError):
            features.Feature(features.QUEUE_AGE, features.TEMPORAL, absent="dunno")

    def test_a_value_that_names_nothing_it_came_from_is_refused(self):
        with self.assertRaises(features.FeatureError) as caught:
            features.Feature(features.QUEUE_AGE, features.TEMPORAL, value=1)
        self.assertIn("derived from", str(caught.exception))

    def test_a_value_naming_something_unlookupable_is_refused(self):
        with self.assertRaises(features.FeatureError) as caught:
            features.Feature(
                features.QUEUE_AGE, features.TEMPORAL, value=1, derived_from=("vibes",)
            )
        self.assertIn("looked up", str(caught.exception))

    def test_zero_and_false_are_values_rather_than_absences(self):
        """The trap this invariant exists to close. A queue age of zero seconds is a
        measurement; if `present` tested truthiness instead of `is not None`, the
        fastest sync in the system would be recorded as no evidence at all."""
        for value in (0, False, (), ""):
            feature = features.Feature(
                features.QUEUE_AGE,
                features.TEMPORAL,
                value=value,
                derived_from=(features.SOURCE_RECEIPT,),
            )
            self.assertTrue(feature.present, repr(value))
            self.assertFalse(feature.adverse, repr(value))

    def test_only_a_failed_feature_reports_itself_adverse(self):
        for reason in sorted(features.ABSENCE_REASONS):
            feature = features.Feature(
                features.QUEUE_AGE, features.TEMPORAL, absent=reason
            )
            self.assertEqual(feature.adverse, reason == features.FAILED, reason)

    def test_an_absent_feature_describes_its_reason_and_no_value(self):
        described = features.Feature(
            features.QUEUE_AGE, features.TEMPORAL, absent=features.UNSUPPORTED
        ).describe()
        self.assertEqual(described["absent"], features.UNSUPPORTED)
        self.assertNotIn("value", described)
        self.assertNotIn("derived_from", described)


class EvidenceTests(Case):
    """Complete in names, sparse in values."""

    def full(self, **over):
        built = {
            name: features.Feature(name, block, absent=features.NOT_OBSERVED)
            for name, block in features.FEATURES.items()
        }
        built.update(over)
        return built

    def test_a_vector_missing_a_feature_is_refused(self):
        short = self.full()
        short.pop(features.QUEUE_AGE)
        with self.assertRaises(features.FeatureError) as caught:
            features.Evidence(features=short)
        self.assertIn(features.QUEUE_AGE, str(caught.exception))

    def test_a_vector_naming_an_undeclared_signal_is_refused(self):
        with self.assertRaises(features.FeatureError):
            features.Evidence(features=self.full(), signals=("signal_i_made_up",))

    def test_every_gate_signal_is_accepted_verbatim(self):
        """The gate's whole signal vocabulary travels through unchanged. A signal the
        vector could not carry would be one the gate recorded and fusion never saw."""
        carried = features.Evidence(
            features=self.full(), signals=tuple(sorted(gates.SIGNALS))
        )
        self.assertEqual(set(carried.signals), gates.SIGNALS)

    def test_an_undeclared_block_cannot_be_asked_for(self):
        with self.assertRaises(features.FeatureError):
            features.Evidence(features=self.full()).block("elsewhere")

    def test_a_block_is_empty_when_nothing_in_it_has_a_value(self):
        vector = features.Evidence(features=self.full())
        for block in features.BLOCKS:
            self.assertTrue(vector.block_is_empty(block), block)

    def test_a_single_value_is_enough_to_make_a_block_non_empty(self):
        vector = features.Evidence(
            features=self.full(
                **{
                    features.QUEUE_AGE: features.Feature(
                        features.QUEUE_AGE,
                        features.TEMPORAL,
                        value=0,
                        derived_from=(features.SOURCE_RECEIPT,),
                    )
                }
            )
        )
        self.assertFalse(vector.block_is_empty(features.TEMPORAL))
        self.assertTrue(vector.block_is_empty(features.NETWORK))

    def test_absent_can_be_asked_by_reason_or_not_at_all(self):
        vector = features.Evidence(
            features=self.full(
                **{
                    features.RELAY_DEPTH: features.Feature(
                        features.RELAY_DEPTH, features.NETWORK, absent=features.FAILED
                    )
                }
            )
        )
        self.assertEqual(vector.absent(features.FAILED), (features.RELAY_DEPTH,))
        self.assertEqual(len(vector.absent()), len(features.FEATURES))

    def test_a_described_vector_lists_only_the_reasons_it_actually_used(self):
        described = features.Evidence(features=self.full()).describe()
        self.assertEqual(list(described["absent"]), [features.NOT_OBSERVED])
        self.assertEqual(described["empty_blocks"], list(features.BLOCKS))


class AbsenceTests(Case):
    """The resolution order, which is the module's argument in four lines."""

    def test_reserved_beats_every_other_reason(self):
        """A mechanism this build does not have cannot have failed and cannot be a
        handset's shortcoming."""
        for failed in (False, True):
            for capabilities in (NO_CAPABILITY, proof.KNOWN_CAPABILITIES):
                self.assertEqual(
                    features.absence(
                        features.ANCHOR_FINGERPRINT,
                        capabilities=capabilities,
                        failed=failed,
                    ),
                    features.RESERVED,
                )

    def test_failed_beats_a_declared_incapacity(self):
        """A handset that says it cannot relay and then submits a chain that does not
        verify is more interesting than one that stayed quiet, not less."""
        self.assertEqual(
            features.absence(
                features.RELAY_DEPTH, capabilities=NO_CAPABILITY, failed=True
            ),
            features.FAILED,
        )

    def test_a_declared_incapacity_beats_mere_silence(self):
        self.assertEqual(
            features.absence(
                features.ORIGIN_DIRECT, capabilities=NO_CAPABILITY, failed=False
            ),
            features.UNSUPPORTED,
        )
        self.assertEqual(
            features.absence(
                features.ORIGIN_DIRECT, capabilities=proof.CAP_BLE_SCAN, failed=False
            ),
            features.NOT_OBSERVED,
        )

    def test_a_feature_no_capability_gates_is_never_unsupported(self):
        """`platform_declared` has no bit behind it, so silence there is silence and
        cannot be blamed on the hardware."""
        ungated = set(features.FEATURES) - set(features.GATING_CAPABILITY) - features.RESERVED_FEATURES
        self.assertIn(features.PLATFORM, ungated)
        for name in ungated:
            self.assertEqual(
                features.absence(name, capabilities=NO_CAPABILITY, failed=False),
                features.NOT_OBSERVED,
                name,
            )

    def test_an_undeclared_feature_has_no_absence(self):
        with self.assertRaises(features.FeatureError):
            features.absence("wishful_thinking", capabilities=NO_CAPABILITY, failed=False)


class ExtractTests(Case):
    """The ordinary proof on the current scope: no radio, no anchors, no spatial claim."""

    def test_the_vector_names_every_feature_in_declaration_order(self):
        vector = self.vector()
        self.assertEqual(list(vector.features), list(features.FEATURES))

    def test_authentication_and_temporal_carry_values_and_nothing_else_does(self):
        vector = self.vector()
        self.assertFalse(vector.block_is_empty(features.AUTHENTICATION))
        self.assertFalse(vector.block_is_empty(features.TEMPORAL))
        self.assertEqual(
            vector.describe()["empty_blocks"], [features.NETWORK, features.SPATIAL]
        )

    def test_the_three_gated_facts_are_established_rather_than_measured(self):
        """Identity, device binding and the committed challenge are `True` on any
        proof that got here, because each is a hard gate. That is the honest shape of
        the evidence and the reason all five sit in one block."""
        vector = self.vector()
        self.assertIs(vector[features.IDENTITY].value, True)
        self.assertIs(vector[features.DEVICE].value, True)
        self.assertEqual(
            vector[features.CHALLENGE].value,
            (challenge.epoch_of(SEQ, self.timing), SEQ),
        )

    def test_the_config_version_is_copied_from_the_gate_not_resolved_again(self):
        cleared = self.clear(self.signed())
        self.assertEqual(
            features.extract(cleared).config_version, cleared.config_version
        )

    def test_the_gates_signals_travel_into_the_vector_unchanged(self):
        cleared = self.clear(
            self.signed(capabilities=proof.CAP_BIOMETRIC | (1 << 29))
        )
        self.assertIn(gates.UNKNOWN_CAPABILITY, cleared.signals)
        self.assertEqual(features.extract(cleared).signals, cleared.signals)

    def test_an_unrecognised_platform_is_a_value_rather_than_a_refusal(self):
        """The open half of the asymmetry `proof` argues: an older server that turned
        away a newer handset would punish a student who has done nothing wrong."""
        vector = self.vector(self.signed(platform=max(proof.PLATFORM_NAMES) + 1))
        self.assertEqual(vector[features.PLATFORM].value, "unrecognised")

    def test_a_handset_that_declares_no_platform_is_not_observed(self):
        vector = self.vector(self.signed(platform=proof.PLATFORM_UNKNOWN))
        self.assertEqual(vector[features.PLATFORM].absent, features.NOT_OBSERVED)

    def test_the_declared_capabilities_are_legible_beside_the_platform(self):
        """So a reader can check every `UNSUPPORTED` verdict in the same row rather
        than taking the extractor's word for it."""
        vector = self.vector(
            self.signed(capabilities=proof.CAP_BIOMETRIC | proof.CAP_BLE_SCAN)
        )
        detail = vector[features.PLATFORM].detail
        self.assertIn("biometric", detail)
        self.assertIn("ble_scan", detail)

    def test_a_handset_declaring_nothing_still_produces_a_complete_vector(self):
        vector = self.vector(
            self.signed(capabilities=NO_CAPABILITY, biometric=proof.BIOMETRIC_ABSENT)
        )
        self.assertEqual(set(vector.features), set(features.FEATURES))
        self.assertEqual(
            set(vector.present()), {features.CHALLENGE, features.DEVICE,
                                    features.IDENTITY, features.PLATFORM,
                                    features.QUEUE_AGE, features.CLOCK_CONSISTENCY}
        )


class NetworkTests(Case):
    """Origin sightings and relay custody, including the RSSI promise."""

    def test_rssi_arrives_as_the_tuple_that_was_recorded(self):
        vector = self.relayed()
        self.assertEqual(vector[features.ORIGIN_DIRECT].value, (-65,))

    def test_several_sightings_keep_their_order_and_are_not_reduced(self):
        readings = (-42, -77, -58)
        seen = [self.sighting(seq=SEQ, rssi=r) for r in readings]
        bodies = tuple(s.encode() for s in seen)
        vector = self.vector(
            self.signed(observations=bodies, capabilities=proof.CAP_BLE_SCAN),
            observations=bodies,
        )
        self.assertEqual(vector[features.ORIGIN_DIRECT].value, readings)

    def test_no_mean_or_minimum_appears_anywhere_in_the_module(self):
        """Structural, because the averaging that §16 forbids is one line to add and
        invisible once added. A room profile is what would license reducing these,
        and it does not exist."""
        source = pathlib.Path(features.__file__).read_text(encoding="utf-8")
        code = "\n".join(
            line for line in source.splitlines() if not line.strip().startswith("#")
        )
        for banned in ("mean(", "fmean", "median", "statistics", "min(", "max("):
            self.assertNotIn(banned, code, banned)

    def test_relay_depth_counts_the_hops_that_verified(self):
        vector = self.relayed()
        self.assertEqual(vector[features.RELAY_DEPTH].value, len(self.relays))
        self.assertIs(vector[features.RELAY_INTEGRITY].value, True)

    def test_each_verified_hop_names_itself_by_the_digest_the_proof_committed_to(self):
        vector = self.relayed()
        seen = self.sighting()
        expected = tuple(
            features.evidence_source(codec.RELAY_HOP.name, h.digest())
            for h in self.hops(chain.root_link(seen.encode()))
        )
        self.assertEqual(vector[features.RELAY_DEPTH].derived_from, expected)

    def test_a_chain_that_arrived_and_did_not_verify_is_failed_not_zero(self):
        """The distinction the four reasons exist for. A depth of zero would read as
        the ordinary case - almost every proof on this build - and a poisoned chain
        is not the ordinary case."""
        vector = self.relayed(resolve_relay=None)
        for name in (features.RELAY_DEPTH, features.RELAY_INTEGRITY):
            self.assertEqual(vector[name].absent, features.FAILED, name)
            self.assertTrue(vector[name].adverse, name)

    def test_a_sighting_that_arrived_and_did_not_verify_is_failed(self):
        elsewhere = keys.SessionKeys.load(OTHER_SESSION, ROOT_SECRET, SIGNING_SEED)
        seen = self.sighting(session_keys=elsewhere)
        bodies = (seen.encode(),)
        vector = self.vector(
            self.signed(observations=bodies, capabilities=proof.CAP_BLE_SCAN),
            observations=bodies,
        )
        self.assertEqual(vector[features.ORIGIN_DIRECT].absent, features.FAILED)

    def test_a_capable_handset_that_heard_nothing_is_not_observed(self):
        capable = proof.CAP_BLE_SCAN | proof.CAP_RELAY
        vector = self.vector(self.signed(capabilities=capable))
        for name in (features.ORIGIN_DIRECT, features.RELAY_DEPTH, features.RELAY_INTEGRITY):
            self.assertEqual(vector[name].absent, features.NOT_OBSERVED, name)
            self.assertFalse(vector[name].adverse, name)

    def test_an_incapable_handset_that_heard_nothing_is_unsupported(self):
        vector = self.vector(self.signed(capabilities=proof.CAP_BIOMETRIC))
        for name in (features.ORIGIN_DIRECT, features.RELAY_DEPTH, features.RELAY_INTEGRITY):
            self.assertEqual(vector[name].absent, features.UNSUPPORTED, name)

    def test_silence_and_failure_produce_different_records(self):
        """The reason `Dropped` is carried through the gate at all. "No relay
        evidence" and "relay evidence that failed to verify" must never be the same
        row, because only one of them is worth looking into."""
        quiet = self.vector(self.signed(capabilities=proof.CAP_RELAY))
        broken = self.relayed(resolve_relay=None)
        self.assertNotEqual(
            quiet[features.RELAY_DEPTH].describe(),
            broken[features.RELAY_DEPTH].describe(),
        )


class SpatialTests(Case):
    """The block that would answer the question this build cannot answer."""

    def test_both_spatial_features_are_reserved_on_every_proof(self):
        for capabilities in (NO_CAPABILITY, proof.KNOWN_CAPABILITIES):
            vector = self.vector(self.signed(capabilities=capabilities))
            for name in sorted(features.RESERVED_FEATURES):
                self.assertEqual(vector[name].absent, features.RESERVED, name)

    def test_a_reserved_absence_is_never_adverse(self):
        """Anchors are a procurement decision. Charging one to a student would be the
        clearest possible case of missing evidence acting as negative evidence."""
        vector = self.vector()
        for name in sorted(features.RESERVED_FEATURES):
            self.assertFalse(vector[name].adverse, name)

    def test_the_spatial_block_is_named_even_though_it_is_empty(self):
        """A vector that omitted it would let a decision rest on an empty spatial
        claim. Naming it and marking it reserved is what makes the gap countable."""
        vector = self.vector()
        self.assertEqual(len(vector.block(features.SPATIAL)), len(features.RESERVED_FEATURES))
        self.assertTrue(vector.block_is_empty(features.SPATIAL))
        self.assertIn(features.SPATIAL, vector.describe()["empty_blocks"])

    def test_the_detail_says_unbuilt_rather_than_unobserved(self):
        vector = self.vector()
        detail = vector[features.ANCHOR_FINGERPRINT].detail
        self.assertIn("unbuilt", detail)


class TemporalTests(Case):
    """Two server-derived numbers, neither compared to anything."""

    def test_queue_age_is_the_receipt_number_and_not_a_claim(self):
        cleared = self.clear(self.signed())
        vector = features.extract(cleared)
        self.assertEqual(
            vector[features.QUEUE_AGE].value, cleared.receipt.queued_seconds
        )
        self.assertEqual(
            vector[features.QUEUE_AGE].derived_from, (features.SOURCE_RECEIPT,)
        )

    def test_clock_consistency_is_signed_and_the_sign_means_something(self):
        start = challenge.step_bounds(START, SEQ, self.timing)[0]
        ahead = self.vector(self.signed(captured_at=start + self.timing.step_seconds))
        self.assertEqual(
            ahead[features.CLOCK_CONSISTENCY].value, self.timing.step_seconds
        )
        self.ledger = replay.MemoryLedger()
        behind = self.vector(self.signed(captured_at=start - 1))
        self.assertEqual(behind[features.CLOCK_CONSISTENCY].value, -1)

    def test_a_handset_whose_clock_matches_the_step_reads_zero_not_absent(self):
        start = challenge.step_bounds(START, SEQ, self.timing)[0]
        vector = self.vector(self.signed(captured_at=start))
        feature = vector[features.CLOCK_CONSISTENCY]
        self.assertTrue(feature.present)
        self.assertEqual(feature.value, 0)

    def test_the_temporal_block_is_never_empty(self):
        """It is the only block that always carries values on this scope, which is
        why an empty-block list of [network, spatial] is the expected honest picture
        rather than a sign that something failed."""
        for capabilities in (NO_CAPABILITY, proof.KNOWN_CAPABILITIES):
            vector = self.vector(self.signed(capabilities=capabilities))
            self.assertFalse(vector.block_is_empty(features.TEMPORAL))

    def test_no_lateness_verdict_is_reached_here(self):
        """The single offline boundary lives in `replay` and was enforced before this
        module ran. Duplicating it as a comparison is how one threshold becomes two
        that drift apart."""
        source = pathlib.Path(features.__file__).read_text(encoding="utf-8")
        for banned in ("max_offline", "too_old", "TOO_OLD", "expired"):
            self.assertNotIn(banned, source, banned)


class BiometricTests(Case):
    """The outcome as recorded, including the negative one."""

    def test_a_failed_biometric_is_a_value_and_not_an_absence(self):
        """§09's rule has a consequence that is easy to lose here: `FAILED` in this
        module means evidence that arrived and did not verify. A biometric that
        verified fine and returned no match is a measurement with an unwelcome
        result, and filing it as an absence would make a wet thumb and a forged proof
        the same record."""
        vector = self.vector(self.signed(biometric=proof.BIOMETRIC_FAILED))
        feature = vector[features.BIOMETRIC]
        self.assertEqual(feature.value, "failed")
        self.assertTrue(feature.present)
        self.assertFalse(feature.adverse)

    def test_every_declared_outcome_reaches_the_vector_by_name(self):
        for outcome, name in sorted(proof.BIOMETRIC_NAMES.items()):
            if outcome == proof.BIOMETRIC_ABSENT:
                continue
            self.ledger = replay.MemoryLedger()
            vector = self.vector(self.signed(biometric=outcome))
            self.assertEqual(vector[features.BIOMETRIC].value, name)

    def test_a_capable_handset_that_submitted_no_outcome_is_not_observed(self):
        vector = self.vector(
            self.signed(
                biometric=proof.BIOMETRIC_ABSENT, capabilities=proof.CAP_BIOMETRIC
            )
        )
        self.assertEqual(vector[features.BIOMETRIC].absent, features.NOT_OBSERVED)

    def test_a_handset_without_the_capability_is_unsupported(self):
        vector = self.vector(
            self.signed(biometric=proof.BIOMETRIC_ABSENT, capabilities=NO_CAPABILITY)
        )
        self.assertEqual(vector[features.BIOMETRIC].absent, features.UNSUPPORTED)

    def test_no_raw_biometric_material_can_reach_the_vector_at_all(self):
        """There is nowhere to put it. The proof schema carries an outcome code and
        the vector carries its name, so "do not store templates" is a property of the
        wire format rather than a rule someone has to remember."""
        vector = self.vector(self.signed(biometric=proof.BIOMETRIC_SUCCESS))
        self.assertIn(vector[features.BIOMETRIC].value, set(proof.BIOMETRIC_NAMES.values()))
        self.assertNotIsInstance(vector[features.BIOMETRIC].value, (bytes, bytearray))


class AdverseTests(Case):
    """Decision 3 of the plan, as assertions instead of a paragraph.

    Missing evidence lowers confidence toward SECONDARY and is never negative
    evidence. That has to be checkable, because the failure mode is silent: a fusion
    layer reading a benign absence as a penalty produces slightly worse outcomes for
    students with older phones and nothing anywhere says so.
    """

    def test_a_handset_that_declares_nothing_produces_no_adverse_feature(self):
        vector = self.vector(
            self.signed(capabilities=NO_CAPABILITY, biometric=proof.BIOMETRIC_ABSENT)
        )
        self.assertEqual([n for n, f in vector.features.items() if f.adverse], [])

    def test_the_only_adverse_feature_on_any_vector_is_one_that_failed(self):
        vector = self.relayed(resolve_relay=None)
        adverse = [n for n, f in vector.features.items() if f.adverse]
        self.assertEqual(set(adverse), {features.RELAY_DEPTH, features.RELAY_INTEGRITY})
        for name in adverse:
            self.assertEqual(vector[name].absent, features.FAILED)

    def test_no_present_feature_is_ever_adverse(self):
        """`adverse` asks about an absence. A value that looked adverse would be a
        verdict, and verdicts are `fusion`'s and `decide`'s to reach."""
        for vector in (self.vector(), self.relayed()):
            for name, feature in vector.features.items():
                if feature.present:
                    self.assertFalse(feature.adverse, name)

    def test_a_cancelled_biometric_is_not_adverse_either(self):
        """A student who dismissed the prompt has produced a weaker proof, not a
        suspicious one, and the difference belongs to fusion's weights rather than to
        a flag set here."""
        vector = self.vector(self.signed(biometric=proof.BIOMETRIC_CANCELLED))
        self.assertFalse(vector[features.BIOMETRIC].adverse)

    def test_no_absence_reason_but_failed_appears_adverse_anywhere(self):
        for reason in sorted(features.BENIGN_ABSENCES):
            feature = features.Feature(
                features.ORIGIN_DIRECT, features.NETWORK, absent=reason
            )
            self.assertFalse(feature.adverse, reason)


class PrivacyTests(Case):
    """What a described vector must not contain, checked by searching for it."""

    def described(self, vector):
        return json.dumps(vector.describe())

    def test_no_key_material_survives_into_the_audit_row(self):
        rendered = self.described(self.relayed())
        for secret in (
            ROOT_SECRET,
            SIGNING_SEED,
            self.keys.epoch_key(challenge.epoch_of(SEQ, self.timing)),
            self.value_for(),
            self.device.public().public_bytes,
        ):
            self.assertNotIn(secret.hex(), rendered)

    def test_no_student_or_device_identifier_appears(self):
        """The vector is about what the evidence says. Who it was about is the
        record's business, and duplicating an identifier into the evidence would
        spread it across two retention policies instead of one.

        The word "student" does appear, in prose explaining what a check means. That
        is the difference being asserted: an explanation naming the concept is not an
        identifier naming the person, and only the second one is a leak.
        """
        rendered = self.described(self.relayed())
        identifiers = [
            self.device.public().key_id.hex(),
            self.device.public().public_bytes.hex(),
            SESSION_ID.hex(),
        ]
        identifiers.extend(d.public().key_id.hex() for d in self.relays)
        identifiers.extend(d.public().public_bytes.hex() for d in self.relays)
        for identifier in identifiers:
            self.assertNotIn(identifier, rendered)

    def test_no_relay_pseudonym_appears_beside_a_verified_chain(self):
        """§43 again: the chain must not carry permanent identity, and a pseudonym is
        stable within a session, so it does not belong in a row that outlives one."""
        rendered = self.described(self.relayed())
        for device in self.relays:
            pseudonym = chain.pseudonym(SESSION_ID, device.public().public_bytes)
            self.assertNotIn(pseudonym.hex(), rendered)

    def test_a_described_vector_is_json_serialisable_as_it_stands(self):
        """So an audit row can be written without a bespoke encoder deciding what to
        do about bytes it should never have been handed."""
        rendered = json.loads(self.described(self.relayed()))
        self.assertEqual(len(rendered["features"]), len(features.FEATURES))


class SourceTests(Case):
    """Every value names something that can be looked up, and nothing tuned."""

    def test_the_module_reads_no_configuration_at_all(self):
        """The safeguard behind the whole layering. A threshold inside a feature
        extractor looks like data cleaning, so the only reliable defence is that this
        module has no access to a tuned number in the first place."""
        source = pathlib.Path(features.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import config", source)
        self.assertNotIn("config.", source.replace("config_version", ""))

    def test_a_vector_can_be_extracted_with_no_active_artifact(self):
        config.set_active(None)
        vector = self.vector()
        self.assertEqual(set(vector.features), set(features.FEATURES))

    def test_every_present_feature_names_only_lookupable_sources(self):
        for vector in (self.vector(), self.relayed()):
            for name, feature in vector.features.items():
                if feature.present:
                    self.assertTrue(feature.derived_from, name)
                    for source in feature.derived_from:
                        self.assertTrue(features.is_source(source), (name, source))

    def test_an_observation_kind_with_no_schema_cannot_name_itself(self):
        with self.assertRaises(features.FeatureError):
            features.evidence_source("hearsay", b"\x00")

    def test_a_source_needs_a_digest_and_a_real_hex_one(self):
        self.assertFalse(features.is_source(codec.RELAY_HOP.name))
        self.assertFalse(features.is_source("%s:" % (codec.RELAY_HOP.name,)))
        self.assertFalse(features.is_source("%s:zz" % (codec.RELAY_HOP.name,)))
        self.assertTrue(features.is_source("%s:00ff" % (codec.RELAY_HOP.name,)))

    def test_the_anchor_schema_may_already_name_itself(self):
        """Phase 5's readings are unbuilt, not unspecified. Listing the kind now is
        what lets the spatial block arrive later without touching this module."""
        self.assertIn(codec.ANCHOR_READING.name, features.SOURCE_KINDS)


class BoundaryTests(Case):
    """There is no vector for a proof that did not clear the gates.

    The signature `extract(cleared)` is most of the safeguard, and the rest is these
    two checks. A refusal is a decision already taken; manufacturing a weak vector
    for it would hand a fusion layer the chance to weigh it back up into an
    admission, which is exactly how a hard gate gets talked past.
    """

    def test_a_biometric_outcome_this_build_has_no_name_for_is_refused(self):
        cleared = self.by_hand(biometric=max(proof.BIOMETRIC_NAMES) + 1)
        with self.assertRaises(features.FeatureError) as caught:
            features.extract(cleared)
        self.assertIn("gates", str(caught.exception))

    def test_a_claimed_status_this_build_has_no_name_for_is_refused(self):
        boastful = replace(
            self.by_hand().signed.proof.claims, status=max(proof.STATUS_NAMES) + 1
        )
        cleared = self.by_hand(claims=boastful)
        with self.assertRaises(features.FeatureError):
            features.extract(cleared)

    def test_a_hand_built_cleared_with_an_honest_body_still_extracts(self):
        """So the two refusals above are about the body and not about the fixture."""
        vector = features.extract(self.by_hand())
        self.assertEqual(set(vector.features), set(features.FEATURES))

    def test_no_client_claim_becomes_a_feature(self):
        """§39, structurally. A proof that awards itself `PRESENT`, full confidence
        and 99 hops produces a vector identical to a modest one - so there is no
        route by which fusion could read a claim and mistake it for evidence."""
        boastful = proof.Claims(
            status=proof.STATUS_PRESENT,
            confidence_milli=proof.CONFIDENCE_MILLI_MAX,
            hop_count=99,
        )
        loud = self.vector(self.signed(claims=boastful))
        quiet = self.vector(self.signed())
        self.assertEqual(loud.describe(), quiet.describe())

    def test_a_claimed_hop_count_does_not_populate_relay_depth(self):
        """The one claim a careless reading would take at face value, because it is
        the only one that shares a name with a feature. `relay_depth` counts hops
        that verified; a handset asserting 99 with no chain attached is absent."""
        boastful = proof.Claims(status=proof.STATUS_PRESENT, hop_count=99)
        vector = self.vector(self.signed(claims=boastful))
        depth = vector[features.RELAY_DEPTH]
        self.assertIsNone(depth.value)
        self.assertEqual(depth.absent, features.UNSUPPORTED)
        self.assertNotIn("99", json.dumps(vector.describe()))
