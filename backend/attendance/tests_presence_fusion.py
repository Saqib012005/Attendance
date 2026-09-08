"""Tests for the fusion arithmetic.

Ten claims, and the ones that matter most are about what the arithmetic refuses
to do.

**Nothing is ever subtracted** (`AbsenceTests`). An origin frame that arrived and
did not verify scores exactly what silence from the same capable handset scores -
the same three figures, the same supplied fraction - and the only difference is that
the first is listed as adverse for `decide` to route on. A biometric the platform
rejected goes further still and is credited in full, because a rejection is an
outcome the handset reported rather than a check that went missing: the student with
the wet thumb is not charged for a forged proof. A negative weight anywhere here
would need a likelihood ratio for *failed given proxying* that nobody has measured.

**More evidence never scores less** (`MonotonicityTests`). Over a lattice of
vectors, adding an observation cannot lower the figure - which is also what makes
the three-number invariant provable rather than asserted.

**Within a block, the naive sum is unreachable** (`BlockTests`). Four verified
authentication features score strictly below the sum of their weights, because §21
forbids multiplying likelihood ratios that share most of their evidence. The test
that a credit of 100 percent cannot be *loaded* is the same claim from the other
side: the naive independence assumption is not a configuration option.

**Coverage on this build is about a quarter** (`ScopeTests`). The accepted residual
risk stated as arithmetic. A perfect student on a perfect handset reaches roughly
27 percent of the designed evidence base, because the spatial block is RESERVED and
the network block needs a radio this build does not use. This is the test that fails
if somebody quietly reweights the table to make a demo look convincing.

**A confidence is not a probability until it is calibrated** (`PosteriorTests`).
Four cases, three of which withhold the posterior and say which condition failed.
There is no fourth combination, and `Fused.__post_init__` refuses to hold a
posterior and an ordering-only flag at once, so the two can never disagree.

**The prior comes from data or it is declared absent** (`PriorTests`). Zero
sessions, zero attendance and perfect attendance all yield an undetermined prior
with a reason. `SourceTests` then checks the module contains no `0.5` at all, which
is the only way to be sure a default did not creep back in as a fallback.

**No client claim moves the score** (`ClaimTests`). §39 as arithmetic: a proof that
awards itself `PRESENT`, full confidence and 99 hops fuses to the same number as a
modest one.

**Fusion reaches no verdict** (`VerdictTests`). Structural, not stylistic - no
status, no threshold, no comparison against one, and no field a caller could mistake
for a decision.

**A vector that cannot be explained is refused rather than weighed**
(`RefusalTests`). An incomplete vector, one carrying a feature nothing declares, one
extracted under a different artifact, and a hop count that is not a count all fail
closed. Any of them scored would produce a modest-looking figure that no
configuration version could afterwards re-derive.

**An audit row records what was weighed, not who was there** (`PrivacyTests`). The
body is JSON-native, so no key id, nonce or observation digest can ride along as
bytes, and no recorded signal strength appears anywhere in it.

The fixture comes from `tests_presence_features` on purpose. These are adjacent
layers of one chain, and a fusion test that built its own proofs could pass while
the real `extract` produced something else.
"""
import ast
import json
import pathlib
from dataclasses import replace

from .presence import chain, config, decide, features, fusion, keys, proof
from .tests_presence_features import OTHER_SESSION, SESSION_ID, Case as FeatureCase

# Every feature carrying a value, including the two the build cannot yet produce.
# Used only where the point is arithmetic over features no proof can populate on
# this scope - the ceiling, and the monotonicity lattice. Nothing here is a proof.
COMPLETE = {
    features.IDENTITY: {"value": True},
    features.DEVICE: {"value": True},
    features.CHALLENGE: {"value": True},
    features.BIOMETRIC: {"value": True},
    features.PLATFORM: {"value": "android"},
    features.ORIGIN_DIRECT: {"value": True},
    features.RELAY_DEPTH: {"value": 3},
    features.RELAY_INTEGRITY: {"value": True},
    features.ANCHOR_FINGERPRINT: {"value": True},
    features.SPATIAL_STABILITY: {"value": True},
    features.QUEUE_AGE: {"value": 0},
    features.CLOCK_CONSISTENCY: {"value": True},
}

# What this build can actually collect: authentication and a clock, nothing else.
SCOPE = dict(
    COMPLETE,
    **{
        features.ORIGIN_DIRECT: {"absent": features.UNSUPPORTED},
        features.RELAY_DEPTH: {"absent": features.UNSUPPORTED},
        features.RELAY_INTEGRITY: {"absent": features.UNSUPPORTED},
        features.ANCHOR_FINGERPRINT: {"absent": features.RESERVED},
        features.SPATIAL_STABILITY: {"absent": features.RESERVED},
    }
)

# The naive sum of the authentication weights, computed from the artifact rather
# than written down, so the test compares against configuration and not a memory
# of it.
AUTHENTICATION_FEATURES = (
    features.IDENTITY,
    features.DEVICE,
    features.CHALLENGE,
    features.BIOMETRIC,
)

# A handset that declares every capability the vector can gate on, so that an
# absence means silence rather than "this phone cannot".
CAPABLE = proof.CAP_BIOMETRIC | proof.CAP_BLE_SCAN | proof.CAP_RELAY


def assemble(spec=None, **over):
    """Build an evidence vector from a spec dict, bypassing proof extraction.

    A module-level function rather than only a method because the storage tests
    need a real decision to store, and a decision needs a vector. Two copies of
    this loop in two test files would be two chances for the vectors they build to
    stop meaning the same thing.
    """
    chosen = dict(SCOPE if spec is None else spec)
    chosen.update(over)
    made = {}
    for name, how in chosen.items():
        settings = dict(how)
        if "value" in settings:
            settings.setdefault("derived_from", (features.SOURCE_PROOF,))
        made[name] = features.Feature(
            name=name, block=features.FEATURES[name], **settings
        )
    return features.Evidence(features=made)


class Case(FeatureCase):
    """The features fixture, plus vectors for features no proof can populate yet."""

    def artifact(self, values=None, calibration=None):
        """The live artifact with named parameters replaced. Never registered."""
        live = config.active()
        merged = dict(live.values)
        merged.update(values or {})
        return config.Artifact(
            version=live.version,
            calibration=live.calibration if calibration is None else calibration,
            notes="",
            values=merged,
        )

    def weights(self, values=None, calibration=None):
        return fusion.Weights.load(self.artifact(values, calibration))

    def synthetic(self, spec=None, **over):
        """A complete vector assembled directly, not extracted from a proof.

        Needed because the ceiling and the monotonicity lattice both range over the
        spatial features, and no proof on this build can carry one. Every test that
        can use a real proof uses `vector()` or `relayed()` instead.
        """
        return assemble(spec, **over)

    def naive(self, block, weights=None):
        """What a block would come to if its features were treated as independent."""
        table = weights or fusion.Weights.load()
        return sum(
            table.gross(name)
            for name, owner in features.FEATURES.items()
            if owner == block and name not in fusion.NON_EVIDENTIAL
        )

    def scored(self, fused, block):
        found = [one for one in fused.blocks if one.block == block]
        self.assertEqual(len(found), 1, block)
        return found[0]

    def credited(self, fused, feature):
        for block in fused.blocks:
            for contribution in block.contributions:
                if contribution.feature == feature:
                    return contribution
        self.fail("%s contributed nothing at all, not even a zero" % (feature,))

    def rejected(self):
        """A vector where a sighting arrived and did not verify: an adverse absence.

        Built from another session's origin frame, which is the shape the attack
        takes in practice - a frame that exists, is well formed, and belongs
        somewhere else. The gate drops it, and `features` files the absence as
        FAILED rather than UNSUPPORTED because evidence that arrived says something
        whatever the handset claims about itself.
        """
        stranger = keys.SessionKeys.load(
            OTHER_SESSION,
            b"other-root".ljust(keys.SEED_LEN, b"."),
            b"other-seed".ljust(keys.SEED_LEN, b"."),
        )
        bodies = (self.sighting(session_keys=stranger).encode(),)
        return self.vector(
            self.signed(observations=bodies, capabilities=CAPABLE),
            observations=bodies,
        )

    def quiet(self):
        """The same capable handset, having seen nothing at all."""
        return self.vector(self.signed(capabilities=CAPABLE))

    def one_hop(self):
        """A verified sighting and a chain exactly one hop deep."""
        seen = self.sighting()
        bodies = (seen.encode(),) + chain.encode_chain(
            self.hops(chain.root_link(seen.encode()), devices=self.relays[:1])
        )
        return self.vector(
            self.signed(observations=bodies, capabilities=CAPABLE),
            observations=bodies,
            resolve_relay=self.cohort(),
        )


class WeightTests(Case):
    """Weights come from the artifact, or loading fails. No defaults anywhere."""

    def test_every_evidential_feature_is_priced_and_no_other_is(self):
        table = fusion.Weights.load()
        for name in features.FEATURES:
            if name in fusion.NON_EVIDENTIAL:
                self.assertNotIn(name, table.millinats, name)
            else:
                self.assertIn(name, table.millinats, name)

    def test_an_unpriced_feature_fails_to_load_rather_than_scoring_nothing(self):
        """A weight of zero chosen by omission is the same mistake as a hardcoded
        threshold and quieter: the feature would still be extracted, still be
        reported present, and still be worth nothing to the score."""
        live = config.active()
        thinned = dict(live.values)
        thinned.pop(fusion.WEIGHT_PREFIX + features.ORIGIN_DIRECT)
        with self.assertRaises(fusion.FusionError) as caught:
            fusion.Weights.load(
                config.Artifact(
                    version=live.version,
                    calibration=live.calibration,
                    notes="",
                    values=thinned,
                )
            )
        self.assertIn(features.ORIGIN_DIRECT, str(caught.exception))

    def test_no_weight_is_zero_or_negative(self):
        for name, weight in fusion.Weights.load().millinats.items():
            self.assertGreater(weight, 0, name)

    def test_subtraction_is_impossible_because_the_bound_forbids_it(self):
        """Not a convention held by the loader - a declaration the artifact cannot
        satisfy. Adverse evidence is reported and credited nothing; there is nowhere
        for a penalty to be configured."""
        declared = config.PARAMETERS[fusion.WEIGHT_PREFIX + features.IDENTITY]
        for refused in (-1, 0):
            with self.assertRaises(config.ConfigError):
                declared.check("weight", refused)

    def test_the_naive_independence_assumption_cannot_be_configured(self):
        """A credit of 100 percent is exactly the error §21 names, so it is out of
        declared bounds rather than merely discouraged in a comment."""
        declared = config.PARAMETERS["fusion.correlated_credit_pct"]
        with self.assertRaises(config.ConfigError):
            declared.check("credit", fusion.PCT)
        self.assertEqual(declared.check("credit", fusion.PCT - 1), fusion.PCT - 1)

    def test_a_credit_of_nothing_cannot_be_configured_either(self):
        """Zero would discard genuinely additional mechanisms. A biometric outcome
        is not a restatement of a signature, so the discount has a floor as well."""
        with self.assertRaises(config.ConfigError):
            config.PARAMETERS["fusion.correlated_credit_pct"].check("credit", 0)

    def test_relay_depth_is_priced_per_hop_up_to_the_protocol_bound(self):
        """The same bound the chain enforces. A chain cannot be worth more here than
        it was allowed to be there."""
        table = fusion.Weights.load()
        self.assertEqual(table.units[features.RELAY_DEPTH], chain.max_hops())
        self.assertEqual(
            table.gross(features.RELAY_DEPTH),
            table.millinats[features.RELAY_DEPTH] * chain.max_hops(),
        )

    def test_every_other_feature_is_priced_once(self):
        table = fusion.Weights.load()
        for name, units in table.units.items():
            if name not in fusion.PER_UNIT:
                self.assertEqual(units, 1, name)

    def test_the_table_records_which_artifact_priced_it(self):
        live = config.active()
        table = fusion.Weights.load()
        self.assertEqual(table.config_version, live.version)
        self.assertEqual(table.calibration, live.calibration)

    def test_the_largest_weight_in_the_table_is_one_this_build_cannot_collect(self):
        """Uncomfortable on purpose. The single most valuable feature in the design
        is the one that bears on location, and it is RESERVED - so a table that
        ranked an authentication feature first would be pricing identity as though it
        were presence."""
        table = fusion.Weights.load()
        largest = max(table.millinats, key=table.millinats.get)
        self.assertEqual(largest, features.ANCHOR_FINGERPRINT)
        self.assertIn(largest, features.RESERVED_FEATURES)

    def test_the_reserved_features_outweigh_everything_this_build_can_collect(self):
        """The residual risk, priced. Whatever a student does on this scope, more of
        the designed evidence base is missing than is available."""
        table = fusion.Weights.load()
        reserved = sum(table.gross(name) for name in features.RESERVED_FEATURES)
        collectable = sum(
            table.gross(name)
            for name, how in SCOPE.items()
            if "value" in how and name in table.millinats
        )
        self.assertGreater(reserved, collectable)


class BlockTests(Case):
    """Strongest feature in full, the rest discounted, the total capped."""

    def test_four_verified_features_score_below_the_sum_of_their_weights(self):
        """§21. Crediting each in full would multiply likelihood ratios that share
        most of their evidence - a committed challenge nearly implies a valid
        session, so the second one is not a second mechanism."""
        fused = fusion.fuse(self.vector())
        block = self.scored(fused, features.AUTHENTICATION)
        for name in AUTHENTICATION_FEATURES:
            self.assertTrue(self.credited(fused, name).present, name)
        self.assertLess(block.millinats, self.naive(features.AUTHENTICATION))

    def test_exactly_one_feature_leads_a_block_and_it_is_the_strongest(self):
        fused = fusion.fuse(self.synthetic(COMPLETE))
        for block in fused.blocks:
            leading = [one for one in block.contributions if one.leading]
            self.assertEqual(len(leading), 1, block.block)
            self.assertEqual(
                leading[0].gross_millinats,
                max(one.gross_millinats for one in block.contributions),
                block.block,
            )

    def test_the_leader_is_credited_in_full_and_the_rest_at_the_declared_fraction(self):
        table = fusion.Weights.load()
        fused = fusion.fuse(self.vector())
        for contribution in self.scored(fused, features.AUTHENTICATION).contributions:
            expected = (
                contribution.gross_millinats
                if contribution.leading
                else contribution.gross_millinats
                * table.correlated_credit_pct
                // fusion.PCT
            )
            self.assertEqual(
                contribution.credited_millinats, expected, contribution.feature
            )

    def test_the_credited_contributions_add_up_to_the_block_and_the_blocks_to_the_whole(
        self,
    ):
        """The analytics layer's second invariant: every derived figure traces back
        to the observations that produced it. A total nobody can take apart again is
        not auditable, whatever it is called."""
        fused = fusion.fuse(self.synthetic(COMPLETE))
        for block in fused.blocks:
            self.assertEqual(
                block.uncapped_millinats,
                sum(one.credited_millinats for one in block.contributions),
                block.block,
            )
        self.assertEqual(
            fused.millinats, sum(block.millinats for block in fused.blocks)
        )

    def test_a_block_holding_one_feature_credits_it_in_full(self):
        """The leader rule read from the other end. A discount applied to a solitary
        feature would be a discount for correlation with nothing."""
        fused = fusion.fuse(self.vector())
        only = self.credited(fused, features.CLOCK_CONSISTENCY)
        self.assertTrue(only.leading)
        self.assertEqual(only.credited_millinats, only.gross_millinats)

    def test_the_cap_bites_and_reports_that_it_did(self):
        """Reported, not silent. A block that was cut has a different meaning from a
        block that happened to land on the same figure, and only one of them tells a
        reviewer that the arithmetic stopped counting."""
        table = self.weights(values={
            fusion.WEIGHT_PREFIX + features.ANCHOR_FINGERPRINT: 10000,
            fusion.WEIGHT_PREFIX + features.SPATIAL_STABILITY: 10000,
        })
        fused = fusion.fuse(self.synthetic(COMPLETE), weights=table)
        block = self.scored(fused, features.SPATIAL)
        self.assertTrue(block.capped)
        self.assertEqual(block.millinats, table.block_cap_millinats)
        self.assertLess(block.millinats, block.uncapped_millinats)
        # The cap survives into the whole rather than being undone by the sum.
        self.assertEqual(
            fused.millinats, sum(one.millinats for one in fused.blocks)
        )

    def test_no_single_block_can_reach_the_ceiling_on_its_own(self):
        """The arithmetic form of the rule that no one signal is allowed to mean
        present. Nothing in `fuse` compares a block to a threshold - the cap is what
        makes the comparison impossible in the first place."""
        table = fusion.Weights.load()
        fused = fusion.fuse(self.synthetic(COMPLETE))
        self.assertLess(table.block_cap_millinats, fused.ceiling_millinats)
        for block in fused.blocks:
            self.assertLessEqual(block.millinats, table.block_cap_millinats)

    def test_an_empty_block_contributes_exactly_nothing_and_says_which(self):
        """Not a small number. The difference between "no spatial evidence exists"
        and "the student was in the room" is the whole point of the block, and a
        block that quietly scored a little would erase it."""
        fused = fusion.fuse(self.vector())
        self.assertEqual(
            fused.empty_blocks, (features.NETWORK, features.SPATIAL)
        )
        for name in fused.empty_blocks:
            block = self.scored(fused, name)
            self.assertTrue(block.empty)
            self.assertEqual(block.millinats, 0)
            self.assertEqual(block.uncapped_millinats, 0)

    def test_an_absent_feature_is_still_reported_as_a_zero_carrying_its_reason(self):
        """Omitting it would be cheaper and would lose the audit. A reviewer has to
        be able to see that the anchor fingerprint was considered and was RESERVED,
        not infer it from a feature that never appears."""
        fused = fusion.fuse(self.vector())
        for name in features.RESERVED_FEATURES:
            contribution = self.credited(fused, name)
            self.assertFalse(contribution.present)
            self.assertEqual(contribution.absent, features.RESERVED)
            self.assertEqual(contribution.credited_millinats, 0)
            self.assertEqual(contribution.gross_millinats, 0)
            self.assertEqual(contribution.units, 0)
            # The weight is still reported, so the audit row says what was forgone.
            self.assertGreater(contribution.weight_millinats, 0)


class ScopeTests(Case):
    """The accepted residual risk, stated as arithmetic rather than as a caveat."""

    def test_a_perfect_student_on_this_build_reaches_about_a_quarter(self):
        """Not a defect in the student or the handset. The two features that bear on
        location are RESERVED and the network block needs a radio this build does not
        use, so this is the ceiling the scope itself imposes."""
        fused = fusion.fuse(self.vector())
        self.assertIsNotNone(fused.coverage_pct)
        self.assertGreater(fused.coverage_pct, 20.0)
        self.assertLess(fused.coverage_pct, 35.0)

    def test_the_missing_evidence_is_missing_by_design_not_withheld(self):
        """Both figures matter and they say different things. Coverage near a quarter
        with everything supplied is a build limitation; the same coverage with
        something withheld would be a handset that did not answer."""
        fused = fusion.fuse(self.vector())
        self.assertEqual(fused.supplied_pct, 100.0)
        self.assertEqual(fused.millinats, fused.obtainable_millinats)
        self.assertLess(fused.obtainable_millinats, fused.ceiling_millinats)

    def test_the_two_blocks_that_bear_on_being_in_the_room_are_the_empty_ones(self):
        """The uncomfortable part written down. What this build verifies well is who
        submitted the proof and when; what it cannot verify at all is where from."""
        fused = fusion.fuse(self.vector())
        self.assertIn(features.SPATIAL, fused.empty_blocks)
        self.assertIn(features.NETWORK, fused.empty_blocks)
        self.assertNotIn(features.AUTHENTICATION, fused.empty_blocks)
        self.assertNotIn(features.TEMPORAL, fused.empty_blocks)

    def test_a_relayed_proof_reaches_further_and_still_leaves_spatial_empty(self):
        """Phase 4-6 evidence, exercised through the real gate to prove the vector
        accepts it. Even a verified origin frame and a verified chain leave the
        spatial block empty, because a chain of custody is not a location."""
        thin = fusion.fuse(self.vector())
        rich = fusion.fuse(self.relayed())
        self.assertGreater(rich.millinats, thin.millinats)
        self.assertEqual(rich.ceiling_millinats, thin.ceiling_millinats)
        self.assertEqual(rich.empty_blocks, (features.SPATIAL,))
        self.assertLess(rich.coverage_pct, 100.0)

    def test_the_ceiling_is_the_same_number_whatever_arrived(self):
        """It has to be, or coverage would be a ratio against a moving denominator
        and two students could not be compared."""
        table = fusion.Weights.load()
        designed = sum(table.gross(name) for name in table.millinats)
        for vector in (self.vector(), self.relayed(), self.synthetic(COMPLETE)):
            fused = fusion.fuse(vector)
            self.assertLessEqual(fused.ceiling_millinats, designed)
            self.assertEqual(fused.ceiling_millinats, fusion.fuse(self.vector()).ceiling_millinats)


class AbsenceTests(Case):
    """Nothing is ever subtracted. Adverse evidence is reported, never charged for."""

    def test_a_rejected_observation_scores_exactly_what_silence_scores(self):
        """The claim the module rests on. A frame that arrived and did not verify and
        a capable handset that saw nothing produce the same three figures; the only
        difference is that the first is named in `adverse`.

        A negative weight here would be the point where a wet thumb starts to look
        like a forged proof, and the likelihood ratio that would justify the
        difference has never been measured.
        """
        rejected = fusion.fuse(self.rejected())
        quiet = fusion.fuse(self.quiet())
        self.assertEqual(rejected.millinats, quiet.millinats)
        self.assertEqual(rejected.obtainable_millinats, quiet.obtainable_millinats)
        self.assertEqual(rejected.ceiling_millinats, quiet.ceiling_millinats)
        self.assertEqual(rejected.supplied_pct, quiet.supplied_pct)
        self.assertEqual(rejected.adverse, (features.ORIGIN_DIRECT,))
        self.assertEqual(quiet.adverse, ())

    def test_the_adverse_absence_is_reported_with_its_reason_intact(self):
        """Scoring it at nothing is not the same as ignoring it. `decide` is the layer
        entitled to treat a rejection as a signal, and it can only do that if the
        arithmetic passed the fact along instead of absorbing it."""
        fused = fusion.fuse(self.rejected())
        contribution = self.credited(fused, features.ORIGIN_DIRECT)
        self.assertEqual(contribution.absent, features.FAILED)
        self.assertEqual(contribution.credited_millinats, 0)
        self.assertTrue(contribution.obtainable)

    def test_a_biometric_the_platform_rejected_scores_what_one_it_accepted_scores(self):
        """Deliberate, and the sharpest edge of the rule. A failed fingerprint is a
        measurement with an unwelcome result, not evidence that failed to arrive, so
        `features` carries it as a value and fusion weighs the outcome rather than
        the verdict inside it.

        The student with the wet thumb is the one who would pay for the alternative.
        """
        accepted = fusion.fuse(self.vector())
        denied = fusion.fuse(
            self.vector(self.signed(biometric=proof.BIOMETRIC_FAILED))
        )
        self.assertEqual(denied.millinats, accepted.millinats)
        self.assertTrue(self.credited(denied, features.BIOMETRIC).present)
        self.assertEqual(denied.adverse, ())

    def test_a_biometric_nobody_answered_lowers_what_was_supplied(self):
        """The other side of the same coin. A capable handset that submitted no
        outcome withheld something it could have supplied, and that shows up in
        `supplied_pct` rather than as a penalty in the score."""
        accepted = fusion.fuse(self.vector())
        silent = fusion.fuse(
            self.vector(self.signed(biometric=proof.BIOMETRIC_ABSENT))
        )
        self.assertLess(silent.millinats, accepted.millinats)
        self.assertEqual(silent.obtainable_millinats, accepted.obtainable_millinats)
        self.assertLess(silent.supplied_pct, 100.0)
        self.assertEqual(
            self.credited(silent, features.BIOMETRIC).absent, features.NOT_OBSERVED
        )

    def test_an_absence_nobody_could_have_prevented_is_not_a_withheld_observation(self):
        """UNSUPPORTED and RESERVED leave `obtainable` alone, so a student on an old
        handset reads as fully supplied at a low coverage rather than as having held
        something back. Decision 3 as arithmetic: missing evidence lowers confidence,
        and never behaves like negative evidence."""
        incapable = fusion.fuse(
            self.vector(
                self.signed(biometric=proof.BIOMETRIC_ABSENT, capabilities=0)
            )
        )
        capable = fusion.fuse(
            self.vector(self.signed(biometric=proof.BIOMETRIC_ABSENT))
        )
        self.assertEqual(incapable.millinats, capable.millinats)
        self.assertEqual(incapable.supplied_pct, 100.0)
        self.assertLess(capable.supplied_pct, 100.0)
        self.assertLess(incapable.obtainable_millinats, capable.obtainable_millinats)
        self.assertFalse(self.credited(incapable, features.BIOMETRIC).obtainable)

    def test_the_reserved_features_never_count_as_withheld_on_any_vector(self):
        """Nothing a student does can supply them, so charging anybody for their
        absence would be charging for a procurement decision."""
        for vector in (self.vector(), self.relayed(), self.rejected()):
            fused = fusion.fuse(vector)
            for name in features.RESERVED_FEATURES:
                self.assertFalse(self.credited(fused, name).obtainable, name)


class MonotonicityTests(Case):
    """More evidence never scores less. Proved over the lattice, not asserted."""

    def lattice(self):
        """Every combination of the priced features, present or silent.

        Ten features, so 1024 vectors. Each one also has to survive
        `Fused.__post_init__`, which means the ordering invariant
        `0 <= millinats <= obtainable <= ceiling` is checked across the whole lattice
        as a side effect of building it.
        """
        priced = tuple(sorted(fusion.Weights.load().millinats))
        scores = {}
        for mask in range(1 << len(priced)):
            chosen = frozenset(
                name for index, name in enumerate(priced) if mask & (1 << index)
            )
            spec = {
                features.PLATFORM: {"value": "android"},
                features.QUEUE_AGE: {"value": 0},
            }
            for name in priced:
                if name in chosen:
                    spec[name] = {
                        "value": 3 if name == features.RELAY_DEPTH else True
                    }
                else:
                    spec[name] = {"absent": features.NOT_OBSERVED}
            scores[chosen] = fusion.fuse(self.synthetic(spec)).millinats
        return priced, scores

    def test_adding_any_one_observation_to_any_vector_never_lowers_the_score(self):
        priced, scores = self.lattice()
        for chosen, score in scores.items():
            for name in priced:
                if name in chosen:
                    continue
                richer = scores[chosen | {name}]
                self.assertGreaterEqual(
                    richer,
                    score,
                    "adding %s to %s lowered the score from %d to %d"
                    % (name, sorted(chosen) or ["nothing"], score, richer),
                )

    def test_the_empty_vector_scores_nothing_and_the_full_one_scores_the_ceiling(self):
        priced, scores = self.lattice()
        self.assertEqual(scores[frozenset()], 0)
        self.assertEqual(
            scores[frozenset(priced)],
            fusion.fuse(self.synthetic(COMPLETE)).ceiling_millinats,
        )

    def test_the_score_still_rises_when_the_new_observation_takes_the_lead(self):
        """The case the proof has to cover explicitly. Crediting a new leader in full
        demotes the old one to the discounted fraction, so the block total could in
        principle fall - it cannot, because the new leader is worth at least as much
        as the old one was and the old one keeps a positive share of its weight."""
        table = self.weights(values={fusion.WEIGHT_PREFIX + features.DEVICE: 10000})
        without = self.synthetic(
            COMPLETE, **{features.DEVICE: {"absent": features.NOT_OBSERVED}}
        )
        with_it = self.synthetic(COMPLETE)
        lower = fusion.fuse(without, weights=table)
        upper = fusion.fuse(with_it, weights=table)
        self.assertEqual(
            self.credited(lower, features.CHALLENGE).leading, True
        )
        self.assertEqual(self.credited(upper, features.DEVICE).leading, True)
        self.assertGreater(
            self.scored(upper, features.AUTHENTICATION).millinats,
            self.scored(lower, features.AUTHENTICATION).millinats,
        )

    def test_a_deeper_verified_chain_never_scores_below_a_shallower_one(self):
        """Per-hop pricing has to be monotone in the count as well as in presence,
        because relay depth is the one feature whose value is a quantity."""
        seen = [
            fusion.fuse(
                self.synthetic(COMPLETE, **{features.RELAY_DEPTH: {"value": depth}})
            ).millinats
            for depth in (0, 1, 2, 3, 99)
        ]
        self.assertEqual(seen, sorted(seen))
        # And clipped at the protocol bound, so a claimed 99 is worth exactly 3.
        self.assertEqual(seen[-1], seen[-2])


class PriorTests(Case):
    """A base rate is observed or it is declared absent. There is no third option."""

    def test_an_observed_rate_becomes_log_odds(self):
        prior = fusion.Prior.from_base_rate(6, 8)
        self.assertTrue(prior.determined)
        self.assertEqual(prior.base_rate_pct, 75.0)
        self.assertEqual(prior.log_odds_milli, 1099)
        self.assertEqual(prior.reason, "")

    def test_a_cohort_that_mostly_does_not_attend_yields_a_prior_below_even(self):
        """Worth stating on its own, because it is the one place a negative figure is
        correct. No *weight* may be negative - evidence is never subtracted - but a
        base rate under half genuinely argues against presence before any evidence
        is read, and clamping it at zero would be inventing optimism."""
        prior = fusion.Prior.from_base_rate(1, 100)
        self.assertTrue(prior.determined)
        self.assertLess(prior.log_odds_milli, 0)
        self.assertEqual(prior.log_odds_milli, -4595)

    def test_no_expected_sessions_yields_no_rate_rather_than_a_half(self):
        prior = fusion.Prior.from_base_rate(0, 0)
        self.assertFalse(prior.determined)
        self.assertIsNone(prior.base_rate_pct)
        self.assertIn("no observed rate", prior.reason)
        # The same refusal `metrics.safe_pct` makes everywhere else in the codebase,
        # rather than a second convention invented for this layer.
        self.assertIsNone(fusion.metrics.safe_pct(0, 0))

    def test_the_two_degenerate_rates_are_refused_and_not_clamped(self):
        """0% and 100% have infinite log odds. A large finite stand-in would be an
        assertion about how certain the base rate is, dressed as an estimate."""
        for present, expected, rate in ((0, 8, 0.0), (8, 8, 100.0)):
            prior = fusion.Prior.from_base_rate(present, expected)
            self.assertFalse(prior.determined)
            self.assertEqual(prior.base_rate_pct, rate)
            self.assertEqual(prior.log_odds_milli, 0)
            self.assertIn("no finite log odds", prior.reason)

    def test_counts_that_cannot_describe_one_cohort_are_an_error(self):
        with self.assertRaises(fusion.FusionError):
            fusion.Prior.from_base_rate(-1, 8)
        with self.assertRaises(fusion.FusionError):
            fusion.Prior.from_base_rate(3, -8)
        with self.assertRaises(fusion.FusionError):
            fusion.Prior.from_base_rate(9, 8)

    def test_an_undetermined_prior_describes_itself_without_a_number(self):
        """The audit row has to be readable as "there was no base rate" and not as
        "the base rate was zero", which is a different and much stronger claim."""
        body = fusion.Prior.from_base_rate(0, 0).describe()
        self.assertIsNone(body["log_odds_milli"])
        self.assertIsNone(body["base_rate_pct"])
        self.assertFalse(body["determined"])
        self.assertTrue(body["reason"])


class PosteriorTests(Case):
    """A confidence becomes a probability under two conditions, or it stays an order."""

    def calibrated(self):
        return self.weights(calibration=config.FIELD_VALIDATED)

    def test_a_calibrated_artifact_with_an_observed_prior_states_a_probability(self):
        fused = fusion.fuse(
            self.vector(),
            weights=self.calibrated(),
            prior=fusion.Prior.from_base_rate(6, 8),
        )
        self.assertFalse(fused.ordering_only)
        self.assertEqual(fused.ordering_reason, "")
        self.assertEqual(fused.posterior_milli, 976)

    def test_an_uncalibrated_artifact_withholds_the_posterior_and_says_so(self):
        """§23. The shipped artifact is uncalibrated, so this is the branch that runs
        in production today - which is why the reason string names the artifact."""
        fused = fusion.fuse(self.vector(), prior=fusion.Prior.from_base_rate(6, 8))
        self.assertTrue(fused.ordering_only)
        self.assertIsNone(fused.posterior_milli)
        self.assertIn(config.UNCALIBRATED, fused.ordering_reason)
        self.assertIn(config.DEFAULT_VERSION, fused.ordering_reason)
        self.assertIn("is not a probability", fused.ordering_reason)

    def test_a_missing_prior_withholds_the_posterior_rather_than_assuming_one(self):
        fused = fusion.fuse(self.vector(), weights=self.calibrated())
        self.assertTrue(fused.ordering_only)
        self.assertIsNone(fused.posterior_milli)
        self.assertIn("no prior was supplied", fused.ordering_reason)
        self.assertIn("artifact of the assumption", fused.ordering_reason)

    def test_an_undetermined_prior_withholds_the_posterior_and_carries_its_reason(self):
        """The refusal propagates. A prior that could not be computed must not become
        a posterior that looks computed."""
        prior = fusion.Prior.from_base_rate(8, 8)
        fused = fusion.fuse(self.vector(), weights=self.calibrated(), prior=prior)
        self.assertTrue(fused.ordering_only)
        self.assertIsNone(fused.posterior_milli)
        self.assertIn("the prior is undetermined", fused.ordering_reason)
        self.assertIn(prior.reason, fused.ordering_reason)

    def test_the_two_tails_saturate_into_range_instead_of_overflowing(self):
        """`math.exp` on a large log-odds figure would raise; the branch that avoids
        it is only exercised by a prior no cohort produces, so it is exercised here
        by hand rather than left to be discovered in a stack trace."""
        for extreme, expect in ((10 ** 7, 1000), (-(10 ** 7), 0)):
            prior = fusion.Prior(
                log_odds_milli=extreme,
                observed_present=1,
                observed_expected=2,
                determined=True,
                base_rate_pct=50.0,
            )
            fused = fusion.fuse(
                self.vector(), weights=self.calibrated(), prior=prior
            )
            self.assertEqual(fused.posterior_milli, expect)

    def test_a_posterior_and_an_ordering_only_flag_cannot_both_be_held(self):
        """Two fields that could disagree are two fields a caller could read the
        wrong one of. The dataclass refuses the combination at construction."""
        fused = fusion.fuse(self.vector())
        with self.assertRaises(fusion.FusionError):
            replace(fused, posterior_milli=900, ordering_only=True)
        with self.assertRaises(fusion.FusionError):
            replace(fused, posterior_milli=None, ordering_only=False)

    def test_a_high_posterior_over_thin_coverage_is_reported_as_both(self):
        """The honest reading of a calibrated figure on this build: near-certain
        given what was collected, resting on about a quarter of the designed
        evidence. Both numbers survive into `describe`, because a posterior quoted
        without its coverage is the claim this scope is not allowed to make."""
        body = fusion.fuse(
            self.vector(),
            weights=self.calibrated(),
            prior=fusion.Prior.from_base_rate(6, 8),
        ).describe()
        self.assertGreater(body["posterior_milli"], 900)
        self.assertLess(body["coverage_pct"], 35.0)
        self.assertEqual(body["calibration"], config.FIELD_VALIDATED)


class ClaimTests(Case):
    """§39, as arithmetic and as structure. A proof does not get to grade itself."""

    def test_a_proof_that_awards_itself_everything_scores_what_a_modest_one_scores(self):
        boastful = fusion.fuse(
            self.vector(
                self.signed(claims=proof.Claims(
                    status=proof.STATUS_PRESENT,
                    confidence_milli=1000,
                    hop_count=99,
                ))
            )
        )
        modest = fusion.fuse(self.vector())
        self.assertEqual(boastful.millinats, modest.millinats)
        self.assertEqual(boastful.obtainable_millinats, modest.obtainable_millinats)
        self.assertEqual(boastful.ceiling_millinats, modest.ceiling_millinats)
        self.assertEqual(boastful.posterior_milli, modest.posterior_milli)
        self.assertEqual(boastful.signals, modest.signals)

    def test_a_claimed_hop_count_cannot_buy_depth_the_chain_did_not_carry(self):
        """The clip is at the protocol bound rather than at some fusion-local number,
        so a chain cannot be worth more here than `chain` was willing to accept."""
        claimed = fusion.fuse(
            self.synthetic(COMPLETE, **{features.RELAY_DEPTH: {"value": 99}})
        )
        allowed = fusion.fuse(
            self.synthetic(
                COMPLETE, **{features.RELAY_DEPTH: {"value": chain.max_hops()}}
            )
        )
        self.assertEqual(claimed.millinats, allowed.millinats)
        self.assertEqual(
            self.credited(claimed, features.RELAY_DEPTH).units, chain.max_hops()
        )

    def test_the_module_cannot_read_a_claim_because_it_never_imports_proof(self):
        """Stronger than a test that a claim is ignored, which would only cover the
        paths a test happens to walk. `fusion` has no name for `proof` at all, so
        nothing a client asserts about itself is reachable from the arithmetic."""
        source = pathlib.Path(fusion.__file__).read_text(encoding="utf-8")
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
        self.assertNotIn("proof", imported)
        self.assertIn("features", imported)
        self.assertIn("config", imported)


class NonEvidentialTests(Case):
    """Two features are recorded and never priced. They must not leak a weight."""

    def test_the_unpriced_features_have_no_weight_to_read(self):
        table = fusion.Weights.load()
        for name in (features.PLATFORM, features.QUEUE_AGE):
            self.assertIn(name, features.FEATURES)
            self.assertNotIn(name, table.millinats)

    def test_they_produce_no_contribution_row_in_any_block(self):
        """Not a zero row. A zero would say "considered and worth nothing", which is
        wrong: the platform a proof came from is context for reading the other
        features, and the queue age is a replay bound. Neither is evidence of being
        in a room, and giving either an audit row would invite a later weight."""
        fused = fusion.fuse(self.synthetic(COMPLETE))
        priced = {
            contribution.feature
            for block in fused.blocks
            for contribution in block.contributions
        }
        self.assertNotIn(features.PLATFORM, priced)
        self.assertNotIn(features.QUEUE_AGE, priced)
        self.assertEqual(priced, set(fusion.Weights.load().millinats))

    def test_changing_the_platform_does_not_change_the_score(self):
        android = fusion.fuse(self.synthetic(COMPLETE))
        web = fusion.fuse(
            self.synthetic(COMPLETE, **{features.PLATFORM: {"value": "web"}})
        )
        self.assertEqual(android.millinats, web.millinats)
        self.assertEqual(android.ceiling_millinats, web.ceiling_millinats)


class RefusalTests(Case):
    """What the arithmetic will not weigh at all. Every one of these fails closed."""

    def stand_in(self, **over):
        """A vector-shaped object that is not a vector.

        `Evidence` enforces completeness in its own constructor, so an incomplete
        one cannot be built - which is exactly why `fuse` re-checks against a
        stand-in rather than trusting its argument's type. A caller assembling a
        mapping by hand is the realistic way an incomplete vector arrives.
        """
        class NotQuiteEvidence(object):
            def __init__(self, mapping):
                self.features = mapping
                self.config_version = ""
                self.signals = ()

        real = self.synthetic(COMPLETE)
        mapping = dict(real.features)
        mapping.update(over)
        for name in [key for key, value in over.items() if value is None]:
            mapping.pop(name, None)
        return NotQuiteEvidence(mapping)

    def test_a_vector_with_a_feature_left_out_is_refused_and_not_scored_low(self):
        """The failure mode worth spending a check on. A missing feature scored as
        absent would look like a modest but valid proof, and the difference between
        "the anchor said nothing" and "nobody asked the anchor" would vanish."""
        with self.assertRaises(fusion.FusionError) as caught:
            fusion.fuse(self.stand_in(**{features.CHALLENGE: None}))
        self.assertIn(features.CHALLENGE, str(caught.exception))
        self.assertIn("score as a modest one", str(caught.exception))

    def test_a_vector_carrying_a_feature_nobody_declared_is_refused(self):
        with self.assertRaises(fusion.FusionError) as caught:
            fusion.fuse(self.stand_in(invented_feature=object()))
        self.assertIn("invented_feature", str(caught.exception))

    def test_a_vector_extracted_under_another_artifact_is_refused(self):
        """§48 at the boundary between two layers. Scoring a vector against weights
        it was not extracted under would produce a figure no version could explain,
        and the audit trail's whole purpose is that a verdict can be re-derived."""
        vector = replace(self.synthetic(COMPLETE), config_version="2020.01-other")
        with self.assertRaises(fusion.FusionError) as caught:
            fusion.fuse(vector)
        message = str(caught.exception)
        self.assertIn("2020.01-other", message)
        self.assertIn(config.DEFAULT_VERSION, message)
        self.assertIn("cannot name one configuration", message)

    def test_a_per_unit_feature_whose_value_is_not_a_count_is_a_bug_not_a_guess(self):
        for value in (True, "three", 2.5):
            with self.assertRaises(fusion.FusionError) as caught:
                fusion.fuse(
                    self.synthetic(
                        COMPLETE, **{features.RELAY_DEPTH: {"value": value}}
                    )
                )
            self.assertIn("must be a count", str(caught.exception))

    def test_a_negative_hop_count_is_refused_rather_than_clamped_to_zero(self):
        with self.assertRaises(fusion.FusionError) as caught:
            fusion.fuse(
                self.synthetic(COMPLETE, **{features.RELAY_DEPTH: {"value": -2}})
            )
        self.assertIn("negative count", str(caught.exception))

    def test_a_credit_of_full_independence_cannot_be_loaded_at_all(self):
        """The naive assumption is not a configuration option.

        Asserted against the declaration rather than against a loaded artifact,
        because the declaration is where the bound lives and `Parameter.check` is
        the gate every parameter of every artifact passes through on the way in. A
        widened bound would slip past a test that only ever loaded the shipped file.
        """
        declared = config.PARAMETERS["fusion.correlated_credit_pct"]
        self.assertLess(declared.maximum, 100)
        self.assertGreater(declared.minimum, 0)
        with self.assertRaises(config.ConfigError) as caught:
            declared.check("fusion.correlated_credit_pct", 100)
        self.assertIn("above the declared maximum", str(caught.exception))
        with self.assertRaises(config.ConfigError):
            declared.check("fusion.correlated_credit_pct", 0)

    def test_no_weight_may_be_declared_worthless(self):
        """A zero would mean "declared and worthless", which is better said by not
        declaring the feature as evidence at all - and it would also leave the config
        hygiene sweep unable to tell a tuned value from the integer zero."""
        for name in fusion.Weights.load().millinats:
            declared = config.PARAMETERS[fusion.WEIGHT_PREFIX + name]
            self.assertGreaterEqual(declared.minimum, 1)
            with self.assertRaises(config.ConfigError):
                declared.check(fusion.WEIGHT_PREFIX + name, 0)
            with self.assertRaises(config.ConfigError):
                declared.check(fusion.WEIGHT_PREFIX + name, -1)


# A signal strength no room would coincidentally produce twice, so that finding it
# anywhere in the audit body is unambiguous rather than a suspicious-looking integer.
RSSI_MARKER = -73


class PrivacyTests(Case):
    """Privacy at the audit boundary: what reaches a record, and what never can."""

    def audited(self):
        """The richest vector this build can assemble, plus the identifiers in it."""
        marker = bytes(range(proof.NONCE_LEN))
        seen = self.sighting(rssi=RSSI_MARKER)
        bodies = (seen.encode(),) + chain.encode_chain(
            self.hops(chain.root_link(seen.encode()))
        )
        body = self.signed(observations=bodies, capabilities=CAPABLE, nonce=marker)
        fused = fusion.fuse(
            self.vector(body, observations=bodies, resolve_relay=self.cohort())
        )
        return marker, bodies, fused

    def test_the_audit_body_is_json_native_so_no_raw_bytes_can_ride_along(self):
        """Dumped without a fallback encoder on purpose. A default encoder would
        quietly stringify a key id or a nonce into the record and the leak would look
        like a formatting detail; without one, any bytes field fails immediately."""
        marker, bodies, fused = self.audited()
        json.dumps(fused.describe())

    def test_no_identifier_from_the_proof_survives_into_the_audit_body(self):
        marker, bodies, fused = self.audited()
        text = json.dumps(fused.describe())
        secrets = {
            "session id": SESSION_ID,
            "device key id": self.device.public().key_id,
            "proof nonce": marker,
        }
        for index, digest in enumerate(proof.observation_digests(*bodies)):
            secrets["observation digest %d" % (index,)] = digest
        for label, raw in secrets.items():
            self.assertNotIn(raw.hex(), text, "%s reached the audit body" % (label,))
            self.assertNotIn(str(raw), text, "%s reached the audit body" % (label,))

    def test_no_signal_strength_reaches_the_audit_body(self):
        """The scoring rules read as a privacy claim. Recorded signal strengths are
        carried for room calibration and are never read during fusion, so a figure
        appearing here would mean either a leak or a threshold."""
        marker, bodies, fused = self.audited()
        found = []

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    found.append(key)
                    walk(value)
            elif isinstance(node, (list, tuple)):
                for value in node:
                    walk(value)
            else:
                found.append(node)

        walk(fused.describe())
        self.assertNotIn(RSSI_MARKER, found)
        self.assertNotIn(str(RSSI_MARKER), found)
        self.assertNotIn("rssi", json.dumps(fused.describe()))

    def test_the_audit_body_says_what_was_weighed_without_saying_who(self):
        """The record has to be enough to re-derive the figure and not enough to
        rebuild a movement history: feature names, weights and reasons, with no
        identifiers, no observations and no positions."""
        marker, bodies, fused = self.audited()
        body = fused.describe()
        weighed = {
            contribution["feature"]
            for block in body["blocks"]
            for contribution in block["contributions"]
        }
        self.assertEqual(weighed, set(fusion.Weights.load().millinats))
        self.assertEqual(body["millinats"], fused.millinats)
        self.assertEqual(body["config_version"], config.DEFAULT_VERSION)


class VerdictTests(Case):
    """Fusion scores and does not rule. Structural, so it cannot drift back."""

    FORBIDDEN = ("status", "verdict", "decision", "threshold")

    def test_no_field_of_the_result_could_be_mistaken_for_a_ruling(self):
        for name in fusion.Fused.__dataclass_fields__:
            for word in self.FORBIDDEN:
                self.assertNotIn(word, name)

    def test_no_key_of_the_audit_body_could_be_mistaken_for_a_ruling(self):
        seen = []

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    seen.append(key)
                    walk(value)
            elif isinstance(node, (list, tuple)):
                for value in node:
                    walk(value)

        walk(fusion.fuse(self.relayed()).describe())
        self.assertTrue(seen)
        for key in seen:
            for word in self.FORBIDDEN:
                self.assertNotIn(word, key)

    def test_the_configuration_declares_no_fusion_threshold_to_compare_against(self):
        """A threshold in the same artifact as the weights would let a policy change
        arrive disguised as a scoring change. Operating points do exist now - they
        are the four `decide.*` parameters - and what this asserts is that not one of
        them is a `fusion.*` parameter. Nothing this module reads is a comparison
        target, so a review of a weight change is a review of evidence pricing and
        never accidentally a review of who gets marked present."""
        for name in config.PARAMETERS:
            self.assertNotIn("threshold", name)
        priced = {n for n in config.PARAMETERS if n.startswith("fusion.")}
        points = {n for n in config.PARAMETERS if n.startswith(decide.PARAMETER_PREFIX)}
        self.assertTrue(priced and points)
        self.assertEqual(priced & points, set())
        for field in set(decide.Policy.__dataclass_fields__) - {"config_version"}:
            self.assertNotIn("fusion." + field, config.PARAMETERS)

    def test_the_module_names_no_status_and_compares_against_no_threshold(self):
        """Read from the syntax tree rather than from the text, so that the prose -
        which discusses thresholds at length in order to refuse them - cannot make
        the test pass or fail for the wrong reason."""
        tree = ast.parse(pathlib.Path(fusion.__file__).read_text(encoding="utf-8"))
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                identifier = node.id
            elif isinstance(node, ast.Attribute):
                identifier = node.attr
            else:
                continue
            for word in self.FORBIDDEN:
                if word in identifier.lower():
                    offenders.append(identifier)
        self.assertEqual(offenders, [])


class SourceTests(Case):
    """The config rules read at the syntax level: the module holds no tuned number."""

    def literals(self):
        tree = ast.parse(pathlib.Path(fusion.__file__).read_text(encoding="utf-8"))
        return [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, (int, float))
            and not isinstance(node.value, bool)
        ]

    def test_the_module_contains_no_floating_point_literal_at_all(self):
        """The only way to be sure the default prior of one half did not creep back
        in as a fallback. The prose mentions that number twice in order to deny it,
        so a text search would find those two and pass for the wrong reason."""
        self.assertEqual(
            [value for value in self.literals() if isinstance(value, float)], []
        )

    def test_every_integer_literal_is_structural_rather_than_tuned(self):
        """0 and 1 are arithmetic, 100 is what a percentage is out of, and 1000 is
        what a millinat is a thousandth of. Every weight, cap and credit comes from
        the artifact, so any other number here is a tuned value that has escaped the
        registry - which is the sweep this test performs on one file at close range."""
        self.assertEqual(set(self.literals()), {0, 1, 100, 1000})

    def test_every_weight_the_module_uses_comes_from_a_declared_parameter(self):
        table = fusion.Weights.load()
        for name in table.millinats:
            self.assertIn(fusion.WEIGHT_PREFIX + name, config.PARAMETERS)
        self.assertEqual(
            table.block_cap_millinats, config.get("fusion.block_cap_millinats")
        )
        self.assertEqual(
            table.correlated_credit_pct,
            config.get("fusion.correlated_credit_pct"),
        )
