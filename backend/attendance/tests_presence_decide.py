"""What a verdict is allowed to be, checked against verdicts the real gate produced.

`decide` is the only module in this package that encodes an institutional choice
rather than a fact, so these tests are less about arithmetic than about whether the
choices are the ones the design says they are. Eleven claims:

**The operating points live in the artifact** (`PolicyTests`). Not one of them is a
literal in `decide.py`, the review band cannot be inverted, and a present point set
where no evidence could reach it fails the activation cross-check rather than
silently making PRESENT impossible.

**All four verdicts are reachable, and one of them is not reachable the way you
would expect** (`RoutingTests`). A complete authentication block is PRESENT; a
handset with no biometric hardware is SECONDARY; a capture claim two minutes ahead of
the server is SUSPICIOUS. NOT VERIFIED on the admitted path is not reachable at all
on this artifact, because the gate mandates identity, device binding and a live
challenge, and those three together already clear the review band. That is asserted
rather than glossed: on this build a proof fails by being refused, and the refusal
path is where NOT VERIFIED actually comes from.

**A local check that came back negative does not mark anybody present**
(`BiometricTests`). FAILED and CANCELLED route to review, SUCCESS is the only
affirmative outcome, and an outcome that never ran is not charged a second time on
top of the weight it did not earn. None of the three is SUSPICIOUS - the wet thumb
is not an accusation.

**A high score over thin coverage is not PRESENT** (`CoverageTests`). The obligation
`fuse` hands over in as many words, tested by raising the floor above what this build
can reach and watching a flawless proof land in review.

**Nothing adverse ever accuses** (`AdverseTests`). An origin frame that arrived and
did not verify scores exactly what silence scores and differs only in the reason list
- because a rogue device can put a foreign frame in front of any handset in radio
range, and a scheme where that denies attendance is a scheme with a remote off switch.

**Suspicion is reserved for self-contradiction** (`ContradictionTests`). Each of the
four contradictory signals routes to SUSPICIOUS, each of the three merely noted ones
does not, and the two sets are asserted to partition `gates.SIGNALS` so a new signal
cannot arrive unclassified.

**Every refusal has exactly one shape** (`RefusalTests`). The classification is
proved total against `gates.REASON_CODES`, forgery-shaped codes reach review as
SUSPICIOUS, late-and-honest ones as NOT VERIFIED, the reason reported is the gate's
own code unaltered, and the one code a caller should answer idempotently says so.

**A claim cannot become a verdict** (`ClaimTests`). `decide` refuses a `Cleared`
outright, and an AST sweep shows the only names it reads from `proof` are the two
wire vocabularies - no claimed status, no claimed confidence, no claimed hop count.

**A decision that cannot be stated is refused** (`InvariantTests`), the same way a
vector that cannot be explained is refused one layer down.

**An audit row records what was weighed, not who was there** (`PrivacyTests`).

**No tuned number and no undeclared reason code is inlined** (`SourceTests`).
"""
import ast
import json
import pathlib

from dataclasses import replace

from .presence import (
    chain,
    challenge,
    config,
    decide,
    features,
    fusion,
    gates,
    origin,
    proof,
    replay,
)
from .tests_presence_features import SESSION_ID
from .tests_presence_fusion import (
    CAPABLE,
    COMPLETE,
    RSSI_MARKER,
    SCOPE,
    Case as FusionCase,
)

# What a handset this build can actually ship declares: a keystore to hold the
# signing key and, where the platform has one, a biometric prompt. No BLE bit,
# because the app has no radio code at all on this scope - which is the honest
# capability declaration and the reason a real student is not charged for the
# network evidence that does not exist yet.
SHIPPABLE = proof.CAP_BIOMETRIC | proof.CAP_HARDWARE_KEYSTORE
NO_BIOMETRIC = proof.CAP_HARDWARE_KEYSTORE


class Case(FusionCase):
    """The fusion fixture, plus the two things a policy test needs beyond a score."""

    def verdict(self, vector, biometric=proof.BIOMETRIC_SUCCESS, policy=None, **fuse):
        """Score a vector and rule on it, in one step, through the real functions."""
        return decide.decide(
            fusion.fuse(vector, **fuse), biometric=biometric, policy=policy
        )

    def shippable(self, **over):
        """A vector from a proof this build could actually produce today.

        The capability word is `SHIPPABLE`, not the fixture's `CAPABLE`: a real
        client declares a keystore and a biometric prompt and says nothing about
        radio, because there is no radio code in the app. That distinction is the
        whole of `supplied_pct` - a handset that never claimed BLE is not charged
        for the BLE evidence it did not send.
        """
        return self.vector(self.signed(capabilities=SHIPPABLE, **over))

    def floor(self):
        """The thinnest vector the gate can admit: identity, device, challenge.

        Not a hypothetical. `gates` mandates all three, so no admitted proof can
        carry less, which makes this the arithmetic floor of the whole admitted
        path. Built synthetically because the honest absences here - no biometric
        hardware and a handset whose clock check could not run - do not co-occur in
        any single fixture proof.
        """
        thinned = dict(SCOPE)
        thinned[features.BIOMETRIC] = {"absent": features.UNSUPPORTED}
        thinned[features.CLOCK_CONSISTENCY] = {"absent": features.UNSUPPORTED}
        return self.synthetic(thinned)

    def flawless(self):
        """Every feature carrying a value, including the two nothing can populate."""
        return self.synthetic(COMPLETE)

    def signalled(self, *signals, vector=None):
        """A real score with signals substituted, for routing one signal at a time.

        `ContradictionTests` reaches every classified signal this way and then
        proves the end-to-end path separately with a claim the real gate flags, so
        the substitution is a way to enumerate rather than a way to avoid the gate.
        """
        return replace(fusion.fuse(vector or self.flawless()), signals=tuple(signals))


class PolicyTests(Case):
    """Where a score becomes a verdict is a policy choice, so it lives in the artifact."""

    def test_every_operating_point_is_read_from_the_artifact(self):
        live = config.active()
        loaded = decide.Policy.load()
        for field in (
            "present_millinats",
            "secondary_millinats",
            "min_coverage_pct",
            "min_supplied_pct",
        ):
            self.assertEqual(
                getattr(loaded, field),
                live[decide.PARAMETER_PREFIX + field],
                field,
            )
        self.assertEqual(loaded.config_version, live.version)

    def test_a_missing_operating_point_fails_to_load_rather_than_defaulting(self):
        """A default here would be the same mistake as a default weight and worse:
        the number that decides who is marked present would be the one number
        nobody signed off on."""
        for field in ("present_millinats", "min_coverage_pct"):
            self.assertIn(decide.PARAMETER_PREFIX + field, config.PARAMETERS)
            self.assertNotIn(
                "None", repr(config.PARAMETERS[decide.PARAMETER_PREFIX + field])
            )

    def test_the_review_band_is_ordered(self):
        loaded = decide.Policy.load()
        self.assertLess(loaded.secondary_millinats, loaded.present_millinats)

    def test_an_inverted_review_band_fails_activation(self):
        """Not a comment about how to configure it: the cross-check refuses. With
        the two points equal there is no band at all, and SECONDARY - the verdict
        the whole degraded-platform design routes to - would stop existing."""
        equal = config.active()["decide.present_millinats"]
        for wrong in (equal, 20000):
            config.set_active(
                self.artifact({"decide.secondary_millinats": wrong})
            )
            problems = config.cross_check()
            self.assertTrue(
                any("secondary_millinats" in one for one in problems),
                (wrong, problems),
            )

    def test_a_present_point_no_evidence_could_reach_fails_activation(self):
        """The failure mode this catches is silent: PRESENT would simply never be
        returned, every genuine student would land in review, and the log would
        show a working system making a defensible-looking choice every time."""
        reachable = sum(
            value
            for name, value in config.active().values.items()
            if name.startswith(fusion.WEIGHT_PREFIX)
        )
        config.set_active(
            self.artifact({"decide.present_millinats": reachable + 1})
        )
        problems = config.cross_check()
        self.assertTrue(
            any("present_millinats" in one for one in problems), problems
        )

    def test_the_live_artifact_activates_clean(self):
        self.assertEqual(config.cross_check(), ())


class RoutingTests(Case):
    """All four verdicts, and an honest account of how the fourth is reached."""

    def test_a_complete_authentication_block_is_present(self):
        """The whole point of the exercise: a student who authenticated, on their
        own bound device, against a live challenge, with a biometric that answered
        yes, is marked present without a human looking at it."""
        ruled = self.verdict(self.shippable())
        self.assertEqual(ruled.status, decide.PRESENT)
        self.assertEqual(ruled.status_name, "present")
        self.assertEqual(ruled.reasons, ())
        self.assertFalse(ruled.refused)

    def test_a_handset_with_no_biometric_hardware_is_secondary(self):
        """Decision 3 in one test. The score is lower because a weight went
        uncredited, not because anything was held against the student, and the only
        reason given is the arithmetic one."""
        ruled = self.verdict(
            self.vector(
                self.signed(
                    capabilities=NO_BIOMETRIC, biometric=proof.BIOMETRIC_ABSENT
                )
            ),
            biometric=proof.BIOMETRIC_ABSENT,
        )
        self.assertEqual(ruled.status, decide.SECONDARY)
        self.assertEqual(ruled.reasons, (decide.BELOW_PRESENT,))
        self.assertNotIn(decide.BIOMETRIC_NOT_AFFIRMATIVE, ruled.reasons)
        self.assertEqual(
            ruled.evidence_missing[features.BIOMETRIC], features.UNSUPPORTED
        )

    def test_a_capture_claim_ahead_of_the_server_is_suspicious(self):
        """End to end through the real gate, not a substituted signal. The proof is
        otherwise flawless: correct session, live challenge, valid signature, real
        biometric. It claims to have been captured after the server received it,
        and two impeccable halves that disagree about time is the one thing this
        design is willing to call suspicious."""
        skew = config.get("proof.max_future_skew_seconds")
        for ahead, expected in ((0, decide.PRESENT), (skew, decide.PRESENT),
                                (skew + 1, decide.SUSPICIOUS)):
            got = self.verdict(
                self.vector(
                    self.signed(captured_at=self.at() + ahead), received_at=self.at()
                )
            )
            self.assertEqual(got.status, expected, ahead)
        self.assertEqual(got.reasons, (decide.SELF_CONTRADICTION,))
        self.assertEqual(got.contradictions, (replay.SIGNAL_FUTURE_CLAIM,))

    def test_no_proof_the_gate_admits_can_fall_below_the_review_band(self):
        """Stated rather than hidden: on this artifact NOT VERIFIED is unreachable
        on the admitted path.

        `gates` mandates identity, device binding and a live challenge, so the
        thinnest admissible vector already scores 1960 against a review point of
        1000. That is not an accident to be corrected - it is what it means for
        those three to be mandatory. A proof on this build fails by being refused,
        and `RefusalTests` is where NOT VERIFIED actually comes from.
        """
        thinnest = fusion.fuse(self.floor())
        band = decide.Policy.load()
        self.assertGreaterEqual(thinnest.millinats, band.secondary_millinats)
        self.assertEqual(
            self.verdict(self.floor(), biometric=proof.BIOMETRIC_ABSENT).status,
            decide.SECONDARY,
        )

    def test_the_thinnest_admissible_proof_still_clears_the_coverage_floor(self):
        """The tightest margin in the artifact, asserted so a weight change cannot
        quietly close it.

        A client that can only supply authentication and a clock covers 20.3
        percent of the evidence base against a floor of 20. Raise a spatial weight
        and that fraction falls, at which point every genuine student on every
        shipped handset lands in review at once and the reason code says the
        evidence was too thin rather than that the artifact moved.
        """
        thinnest = fusion.fuse(self.floor())
        floor = decide.Policy.load().min_coverage_pct
        self.assertIsNotNone(thinnest.coverage_pct)
        self.assertGreaterEqual(thinnest.coverage_pct, floor)
        self.assertLess(thinnest.coverage_pct, floor + 1)

    def test_a_verdict_below_the_review_band_is_not_verified(self):
        """Reached by raising the band rather than by weakening a proof, because no
        proof this build admits can get under it. The routing itself still has to
        be exercised: a future artifact with spatial weights in force makes this
        band reachable, and the reason list must drop the redundant below-present
        code rather than report both."""
        raised = replace(
            decide.Policy.load(), secondary_millinats=9000, present_millinats=9500
        )
        ruled = self.verdict(self.shippable(), policy=raised)
        self.assertEqual(ruled.status, decide.NOT_VERIFIED)
        self.assertIn(decide.BELOW_SECONDARY, ruled.reasons)
        self.assertNotIn(decide.BELOW_PRESENT, ruled.reasons)

    def test_the_four_statuses_are_the_wire_vocabulary_and_nothing_else(self):
        """A verdict the client cannot name is a verdict nobody can act on."""
        for status in (decide.PRESENT, decide.SECONDARY, decide.NOT_VERIFIED,
                       decide.SUSPICIOUS):
            self.assertIn(status, proof.STATUS_NAMES)
        self.assertNotIn(
            proof.STATUS_UNKNOWN,
            {decide.PRESENT, decide.SECONDARY, decide.NOT_VERIFIED,
             decide.SUSPICIOUS},
        )


class BiometricTests(Case):
    """A local check that came back negative does not mark anybody present."""

    def test_success_is_the_only_affirmative_outcome(self):
        self.assertEqual(
            decide.AFFIRMATIVE_BIOMETRIC, frozenset({proof.BIOMETRIC_SUCCESS})
        )

    def test_a_failed_or_cancelled_check_routes_to_review(self):
        """`features` files a failed check as a value rather than an absence and
        `fusion` credits it in full, both for the same good reason: a wet thumb must
        not be indistinguishable from a forged proof. Neither layer is entitled to
        say that an unauditable local check which answered no should clear a student
        unattended. That is a policy question, so it is answered here."""
        for outcome in (proof.BIOMETRIC_FAILED, proof.BIOMETRIC_CANCELLED):
            ruled = self.verdict(
                self.vector(self.signed(capabilities=SHIPPABLE, biometric=outcome)),
                biometric=outcome,
            )
            self.assertEqual(ruled.status, decide.SECONDARY, outcome)
            self.assertIn(decide.BIOMETRIC_NOT_AFFIRMATIVE, ruled.reasons)

    def test_a_negative_check_is_never_an_accusation(self):
        """The humane half of the same rule. A student whose fingerprint would not
        read stands in front of the teacher and gets looked at; they are not
        recorded as having attempted a fraud."""
        for outcome in (proof.BIOMETRIC_FAILED, proof.BIOMETRIC_CANCELLED,
                        proof.BIOMETRIC_ABSENT):
            ruled = self.verdict(
                self.vector(self.signed(capabilities=SHIPPABLE, biometric=outcome)),
                biometric=outcome,
            )
            self.assertNotEqual(ruled.status, decide.SUSPICIOUS, outcome)
            self.assertEqual(ruled.contradictions, ())

    def test_an_outcome_that_never_ran_is_not_charged_twice(self):
        """ABSENT is deliberately outside the affirmative set and deliberately
        outside the penalty: the score already reflects a weight that went
        uncredited, and adding a reason code on top would charge a handset twice for
        lacking hardware it cannot grow."""
        ruled = self.verdict(
            self.vector(
                self.signed(
                    capabilities=NO_BIOMETRIC, biometric=proof.BIOMETRIC_ABSENT
                )
            ),
            biometric=proof.BIOMETRIC_ABSENT,
        )
        self.assertNotIn(decide.BIOMETRIC_NOT_AFFIRMATIVE, ruled.reasons)

    def test_the_outcome_is_a_required_keyword(self):
        """A caller who forgets it gets a TypeError, not a silent present for a
        check that came back negative. This is the argument the module docstring
        makes about the signature being the security property, as a test."""
        with self.assertRaises(TypeError):
            decide.decide(fusion.fuse(self.shippable()))

    def test_an_unnamed_outcome_is_refused_rather_than_read_as_absent(self):
        """The four outcomes are a closed wire vocabulary. A fifth integer means the
        caller and this module disagree about what they are saying, and the only safe
        reading of that is none of them."""
        for wrong in (-1, 4, 99, "success", None):
            with self.assertRaises(decide.DecisionError):
                decide.decide(fusion.fuse(self.shippable()), biometric=wrong)

    def test_a_bool_is_refused_although_it_would_have_worked(self):
        """The one wrong argument that would not have looked wrong. True equals
        SUCCESS by integer accident and would have been accepted; False equals
        ABSENT, which would have turned a check that answered no into a check that
        never ran and dropped the reason code on the way. A caller passing a bool
        here has confused an outcome with a yes, and the failure should be loud
        while it is still cheap."""
        for wrong in (True, False):
            with self.assertRaises(decide.DecisionError):
                decide.decide(fusion.fuse(self.shippable()), biometric=wrong)


class CoverageTests(Case):
    """A high score over thin evidence is not PRESENT."""

    def test_a_flawless_proof_over_thin_coverage_lands_in_review(self):
        """The obligation `fuse` hands over in as many words: a posterior says
        nothing about how much of the evidence base existed. Tested by raising the
        floor above what this build can reach, since on this scope the spatial block
        is empty by construction and the only honest thing to do with a coverage rule
        is to state it and let it bind."""
        demanding = replace(decide.Policy.load(), min_coverage_pct=50)
        scored = fusion.fuse(self.shippable())
        ruled = decide.decide(
            scored, biometric=proof.BIOMETRIC_SUCCESS, policy=demanding
        )
        self.assertGreaterEqual(scored.millinats, demanding.present_millinats)
        self.assertEqual(ruled.status, decide.SECONDARY)
        self.assertEqual(ruled.reasons, (decide.COVERAGE_TOO_THIN,))

    def test_a_handset_that_claimed_a_radio_and_showed_nothing_is_reviewed(self):
        """The discrimination `supplied_pct` exists for, and the one place this scope
        can still tell two students apart. An old phone that never claimed BLE
        supplies everything it declared and reads 100 percent. A handset that
        declared a scanner and produced no sighting supplies less than half of what
        it said it could - the shape of a student at the window, and of a student
        holding the radio off."""
        withholding = fusion.fuse(self.quiet())
        honest = fusion.fuse(self.shippable())
        self.assertEqual(withholding.millinats, honest.millinats)
        self.assertEqual(honest.supplied_pct, 100.0)
        self.assertLess(withholding.supplied_pct, honest.supplied_pct)
        ruled = decide.decide(withholding, biometric=proof.BIOMETRIC_SUCCESS)
        self.assertEqual(ruled.status, decide.SECONDARY)
        self.assertEqual(ruled.reasons, (decide.SUPPLIED_TOO_THIN,))

    def test_a_fraction_that_could_not_be_computed_is_not_read_as_passing(self):
        """`safe_pct` returns None on a zero denominator rather than inventing a
        number, and `_meets` reads None as a failure. The alternative - treating an
        uncomputable fraction as satisfying its own floor - is how a check that cannot
        run turns into a check that always passes."""
        self.assertFalse(decide._meets(None, 20))
        self.assertFalse(decide._meets(19.9, 20))
        self.assertTrue(decide._meets(20.0, 20))

    def test_both_fractions_are_reported_on_every_decision(self):
        """A reviewer looking at a SECONDARY needs to know which of the two thin
        things it was, and a reviewer looking at a PRESENT needs to know how much of
        the design was behind it."""
        ruled = self.verdict(self.shippable())
        self.assertIsNotNone(ruled.coverage_pct)
        self.assertIsNotNone(ruled.supplied_pct)
        self.assertEqual(ruled.supplied_pct, 100.0)


class AdverseTests(Case):
    """Nothing adverse ever accuses, and nothing adverse ever subtracts."""

    def test_a_frame_that_arrived_and_failed_scores_what_silence_scores(self):
        """A rogue device can put a foreign but well-formed origin frame in front of
        any handset in radio range. If that denied attendance, the scheme would ship
        with a remote off switch, so the frame is worth exactly what having seen
        nothing is worth - and the difference appears in the reason list, where a
        human can act on it, rather than in the score, where an attacker could."""
        adverse = fusion.fuse(self.rejected())
        silent = fusion.fuse(self.quiet())
        self.assertEqual(adverse.millinats, silent.millinats)
        self.assertEqual(adverse.adverse, (features.ORIGIN_DIRECT,))
        self.assertEqual(silent.adverse, ())

    def test_adverse_evidence_routes_to_review_and_not_to_suspicion(self):
        ruled = decide.decide(
            fusion.fuse(self.rejected()), biometric=proof.BIOMETRIC_SUCCESS
        )
        self.assertEqual(ruled.status, decide.SECONDARY)
        self.assertIn(decide.ADVERSE_EVIDENCE, ruled.reasons)
        self.assertEqual(ruled.adverse, (features.ORIGIN_DIRECT,))

    def test_the_reason_names_the_feature_without_naming_the_frame(self):
        """What is reported is that origin evidence arrived and did not verify. Not
        the session it belonged to, not its counter, not its signature - a teacher
        cannot act on any of that, and an attacker probing for it learns nothing."""
        body = json.dumps(
            decide.decide(
                fusion.fuse(self.rejected()), biometric=proof.BIOMETRIC_SUCCESS
            ).describe()
        )
        self.assertIn(features.ORIGIN_DIRECT, body)
        self.assertNotIn("other-root", body)
        self.assertNotIn("signature", body)


class ContradictionTests(Case):
    """Suspicion is reserved for a proof that disagrees with itself."""

    def test_the_two_classifications_partition_every_signal_the_gate_can_raise(self):
        """The assertion that keeps this honest as the gate grows. A signal nobody
        classified would fall through to the merely-noted arm by default, which is
        how a contradiction quietly becomes a footnote."""
        self.assertEqual(
            decide.CONTRADICTION_SIGNALS | decide.NOTED_SIGNALS, set(gates.SIGNALS)
        )
        self.assertEqual(decide.CONTRADICTION_SIGNALS & decide.NOTED_SIGNALS, set())
        self.assertTrue(decide.CONTRADICTION_SIGNALS <= set(gates.SIGNALS))

    def test_each_contradictory_signal_reaches_suspicious(self):
        """One at a time, over a proof that is otherwise perfect, so what is being
        tested is the classification and not some other shortfall carrying it."""
        for signal in sorted(decide.CONTRADICTION_SIGNALS):
            ruled = decide.decide(
                self.signalled(signal), biometric=proof.BIOMETRIC_SUCCESS
            )
            self.assertEqual(ruled.status, decide.SUSPICIOUS, signal)
            self.assertEqual(ruled.reasons, (decide.SELF_CONTRADICTION,), signal)
            self.assertEqual(ruled.contradictions, (signal,), signal)

    def test_a_merely_noted_signal_does_not_accuse(self):
        """A relay chain sitting exactly at the configured depth limit, an origin
        counter behind where the server thinks it is, a capability bit this build has
        no name for: all three are worth recording and none is evidence of anything a
        student did. They ride along in `signals` and change no verdict."""
        for signal in sorted(decide.NOTED_SIGNALS):
            ruled = decide.decide(
                self.signalled(signal), biometric=proof.BIOMETRIC_SUCCESS
            )
            self.assertEqual(ruled.status, decide.PRESENT, signal)
            self.assertEqual(ruled.reasons, (), signal)
            self.assertEqual(ruled.contradictions, (), signal)
            self.assertEqual(ruled.signals, (signal,), signal)

    def test_the_counter_asymmetry_follows_the_artifact_and_not_a_hunch(self):
        """A claim ahead of the counter contradicts; a claim behind it does not. That
        is not a preference - the artifact bounds one direction and nothing bounds the
        other. A frame can be old because a phone was in a pocket; it cannot be newer
        than the counter that has not been advanced yet."""
        self.assertIn(origin.CLAIM_AHEAD, decide.CONTRADICTION_SIGNALS)
        self.assertIn(origin.CLAIM_BEHIND, decide.NOTED_SIGNALS)
        self.assertIn("max_future_skew_seconds", str(config.PARAMETERS.keys()))

    def test_suspicion_reports_the_contradiction_and_the_shortfalls_together(self):
        """A suspicious verdict does not swallow the arithmetic. A reviewer needs to
        see that the score was also thin, or that a biometric also failed, because the
        two together are a different conversation from either alone."""
        ruled = decide.decide(
            self.signalled(replay.SIGNAL_FUTURE_CLAIM, vector=self.quiet()),
            biometric=proof.BIOMETRIC_FAILED,
        )
        self.assertEqual(ruled.status, decide.SUSPICIOUS)
        self.assertEqual(ruled.reasons[0], decide.SELF_CONTRADICTION)
        self.assertIn(decide.SUPPLIED_TOO_THIN, ruled.reasons)
        self.assertIn(decide.BIOMETRIC_NOT_AFFIRMATIVE, ruled.reasons)

    def test_a_contradiction_outranks_a_perfect_score(self):
        """The ordering that matters: contradiction is checked before the score, so a
        proof that clears every operating point is still suspicious. A design where a
        high enough score buys its way past a contradiction is a design where the
        contradiction check is decorative."""
        flawless = fusion.fuse(self.flawless())
        self.assertGreaterEqual(
            flawless.millinats, decide.Policy.load().present_millinats
        )
        ruled = decide.decide(
            replace(flawless, signals=(replay.SIGNAL_FUTURE_CLAIM,)),
            biometric=proof.BIOMETRIC_SUCCESS,
        )
        self.assertEqual(ruled.status, decide.SUSPICIOUS)


class RefusalTests(Case):
    """Every refusal has exactly one shape, and a refusal is not a low score."""

    def test_the_classification_is_total_over_every_gate_reason_code(self):
        """Asserted here as well as guarded at import, because the import guard only
        fires for whoever imports the module and this is the statement a reviewer
        reads. Twenty-six codes, each in exactly one table."""
        self.assertEqual(
            decide.FORGERY_SHAPED | decide.UNRESOLVED, set(gates.REASON_CODES)
        )
        self.assertEqual(decide.FORGERY_SHAPED & decide.UNRESOLVED, set())

    def test_every_gate_reason_code_produces_a_verdict(self):
        """No code reaches a default arm and no code raises. A refusal the policy
        layer cannot name would leave the marking endpoint with an exception where a
        decision belongs, which is the one outcome a student cannot be told."""
        for code in sorted(gates.REASON_CODES):
            ruled = decide.refuse(gates.GateError(code, "under test"))
            self.assertIn(
                ruled.status, (decide.SUSPICIOUS, decide.NOT_VERIFIED), code
            )
            self.assertTrue(ruled.refused, code)
            self.assertEqual(ruled.gate_code, code)
            self.assertEqual(ruled.reasons, (code,), code)

    def test_forgery_shaped_refusals_are_suspicious(self):
        """A signature that did not verify, a challenge from another session, a nonce
        already spent, a device that was revoked. None of these has an innocent
        version, so review is the wrong word for them."""
        for code in sorted(decide.FORGERY_SHAPED):
            self.assertEqual(
                decide.refuse(gates.GateError(code, "under test")).status,
                decide.SUSPICIOUS,
                code,
            )

    def test_late_and_honest_refusals_are_not_verified(self):
        """The other half, and the half that matters more in practice: a proof that
        expired, a session that had closed, a body that would not decode. Something
        went wrong and nobody is accused of it."""
        for code in sorted(decide.UNRESOLVED):
            self.assertEqual(
                decide.refuse(gates.GateError(code, "under test")).status,
                decide.NOT_VERIFIED,
                code,
            )

    def test_a_slow_scan_is_reviewed_rather_than_accused(self):
        """The deliberate placement in the table, singled out because the argument
        cuts both ways. A forwarded screenshot is exactly what produces a stale step -
        and so is a slow scan from the back of a crowded room on a cheap handset. The
        two are indistinguishable at this layer, so the humane reading wins and the
        stale-step code is UNRESOLVED."""
        self.assertIn(challenge.STALE_STEP, decide.UNRESOLVED)
        self.assertNotIn(challenge.STALE_STEP, decide.FORGERY_SHAPED)
        self.assertEqual(
            decide.refuse(gates.GateError(challenge.STALE_STEP, "slow")).status,
            decide.NOT_VERIFIED,
        )

    def test_the_reason_reported_is_the_gate_code_unaltered(self):
        """Not a translation, not a category, not a friendlier string. Whatever the
        gate called it is what the audit row says, so a reason code in a support
        ticket can be traced to the check that produced it."""
        for code in sorted(gates.REASON_CODES):
            ruled = decide.refuse(gates.GateError(code, "under test"))
            self.assertEqual(ruled.describe()["gate_code"], code)
            self.assertEqual(ruled.describe()["reasons"], [code])

    def test_the_one_code_a_caller_should_retry_idempotently_says_so(self):
        """A duplicate proof is the shape of a client that synced twice, which is
        what an offline queue does when a response is lost. The endpoint has to answer
        it with the verdict already on file rather than recording a fresh refusal, and
        it needs to be told that from the decision rather than by matching on a
        string."""
        duplicate = decide.refuse(
            gates.GateError(replay.DUPLICATE_PROOF, "seen this one")
        )
        self.assertTrue(duplicate.idempotent_retry)
        for code in sorted(gates.REASON_CODES - decide.IDEMPOTENT):
            self.assertFalse(
                decide.refuse(gates.GateError(code, "under test")).idempotent_retry,
                code,
            )

    def test_a_refusal_carries_no_score_and_no_evidence(self):
        """Zero here is not a low score, and the distinction is load-bearing: a
        refusal never reached the fusion layer, so there is no coverage figure, no
        evidence list and nothing for a reviewer to weigh. The `ordering_reason` says
        that in words rather than leaving a zero to be misread."""
        ruled = decide.refuse(gates.GateError(proof.BAD_SIGNATURE, "no"))
        self.assertEqual(ruled.millinats, 0)
        self.assertIsNone(ruled.fused)
        self.assertIsNone(ruled.coverage_pct)
        self.assertIsNone(ruled.supplied_pct)
        self.assertEqual(ruled.evidence_present, ())
        self.assertEqual(dict(ruled.evidence_missing), {})
        self.assertTrue(ruled.ordering_only)
        self.assertIn("no score", ruled.ordering_reason)

    def test_our_own_bug_is_not_answered_with_a_verdict_about_a_student(self):
        """`refuse` takes a GateError and nothing else. A TypeError or a KeyError from
        somewhere in the pipeline is our defect, and turning it into NOT VERIFIED
        would file our bug in somebody's attendance record."""
        for wrong in (ValueError("bug"), TypeError("bug"), None, "gate_unknown_device"):
            with self.assertRaises(decide.DecisionError):
                decide.refuse(wrong)


class ClaimTests(Case):
    """A claim cannot become a verdict, and the argument list is why."""

    def test_a_boastful_proof_gets_the_same_verdict_as_a_modest_one(self):
        """The end of the chain `features` starts. A proof awarding itself PRESENT,
        full confidence and 99 hops decides exactly as one that claims nothing, and
        the audit row is identical down to the reason list."""
        boastful = proof.Claims(
            status=proof.STATUS_PRESENT,
            confidence_milli=proof.CONFIDENCE_MILLI_MAX,
            hop_count=99,
        )
        loud = self.verdict(self.vector(self.signed(claims=boastful)))
        quiet = self.verdict(self.vector(self.signed()))
        self.assertEqual(loud.describe(), quiet.describe())
        self.assertNotIn("99", json.dumps(loud.describe()))

    def test_a_claimed_suspicious_status_does_not_make_a_student_suspicious(self):
        """The direction nobody tests. A client that claims the worst about itself is
        either broken or being used to poison somebody's record, and either way the
        server computes the verdict."""
        accusing = proof.Claims(status=proof.STATUS_SUSPICIOUS, confidence_milli=0)
        ruled = self.verdict(self.vector(self.signed(claims=accusing)))
        self.assertEqual(ruled.status, decide.PRESENT)
        self.assertEqual(ruled.contradictions, ())

    def test_a_cleared_proof_cannot_be_handed_to_decide_at_all(self):
        """`Cleared` carries `claims`, so accepting one would put the client's
        preferred verdict one attribute access away from the policy layer. It is
        refused by type rather than ignored by convention."""
        with self.assertRaises(decide.DecisionError):
            decide.decide(self.clear(self.signed()), biometric=proof.BIOMETRIC_SUCCESS)

    def test_a_score_from_another_artifact_is_refused(self):
        """Operating points and weights are one negotiated set. A score computed
        under last month's weights compared against this month's thresholds is a
        verdict nobody chose, so the mismatch fails rather than resolving quietly in
        whichever direction the numbers happen to fall."""
        stale = replace(fusion.fuse(self.shippable()), config_version="1999.01-old")
        with self.assertRaises(decide.DecisionError) as caught:
            decide.decide(stale, biometric=proof.BIOMETRIC_SUCCESS)
        self.assertIn("1999.01-old", str(caught.exception))

    def test_the_only_names_read_from_proof_are_the_two_wire_vocabularies(self):
        """§39 as a structural sweep rather than a habit. Every `proof.X` in the
        module is a status integer, a biometric outcome, or one of the four reason
        codes it has to classify. No field of a proof body appears - not `claims`,
        not `confidence_milli`, not `hop_count` - so there is no line to delete that
        would start trusting the client."""
        tree = ast.parse(pathlib.Path(decide.__file__).read_text())
        read = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "proof"
        }
        self.assertTrue(read)
        for name in sorted(read):
            self.assertTrue(
                name.startswith("STATUS_")
                or name.startswith("BIOMETRIC_")
                or getattr(proof, name) in proof.REASON_CODES,
                name,
            )
        for forbidden in ("claims", "Claims", "confidence_milli", "hop_count",
                          "Body", "nonce", "signature"):
            self.assertNotIn(forbidden, read)

    def test_no_module_in_the_package_is_read_for_anything_but_a_vocabulary(self):
        """The same sweep widened. `decide` imports six sibling modules and touches
        none of their functions: what it needs from all of them is reason codes,
        signal names and the two status vocabularies. A policy layer that started
        calling into `challenge` or `replay` would be re-deriving facts it was handed,
        which is where a second, disagreeing implementation comes from."""
        tree = ast.parse(pathlib.Path(decide.__file__).read_text())
        for module in ("challenge", "replay", "origin", "chain"):
            read = {
                node.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == module
            }
            self.assertTrue(read, module)
            for name in sorted(read):
                self.assertEqual(name, name.upper(), "%s.%s" % (module, name))


class InvariantTests(Case):
    """A decision that cannot be stated is refused, not rounded off."""

    def sound(self, **over):
        """A well-formed decision, so each test below changes exactly one thing."""
        base = self.verdict(self.shippable())
        return replace(base, **over) if over else base

    def test_a_status_outside_the_four_is_refused(self):
        """Including STATUS_UNKNOWN, which is the dangerous one: it exists in the wire
        vocabulary as the absence of a verdict, and a decision object is precisely the
        thing that is not allowed to be undecided."""
        for wrong in (proof.STATUS_UNKNOWN, -1, 5, 99, None):
            with self.assertRaises(decide.DecisionError):
                self.sound(status=wrong)

    def test_a_reason_nobody_declared_is_refused(self):
        """The reason list is what a teacher reads and what an audit replays. An
        ad-hoc string in it would be a private message from whichever function wrote
        it, so the vocabulary is closed to this module's codes and the gate's."""
        with self.assertRaises(decide.DecisionError):
            self.sound(reasons=("decide_it_felt_wrong",))
        allowed = decide.REASON_CODES | gates.REASON_CODES
        for code in sorted(allowed):
            self.assertIsNotNone(self.sound(reasons=(code,)))

    def test_a_score_that_claims_to_be_a_probability_and_is_not_is_refused(self):
        """`ordering_only` and `confidence_milli` are two statements about the same
        thing, and the pair is the honesty invariant of the whole layer: on an
        uncalibrated artifact there is no probability to report, so a decision that
        carried both an ordering flag and a confidence number would be inviting a UI
        to print a percentage that means nothing."""
        with self.assertRaises(decide.DecisionError):
            self.sound(ordering_only=True, confidence_milli=950)
        with self.assertRaises(decide.DecisionError):
            self.sound(ordering_only=False, confidence_milli=None)

    def test_a_decision_rests_on_exactly_one_of_a_refusal_and_a_score(self):
        """Both would mean the proof was refused and weighed; neither would mean the
        verdict came from nowhere. Either way there is no defensible audit row, so
        the object will not exist."""
        scored = self.sound()
        with self.assertRaises(decide.DecisionError):
            replace(scored, gate_code=proof.BAD_SIGNATURE)
        refused = decide.refuse(gates.GateError(proof.BAD_SIGNATURE, "no"))
        with self.assertRaises(decide.DecisionError):
            replace(refused, fused=fusion.fuse(self.shippable()))

    def test_the_uncalibrated_artifact_reports_no_confidence_at_all(self):
        """The live consequence of the invariant above, stated as its own test because
        it is the sentence somebody will want to remove. Until §60 field data exists
        there is no posterior, so every decision this build makes is an ordering and
        `confidence_milli` is None."""
        ruled = self.verdict(self.shippable())
        self.assertTrue(ruled.ordering_only)
        self.assertIsNone(ruled.confidence_milli)
        self.assertEqual(ruled.calibration, config.active().calibration)
        self.assertIn("uncalibrated", ruled.calibration)

    def test_the_decision_records_which_artifact_ruled(self):
        """Not decoration. A threshold change is a policy change, and a decision that
        did not record the version it was made under cannot be defended six months
        later when the numbers have moved."""
        ruled = self.verdict(self.shippable())
        self.assertEqual(ruled.config_version, config.active().version)
        self.assertEqual(ruled.policy.config_version, ruled.config_version)

    def test_no_model_version_is_reported_because_there_is_no_model(self):
        """A deliberate absence. `decide` runs a threshold comparison over a weighted
        sum, and a `model_version` field would hold either a lie or a placeholder that
        a later reader would take for a trained artifact."""
        self.assertNotIn("model_version", self.verdict(self.shippable()).describe())
        self.assertFalse(hasattr(self.verdict(self.shippable()), "model_version"))


class PrivacyTests(Case):
    """An audit row records what was weighed, not who was there."""

    def audited(self):
        """The richest decision this build can reach, plus the identifiers behind it."""
        marker = bytes(range(proof.NONCE_LEN))
        seen = self.sighting(rssi=RSSI_MARKER)
        bodies = (seen.encode(),) + chain.encode_chain(
            self.hops(chain.root_link(seen.encode()))
        )
        body = self.signed(observations=bodies, capabilities=CAPABLE, nonce=marker)
        ruled = self.verdict(
            self.vector(body, observations=bodies, resolve_relay=self.cohort())
        )
        return marker, bodies, ruled

    def test_the_audit_body_is_json_native_so_no_raw_bytes_can_ride_along(self):
        """Dumped with no fallback encoder, the same way `fusion` does it. A default
        encoder would stringify a key id or a nonce into the persisted decision and
        the leak would look like a formatting detail."""
        marker, bodies, ruled = self.audited()
        json.dumps(ruled.describe())
        json.dumps(decide.refuse(gates.GateError(proof.BAD_SIGNATURE, "no")).describe())

    def test_no_identifier_from_the_proof_survives_into_the_decision(self):
        """The decision is the row that outlives the session - `PresenceObservation`
        is purged when the teacher closes it, and this is what remains. If an
        identifier reached here it would be the one place a movement history could be
        rebuilt from."""
        marker, bodies, ruled = self.audited()
        text = json.dumps(ruled.describe())
        secrets = {
            "session id": SESSION_ID,
            "device key id": self.device.public().key_id,
            "proof nonce": marker,
        }
        for index, digest in enumerate(proof.observation_digests(*bodies)):
            secrets["observation digest %d" % (index,)] = digest
        for label, raw in secrets.items():
            self.assertNotIn(raw.hex(), text, "%s reached the decision" % (label,))
            self.assertNotIn(str(raw), text, "%s reached the decision" % (label,))

    def test_no_signal_strength_reaches_the_decision(self):
        """§85, at the layer that persists. A recorded RSSI is carried for room
        calibration and read by nothing in the decision path, so a figure appearing
        here would mean either a leak or a threshold that should not exist."""
        marker, bodies, ruled = self.audited()
        text = json.dumps(ruled.describe())
        self.assertNotIn(str(RSSI_MARKER), text)
        self.assertNotIn("rssi", text)

    def test_the_row_is_enough_to_defend_the_verdict_and_no_more(self):
        """What a review needs: the verdict, the score, the operating points it was
        compared against, the evidence that was present, the evidence that was not and
        why, and the artifact version. What it does not need is who, where, or which
        device."""
        marker, bodies, ruled = self.audited()
        body = ruled.describe()
        for expected in ("status", "status_name", "millinats", "reasons",
                         "evidence_present", "evidence_missing", "policy",
                         "config_version", "calibration"):
            self.assertIn(expected, body, expected)
        self.assertEqual(body["status"], ruled.status)
        self.assertEqual(body["status_name"], ruled.status_name)
        self.assertEqual(body["policy"]["present_millinats"],
                         ruled.policy.present_millinats)

    def test_a_missing_feature_is_explained_by_category_and_not_by_narrative(self):
        """`evidence_missing` maps a feature to one of the fixed absence words. A free
        string here would eventually carry a device model, an OS build or a room - and
        it would be written by whichever layer happened to know."""
        ruled = self.verdict(
            self.vector(
                self.signed(
                    capabilities=NO_BIOMETRIC, biometric=proof.BIOMETRIC_ABSENT
                )
            ),
            biometric=proof.BIOMETRIC_ABSENT,
        )
        self.assertTrue(ruled.evidence_missing)
        for feature, why in ruled.evidence_missing.items():
            self.assertIn(feature, features.FEATURES, feature)
            self.assertIn(why, features.ABSENCE_REASONS, why)

    def test_the_evidence_lists_partition_the_priced_features(self):
        """Every feature is either present or explained. A feature in neither list
        would be one the score used and the record cannot account for."""
        marker, bodies, ruled = self.audited()
        priced = set(fusion.Weights.load().millinats)
        accounted = set(ruled.evidence_present) | set(ruled.evidence_missing)
        self.assertTrue(priced <= accounted)
        self.assertEqual(
            set(ruled.evidence_present) & set(ruled.evidence_missing), set()
        )


class SourceTests(Case):
    """Structural claims about the module itself, so they cannot drift back."""

    def source(self):
        return pathlib.Path(decide.__file__).read_text(encoding="utf-8")

    # `Policy` carries the artifact's identity alongside its numbers, and neither
    # half of that identity is a tuned value: `config_version` names the artifact
    # and `calibration` says whether its numbers were measured. Both are provenance
    # travelling with the points they describe, so both are excluded from the
    # declared-parameter comparison rather than expected to appear in PARAMETERS.
    PROVENANCE = {"config_version", "calibration"}

    def test_every_declared_operating_point_is_read_and_no_other_is(self):
        """Both directions. A declared parameter nobody reads is a number an owner
        signed off on that does nothing; a parameter read but not declared would be a
        threshold with no bounds and no review."""
        declared = {
            name[len(decide.PARAMETER_PREFIX):]
            for name in config.PARAMETERS
            if name.startswith(decide.PARAMETER_PREFIX)
        }
        read = set(decide.Policy.__dataclass_fields__) - self.PROVENANCE
        self.assertEqual(declared, read)

    def test_a_refusal_reports_the_calibration_of_the_artifact_it_was_judged_under(self):
        """A refused proof has no score, so it cannot inherit calibration from one.

        Reading it from whatever artifact happens to be deployed would let a refusal
        recorded against last term's version claim this term's calibration state -
        and the field exists precisely to stop an uncalibrated ordering being read as
        a probability, so a wrong one is worse than none.
        """
        pinned = replace(
            decide.Policy.load(),
            config_version="2000.01-elsewhere",
            calibration=config.SIMULATOR_FITTED,
        )
        ruled = decide.refuse(
            gates.GateError(proof.BAD_SIGNATURE, "no"), policy=pinned
        )
        self.assertEqual(ruled.calibration, config.SIMULATOR_FITTED)
        self.assertEqual(ruled.config_version, "2000.01-elsewhere")
        self.assertNotEqual(config.active().calibration, config.SIMULATOR_FITTED)

    def test_the_thresholds_are_compared_against_the_score_and_never_the_posterior(self):
        """The handoff `fuse` documents, kept. A posterior is a probability under the
        artifact's own weights and says nothing about how much of the evidence base
        existed; on this uncalibrated build there is no posterior at all, so an
        operating point defined against one would silently stop existing."""
        points = set(decide.Policy.__dataclass_fields__) - self.PROVENANCE
        probabilities = {"posterior_milli", "confidence_milli"}
        against = set()
        for node in ast.walk(ast.parse(self.source())):
            if not isinstance(node, ast.Compare):
                continue
            named = {
                side.attr
                for side in [node.left] + list(node.comparators)
                if isinstance(side, ast.Attribute)
            }
            if named & points:
                self.assertEqual(named & probabilities, set(), ast.dump(node))
                against |= named - points
        self.assertIn("millinats", against)
        self.assertTrue(points <= set(decide.Policy.__dataclass_fields__))

    def test_every_reason_code_is_namespaced_and_declared(self):
        """A reason code is a wire string a teacher sees and an analytics layer counts.
        An undeclared one would be readable and uncountable."""
        for code in decide.REASON_CODES:
            self.assertTrue(code.startswith("decide_"), code)
        module_level = {
            value
            for name, value in vars(decide).items()
            if name.isupper() and isinstance(value, str) and value.startswith("decide_")
        }
        self.assertEqual(module_level, set(decide.REASON_CODES))

    def test_the_policy_codes_do_not_collide_with_the_gate_codes(self):
        """Two vocabularies in one field, so the prefixes have to keep them apart. A
        collision would make a refusal and a shortfall indistinguishable in the
        persisted row."""
        self.assertEqual(decide.REASON_CODES & gates.REASON_CODES, set())

    def test_the_module_holds_no_fraction_of_its_own(self):
        """Percentages arrive as integers from the artifact and are compared to
        floats from `safe_pct`. A float literal here would be a tuned value the
        hygiene sweep cannot see, because that sweep only looks for integers."""
        for node in ast.walk(ast.parse(self.source())):
            if isinstance(node, ast.Constant) and isinstance(node.value, float):
                self.fail("decide.py carries the float literal %r" % (node.value,))

    def test_the_decision_path_imports_nothing_that_needs_a_database(self):
        """A verdict has to be re-derivable from a stored proof anywhere - in a test,
        on a laptop, in a courtroom - so the policy layer imports its siblings and the
        standard library and nothing else. The moment it imports a model, replaying
        last term's decision needs last term's database."""
        tree = ast.parse(self.source())
        outside = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                outside.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                outside.add(node.module or "")
        for name in sorted(outside):
            self.assertIn(
                name.split(".")[0],
                {"ast", "dataclasses", "json", "math", "types", "typing"},
                name,
            )
        self.assertNotIn("django", self.source())
