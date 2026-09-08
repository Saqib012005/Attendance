"""Tests for CampusGuard empirical calibration and diagnostics engine."""
from django.test import SimpleTestCase

from .presence import calibrate, config
from .presence.calibrate import LabelledSample


class CalibrationTests(SimpleTestCase):
    def setUp(self):
        # Generate synthetic ground-truth dataset
        self.samples = []
        # 30 positive samples (genuine inside classroom presence)
        for i in range(30):
            self.samples.append(LabelledSample(
                features={
                    "identity_authenticated": True,
                    "device_bound": True,
                    "challenge_committed": True,
                    "biometric_outcome": True,
                    "origin_direct": (i % 5 != 0),
                    "clock_consistency": True,
                },
                is_ground_truth_present=True,
            ))
        # 30 negative samples (proxy/exterior attempts)
        for i in range(30):
            self.samples.append(LabelledSample(
                features={
                    "identity_authenticated": (i % 2 == 0),
                    "device_bound": (i % 3 == 0),
                    "challenge_committed": False,
                    "biometric_outcome": (i % 2 == 0),
                    "origin_direct": False,
                    "clock_consistency": False,
                },
                is_ground_truth_present=False,
            ))

    def test_calculate_feature_log_odds_positive_for_discriminating_signal(self):
        weight = calibrate.calculate_feature_log_odds(self.samples, "challenge_committed")
        self.assertGreater(weight, 1000)

    def test_brier_score_and_reliability_diagram(self):
        probs = [0.9] * 30 + [0.1] * 30
        labels = [True] * 30 + [False] * 30
        brier = calibrate.compute_brier_score(probs, labels)
        self.assertLess(brier, 0.05)

        ece, bins = calibrate.compute_reliability_diagram(probs, labels, num_bins=5)
        self.assertLessEqual(ece, 0.15)
        self.assertGreater(len(bins), 0)

    def test_operating_curve_generation(self):
        scores = [5000] * 30 + [1000] * 30
        labels = [True] * 30 + [False] * 30
        curve = calibrate.compute_operating_curve(scores, labels, threshold_step=500)
        self.assertGreater(len(curve), 3)
        for pt in curve:
            self.assertIn("far_pct", pt)
            self.assertIn("frr_pct", pt)

    def test_fit_and_emit_artifact_creates_valid_artifact(self):
        artifact, diag = calibrate.fit_and_emit_artifact(
            samples=self.samples,
            version_tag="2026.09-lab-fitted",
            calibration_state=config.SIMULATOR_FITTED,
            notes="Fitted during unit testing",
        )
        self.assertEqual(artifact.version, "2026.09-lab-fitted")
        self.assertEqual(artifact.calibration, config.SIMULATOR_FITTED)
        self.assertGreater(diag.sample_count, 0)
        self.assertEqual(diag.positive_count, 30)
        self.assertEqual(diag.negative_count, 30)

    def test_insufficient_samples_raises_value_error(self):
        with self.assertRaises(ValueError):
            calibrate.fit_and_emit_artifact(
                samples=self.samples[:5],
                version_tag="2026.09-too-few",
            )
