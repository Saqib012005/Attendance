"""Tests for CampusGuard Adversarial Lab (RF propagation, mesh, and scenarios)."""
import random
from django.test import SimpleTestCase

from .presence.lab import (
    Position,
    ScenarioLab,
    compute_path_loss,
    generate_classroom_cohort,
    run_adversarial_matrix,
    run_fuzz_sweep,
    run_mesh_scale_benchmark,
    simulate_anchor_readings,
    simulate_mesh_propagation,
)
from .presence.lab.propagation import (
    DEFAULT_ANCHORS,
    DEFAULT_TEACHER_POS,
    TEST_POSITIONS,
    evaluate_fingerprint_match,
)


class PropagationTests(SimpleTestCase):
    def test_distance_calculation(self):
        p1 = Position(x=0.0, y=0.0, z=0.0)
        p2 = Position(x=3.0, y=4.0, z=0.0)
        self.assertAlmostEqual(p1.distance_to(p2), 5.0, places=4)

    def test_path_loss_increases_with_distance(self):
        p_tx = Position(x=0.0, y=0.0, z=1.0, zone="inside")
        p_close = Position(x=1.0, y=0.0, z=1.0, zone="inside")
        p_far = Position(x=5.0, y=0.0, z=1.0, zone="inside")

        rssi_close = compute_path_loss(p_tx, p_close)
        rssi_far = compute_path_loss(p_tx, p_far)
        self.assertGreater(rssi_close, rssi_far)

    def test_wall_and_window_attenuation_reduces_rssi(self):
        inside_pos = TEST_POSITIONS["inside_window_edge"]
        outside_window_pos = TEST_POSITIONS["outside_window"]
        adjacent_room_pos = TEST_POSITIONS["adjacent_room"]

        rssi_inside = compute_path_loss(DEFAULT_TEACHER_POS, inside_pos)
        rssi_outside = compute_path_loss(DEFAULT_TEACHER_POS, outside_window_pos)
        rssi_adj = compute_path_loss(DEFAULT_TEACHER_POS, adjacent_room_pos)

        self.assertGreater(rssi_inside, rssi_outside)
        self.assertGreater(rssi_outside, rssi_adj)

    def test_anchor_simulation_and_fingerprint_matching(self):
        # Generate baseline inside profile
        rng = random.Random(42)
        readings_inside = simulate_anchor_readings(
            TEST_POSITIONS["inside_center"], sample_count=10, rng=rng
        )
        self.assertEqual(len(readings_inside), len(DEFAULT_ANCHORS))

        profile = {
            aid: (stats["mean_rssi"], stats["std_rssi"])
            for aid, stats in readings_inside.items()
        }

        # Exact match score should be near 1.0
        score_self = evaluate_fingerprint_match(
            {aid: stats["mean_rssi"] for aid, stats in readings_inside.items()},
            profile,
        )
        self.assertGreater(score_self, 0.90)

        # Outside window match score should be markedly degraded
        readings_outside = simulate_anchor_readings(
            TEST_POSITIONS["outside_window"], sample_count=10, rng=random.Random(42)
        )
        score_outside = evaluate_fingerprint_match(
            {aid: stats["mean_rssi"] for aid, stats in readings_outside.items()},
            profile,
        )
        self.assertLess(score_outside, score_self)


class MeshNetworkTests(SimpleTestCase):
    def test_classroom_cohort_generation(self):
        t_pos, nodes = generate_classroom_cohort(30, seed=123)
        self.assertEqual(len(nodes), 30)
        for n in nodes:
            self.assertEqual(n.position.zone, "inside")
            self.assertGreaterEqual(n.position.x, 0.4)
            self.assertLessEqual(n.position.x, 4.57)

    def test_mesh_propagation_achieves_high_coverage(self):
        t_pos, nodes = generate_classroom_cohort(50, seed=42)
        result = simulate_mesh_propagation(nodes, t_pos, seed=42)

        self.assertEqual(result.node_count, 50)
        self.assertGreater(result.coverage_pct, 90.0)
        self.assertGreater(result.direct_reach_count, 0)
        self.assertLessEqual(result.max_hop_depth, 3)

    def test_mesh_scale_benchmark_runs_all_cohorts(self):
        results = run_mesh_scale_benchmark([10, 30, 50])
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertIn("coverage_pct", r)
            self.assertGreater(r["coverage_pct"], 80.0)


class AdversarialScenariosTests(SimpleTestCase):
    def setUp(self):
        self.lab = ScenarioLab()

    def test_all_matrix_scenarios_pass_determinstically(self):
        results = run_adversarial_matrix()
        self.assertGreater(len(results), 5)
        for r in results:
            self.assertTrue(r.passed, f"Scenario #{r.row} ({r.name}) failed: {r.actual_outcome}")

    def test_fuzz_sweep_produces_no_false_accepts(self):
        stats = run_fuzz_sweep(iterations=25, seed=99)
        self.assertEqual(stats["false_accepts"], 0)
        self.assertEqual(stats["refused_correctly"], 25)
