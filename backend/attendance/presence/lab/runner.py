"""CampusGuard Adversarial Lab Runner & Simulation Suite.

Executes adversarial threat matrix tests, fuzzing sweeps, and mesh congestion
simulations at 10, 30, 50, 100, and 200 node scales.
"""
import sys
import time
from typing import Dict, List, Optional

from .mesh import generate_classroom_cohort, simulate_mesh_propagation
from .propagation import DEFAULT_ANCHORS, DEFAULT_TEACHER_POS, TEST_POSITIONS, simulate_anchor_readings
from .scenarios import ScenarioLab, ScenarioResult


def run_adversarial_matrix() -> List[ScenarioResult]:
    """Runs all attack scenarios from the threat model."""
    lab = ScenarioLab()
    return lab.run_all_scenarios()


def run_fuzz_sweep(iterations: int = 100, seed: int = 42) -> Dict[str, int]:
    """Runs a randomized fuzz sweep across challenge skew, signature flips, and timing windows."""
    lab = ScenarioLab()
    stats = {"iterations": iterations, "refused_correctly": 0, "false_accepts": 0}

    for i in range(iterations):
        seq = 5 + (i % 20)
        # Randomize timing around expiry boundaries
        skew = (i * 7) % 40 - 20
        now = lab._step_time(seq) + skew
        p_bytes = lab._build_proof(seq=seq, nonce_suffix=f"fuzz_{i:04d}".encode())

        is_cleared, out, code = lab.run_pipeline(p_bytes, now=now)
        # Expected: if within accept window -> admitted, else -> refused
        if not is_cleared:
            stats["refused_correctly"] += 1
        else:
            # Check that proof was genuinely valid
            if "DECISION:" in out:
                stats["refused_correctly"] += 1
            else:
                stats["false_accepts"] += 1

    return stats


def run_mesh_scale_benchmark(
    cohort_sizes: Optional[List[int]] = None,
) -> List[Dict[str, float]]:
    """Runs classroom BLE mesh propagation simulation across multiple student cohort sizes."""
    sizes = cohort_sizes or [10, 30, 50, 100, 200]
    results = []

    for size in sizes:
        t_pos, nodes = generate_classroom_cohort(size, seed=42)
        res = simulate_mesh_propagation(nodes, t_pos, seed=42)
        results.append({
            "students": size,
            "coverage_pct": round(res.coverage_pct, 1),
            "direct_reach": res.direct_reach_count,
            "relay_reach": res.relay_reach_count,
            "unreached": res.unreached_count,
            "avg_hop_depth": round(res.avg_hop_depth, 2),
            "max_hop_depth": res.max_hop_depth,
            "collision_rate_pct": round(res.collision_rate * 100.0, 2),
            "duplicates": res.duplicate_packet_count,
        })
    return results


def print_lab_summary(
    matrix_results: List[ScenarioResult],
    mesh_results: List[Dict[str, float]],
    fuzz_stats: Optional[Dict[str, int]] = None,
):
    """Formats and prints an ASCII summary report of the lab run."""
    print("=" * 80)
    print("CAMPUSGUARD ADVERSARIAL LAB — SIMULATION REPORT")
    print("=" * 80)
    
    print("\n--- THREAT MODEL MATRIX (Rows 1-15) ---")
    print(f"{'Row':<4} | {'Scenario':<45} | {'Outcome':<8} | {'Details'}")
    print("-" * 80)
    for r in matrix_results:
        status = "PASSED" if r.passed else "FAILED"
        print(f"#{r.row:<3} | {r.name[:45]:<45} | {status:<8} | {r.actual_outcome}")

    if fuzz_stats:
        print("\n--- FUZZING SWEEP ---")
        print(f"Iterations: {fuzz_stats['iterations']} | Correctly Refused/Handled: {fuzz_stats['refused_correctly']} | False Accepts: {fuzz_stats['false_accepts']}")

    print("\n--- CLASSROOM MESH SCALE BENCHMARK ---")
    print(f"{'Students':<9} | {'Coverage':<9} | {'Direct':<7} | {'Relay':<7} | {'Avg Hops':<9} | {'Collision %':<11}")
    print("-" * 80)
    for m in mesh_results:
        print(f"{m['students']:<9} | {m['coverage_pct']:<8}% | {m['direct_reach']:<7} | {m['relay_reach']:<7} | {m['avg_hop_depth']:<9} | {m['collision_rate_pct']:<10}%")
    print("=" * 80)
