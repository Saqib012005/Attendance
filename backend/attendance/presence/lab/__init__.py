"""CampusGuard presence lab package."""
from .mesh import MeshSimulationResult, StudentNode, generate_classroom_cohort, simulate_mesh_propagation
from .propagation import Position, compute_path_loss, simulate_anchor_readings
from .runner import print_lab_summary, run_adversarial_matrix, run_fuzz_sweep, run_mesh_scale_benchmark
from .scenarios import ScenarioLab, ScenarioResult

__all__ = [
    "Position",
    "compute_path_loss",
    "simulate_anchor_readings",
    "StudentNode",
    "MeshSimulationResult",
    "generate_classroom_cohort",
    "simulate_mesh_propagation",
    "ScenarioLab",
    "ScenarioResult",
    "run_adversarial_matrix",
    "run_fuzz_sweep",
    "run_mesh_scale_benchmark",
    "print_lab_summary",
]
