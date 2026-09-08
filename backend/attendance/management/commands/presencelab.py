"""Django management command to run the CampusGuard Adversarial Lab."""
import sys
from django.core.management.base import BaseCommand

from attendance.presence.lab.runner import (
    print_lab_summary,
    run_adversarial_matrix,
    run_fuzz_sweep,
    run_mesh_scale_benchmark,
)


class Command(BaseCommand):
    help = "Run the CampusGuard presence simulation lab and adversarial test matrix."

    def add_arguments(self, parser):
        parser.add_argument(
            "--matrix",
            action="store_true",
            help="Run Threat Model Rows 1-15 attack scenarios.",
        )
        parser.add_argument(
            "--fuzz",
            type=int,
            default=0,
            help="Run randomized fuzzing iterations against verification gates.",
        )
        parser.add_argument(
            "--mesh",
            action="store_true",
            help="Run classroom mesh propagation and congestion benchmarks (10-200 nodes).",
        )
        parser.add_argument(
            "--all",
            action="store_true",
            help="Run all lab simulations and benchmarks.",
        )

    def handle(self, *args, **options):
        run_all = options["all"] or not (options["matrix"] or options["mesh"] or options["fuzz"] > 0)
        
        matrix_results = []
        if options["matrix"] or run_all:
            self.stdout.write("Running adversarial threat matrix...")
            matrix_results = run_adversarial_matrix()

        fuzz_stats = None
        fuzz_count = options["fuzz"] if options["fuzz"] > 0 else (100 if run_all else 0)
        if fuzz_count > 0:
            self.stdout.write(f"Running fuzz sweep ({fuzz_count} iterations)...")
            fuzz_stats = run_fuzz_sweep(iterations=fuzz_count)

        mesh_results = []
        if options["mesh"] or run_all:
            self.stdout.write("Running classroom BLE mesh scale benchmark...")
            mesh_results = run_mesh_scale_benchmark()

        print_lab_summary(matrix_results, mesh_results, fuzz_stats)

        # Check if any scenario failed
        failures = [r for r in matrix_results if not r.passed]
        if failures:
            self.stderr.write(self.style.ERROR(f"\n{len(failures)} adversarial scenario(s) FAILED!"))
            sys.exit(1)
        else:
            self.stdout.write(self.style.SUCCESS("\nAll executed lab scenarios and benchmarks PASSED."))
