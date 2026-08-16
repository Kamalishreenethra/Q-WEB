"""
CLI execution interface for SignChain research experiments and performance benchmarks.
"""
import argparse
import sys
import json
from pathlib import Path
from signchain.research.runner import BenchmarkRunner
from signchain.research.plotting import generate_benchmark_plots


def main():
    parser = argparse.ArgumentParser(description="SignChain Automated Research Benchmark Runner")
    parser.add_argument("--size", type=int, default=1000, help="Artifact count for single workload experiment")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--repetitions", type=int, default=5, help="Number of benchmark repetitions (Track A only)")
    parser.add_argument("--output", type=str, default="research/results", help="Directory to save raw results")
    parser.add_argument("--plots-dir", type=str, default="research/plots", help="Directory to save generated figures")
    parser.add_argument("--run-all", action="store_true", help="Execute complete benchmark matrix (100 to 10,000 artifacts)")
    parser.add_argument("--include-25k", action="store_true", help="Include 25,000 artifact workload in run-all")

    args = parser.parse_args()

    runner = BenchmarkRunner(output_dir=args.output)

    if args.run_all:
        sizes = [100, 500, 1000, 5000, 10000]
        if args.include_25k:
            sizes.append(25000)

        print(f"[*] Starting Track A Benchmarking on workloads: {sizes} (reps={args.repetitions}, seed={args.seed})...")
        track_a_res = runner.run_track_a_benchmark(sizes=sizes, repetitions=args.repetitions, seed=args.seed)
        print("[+] Track A Complete. Summary saved to performance_summary.csv")

        print(f"[*] Starting Track B Comparative Experiment on N=1000...")
        # Track B does not accept repetitions — it is a single deterministic experiment
        track_b_res = runner.run_track_b_experiment(size=1000, seed=args.seed)
        print("[+] Track B Complete.")

        print(f"[*] Generating publication-quality figures in '{args.plots_dir}'...")
        plots = generate_benchmark_plots(track_a_res["results"], track_b_res, output_dir=args.plots_dir)
        print(f"[+] Generated {len(plots)} scientific figures.")

    else:
        print(f"[*] Running Track A on workload size N={args.size}...")
        track_a_res = runner.run_track_a_benchmark(sizes=[args.size], repetitions=args.repetitions, seed=args.seed)

        print(f"[*] Running Track B on workload size N={args.size}...")
        # Track B does not accept repetitions
        track_b_res = runner.run_track_b_experiment(size=args.size, seed=args.seed)

        plots = generate_benchmark_plots(track_a_res["results"], track_b_res, output_dir=args.plots_dir)
        print(f"[+] Results saved. Generated {len(plots)} figures.")


if __name__ == "__main__":
    main()
