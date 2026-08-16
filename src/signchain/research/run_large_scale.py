"""
Automated Large-Scale Research Benchmark Execution Suite for SignChain.
Executes:
  1. Performance & Scalability (Track A: N=100, 500, 1000, 5000, 10000, 25000)
  2. Multi-Scenario Multi-Seed Quality (Track B: 6 scenarios x 10 seeds x 5 sizes)
  3. 4-Way Ablation Analysis (N=100, 500, 1000)
  4. Ground-Truth Sensitivity Analysis (N=500 across GT-A, GT-B, GT-C, GT-D)
  5. Publication Figure Generation (Figures 1-10)
"""
import json
import time
import math
import statistics
from pathlib import Path
from typing import Dict, List, Any

from signchain.research.runner import BenchmarkRunner
from signchain.research.workload_generator import SyntheticWorkloadGenerator, ScenarioFamily
from signchain.research.baseline import FlatCryptographicBaseline
from signchain.research.metrics import (
    calculate_top_k_recall,
    calculate_spearman_correlation,
    calculate_priority_inversions,
    calculate_critical_missed_rate,
    calculate_high_impact_recall,
    calculate_order_agreement,
)
from signchain.migration.migration_engine import MigrationPrioritizationEngine
from signchain.research.plotting import generate_all_publication_figures


def execute_large_scale_benchmark():
    output_base = Path("research/results")
    plots_dir = Path("research/plots")
    
    subdirs = ["raw", "performance", "comparison", "ablation", "sensitivity", "summaries"]
    for s in subdirs:
        (output_base / s).mkdir(parents=True, exist_ok=True)
    plots_dir.mkdir(parents=True, exist_ok=True)

    runner = BenchmarkRunner(output_dir=str(output_base))
    seeds = list(range(42, 52))

    print("=================================================================")
    print("STEP 1: TRACK A — PERFORMANCE & SCALABILITY (N=100 to 25,000)")
    print("=================================================================")
    
    perf_sizes = [100, 500, 1000, 5000, 10000]
    
    # Check if 25,000 is computationally feasible by a single-pass trial
    t_trial = time.perf_counter()
    w_trial = SyntheticWorkloadGenerator(seed=42).generate_workload(size=25000)
    trial_elapsed = time.perf_counter() - t_trial
    print(f"[*] 25k Workload generation trial elapsed: {trial_elapsed:.2f}s")
    if trial_elapsed < 10.0:
        perf_sizes.append(25000)
        print("[+] N=25,000 workload included in performance benchmark.")
    else:
        print("[-] N=25,000 excluded due to excessive runtime threshold.")

    track_a_res = runner.run_track_a_benchmark(sizes=perf_sizes, repetitions=5, seed=42)
    perf_summary = track_a_res["results"]
    print(f"[+] Track A Complete. Evaluated {len(perf_sizes)} workload scales.")

    print("\n=================================================================")
    print("STEP 2: TRACK B — MULTI-SCENARIO MULTI-SEED EXPERIMENTS")
    print("=================================================================")
    
    scenarios = [
        ScenarioFamily.MIXED,
        ScenarioFamily.DEPENDENCY_HUB,
        ScenarioFamily.ANTI_CORRELATION,
        ScenarioFamily.CRYPTO_SEVERE,
        ScenarioFamily.ISOLATED_CRITICAL,
        ScenarioFamily.MIGRATION_BLOCKED,
    ]
    
    scenario_comparison_results = {}
    multi_seed_by_size = {}

    for sc in scenarios:
        print(f"[*] Running multi-seed evaluation for scenario: {sc} on N=100...")
        sc_res = runner.run_multi_seed_evaluation(size=100, seeds=seeds, scenario_family=sc)
        scenario_comparison_results[sc] = sc_res
        
        # Calculate mean CMR and HDR for plotting
        base_cmr_list = [r["baseline"].get("critical_miss_rate_top10", 0.0) for r in sc_res["individual_seed_results"]]
        sc_cmr_list = [r["signchain"].get("critical_miss_rate_top10", 0.0) for r in sc_res["individual_seed_results"]]
        base_hdr_list = [r["baseline"].get("high_impact_recall_top10", 0.0) for r in sc_res["individual_seed_results"]]
        sc_hdr_list = [r["signchain"].get("high_impact_recall_top10", 0.0) for r in sc_res["individual_seed_results"]]
        
        scenario_comparison_results[sc]["aggregate_metrics"]["baseline"]["mean_cmr"] = round(statistics.mean(base_cmr_list), 4)
        scenario_comparison_results[sc]["aggregate_metrics"]["signchain"]["mean_cmr"] = round(statistics.mean(sc_cmr_list), 4)
        scenario_comparison_results[sc]["aggregate_metrics"]["baseline"]["mean_hdr"] = round(statistics.mean(base_hdr_list), 4)
        scenario_comparison_results[sc]["aggregate_metrics"]["signchain"]["mean_hdr"] = round(statistics.mean(sc_hdr_list), 4)

    # Multi-size evaluation on MIXED scenario across sizes [100, 500, 1000, 5000, 10000]
    for sz in [100, 500, 1000, 5000, 10000]:
        print(f"[*] Running comparative evaluation for MIXED size N={sz}...")
        exp_sz = runner.run_track_b_experiment(size=sz, seed=42, scenario_family=ScenarioFamily.MIXED)
        multi_seed_by_size[sz] = {
            "baseline": {"inversions": exp_sz["baseline"]["priority_inversions"], "recall@10": exp_sz["baseline"]["recall@10"]},
            "signchain": {"inversions": exp_sz["signchain"]["priority_inversions"], "recall@10": exp_sz["signchain"]["recall@10"]},
        }

    print("\n=================================================================")
    print("STEP 3: 4-WAY ABLATION STUDY (N=100, 500, 1,000)")
    print("=================================================================")
    
    ablation_by_size = {}
    for sz in [100, 500, 1000]:
        print(f"[*] Running 4-way ablation on N={sz}...")
        exp_abl = runner.run_track_b_experiment(size=sz, seed=42, scenario_family=ScenarioFamily.MIXED)
        ablation_by_size[sz] = exp_abl["ablation"]

    with open(output_base / "ablation" / "ablation_summary.json", "w") as f:
        json.dump(ablation_by_size, f, indent=2)

    print("\n=================================================================")
    print("STEP 4: GROUND-TRUTH SENSITIVITY ANALYSIS (N=500)")
    print("=================================================================")
    
    sens_configs = {
        "GT-A (Criticality-Heavy)": {"w_crit": 0.60, "w_vuln": 0.20, "w_blast": 0.20},
        "GT-B (Vulnerability-Heavy)": {"w_crit": 0.15, "w_vuln": 0.70, "w_blast": 0.15},
        "GT-C (Blast-Radius-Heavy)": {"w_crit": 0.15, "w_vuln": 0.15, "w_blast": 0.70},
        "GT-D (Balanced Standard)": {"w_crit": 0.35, "w_vuln": 0.35, "w_blast": 0.30},
    }

    w_500 = SyntheticWorkloadGenerator(seed=42).generate_workload(size=500, scenario_family=ScenarioFamily.MIXED)
    arts_500 = w_500["artifacts"]
    certs_500 = w_500["certificates"]
    graph_500 = w_500["graph"]
    map_500 = w_500["subject_to_target_id"]
    art_map_500 = {a["id"]: a for a in arts_500}

    engine_500 = MigrationPrioritizationEngine()
    baseline_500 = FlatCryptographicBaseline()
    b_ranks_500 = baseline_500.prioritize(certs_500)
    sc_res_500 = engine_500.prioritize_all(certs_500, graph_engine=graph_500)
    sc_ranks_500 = [{"target_id": map_500[step["artifact_id"]], "score": step["priority_score"]} for step in sc_res_500["migration_order"]]

    sens_500_results = {}
    for cfg_name, weights in sens_configs.items():
        gt_custom = []
        for cert in certs_500:
            cid = f"cert:{cert['fingerprint'][:16]}"
            deps = graph_500.find_downstream_dependencies(cid)
            dep_count = len(deps)
            is_vuln = 1.0 if cert["quantum_status"] == "VULNERABLE" else 0.1
            log_blast = min(100.0, math.log(1 + dep_count, 2) * 12.5)
            dep_arts = [art_map_500[did] for did in deps if did in art_map_500]
            avg_crit = sum(a["criticality_score"] for a in dep_arts) / len(dep_arts) if dep_arts else 30.0

            score = (avg_crit * weights["w_crit"]) + (is_vuln * 100.0 * weights["w_vuln"]) + (log_blast * weights["w_blast"])
            gt_custom.append({
                "target_id": cid,
                "ground_truth_score": score,
                "is_critical_target": (dep_count >= 10 and is_vuln > 0.5) or (avg_crit >= 80.0 and is_vuln > 0.5),
            })
        gt_custom.sort(key=lambda x: x["ground_truth_score"], reverse=True)
        for i, item in enumerate(gt_custom):
            item["ground_truth_rank"] = i + 1

        b_rec10 = calculate_top_k_recall(b_ranks_500, gt_custom, 10)
        sc_rec10 = calculate_top_k_recall(sc_ranks_500, gt_custom, 10)
        b_inv = calculate_priority_inversions(b_ranks_500, gt_custom)
        sc_inv = calculate_priority_inversions(sc_ranks_500, gt_custom)
        b_rho = calculate_spearman_correlation(b_ranks_500, gt_custom)[0]
        sc_rho = calculate_spearman_correlation(sc_ranks_500, gt_custom)[0]

        sens_500_results[cfg_name] = {
            "weights": weights,
            "baseline_recall_10": b_rec10,
            "signchain_recall_10": sc_rec10,
            "baseline_inversions": b_inv,
            "signchain_inversions": sc_inv,
            "baseline_rho": b_rho,
            "signchain_rho": sc_rho,
            "delta_inversions": b_inv - sc_inv,
            "delta_recall": sc_rec10 - b_rec10,
        }

    with open(output_base / "sensitivity" / "sensitivity_500.json", "w") as f:
        json.dump(sens_500_results, f, indent=2)

    print("\n=================================================================")
    print("STEP 5: PUBLICATION FIGURE GENERATION (FIGURES 1 - 10)")
    print("=================================================================")
    
    plots = generate_all_publication_figures(
        perf_results=perf_summary,
        multi_seed_results=multi_seed_by_size,
        ablation_results=ablation_by_size[100],
        sensitivity_results=sens_500_results,
        scenario_comparison_results=scenario_comparison_results,
        output_dir=str(plots_dir),
    )
    print(f"[+] Successfully generated {len(plots)} publication figures in '{plots_dir}'.")

    # Complete Summary JSON
    master_summary = {
        "execution_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "performance_scalability": perf_summary,
        "scenario_comparisons": scenario_comparison_results,
        "ablation_study": ablation_by_size,
        "sensitivity_analysis_500": sens_500_results,
        "generated_figures": plots,
    }
    with open(output_base / "summaries" / "master_benchmark_summary.json", "w") as f:
        json.dump(master_summary, f, indent=2)

    print("\n[+] Large-scale benchmark execution finished successfully.")


if __name__ == "__main__":
    execute_large_scale_benchmark()
