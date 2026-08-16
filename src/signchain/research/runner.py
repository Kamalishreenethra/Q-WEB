"""
Automated research benchmark runner for SignChain.

Executes:
  Track A — Performance & Scalability measurement
  Track B — Comparative Research Experiment (Baseline vs Ablation Models vs SignChain vs Independent Ground Truth)

Features:
  - Multi-seed independent scenario evaluation (seeds 42..51)
  - 6 distinct scenario families
  - Full 4-way ablation (Model A, Model B, Model C, Model D)
  - Statistical significance & effect size testing
  - Win/Loss/Tie outcome analysis
"""
import json
import time
import platform
import statistics
import tracemalloc
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

import psutil
from scipy.stats import wilcoxon

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


class BenchmarkRunner:
    """
    Orchestrates Track A and Track B benchmarks, collecting metrics and saving results.
    """

    def __init__(self, output_dir: str = "research/results"):
        self.output_dir = Path(output_dir)
        self.perf_dir = self.output_dir / "performance"
        self.exp_dir = self.output_dir / "experiments"
        self.raw_dir = self.output_dir / "raw"
        self.comparison_dir = self.output_dir / "comparison"
        self.ablation_dir = self.output_dir / "ablation"

        for d in [self.perf_dir, self.exp_dir, self.raw_dir, self.comparison_dir, self.ablation_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def get_environment_info(self) -> Dict[str, Any]:
        """Collects hardware and software environment metadata automatically."""
        return {
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "total_ram_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "signchain_version": "0.1.0",
        }

    # ----------------------------------------------------------------
    # Track A: Performance & Scalability
    # ----------------------------------------------------------------

    def run_track_a_benchmark(
        self,
        sizes: Optional[List[int]] = None,
        repetitions: int = 5,
        seed: int = 42,
    ) -> Dict[str, Any]:
        if sizes is None:
            sizes = [100, 500, 1000, 5000, 10000]

        env_info = self.get_environment_info()
        generator = SyntheticWorkloadGenerator(seed=seed)
        summary_results = []

        for size in sizes:
            workload = generator.generate_workload(size=size)
            certs = workload["certificates"]
            graph = workload["graph"]

            engine = MigrationPrioritizationEngine()

            # Warmup run
            engine.prioritize_all(certs, graph_engine=graph)

            pipeline_times: List[float] = []
            graph_times: List[float] = []
            mig_times: List[float] = []
            mem_usages: List[float] = []

            for rep in range(repetitions):
                tracemalloc.start()
                t0 = time.perf_counter()

                t_graph_start = time.perf_counter()
                _ = graph.get_graph_statistics()
                t_graph = time.perf_counter() - t_graph_start
                graph_times.append(t_graph)

                t_mig_start = time.perf_counter()
                _ = engine.prioritize_all(certs, graph_engine=graph)
                t_mig = time.perf_counter() - t_mig_start
                mig_times.append(t_mig)

                total_t = time.perf_counter() - t0
                _, peak_mem = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                pipeline_times.append(total_t)
                mem_usages.append(peak_mem / (1024 * 1024))

            result = {
                "workload_size": size,
                "artifacts_count": workload["artifact_count"],
                "certificates_count": workload["certificate_count"],
                "nodes_count": workload["graph_nodes"],
                "edges_count": workload["graph_edges"],
                "total_time_mean_sec": round(statistics.mean(pipeline_times), 6),
                "total_time_median_sec": round(statistics.median(pipeline_times), 6),
                "total_time_stddev_sec": round(statistics.stdev(pipeline_times) if len(pipeline_times) > 1 else 0.0, 6),
                "total_time_min_sec": round(min(pipeline_times), 6),
                "total_time_max_sec": round(max(pipeline_times), 6),
                "migration_time_mean_sec": round(statistics.mean(mig_times), 6),
                "migration_time_median_sec": round(statistics.median(mig_times), 6),
                "graph_time_mean_sec": round(statistics.mean(graph_times), 6),
                "peak_memory_mean_mb": round(statistics.mean(mem_usages), 4),
                "peak_memory_max_mb": round(max(mem_usages), 4),
                "repetitions": repetitions,
            }
            summary_results.append(result)

            raw_record = {
                "environment": env_info,
                "metrics": result,
                "raw_pipeline_times": pipeline_times,
                "raw_graph_times": graph_times,
                "raw_migration_times": mig_times,
                "raw_memory_mb": mem_usages,
            }
            with open(self.perf_dir / f"{size}.json", "w", encoding="utf-8") as f:
                json.dump(raw_record, f, indent=2)

        csv_path = self.output_dir / "performance_summary.csv"
        headers = [
            "workload_size", "nodes_count", "edges_count",
            "total_time_mean_sec", "total_time_median_sec", "total_time_stddev_sec",
            "migration_time_mean_sec", "peak_memory_mean_mb",
        ]
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(",".join(headers) + "\n")
            for r in summary_results:
                f.write(",".join(str(r[h]) for h in headers) + "\n")

        return {
            "status": "SUCCESS",
            "environment": env_info,
            "workload_sizes": sizes,
            "results": summary_results,
        }

    # ----------------------------------------------------------------
    # Track B: Comparative Research Experiment
    # ----------------------------------------------------------------

    def run_track_b_experiment(
        self,
        size: int = 100,
        seed: int = 42,
        scenario_family: str = ScenarioFamily.MIXED,
    ) -> Dict[str, Any]:
        """
        Executes a single deterministic comparative experiment across Baseline, Ablation models, and SignChain.
        """
        generator = SyntheticWorkloadGenerator(seed=seed)
        workload = generator.generate_workload(size=size, scenario_family=scenario_family)
        certs = workload["certificates"]
        graph = workload["graph"]
        ground_truth = workload["ground_truth"]
        subject_to_target_id = workload["subject_to_target_id"]

        # === Model Baseline: Flat Cryptographic Inventory (Zero Graph) ===
        baseline_model = FlatCryptographicBaseline()
        baseline_ranks = baseline_model.prioritize(certs)

        # === Model A (Ablation): Crypto Risk Only ===
        engine_a = MigrationPrioritizationEngine(
            weights={"w_risk": 1.0, "w_dep_impact": 0.0, "w_readiness": 0.0, "w_complexity": 0.0}
        )
        res_a = engine_a.prioritize_all(certs, graph_engine=graph)
        ranks_a = self._extract_ranks(res_a, subject_to_target_id)

        # === Model B (Ablation): Crypto Risk + Dependency Impact ===
        engine_b = MigrationPrioritizationEngine(
            weights={"w_risk": 0.50, "w_dep_impact": 0.50, "w_readiness": 0.0, "w_complexity": 0.0}
        )
        res_b = engine_b.prioritize_all(certs, graph_engine=graph)
        ranks_b = self._extract_ranks(res_b, subject_to_target_id)

        # === Model C (Ablation): Crypto Risk + Dependency + Readiness ===
        engine_c = MigrationPrioritizationEngine(
            weights={"w_risk": 0.40, "w_dep_impact": 0.30, "w_readiness": 0.30, "w_complexity": 0.0}
        )
        res_c = engine_c.prioritize_all(certs, graph_engine=graph)
        ranks_c = self._extract_ranks(res_c, subject_to_target_id)

        # === Model D: Full Production SignChain Engine ===
        signchain_engine = MigrationPrioritizationEngine()
        signchain_result = signchain_engine.prioritize_all(certs, graph_engine=graph)
        signchain_ranks = self._extract_ranks(signchain_result, subject_to_target_id)

        # === Compute Metrics for all models ===
        models = {
            "baseline": baseline_ranks,
            "model_a_crypto_only": ranks_a,
            "model_b_crypto_dep": ranks_b,
            "model_c_crypto_dep_readiness": ranks_c,
            "model_d_full_signchain": signchain_ranks,
        }

        evaluated_metrics = {}
        for m_name, m_ranks in models.items():
            evaluated_metrics[m_name] = {
                "recall@5": calculate_top_k_recall(m_ranks, ground_truth, 5),
                "recall@10": calculate_top_k_recall(m_ranks, ground_truth, 10),
                "recall@20": calculate_top_k_recall(m_ranks, ground_truth, 20),
                "spearman_rho": calculate_spearman_correlation(m_ranks, ground_truth)[0],
                "spearman_pval": calculate_spearman_correlation(m_ranks, ground_truth)[1],
                "priority_inversions": calculate_priority_inversions(m_ranks, ground_truth),
                "critical_miss_rate_top10": calculate_critical_missed_rate(m_ranks, ground_truth, 10),
                "high_impact_recall_top10": calculate_high_impact_recall(m_ranks, ground_truth, 10),
                "order_agreement": calculate_order_agreement(m_ranks, ground_truth),
            }

        # Win/Loss determination (SignChain vs Baseline on Inversions & Recall@10)
        base_inv = evaluated_metrics["baseline"]["priority_inversions"]
        sc_inv = evaluated_metrics["model_d_full_signchain"]["priority_inversions"]
        base_rec10 = evaluated_metrics["baseline"]["recall@10"]
        sc_rec10 = evaluated_metrics["model_d_full_signchain"]["recall@10"]

        if sc_inv < base_inv or sc_rec10 > base_rec10:
            outcome = "SIGNCHAIN_WIN"
        elif sc_inv > base_inv or sc_rec10 < base_rec10:
            outcome = "BASELINE_WIN"
        else:
            outcome = "TIE"

        experiment_summary = {
            "experiment_id": f"track_b_{size}_{scenario_family}_seed{seed}",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "workload_size": size,
            "seed": seed,
            "scenario_family": scenario_family,
            "certificate_count": len(certs),
            "graph_nodes": workload["graph_nodes"],
            "graph_edges": workload["graph_edges"],
            "ground_truth_count": len(ground_truth),
            "critical_targets_count": sum(1 for g in ground_truth if g.get("is_critical_target")),
            "baseline": evaluated_metrics["baseline"],
            "signchain": evaluated_metrics["model_d_full_signchain"],
            "ablation": evaluated_metrics,
            "outcome": outcome,
        }

        with open(self.exp_dir / f"track_b_{size}_{scenario_family}_s{seed}.json", "w", encoding="utf-8") as f:
            json.dump(experiment_summary, f, indent=2)

        return experiment_summary

    def run_multi_seed_evaluation(
        self,
        size: int = 100,
        seeds: Optional[List[int]] = None,
        scenario_family: str = ScenarioFamily.MIXED,
    ) -> Dict[str, Any]:
        """
        Runs rigorous multi-seed evaluation across 10 deterministic seeds (42..51)
        and computes paired statistical tests and effect sizes.
        """
        if seeds is None:
            seeds = [42, 43, 44, 45, 46, 47, 48, 49, 50, 51]

        seed_results = []
        outcomes = {"SIGNCHAIN_WIN": 0, "BASELINE_WIN": 0, "TIE": 0}

        base_inversions_list = []
        sc_inversions_list = []
        base_recall10_list = []
        sc_recall10_list = []
        base_rho_list = []
        sc_rho_list = []

        for s in seeds:
            res = self.run_track_b_experiment(size=size, seed=s, scenario_family=scenario_family)
            seed_results.append(res)
            outcomes[res["outcome"]] = outcomes.get(res["outcome"], 0) + 1

            base_inversions_list.append(res["baseline"]["priority_inversions"])
            sc_inversions_list.append(res["signchain"]["priority_inversions"])
            base_recall10_list.append(res["baseline"]["recall@10"])
            sc_recall10_list.append(res["signchain"]["recall@10"])
            base_rho_list.append(res["baseline"]["spearman_rho"])
            sc_rho_list.append(res["signchain"]["spearman_rho"])

        # Paired Wilcoxon Signed-Rank Test on Inversions across seeds
        diff_inversions = [b - s for b, s in zip(base_inversions_list, sc_inversions_list)]
        wilcoxon_stat = None
        wilcoxon_pval = None

        if len(seeds) >= 6 and not all(d == 0 for d in diff_inversions):
            try:
                w_res = wilcoxon(base_inversions_list, sc_inversions_list)
                wilcoxon_stat = round(float(w_res.statistic), 4)
                wilcoxon_pval = round(float(w_res.pvalue), 6)
            except Exception:
                pass

        # Effect sizes: mean difference and Cohen's d approximation
        mean_inv_diff = statistics.mean(diff_inversions)
        std_inv_diff = statistics.stdev(diff_inversions) if len(diff_inversions) > 1 else 0.0
        cohens_d = (mean_inv_diff / std_inv_diff) if std_inv_diff > 0 else 0.0

        mean_rec10_diff = statistics.mean(sc_recall10_list) - statistics.mean(base_recall10_list)

        multi_summary = {
            "evaluation_type": "Multi-Seed Paired Evaluation",
            "workload_size": size,
            "seeds": seeds,
            "scenario_family": scenario_family,
            "total_independent_runs": len(seeds),
            "outcomes": outcomes,
            "aggregate_metrics": {
                "baseline": {
                    "mean_priority_inversions": round(statistics.mean(base_inversions_list), 2),
                    "std_priority_inversions": round(statistics.stdev(base_inversions_list), 2),
                    "mean_recall_10": round(statistics.mean(base_recall10_list), 4),
                    "mean_spearman_rho": round(statistics.mean(base_rho_list), 4),
                },
                "signchain": {
                    "mean_priority_inversions": round(statistics.mean(sc_inversions_list), 2),
                    "std_priority_inversions": round(statistics.stdev(sc_inversions_list), 2),
                    "mean_recall_10": round(statistics.mean(sc_recall10_list), 4),
                    "mean_spearman_rho": round(statistics.mean(sc_rho_list), 4),
                },
            },
            "effect_size": {
                "mean_inversion_reduction": round(mean_inv_diff, 2),
                "inversion_std_dev": round(std_inv_diff, 2),
                "cohens_d": round(cohens_d, 4),
                "mean_recall_10_improvement": round(mean_rec10_diff, 4),
            },
            "statistical_test": {
                "test": "Wilcoxon Signed-Rank Test (Paired across seeds)",
                "statistic": wilcoxon_stat,
                "p_value": wilcoxon_pval,
                "significant_at_005": (wilcoxon_pval is not None and wilcoxon_pval < 0.05),
            },
            "individual_seed_results": seed_results,
        }

        with open(self.output_dir / f"multi_seed_{size}_{scenario_family}.json", "w", encoding="utf-8") as f:
            json.dump(multi_summary, f, indent=2)

        return multi_summary

    def _extract_ranks(self, result: Dict[str, Any], subject_to_target_id: Dict[str, str]) -> List[Dict[str, Any]]:
        ordered_steps = result.get("migration_order", [])
        ranks = []
        for step in ordered_steps:
            subject = step["artifact_id"]
            target_id = subject_to_target_id.get(subject)
            if target_id:
                ranks.append({
                    "target_id": target_id,
                    "subject": subject,
                    "score": step["priority_score"],
                    "priority_level": step["priority_level"],
                    "downstream_impact": step.get("downstream_impact", 0),
                })
        return ranks
