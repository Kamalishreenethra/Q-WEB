"""
Audit runner script for multi-seed, multi-scenario evaluation.
"""
from signchain.research.runner import BenchmarkRunner
from signchain.research.workload_generator import ScenarioFamily

def run_audit():
    runner = BenchmarkRunner()
    seeds = list(range(42, 52))

    print("=== EXECUTING MULTI-SEED VALIDATION (N=100, seeds=42..51) ===")
    scenarios = [
        ScenarioFamily.MIXED,
        ScenarioFamily.DEPENDENCY_HUB,
        ScenarioFamily.ANTI_CORRELATION,
        ScenarioFamily.CRYPTO_SEVERE,
        ScenarioFamily.ISOLATED_CRITICAL,
        ScenarioFamily.MIGRATION_BLOCKED,
    ]

    for scenario in scenarios:
        res = runner.run_multi_seed_evaluation(size=100, seeds=seeds, scenario_family=scenario)
        out = res["outcomes"]
        ag = res["aggregate_metrics"]
        eff = res["effect_size"]
        st = res["statistical_test"]
        b_inv = ag["baseline"]["mean_priority_inversions"]
        sc_inv = ag["signchain"]["mean_priority_inversions"]
        b_rec = ag["baseline"]["mean_recall_10"]
        sc_rec = ag["signchain"]["mean_recall_10"]
        b_rho = ag["baseline"]["mean_spearman_rho"]
        sc_rho = ag["signchain"]["mean_spearman_rho"]

        print(f"Scenario: {scenario}")
        print(f"  Outcomes across 10 seeds: {out}")
        print(f"  Inversions: Baseline = {b_inv:.1f} +/- {ag['baseline']['std_priority_inversions']:.1f}, SignChain = {sc_inv:.1f} +/- {ag['signchain']['std_priority_inversions']:.1f}")
        print(f"  Inversion Delta: {eff['mean_inversion_reduction']:.2f} (Cohen's d = {eff['cohens_d']:.3f})")
        print(f"  Recall@10: Baseline = {b_rec:.4f}, SignChain = {sc_rec:.4f} (Delta = {eff['mean_recall_10_improvement']:+.4f})")
        print(f"  Spearman rho: Baseline = {b_rho:.4f}, SignChain = {sc_rho:.4f}")
        print(f"  Wilcoxon Paired Test: p-value = {st['p_value']}, Significant (alpha=0.05): {st['significant_at_005']}")
        print("-" * 65)

if __name__ == "__main__":
    run_audit()
