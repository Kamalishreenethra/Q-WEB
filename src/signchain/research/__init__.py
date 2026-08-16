"""
SignChain Research & Benchmarking Framework.
"""
from signchain.research.workload_generator import SyntheticWorkloadGenerator
from signchain.research.baseline import FlatCryptographicBaseline
from signchain.research.metrics import (
    calculate_top_k_recall,
    calculate_spearman_correlation,
    calculate_priority_inversions,
    calculate_critical_missed_rate,
)
from signchain.research.runner import BenchmarkRunner
from signchain.research.plotting import generate_benchmark_plots

__all__ = [
    "SyntheticWorkloadGenerator",
    "FlatCryptographicBaseline",
    "calculate_top_k_recall",
    "calculate_spearman_correlation",
    "calculate_priority_inversions",
    "calculate_critical_missed_rate",
    "BenchmarkRunner",
    "generate_benchmark_plots",
]
