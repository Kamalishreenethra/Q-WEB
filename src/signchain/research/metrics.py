"""
Evaluation metrics for comparing SignChain against baseline models and ground truth.

Includes:
  - Top-K Recall (K=5, 10, 20)
  - Spearman Rank Correlation (rho and p-value)
  - Priority Inversion Count
  - Critical Target Miss Rate
  - High-Impact Dependency Recall
  - Migration Order Agreement
"""
from typing import Any, Dict, List, Set, Tuple
from scipy.stats import spearmanr


def calculate_top_k_recall(
    predicted_rankings: List[Dict[str, Any]],
    ground_truth_rankings: List[Dict[str, Any]],
    k: int = 10,
) -> float:
    """
    Calculates the proportion of top-K ground-truth targets captured in the top-K predicted targets.
    Recall@K = |Top_K(Predicted) ∩ Top_K(GroundTruth)| / K
    """
    if k <= 0 or not ground_truth_rankings or not predicted_rankings:
        return 0.0

    actual_k = min(k, len(ground_truth_rankings), len(predicted_rankings))

    gt_top_k: Set[str] = {item["target_id"] for item in ground_truth_rankings[:actual_k]}
    pred_top_k: Set[str] = {item["target_id"] for item in predicted_rankings[:actual_k]}

    intersection = gt_top_k.intersection(pred_top_k)
    return round(len(intersection) / actual_k, 4)


def calculate_spearman_correlation(
    predicted_rankings: List[Dict[str, Any]],
    ground_truth_rankings: List[Dict[str, Any]],
) -> Tuple[float, float]:
    """
    Calculates Spearman's rank correlation coefficient (rho) and p-value between predicted and ground truth orders.
    """
    gt_map = {item["target_id"]: item.get("ground_truth_rank", i + 1) for i, item in enumerate(ground_truth_rankings)}

    pred_ranks = []
    gt_ranks = []

    for i, item in enumerate(predicted_rankings):
        tid = item["target_id"]
        if tid in gt_map:
            pred_ranks.append(i + 1)
            gt_ranks.append(gt_map[tid])

    if len(pred_ranks) < 2:
        return 0.0, 1.0

    res = spearmanr(pred_ranks, gt_ranks)
    rho = 0.0 if res.statistic != res.statistic else float(res.statistic)  # handle NaN
    p_val = 1.0 if res.pvalue != res.pvalue else float(res.pvalue)

    return round(rho, 4), round(p_val, 6)


def calculate_priority_inversions(
    predicted_rankings: List[Dict[str, Any]],
    ground_truth_rankings: List[Dict[str, Any]],
) -> int:
    """
    Counts the number of priority inversions:
    A priority inversion occurs for a pair (i, j) if Predicted ranks i ahead of j (rank_pred(i) < rank_pred(j)),
    but Ground Truth ranks j strictly ahead of i (rank_gt(j) < rank_gt(i)).
    """
    gt_map = {item["target_id"]: item.get("ground_truth_rank", i + 1) for i, item in enumerate(ground_truth_rankings)}
    common_targets = [item["target_id"] for item in predicted_rankings if item["target_id"] in gt_map]

    inversions = 0
    n = len(common_targets)

    for i in range(n):
        for j in range(i + 1, n):
            target_i = common_targets[i]
            target_j = common_targets[j]

            if gt_map[target_j] < gt_map[target_i]:
                inversions += 1

    return inversions


def calculate_critical_missed_rate(
    predicted_rankings: List[Dict[str, Any]],
    ground_truth_rankings: List[Dict[str, Any]],
    k: int = 10,
) -> float:
    """
    Calculates the proportion of true critical migration targets that were missed in the top-K predictions.
    """
    critical_gt_ids = {
        item["target_id"]
        for item in ground_truth_rankings
        if item.get("is_critical_target", False)
    }

    if not critical_gt_ids:
        return 0.0

    actual_k = min(k, len(predicted_rankings))
    pred_top_k = {item["target_id"] for item in predicted_rankings[:actual_k]}

    missed_count = len(critical_gt_ids.difference(pred_top_k))
    return round(missed_count / len(critical_gt_ids), 4)


def calculate_high_impact_recall(
    predicted_rankings: List[Dict[str, Any]],
    ground_truth_rankings: List[Dict[str, Any]],
    k: int = 10,
) -> float:
    """
    Calculates recall of true high-impact dependency targets (assets with >= 5 dependents) within Top-K.
    """
    high_impact_gt_ids = {
        item["target_id"]
        for item in ground_truth_rankings
        if item.get("is_high_impact_target", False)
    }

    if not high_impact_gt_ids:
        return 1.0  # None existed, not a miss

    actual_k = min(k, len(predicted_rankings))
    pred_top_k = {item["target_id"] for item in predicted_rankings[:actual_k]}

    captured = len(high_impact_gt_ids.intersection(pred_top_k))
    return round(captured / len(high_impact_gt_ids), 4)


def calculate_order_agreement(
    predicted_rankings: List[Dict[str, Any]],
    ground_truth_rankings: List[Dict[str, Any]],
) -> float:
    """
    Calculates pairwise order agreement (Kendall's tau-like concordant pair ratio).
    Agreement = Concordant_Pairs / Total_Pairs
    """
    gt_map = {item["target_id"]: item.get("ground_truth_rank", i + 1) for i, item in enumerate(ground_truth_rankings)}
    common = [item["target_id"] for item in predicted_rankings if item["target_id"] in gt_map]
    n = len(common)
    if n < 2:
        return 1.0

    total_pairs = n * (n - 1) // 2
    concordant = 0
    for i in range(n):
        for j in range(i + 1, n):
            t_i = common[i]
            t_j = common[j]
            # In predicted, i is before j (rank_pred(i) < rank_pred(j))
            if gt_map[t_i] < gt_map[t_j]:
                concordant += 1

    return round(concordant / total_pairs, 4)
