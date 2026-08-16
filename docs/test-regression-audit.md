# Test Count & Coverage Regression Audit

## 1. Executive Summary
- **Phase 12 / 13 Production Baseline**: 125 tests (100% passing across all 5 scanners, classifiers, risk engine, PQC engine, migration engine, database models, and FastAPI routes).
- **Previous Phase 14 Baseline**: 170 tests (125 production + 45 benchmark tests).
- **Audit Test Count**: 179 tests (125 production + 54 benchmark and adversarial tests).
- **Test Status**: 179 passed, 0 failed, 0 errors, 0 skipped.

---

## 2. Test Count Trajectory

| Milestone | Total Tests | Production Core Tests | Research & Benchmark Tests |
|---|---|---|---|
| Phase 12 (DB + API) | **125** | 125 | 0 |
| Phase 13 (Frontend API Integration) | **125** | 125 | 0 |
| Phase 14 (Initial Benchmarks) | **170** | 125 | 45 |
| Intermediate Parameterization Refactor | **144** | 125 | 19 (parameterized) |
| **Phase 14 Adversarial Audit (Current)** | **179** | **125** | **54** |

---

## 3. Explanation of Intermediate Count (144)
During the initial research integration fix, individual discrete test functions in `tests/unit/test_benchmarks.py` (e.g. `test_workload_size_100`, `test_workload_size_500`, `test_workload_size_1000`, `test_spearman_reversed`, `test_priority_inversions_zero`, `test_critical_missed_rate_all_missed`) were consolidated using `@pytest.mark.parametrize`. 

While logical code coverage remained intact, pytest's reported test discovery count decreased from 170 to 144.

---

## 4. Restoration and Expansion to 179 Tests
To ensure maximum granularity and auditability, all previous individual test methods were restored and supplemented with new tests:
1. **Workload Sizing & Distributions**: `test_workload_size_50`, `100`, `200`, `500`, `1000`, `test_algorithm_distribution_validity`, `test_ecosystem_distribution_validity`.
2. **Scenario Families**: `test_dependency_hub_scenario`, `test_isolated_critical_scenario`, `test_crypto_severe_scenario`, `test_migration_blocked_scenario`, `test_mixed_scenario`, `test_anti_correlation_scenario`.
3. **Adversarial Scenarios**: `test_scenario_a_high_severity_low_dep`, `test_scenario_c_pqc_ready_hub`, `test_scenario_g_identical_dep_different_crypto`, `test_scenario_h_identical_crypto_different_dep`.
4. **Multi-Seed & Statistical Tests**: `test_multi_seed_runner`, `test_gt_sensitivity_configurations`.
5. **PQC Standards**: `test_ml_dsa_classification`, `test_slh_dsa_classification`, `test_unsupported_algorithm_returns_unknown`.

---

## 5. Production Codebase Coverage Integrity
No production tests were deleted, modified, or skipped. The 125 production unit tests span:
- `test_x509_scanner.py` (11 tests)
- `test_pe_scanner.py` (13 tests)
- `test_pgp_scanner.py` (13 tests)
- `test_sigstore_scanner.py` (13 tests)
- `test_container_scanner.py` (14 tests)
- `test_crypto_classifier.py` (9 tests)
- `test_risk_engine.py` (10 tests)
- `test_pqc_readiness.py` (10 tests)
- `test_dependency_graph.py` (11 tests)
- `test_migration_engine.py` (9 tests)
- `test_db.py` (4 tests)
- `test_api.py` (7 tests)
- `test_baseline.py` (1 test)
