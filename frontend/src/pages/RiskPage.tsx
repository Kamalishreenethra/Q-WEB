import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, Pagination } from '../components/FeedbackComponents';
import { RiskResponse } from '../types/api';

export const RiskPage: React.FC = () => {
  const [assessments, setAssessments] = useState<RiskResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filter
  const [riskLevel, setRiskLevel] = useState<string>('');

  useEffect(() => {
    loadRiskData();
  }, [page, riskLevel]);

  async function loadRiskData() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getRiskAssessments(page, pageSize, riskLevel || undefined);
      setAssessments(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve quantum risk assessments');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 className="page-title">Quantum Risk Engine Analytics</h1>
      <p className="page-subtitle">
        Transparent weighted risk scoring model: Risk = w_c·R_crypto + w_a·C_asset + w_e·E + w_h·H + w_d·I_dep + w_m·M_comp.
      </p>

      {/* Filter Bar */}
      <div className="filter-bar">
        <select
          className="select-input"
          value={riskLevel}
          onChange={(e) => { setRiskLevel(e.target.value); setPage(1); }}
        >
          <option value="">All Risk Tiers</option>
          <option value="CRITICAL">Critical (Score 80–100)</option>
          <option value="HIGH">High (Score 60–79)</option>
          <option value="MEDIUM">Medium (Score 40–59)</option>
          <option value="LOW">Low (Score 0–39)</option>
        </select>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadRiskData} />}

      {loading ? (
        <LoadingSpinner message="Calculating quantum risk breakdown across assets..." />
      ) : assessments.length === 0 ? (
        <div className="state-box">
          <p>No risk assessments match the selected filter.</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="table-container" style={{ border: 'none' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Artifact ID</th>
                  <th>Risk Score</th>
                  <th>Risk Tier</th>
                  <th>Formula Breakdown & Rationale</th>
                  <th>Model Version</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <code>{r.artifact_id.slice(0, 12)}...</code>
                    </td>
                    <td>
                      <span style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>
                        {r.risk_score.toFixed(1)}
                      </span>
                    </td>
                    <td><Badge label={r.risk_level} /></td>
                    <td>
                      <div style={{ fontSize: '12px', color: '#fff', marginBottom: '4px' }}>
                        {r.calculation_explanation}
                      </div>
                      {r.factor_breakdown && Object.keys(r.factor_breakdown).length > 0 && (
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                          {Object.entries(r.factor_breakdown)
                            .map(([k, v]) => `${k}: ${typeof v === 'number' ? v.toFixed(1) : v}`)
                            .join(' | ')}
                        </div>
                      )}
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-dim)' }}>{r.model_version}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={{ padding: '0 16px' }}>
            <Pagination
              page={page}
              totalPages={totalPages}
              totalItems={total}
              pageSize={pageSize}
              onPageChange={setPage}
            />
          </div>
        </div>
      )}
    </div>
  );
};
