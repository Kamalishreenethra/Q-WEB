import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, EmptyState, Pagination } from '../components/FeedbackComponents';
import { AlertTriangle, RefreshCw, Calculator } from 'lucide-react';
import { RiskResponse } from '../types/api';

export const RiskPage: React.FC = () => {
  const [assessments, setAssessments] = useState<RiskResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filter
  const [riskLevel, setRiskLevel] = useState<string>('');

  useEffect(() => {
    loadRiskData();
  }, [page, pageSize, riskLevel]);

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
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <AlertTriangle size={22} color="var(--status-critical)" />
            Quantum Risk Engine Analytics
          </h1>
          <p className="page-subtitle">
            Transparent multi-factor risk model combining cryptographic algorithm vulnerability, asset criticality, exposure, and dependency blast radius.
          </p>
        </div>
        <button className="btn" onClick={loadRiskData}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Model Formula Explainer Card */}
      <div className="card" style={{ background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.9) 0%, rgba(10, 15, 29, 0.95) 100%)' }}>
        <div className="card-title">
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Calculator size={15} color="var(--color-primary)" />
            Explainable Transparent Risk Model
          </span>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Engine v0.1.0</span>
        </div>
        <div style={{ background: '#04060c', padding: '12px 16px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#38bdf8' }}>
          Risk = 0.35·CryptoRisk + 0.20·AssetCriticality + 0.15·Exposure + 0.10·Horizon + 0.10·DependencyImpact + 0.10·Complexity
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px', marginTop: '12px', fontSize: '12px', color: 'var(--text-muted)' }}>
          <div>• <strong>CryptoRisk:</strong> Shor factorization susceptibility</div>
          <div>• <strong>AssetCriticality:</strong> Core service / binary impact</div>
          <div>• <strong>Exposure:</strong> Public vs internal deployment</div>
          <div>• <strong>DependencyImpact:</strong> Downstream transitive blast radius</div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="filter-bar">
        <select
          className="select-input"
          value={riskLevel}
          onChange={(e) => { setRiskLevel(e.target.value); setPage(1); }}
        >
          <option value="">All Risk Levels</option>
          <option value="CRITICAL">CRITICAL (&gt; 80)</option>
          <option value="HIGH">HIGH (60 - 80)</option>
          <option value="MEDIUM">MEDIUM (30 - 60)</option>
          <option value="LOW">LOW (&lt; 30)</option>
        </select>
      </div>

      {/* Content */}
      {loading ? (
        <LoadingSpinner message="Calculating transparent quantum risk factors..." />
      ) : error ? (
        <ErrorAlert message={error} onRetry={loadRiskData} />
      ) : assessments.length === 0 ? (
        <div className="card">
          <EmptyState
            title="No Risk Assessments Recorded"
            description="Quantum risk assessments are computed deterministically when artifacts and certificate chains are ingested."
            actionCommand="signchain store /path/to/binary.exe"
            onRefresh={loadRiskData}
          />
        </div>
      ) : (
        <div className="card" style={{ padding: '16px' }}>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Artifact Identifier</th>
                  <th>Risk Score</th>
                  <th>Risk Level</th>
                  <th>Factor Breakdown</th>
                  <th>Transparent Explanation</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <code style={{ fontSize: '11px', color: 'var(--color-primary)' }}>
                        {r.artifact_id.slice(0, 12)}...
                      </code>
                    </td>
                    <td>
                      <span style={{ fontSize: '16px', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fff' }}>
                        {r.risk_score.toFixed(1)}
                      </span>
                    </td>
                    <td><Badge label={r.risk_level} /></td>
                    <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      <span title="Crypto Risk">C:{r.factor_breakdown?.crypto_risk ?? '-'}</span> ·{' '}
                      <span title="Criticality">A:{r.factor_breakdown?.asset_criticality ?? '-'}</span> ·{' '}
                      <span title="Exposure">E:{r.factor_breakdown?.exposure ?? '-'}</span> ·{' '}
                      <span title="Dep Impact">D:{r.factor_breakdown?.dependency_impact ?? '-'}</span>
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '380px' }}>
                      {r.calculation_explanation}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <Pagination
            page={page}
            totalPages={totalPages}
            totalItems={total}
            pageSize={pageSize}
            onPageChange={setPage}
            onPageSizeChange={(newSize) => { setPageSize(newSize); setPage(1); }}
          />
        </div>
      )}
    </div>
  );
};
