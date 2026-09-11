import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, EmptyState, Pagination } from '../components/FeedbackComponents';
import { Zap, RefreshCw } from 'lucide-react';
import { PQCReadinessResponse } from '../types/api';

export const PQCReadinessPage: React.FC = () => {
  const [assessments, setAssessments] = useState<PQCReadinessResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filter
  const [readinessState, setReadinessState] = useState<string>('');

  useEffect(() => {
    loadPQCData();
  }, [page, pageSize, readinessState]);

  async function loadPQCData() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getPQCReadiness(page, pageSize, readinessState || undefined);
      setAssessments(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve PQC readiness assessments');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Zap size={22} color="var(--color-violet)" />
            Post-Quantum Cryptographic Readiness Engine
          </h1>
          <p className="page-subtitle">
            Classification of supply chain assets into readiness tiers: NOT_READY $
ightarrow$ PARTIALLY_READY $
ightarrow$ HYBRID_READY $
ightarrow$ PQC_READY based on NIST FIPS 204/205 compliance.
          </p>
        </div>
        <button className="btn" onClick={loadPQCData}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Filter Bar */}
      <div className="filter-bar">
        <select
          className="select-input"
          value={readinessState}
          onChange={(e) => { setReadinessState(e.target.value); setPage(1); }}
        >
          <option value="">All Readiness States</option>
          <option value="NOT_READY">NOT_READY (Classical Only)</option>
          <option value="PARTIALLY_READY">PARTIALLY_READY (Transitional)</option>
          <option value="HYBRID_READY">HYBRID_READY (Composite / Dual Signature)</option>
          <option value="PQC_READY">PQC_READY (ML-DSA / SLH-DSA)</option>
        </select>
      </div>

      {/* Content */}
      {loading ? (
        <LoadingSpinner message="Classifying post-quantum cryptographic readiness states..." />
      ) : error ? (
        <ErrorAlert message={error} onRetry={loadPQCData} />
      ) : assessments.length === 0 ? (
        <div className="card">
          <EmptyState
            title="No PQC Readiness Records Found"
            description="PQC readiness assessments are evaluated dynamically against the SignChain knowledge base and NIST standardized algorithm taxonomies."
            actionCommand="signchain store /path/to/signed-artifact.exe"
            onRefresh={loadPQCData}
          />
        </div>
      ) : (
        <div className="card" style={{ padding: '16px' }}>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Artifact Identifier</th>
                  <th>Readiness State</th>
                  <th>Migration Phase</th>
                  <th>Candidate PQC Algorithms</th>
                  <th>Observed Blockers</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <code style={{ fontSize: '11px', color: 'var(--color-primary)' }}>
                        {p.artifact_id.slice(0, 12)}...
                      </code>
                    </td>
                    <td><Badge label={p.readiness_state} /></td>
                    <td><Badge label={p.migration_phase} variant="info" /></td>
                    <td style={{ fontSize: '12px', color: '#fff' }}>
                      {p.candidate_algorithms && p.candidate_algorithms.length > 0
                        ? p.candidate_algorithms.map((c) => c.name).join(', ')
                        : <span style={{ color: 'var(--text-dim)' }}>Upgrade to FIPS 204 (ML-DSA)</span>}
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {p.blockers && p.blockers.length > 0
                        ? p.blockers.join('; ')
                        : <span style={{ color: 'var(--status-low)' }}>No architectural blockers</span>}
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
