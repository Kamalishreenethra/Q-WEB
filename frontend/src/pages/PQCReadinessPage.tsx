import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, Pagination } from '../components/FeedbackComponents';
import { PQCReadinessResponse } from '../types/api';

export const PQCReadinessPage: React.FC = () => {
  const [assessments, setAssessments] = useState<PQCReadinessResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filter
  const [readinessState, setReadinessState] = useState<string>('');

  useEffect(() => {
    loadPQCData();
  }, [page, readinessState]);

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
      <h1 className="page-title">Post-Quantum Cryptographic Readiness Engine</h1>
      <p className="page-subtitle">
        Systematic readiness evaluation for migration to NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) signature standards.
      </p>

      {/* Filter Bar */}
      <div className="filter-bar">
        <select
          className="select-input"
          value={readinessState}
          onChange={(e) => { setReadinessState(e.target.value); setPage(1); }}
        >
          <option value="">All Readiness States</option>
          <option value="NOT_READY">NOT_READY — Classical algorithms active</option>
          <option value="PARTIALLY_READY">PARTIALLY_READY — Transitional support</option>
          <option value="HYBRID_READY">HYBRID_READY — Composite classical + PQC</option>
          <option value="PQC_READY">PQC_READY — Full post-quantum standard active</option>
        </select>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadPQCData} />}

      {loading ? (
        <LoadingSpinner message="Evaluating PQC compatibility and blockers..." />
      ) : assessments.length === 0 ? (
        <div className="state-box">
          <p>No PQC readiness records match the selected filter.</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="table-container" style={{ border: 'none' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Artifact ID</th>
                  <th>Readiness State</th>
                  <th>Migration Phase</th>
                  <th>Target PQC Candidates</th>
                  <th>Blockers & Constraints</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((p) => (
                  <tr key={p.id}>
                    <td><code>{p.artifact_id.slice(0, 12)}...</code></td>
                    <td><Badge label={p.readiness_state} /></td>
                    <td style={{ fontSize: '12px', color: '#fff' }}>{p.migration_phase}</td>
                    <td>
                      {p.candidate_algorithms && p.candidate_algorithms.length > 0 ? (
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {p.candidate_algorithms.map((c, idx) => (
                            <span key={idx} className="badge badge-info">
                              {typeof c === 'string' ? c : c.name}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-dim)', fontSize: '11px' }}>None identified</span>
                      )}
                    </td>
                    <td>
                      {p.blockers && p.blockers.length > 0 ? (
                        <ul style={{ paddingLeft: '16px', fontSize: '11px', color: 'var(--text-muted)' }}>
                          {p.blockers.map((b, idx) => (
                            <li key={idx}>{typeof b === 'string' ? b : JSON.stringify(b)}</li>
                          ))}
                        </ul>
                      ) : (
                        <span style={{ color: 'var(--status-low)', fontSize: '11px' }}>No active blockers</span>
                      )}
                    </td>
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
