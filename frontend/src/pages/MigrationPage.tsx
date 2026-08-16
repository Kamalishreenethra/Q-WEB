import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, Pagination } from '../components/FeedbackComponents';
import { MigrationResponse } from '../types/api';

export const MigrationPage: React.FC = () => {
  const [assessments, setAssessments] = useState<MigrationResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [priority, setPriority] = useState<string>('');
  const [status, setStatus] = useState<string>('');

  useEffect(() => {
    loadMigrationData();
  }, [page, priority, status]);

  async function loadMigrationData() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getMigrationAssessments(page, pageSize, {
        priority: priority || undefined,
        migration_status: status || undefined,
      });
      setAssessments(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve migration priorities');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 className="page-title">Dependency-Aware Migration Roadmap & Prioritization</h1>
      <p className="page-subtitle">
        Topologically sorted migration sequence combining cryptographic vulnerability, NetworkX graph centrality, and downstream blast radius.
      </p>

      {/* Filter Bar */}
      <div className="filter-bar">
        <select
          className="select-input"
          value={priority}
          onChange={(e) => { setPriority(e.target.value); setPage(1); }}
        >
          <option value="">All Priorities</option>
          <option value="P1">P1 — Critical Priority (Immediate Action)</option>
          <option value="P2">P2 — High Priority</option>
          <option value="P3">P3 — Medium Priority</option>
          <option value="P4">P4 — Low / Routine Migration</option>
        </select>

        <select
          className="select-input"
          value={status}
          onChange={(e) => { setStatus(e.target.value); setPage(1); }}
        >
          <option value="">All Statuses</option>
          <option value="ACTION_REQUIRED">Action Required</option>
          <option value="PLANNED">Planned</option>
          <option value="READY">Ready / Migrated</option>
        </select>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadMigrationData} />}

      {loading ? (
        <LoadingSpinner message="Generating dependency-aware migration prioritization..." />
      ) : assessments.length === 0 ? (
        <div className="state-box">
          <p>No migration priority records match the selected filter.</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="table-container" style={{ border: 'none' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rank</th>
                  <th>Priority</th>
                  <th>Priority Score</th>
                  <th>Status</th>
                  <th>Recommended Action</th>
                  <th>Rationale</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((m, index) => (
                  <tr key={m.id}>
                    <td style={{ fontWeight: 700, color: 'var(--color-primary)' }}>
                      #{(page - 1) * pageSize + index + 1}
                    </td>
                    <td><Badge label={m.priority_code} /></td>
                    <td>
                      <span style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>
                        {m.priority_score.toFixed(1)}
                      </span>
                    </td>
                    <td><Badge label={m.migration_status} /></td>
                    <td>
                      <div style={{ color: '#fff', fontWeight: 500, fontSize: '13px' }}>
                        {m.recommended_action}
                      </div>
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '350px' }}>
                      {m.rationale}
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
