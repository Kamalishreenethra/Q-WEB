import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, EmptyState, Pagination } from '../components/FeedbackComponents';
import { GitPullRequest, RefreshCw } from 'lucide-react';
import { MigrationResponse } from '../types/api';

export const MigrationPage: React.FC = () => {
  const [assessments, setAssessments] = useState<MigrationResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [priority, setPriority] = useState<string>('');
  const [status, setStatus] = useState<string>('');

  useEffect(() => {
    loadMigrationData();
  }, [page, pageSize, priority, status]);

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
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <GitPullRequest size={22} color="var(--color-primary)" />
            Topological Migration Priority Roadmap
          </h1>
          <p className="page-subtitle">
            Dependency-aware topological migration sequencing (P1 $
ightarrow$ P4) resolving priority inversions across upstream certificate authorities and signing identities.
          </p>
        </div>
        <button className="btn" onClick={loadMigrationData}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Filter Bar */}
      <div className="filter-bar">
        <select
          className="select-input"
          value={priority}
          onChange={(e) => { setPriority(e.target.value); setPage(1); }}
        >
          <option value="">All Priorities</option>
          <option value="P1">P1 — Critical (Immediate)</option>
          <option value="P2">P2 — High Priority</option>
          <option value="P3">P3 — Medium Priority</option>
          <option value="P4">P4 — Low Priority</option>
        </select>

        <select
          className="select-input"
          value={status}
          onChange={(e) => { setStatus(e.target.value); setPage(1); }}
        >
          <option value="">All Migration Statuses</option>
          <option value="PENDING">PENDING</option>
          <option value="IN_PROGRESS">IN_PROGRESS</option>
          <option value="MIGRATED">MIGRATED</option>
        </select>
      </div>

      {/* Content */}
      {loading ? (
        <LoadingSpinner message="Calculating topological migration sequences..." />
      ) : error ? (
        <ErrorAlert message={error} onRetry={loadMigrationData} />
      ) : assessments.length === 0 ? (
        <div className="card">
          <EmptyState
            title="No Migration Priorities Generated"
            description="Migration priorities are computed by analyzing graph centrality and downstream transitive dependencies in NetworkX."
            actionCommand="signchain store /path/to/artifact.exe"
            onRefresh={loadMigrationData}
          />
        </div>
      ) : (
        <div className="card" style={{ padding: '16px' }}>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rank</th>
                  <th>Artifact</th>
                  <th>Tier</th>
                  <th>Score</th>
                  <th>Status</th>
                  <th>Recommended Action Plan</th>
                  <th>Rationale</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((m, index) => (
                  <tr key={m.id}>
                    <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      #{(page - 1) * pageSize + index + 1}
                    </td>
                    <td>
                      <code style={{ fontSize: '11px', color: 'var(--color-primary)' }}>
                        {m.artifact_id.slice(0, 12)}...
                      </code>
                    </td>
                    <td><Badge label={m.priority_code} /></td>
                    <td>
                      <span style={{ fontSize: '15px', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fff' }}>
                        {m.priority_score.toFixed(1)}
                      </span>
                    </td>
                    <td><Badge label={m.migration_status} /></td>
                    <td style={{ fontSize: '12px', color: '#fff', maxWidth: '300px' }}>
                      {m.recommended_action}
                    </td>
                    <td style={{ fontSize: '11px', color: 'var(--text-muted)', maxWidth: '300px' }}>
                      {m.rationale}
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
