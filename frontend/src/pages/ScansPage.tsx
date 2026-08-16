import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, Pagination } from '../components/FeedbackComponents';
import { ScanResponse } from '../types/api';

export const ScansPage: React.FC = () => {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
  }, [page]);

  async function loadScans() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getScans(page, pageSize);
      setScans(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve scan history');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 className="page-title">Discovery Scan Execution History</h1>
      <p className="page-subtitle">
        Historical record of static discovery scan executions, artifact counts, durations, and status outcomes.
      </p>

      {error && <ErrorAlert message={error} onRetry={loadScans} />}

      {loading ? (
        <LoadingSpinner message="Loading scan execution history..." />
      ) : scans.length === 0 ? (
        <div className="state-box">
          <p>No historical scans found in the database.</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="table-container" style={{ border: 'none' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Timestamp</th>
                  <th>Status</th>
                  <th>Scanner Version</th>
                  <th>Artifacts Scanned</th>
                  <th>Errors</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <code>{s.id}</code>
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {new Date(s.timestamp).toLocaleString()}
                    </td>
                    <td><Badge label={s.status} /></td>
                    <td>{s.scanner_version}</td>
                    <td style={{ fontWeight: 600, color: '#fff' }}>{s.artifact_count}</td>
                    <td style={{ color: s.error_count > 0 ? 'var(--status-critical)' : 'var(--text-muted)' }}>
                      {s.error_count}
                    </td>
                    <td style={{ fontSize: '12px' }}>{s.duration_sec.toFixed(3)}s</td>
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
