import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, EmptyState, Pagination } from '../components/FeedbackComponents';
import { History, RefreshCw } from 'lucide-react';
import { ScanResponse } from '../types/api';

export const ScansPage: React.FC = () => {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
  }, [page, pageSize]);

  async function loadScans() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getScans(page, pageSize);
      setScans(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve discovery scan history');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <History size={22} color="var(--color-primary)" />
            Cryptographic Discovery Scan History
          </h1>
          <p className="page-subtitle">
            Audit trail of automated static analysis scanner executions across X.509, Authenticode PE, PGP, Sigstore, and OCI container formats.
          </p>
        </div>
        <button className="btn" onClick={loadScans}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {loading ? (
        <LoadingSpinner message="Querying scan execution audit logs..." />
      ) : error ? (
        <ErrorAlert message={error} onRetry={loadScans} />
      ) : scans.length === 0 ? (
        <div className="card">
          <EmptyState
            title="No Discovery Scans Recorded"
            description="The scan execution log is empty. Execute a SignChain scanner command or send a POST request to /scans/ingest to populate scan records."
            actionCommand="signchain store /path/to/signed-artifact.exe"
            onRefresh={loadScans}
          />
        </div>
      ) : (
        <div className="card" style={{ padding: '16px' }}>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scan Identifier</th>
                  <th>Timestamp</th>
                  <th>Status</th>
                  <th>Duration (s)</th>
                  <th>Artifact Count</th>
                  <th>Error Count</th>
                  <th>Scanner Version</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <code style={{ fontSize: '11px', color: 'var(--color-primary)' }}>
                        {s.id}
                      </code>
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {new Date(s.timestamp).toLocaleString()}
                    </td>
                    <td><Badge label={s.status} /></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                      {s.duration_sec.toFixed(3)}s
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{s.artifact_count}</td>
                    <td>
                      {s.error_count > 0 ? (
                        <span style={{ color: 'var(--status-critical)', fontWeight: 600 }}>{s.error_count}</span>
                      ) : (
                        <span style={{ color: 'var(--status-low)' }}>0</span>
                      )}
                    </td>
                    <td><code>{s.scanner_version}</code></td>
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
