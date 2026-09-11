import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, EmptyState, Pagination } from '../components/FeedbackComponents';
import { Search, Layers, ExternalLink, RefreshCw } from 'lucide-react';
import { ArtifactResponse } from '../types/api';

export const ArtifactsPage: React.FC = () => {
  const [artifacts, setArtifacts] = useState<ArtifactResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [ecosystem, setEcosystem] = useState<string>('');
  const [searchName, setSearchName] = useState<string>('');

  useEffect(() => {
    loadArtifacts();
  }, [page, pageSize, ecosystem, searchName]);

  async function loadArtifacts() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getArtifacts(page, pageSize, {
        ecosystem: ecosystem || undefined,
        name: searchName || undefined,
      });
      setArtifacts(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve asset inventory');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Layers size={22} color="var(--color-primary)" />
            Software Supply Chain Asset Inventory
          </h1>
          <p className="page-subtitle">
            Discovered binaries, container images, X.509 certificates, Sigstore attestations, and PGP signed packages.
          </p>
        </div>
        <button className="btn" onClick={loadArtifacts}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Filter Bar */}
      <div className="filter-bar">
        <div className="search-box">
          <Search size={14} />
          <input
            type="text"
            className="search-input"
            placeholder="Search by name / path..."
            value={searchName}
            onChange={(e) => { setSearchName(e.target.value); setPage(1); }}
          />
        </div>

        <select
          className="select-input"
          value={ecosystem}
          onChange={(e) => { setEcosystem(e.target.value); setPage(1); }}
        >
          <option value="">All Ecosystems</option>
          <option value="PE">PE / Authenticode</option>
          <option value="X509">X.509 Certificate</option>
          <option value="SIGSTORE">Sigstore Bundle</option>
          <option value="PGP">PGP Signature</option>
          <option value="CONTAINER">Container (OCI/Docker)</option>
        </select>
      </div>

      {/* Main Content */}
      {loading ? (
        <LoadingSpinner message="Scanning database asset repository..." />
      ) : error ? (
        <ErrorAlert message={error} onRetry={loadArtifacts} />
      ) : artifacts.length === 0 ? (
        <div className="card">
          <EmptyState
            title="No Cryptographic Assets Found"
            description="The asset inventory is currently empty or no artifacts match the active filters. Ingest a signed file using the SignChain CLI to begin."
            actionCommand="signchain store /path/to/artifact.exe"
            onRefresh={loadArtifacts}
          />
        </div>
      ) : (
        <div className="card" style={{ padding: '16px' }}>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Artifact Name</th>
                  <th>Ecosystem</th>
                  <th>Type</th>
                  <th>Source Path / Target</th>
                  <th>Registered</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {artifacts.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <div style={{ fontWeight: 600, color: '#fff' }}>{a.name}</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                        {a.id.slice(0, 8)}...
                      </div>
                    </td>
                    <td><Badge label={a.ecosystem} /></td>
                    <td><Badge label={a.artifact_type} variant="info" /></td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '340px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.path}>
                      <code>{a.path}</code>
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {new Date(a.created_at).toLocaleDateString()}
                    </td>
                    <td>
                      <Link to={`/artifacts/${a.id}`} className="btn" style={{ padding: '3px 8px', fontSize: '11px' }}>
                        Inspect <ExternalLink size={11} />
                      </Link>
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
