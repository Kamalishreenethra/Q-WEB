import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, Pagination } from '../components/FeedbackComponents';
import { Search } from 'lucide-react';
import { ArtifactResponse } from '../types/api';

export const ArtifactsPage: React.FC = () => {
  const [artifacts, setArtifacts] = useState<ArtifactResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [ecosystem, setEcosystem] = useState<string>('');
  const [searchName, setSearchName] = useState<string>('');

  useEffect(() => {
    loadArtifacts();
  }, [page, ecosystem, searchName]);

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
      <h1 className="page-title">Discovered Asset Inventory</h1>
      <p className="page-subtitle">
        Software supply chain artifacts discovered across X.509, Windows Authenticode/PE, OpenPGP, Sigstore, and OCI container ecosystems.
      </p>

      {/* Filter Bar */}
      <div className="filter-bar">
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
          <Search size={16} style={{ position: 'absolute', left: '10px', color: 'var(--text-dim)' }} />
          <input
            type="text"
            className="search-input"
            style={{ paddingLeft: '32px', minWidth: '260px' }}
            placeholder="Search by artifact name..."
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
          <option value="X509">X.509 Certificates</option>
          <option value="AUTHENTICODE">Windows Authenticode (PE)</option>
          <option value="OPENPGP">OpenPGP / GPG</option>
          <option value="SIGSTORE">Sigstore Bundles</option>
          <option value="CONTAINER">OCI / Container Images</option>
        </select>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadArtifacts} />}

      {loading ? (
        <LoadingSpinner message="Querying artifact database..." />
      ) : artifacts.length === 0 ? (
        <div className="state-box">
          <p>No matching software artifacts found in the database.</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="table-container" style={{ border: 'none' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Artifact Name</th>
                  <th>Ecosystem</th>
                  <th>Type</th>
                  <th>Digest / Identifier</th>
                  <th>Discovered</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {artifacts.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <div style={{ fontWeight: 600, color: '#fff' }}>{a.name}</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{a.path}</div>
                    </td>
                    <td><Badge label={a.ecosystem} /></td>
                    <td style={{ fontSize: '12px' }}>{a.artifact_type}</td>
                    <td>
                      <code style={{ fontSize: '11px', color: 'var(--color-primary)' }}>
                        {a.digest ? `${a.digest.slice(0, 20)}...` : 'N/A'}
                      </code>
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {new Date(a.created_at).toLocaleDateString()}
                    </td>
                    <td>
                      <Link to={`/artifacts/${a.id}`} className="btn" style={{ fontSize: '11px', padding: '4px 8px' }}>
                        Inspect Profile
                      </Link>
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
