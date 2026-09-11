import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, EmptyState, Pagination } from '../components/FeedbackComponents';
import { KeyRound, Copy, Check, RefreshCw } from 'lucide-react';
import { CertificateResponse } from '../types/api';

export const CertificatesPage: React.FC = () => {
  const [certificates, setCertificates] = useState<CertificateResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [quantumStatus, setQuantumStatus] = useState<string>('');
  const [algorithm, setAlgorithm] = useState<string>('');
  const [copiedFp, setCopiedFp] = useState<string | null>(null);

  useEffect(() => {
    loadCertificates();
  }, [page, pageSize, quantumStatus, algorithm]);

  async function loadCertificates() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getCertificates(page, pageSize, {
        quantum_status: quantumStatus || undefined,
        algorithm: algorithm || undefined,
      });
      setCertificates(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve cryptographic certificates');
    } finally {
      setLoading(false);
    }
  }

  function handleCopy(fp: string) {
    navigator.clipboard.writeText(fp);
    setCopiedFp(fp);
    setTimeout(() => setCopiedFp(null), 2000);
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <KeyRound size={22} color="var(--color-primary)" />
            Cryptographic Certificate & Key Intelligence
          </h1>
          <p className="page-subtitle">
            Discovered X.509 certificates, code signing keys, and intermediate certificate authorities evaluated against quantum cryptanalysis.
          </p>
        </div>
        <button className="btn" onClick={loadCertificates}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Filter Bar */}
      <div className="filter-bar">
        <select
          className="select-input"
          value={quantumStatus}
          onChange={(e) => { setQuantumStatus(e.target.value); setPage(1); }}
        >
          <option value="">All Quantum Statuses</option>
          <option value="VULNERABLE">VULNERABLE (RSA/ECC)</option>
          <option value="QUANTUM_RESISTANT">QUANTUM_RESISTANT (ML-DSA / SLH-DSA)</option>
          <option value="WEAK_CLASSICAL">WEAK_CLASSICAL</option>
        </select>

        <select
          className="select-input"
          value={algorithm}
          onChange={(e) => { setAlgorithm(e.target.value); setPage(1); }}
        >
          <option value="">All Algorithms</option>
          <option value="RSA-2048">RSA-2048</option>
          <option value="RSA-4096">RSA-4096</option>
          <option value="ECDSA-P256">ECDSA-P256</option>
          <option value="ECDSA-P384">ECDSA-P384</option>
          <option value="Ed25519">Ed25519</option>
          <option value="ML-DSA-65">ML-DSA-65 (FIPS 204)</option>
        </select>
      </div>

      {/* Main Table */}
      {loading ? (
        <LoadingSpinner message="Querying certificate authorities and signing keys..." />
      ) : error ? (
        <ErrorAlert message={error} onRetry={loadCertificates} />
      ) : certificates.length === 0 ? (
        <div className="card">
          <EmptyState
            title="No Signing Certificates Ingested"
            description="The cryptographic identity store is currently empty. Ingest an X.509 certificate or signed binary to inspect public key parameters."
            actionCommand="signchain store /path/to/certificate.pem"
            onRefresh={loadCertificates}
          />
        </div>
      ) : (
        <div className="card" style={{ padding: '16px' }}>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Fingerprint (SHA-256)</th>
                  <th>Algorithm</th>
                  <th>Quantum Status</th>
                  <th>CA</th>
                  <th>Subject Common Name</th>
                  <th>Issuer Authority</th>
                </tr>
              </thead>
              <tbody>
                {certificates.map((c) => (
                  <tr key={c.fingerprint}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <code style={{ fontSize: '11px', color: 'var(--color-primary)' }}>
                          {c.fingerprint.slice(0, 16)}...
                        </code>
                        <button
                          className="btn"
                          style={{ padding: '2px 5px', fontSize: '10px' }}
                          onClick={() => handleCopy(c.fingerprint)}
                          title="Copy Full Fingerprint"
                        >
                          {copiedFp === c.fingerprint ? <Check size={10} color="var(--status-low)" /> : <Copy size={10} />}
                        </button>
                      </div>
                    </td>
                    <td><code>{c.algorithm}</code></td>
                    <td><Badge label={c.quantum_status} /></td>
                    <td><Badge label={c.is_ca ? 'CA_ROOT' : 'END_ENTITY'} variant={c.is_ca ? 'info' : 'unknown'} /></td>
                    <td style={{ fontSize: '12px', color: '#fff', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={c.subject}>
                      {c.subject}
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={c.issuer}>
                      {c.issuer}
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
