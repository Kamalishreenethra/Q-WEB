import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, Pagination } from '../components/FeedbackComponents';
import { CertificateResponse } from '../types/api';

export const CertificatesPage: React.FC = () => {
  const [certificates, setCertificates] = useState<CertificateResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(20);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [quantumStatus, setQuantumStatus] = useState<string>('');
  const [algorithm, setAlgorithm] = useState<string>('');

  useEffect(() => {
    loadCertificates();
  }, [page, quantumStatus, algorithm]);

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
      setError(err.message || 'Failed to retrieve certificate inventory');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 className="page-title">Cryptographic Certificates & Signing Keys</h1>
      <p className="page-subtitle">
        Reusable public key certificates, signing keys, and Certificate Authorities discovered across software pipelines.
      </p>

      {/* Filter Bar */}
      <div className="filter-bar">
        <select
          className="select-input"
          value={quantumStatus}
          onChange={(e) => { setQuantumStatus(e.target.value); setPage(1); }}
        >
          <option value="">All Quantum Statuses</option>
          <option value="VULNERABLE">Quantum Vulnerable</option>
          <option value="QUANTUM_RESISTANT">Quantum Resistant (PQC)</option>
          <option value="UNKNOWN">Unknown / Unclassified</option>
        </select>

        <select
          className="select-input"
          value={algorithm}
          onChange={(e) => { setAlgorithm(e.target.value); setPage(1); }}
        >
          <option value="">All Algorithms</option>
          <option value="RSA-2048">RSA-2048</option>
          <option value="RSA-3072">RSA-3072</option>
          <option value="RSA-4096">RSA-4096</option>
          <option value="ECDSA-secp256r1">ECDSA-secp256r1</option>
          <option value="ECDSA-secp384r1">ECDSA-secp384r1</option>
          <option value="Ed25519">Ed25519</option>
          <option value="ML-DSA-44">ML-DSA-44 (Dilithium2)</option>
          <option value="ML-DSA-65">ML-DSA-65 (Dilithium3)</option>
          <option value="ML-DSA-87">ML-DSA-87 (Dilithium5)</option>
          <option value="SLH-DSA">SLH-DSA (SPHINCS+)</option>
        </select>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadCertificates} />}

      {loading ? (
        <LoadingSpinner message="Querying certificate records..." />
      ) : certificates.length === 0 ? (
        <div className="state-box">
          <p>No matching certificates found in the database.</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="table-container" style={{ border: 'none' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Subject / Common Name</th>
                  <th>Issuer</th>
                  <th>Algorithm & Parameters</th>
                  <th>Quantum Vulnerability</th>
                  <th>Type</th>
                  <th>Fingerprint (SHA-256)</th>
                </tr>
              </thead>
              <tbody>
                {certificates.map((c) => (
                  <tr key={c.fingerprint}>
                    <td>
                      <div style={{ fontWeight: 600, color: '#fff' }}>{c.subject}</div>
                      {c.serial_number && (
                        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>SN: {c.serial_number}</div>
                      )}
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{c.issuer}</td>
                    <td>
                      <strong style={{ color: '#fff' }}>{c.algorithm}</strong>
                      {c.curve && <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Curve: {c.curve}</div>}
                    </td>
                    <td><Badge label={c.quantum_status} /></td>
                    <td><Badge label={c.is_ca ? 'CA' : 'LEAF'} type={c.is_ca ? 'info' : 'unknown'} /></td>
                    <td>
                      <code style={{ fontSize: '11px', color: 'var(--color-primary)' }}>
                        {c.fingerprint.slice(0, 16)}...
                      </code>
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
