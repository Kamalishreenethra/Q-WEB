import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert } from '../components/FeedbackComponents';
import { ArtifactDetailResponse } from '../types/api';
import { ArrowLeft, AlertTriangle, Zap, GitPullRequest, KeyRound, ShieldAlert } from 'lucide-react';

export const ArtifactDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [artifact, setArtifact] = useState<ArtifactDetailResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (id) loadDetail(id);
  }, [id]);

  async function loadDetail(artifactId: string) {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getArtifact(artifactId);
      setArtifact(data);
    } catch (err: any) {
      setError(err.message || `Failed to load details for artifact '${id}'`);
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <LoadingSpinner message="Querying artifact cryptographic evidence..." />;
  if (error) return <ErrorAlert message={error} onRetry={() => id && loadDetail(id)} />;
  if (!artifact) return <ErrorAlert message="Artifact not found in database." />;

  const risk = artifact.risk_assessment;
  const pqc = artifact.pqc_assessment;
  const mig = artifact.migration_assessment;

  return (
    <div>
      <div style={{ marginBottom: '16px' }}>
        <Link to="/artifacts" className="btn" style={{ fontSize: '12px', padding: '4px 10px' }}>
          <ArrowLeft size={13} /> Back to Asset Inventory
        </Link>
      </div>

      <div className="page-header">
        <div>
          <h1 className="page-title">
            <ShieldAlert size={22} color="var(--color-primary)" />
            {artifact.name}
          </h1>
          <p className="page-subtitle" style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
            ID: {artifact.id} · Ecosystem: {artifact.ecosystem} · Type: {artifact.artifact_type}
          </p>
        </div>
      </div>

      {/* 3 Pillar Summary Grid */}
      <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
        {/* Risk Pillar */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <AlertTriangle size={16} color="var(--status-critical)" />
              Quantum Risk Assessment
            </span>
            {risk && <Badge label={risk.risk_level} />}
          </div>
          {risk ? (
            <div>
              <div style={{ fontSize: '28px', fontWeight: 800, color: '#fff', fontFamily: 'var(--font-mono)' }}>
                {risk.risk_score.toFixed(1)} <span style={{ fontSize: '14px', color: 'var(--text-dim)' }}>/ 100</span>
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>
                {risk.calculation_explanation}
              </p>
            </div>
          ) : (
            <p style={{ fontSize: '12px', color: 'var(--text-dim)' }}>No risk assessment registered.</p>
          )}
        </div>

        {/* PQC Pillar */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Zap size={16} color="var(--color-violet)" />
              PQC Readiness Engine
            </span>
            {pqc && <Badge label={pqc.readiness_state} />}
          </div>
          {pqc ? (
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '4px' }}>
                Migration Phase: {pqc.migration_phase}
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {pqc.candidate_algorithms && pqc.candidate_algorithms.length > 0
                  ? `Recommended: ${pqc.candidate_algorithms.map((c) => c.name).join(', ')}`
                  : 'Requires post-quantum cryptographic upgrade.'}
              </p>
            </div>
          ) : (
            <p style={{ fontSize: '12px', color: 'var(--text-dim)' }}>No PQC assessment registered.</p>
          )}
        </div>

        {/* Migration Pillar */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <GitPullRequest size={16} color="var(--color-primary)" />
              Migration Prioritization
            </span>
            {mig && <Badge label={mig.priority_code} />}
          </div>
          {mig ? (
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '4px' }}>
                Score: {mig.priority_score.toFixed(1)} · {mig.migration_status}
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {mig.recommended_action}
              </p>
            </div>
          ) : (
            <p style={{ fontSize: '12px', color: 'var(--text-dim)' }}>No migration priority registered.</p>
          )}
        </div>
      </div>

      {/* Signature Chain Table */}
      <div className="card" style={{ marginTop: '20px' }}>
        <div className="card-title">
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <KeyRound size={16} color="var(--color-primary)" />
            Observed Signature & Certificate Chains
          </span>
        </div>
        {artifact.signatures.length === 0 ? (
          <p style={{ fontSize: '12px', color: 'var(--text-dim)' }}>No signatures attached to this artifact.</p>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Ecosystem</th>
                  <th>Signature Type</th>
                  <th>Algorithm</th>
                  <th>Verification</th>
                  <th>Evidence Status</th>
                  <th>Certificate Subject</th>
                </tr>
              </thead>
              <tbody>
                {artifact.signatures.map((s) => (
                  <tr key={s.id}>
                    <td><Badge label={s.ecosystem} /></td>
                    <td>{s.signature_type}</td>
                    <td><code>{s.algorithm}</code></td>
                    <td><Badge label={s.verification_status} /></td>
                    <td><Badge label={s.evidence_status} variant="info" /></td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {s.certificate?.subject || s.certificate_fingerprint || 'Embedded signature metadata'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
