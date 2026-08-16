import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert } from '../components/FeedbackComponents';
import { ArtifactDetailResponse, SignatureResponse } from '../types/api';
import { ArrowLeft, AlertTriangle, Zap, GitPullRequest, KeyRound } from 'lucide-react';

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

  if (loading) return <LoadingSpinner message="Loading cryptographic profile and engine assessments..." />;
  if (error) return <ErrorAlert message={error} onRetry={() => id && loadDetail(id)} />;
  if (!artifact) return <div className="state-box">Artifact not found.</div>;

  const risk = artifact.risk_assessment;
  const pqc = artifact.pqc_assessment;
  const mig = artifact.migration_assessment;

  return (
    <div>
      <div style={{ marginBottom: '16px' }}>
        <Link to="/artifacts" className="btn" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
          <ArrowLeft size={14} /> Back to Inventory
        </Link>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
        <div>
          <h1 className="page-title" style={{ fontSize: '24px' }}>{artifact.name}</h1>
          <div style={{ color: 'var(--text-muted)', fontSize: '13px', display: 'flex', gap: '12px', alignItems: 'center' }}>
            <span>Ecosystem: <Badge label={artifact.ecosystem} /></span>
            <span>Type: <Badge label={artifact.artifact_type} type="info" /></span>
          </div>
        </div>
      </div>

      {/* Artifact Metadata Card */}
      <div className="card">
        <div className="card-title">Artifact Identification & Identity Bounds</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', fontSize: '13px' }}>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>File Path:</span>
            <div style={{ color: '#fff', wordBreak: 'break-all' }}>{artifact.path}</div>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Cryptographic Digest (Immutable):</span>
            <div style={{ color: 'var(--color-primary)' }}><code>{artifact.digest || 'N/A'}</code></div>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Registry / Repository / Tag:</span>
            <div style={{ color: '#fff' }}>
              {artifact.registry || 'N/A'} / {artifact.repository || 'N/A'} : {artifact.tag || 'N/A'}
            </div>
          </div>
        </div>
      </div>

      {/* Grid of Engine Assessments */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px' }}>
        {/* 1. Cryptographic Signatures */}
        <div className="card">
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <KeyRound size={16} color="var(--color-primary)" /> Signatures & Certificates
            </span>
          </div>
          {artifact.signatures.length === 0 ? (
            <p style={{ color: 'var(--text-muted)' }}>No cryptographic signatures discovered for this asset.</p>
          ) : (
            artifact.signatures.map((sig: SignatureResponse) => (
              <div key={sig.id} style={{ padding: '12px', backgroundColor: 'var(--bg-main)', borderRadius: '6px', marginBottom: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <Badge label={sig.status} />
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{sig.verification_status}</span>
                </div>
                <div style={{ fontSize: '12px' }}>Algorithm: <strong style={{ color: '#fff' }}>{sig.algorithm}</strong></div>
                {sig.certificate && (
                  <div style={{ fontSize: '12px', marginTop: '6px' }}>
                    <div>Subject: <span style={{ color: '#fff' }}>{sig.certificate.subject}</span></div>
                    <div>Issuer: <span style={{ color: 'var(--text-muted)' }}>{sig.certificate.issuer}</span></div>
                    <div style={{ marginTop: '4px' }}>
                      Quantum Status: <Badge label={sig.certificate.quantum_status} />
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* 2. Quantum Risk Assessment */}
        <div className="card">
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertTriangle size={16} color="var(--status-critical)" /> Quantum Risk Engine Assessment
            </span>
            {risk && <Badge label={risk.risk_level} />}
          </div>
          {risk ? (
            <div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '12px' }}>
                <span style={{ fontSize: '32px', fontWeight: 700, color: '#fff' }}>{risk.risk_score.toFixed(1)}</span>
                <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>/ 100 Risk Score</span>
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                {risk.calculation_explanation}
              </p>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                Model Version: {risk.model_version}
              </div>
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)' }}>No risk assessment record available.</p>
          )}
        </div>

        {/* 3. PQC Readiness Assessment */}
        <div className="card">
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Zap size={16} color="var(--color-primary)" /> PQC Readiness Assessment
            </span>
            {pqc && <Badge label={pqc.readiness_state} />}
          </div>
          {pqc ? (
            <div style={{ fontSize: '13px' }}>
              <div style={{ marginBottom: '8px' }}>
                Migration Phase: <strong style={{ color: '#fff' }}>{pqc.migration_phase}</strong>
              </div>
              {pqc.candidate_algorithms && pqc.candidate_algorithms.length > 0 && (
                <div style={{ marginTop: '8px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Target PQC Algorithms:</span>
                  <div style={{ display: 'flex', gap: '6px', marginTop: '4px', flexWrap: 'wrap' }}>
                    {pqc.candidate_algorithms.map((c: any, i: number) => (
                      <span key={i} className="badge badge-info">{typeof c === 'string' ? c : c.name}</span>
                    ))}
                  </div>
                </div>
              )}
              {pqc.blockers && pqc.blockers.length > 0 && (
                <div style={{ marginTop: '12px' }}>
                  <span style={{ color: 'var(--status-critical)' }}>Migration Blockers:</span>
                  <ul style={{ paddingLeft: '18px', marginTop: '4px', fontSize: '12px', color: 'var(--text-muted)' }}>
                    {pqc.blockers.map((b: any, i: number) => (
                      <li key={i}>{typeof b === 'string' ? b : JSON.stringify(b)}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)' }}>No PQC readiness evaluation available.</p>
          )}
        </div>

        {/* 4. Migration Prioritization */}
        <div className="card">
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <GitPullRequest size={16} color="var(--color-primary)" /> Migration Prioritization
            </span>
            {mig && <Badge label={mig.priority_code} />}
          </div>
          {mig ? (
            <div style={{ fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span>Priority Tier: <strong style={{ color: '#fff' }}>{mig.priority_level}</strong></span>
                <span>Priority Score: <strong style={{ color: 'var(--color-primary)' }}>{mig.priority_score.toFixed(1)}</strong></span>
              </div>
              <div style={{ backgroundColor: 'var(--bg-main)', padding: '10px', borderRadius: '4px', marginBottom: '10px' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '11px', textTransform: 'uppercase' }}>Recommended Action</span>
                <div style={{ color: '#fff', fontWeight: 500 }}>{mig.recommended_action}</div>
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{mig.rationale}</p>
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)' }}>No migration priority record available.</p>
          )}
        </div>
      </div>
    </div>
  );
};
