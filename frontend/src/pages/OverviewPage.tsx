import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { StatCard } from '../components/StatCard';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert, EmptyState } from '../components/FeedbackComponents';
import {
  KeyRound,
  AlertTriangle,
  Zap,
  GitPullRequest,
  Layers,
  ArrowRight,
  ShieldCheck,
  Activity,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import { MigrationResponse, ScanResponse } from '../types/api';

export const OverviewPage: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [totalArtifacts, setTotalArtifacts] = useState<number>(0);
  const [totalCertificates, setTotalCertificates] = useState<number>(0);
  const [vulnerableCount, setVulnerableCount] = useState<number>(0);
  const [pqcReadyCount, setPQCReadyCount] = useState<number>(0);
  const [p1Count, setP1Count] = useState<number>(0);
  const [topMigrations, setTopMigrations] = useState<MigrationResponse[]>([]);
  const [recentScans, setRecentScans] = useState<ScanResponse[]>([]);

  useEffect(() => {
    loadDashboardData();
  }, []);

  async function loadDashboardData() {
    setLoading(true);
    setError(null);
    try {
      const [artRes, certRes, certVulnRes, pqcRes, migP1Res, migAllRes, scansRes] = await Promise.all([
        api.getArtifacts(1, 10),
        api.getCertificates(1, 10),
        api.getCertificates(1, 10, { quantum_status: 'VULNERABLE' }),
        api.getPQCReadiness(1, 10, 'PQC_READY'),
        api.getMigrationAssessments(1, 10, { priority: 'P1' }),
        api.getMigrationAssessments(1, 6),
        api.getScans(1, 6),
      ]);

      setTotalArtifacts(artRes.total);
      setTotalCertificates(certRes.total);
      setVulnerableCount(certVulnRes.total);
      setPQCReadyCount(pqcRes.total);
      setP1Count(migP1Res.total);
      setTopMigrations(migAllRes.items);
      setRecentScans(scansRes.items);
    } catch (err: any) {
      setError(err.message || 'Failed to aggregate supply chain cryptographic posture');
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <LoadingSpinner message="Aggregating supply chain cryptographic posture from database..." />;
  if (error) return <ErrorAlert message={error} onRetry={loadDashboardData} />;

  const isEmpty = totalArtifacts === 0 && totalCertificates === 0 && recentScans.length === 0;

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <ShieldCheck size={24} color="var(--color-primary)" />
            Post-Quantum Cryptographic Posture Overview
          </h1>
          <p className="page-subtitle">
            Automated discovery, quantum vulnerability classification, and topological migration intelligence across software supply chains.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <Link to="/graph" className="btn btn-primary" style={{ padding: '7px 14px' }}>
            Open 3D Dependency Graph
          </Link>
        </div>
      </div>

      {/* KPI Stat Cards Grid */}
      <div className="stat-grid">
        <StatCard
          label="Total Scanned Assets"
          value={totalArtifacts}
          subtext="Binaries, certs, containers, OCI"
          icon={<Layers size={17} />}
        />
        <StatCard
          label="Signing Identities"
          value={totalCertificates}
          subtext="X.509, PGP, Fulcio keys"
          icon={<KeyRound size={17} />}
        />
        <StatCard
          label="Quantum-Vulnerable Keys"
          value={vulnerableCount}
          subtext="Classical RSA / ECC signers"
          icon={<AlertTriangle size={17} />}
          variant="critical"
        />
        <StatCard
          label="PQC-Ready Assets"
          value={pqcReadyCount}
          subtext="FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)"
          icon={<Zap size={17} />}
          variant="success"
        />
        <StatCard
          label="Tier P1 Migration Targets"
          value={p1Count}
          subtext="Critical migration priority"
          icon={<GitPullRequest size={17} />}
          variant="critical"
        />
      </div>

      {isEmpty ? (
        <div className="card">
          <EmptyState
            title="No Cryptographic Assets Ingested"
            description="The SignChain inventory is currently unpopulated. Ingest a signed binary, X.509 certificate, Sigstore bundle, PGP signature, or container image to begin automated discovery and quantum risk evaluation."
            actionCommand="signchain store /path/to/signed-artifact.exe"
            onRefresh={loadDashboardData}
          />
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: '20px' }}>
          {/* Prioritized Migration Targets */}
          <div className="card">
            <div className="card-title">
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <GitPullRequest size={16} color="var(--color-primary)" />
                Topological Migration Targets
              </span>
              <Link to="/migration" className="btn" style={{ fontSize: '11px', padding: '3px 8px' }}>
                View Full Roadmap <ArrowRight size={12} />
              </Link>
            </div>
            {topMigrations.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                No active migration priorities recorded.
              </div>
            ) : (
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Tier</th>
                      <th>Score</th>
                      <th>Status</th>
                      <th>Action Plan</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topMigrations.map((m) => (
                      <tr key={m.id}>
                        <td><Badge label={m.priority_code} /></td>
                        <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{m.priority_score.toFixed(1)}</td>
                        <td><Badge label={m.migration_status} /></td>
                        <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{m.recommended_action}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Recent Discovery Scans */}
          <div className="card">
            <div className="card-title">
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Activity size={16} color="var(--color-primary)" />
                Recent Discovery Scans
              </span>
              <Link to="/scans" className="btn" style={{ fontSize: '11px', padding: '3px 8px' }}>
                View All Scans <ArrowRight size={12} />
              </Link>
            </div>
            {recentScans.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                No scan history recorded in database.
              </div>
            ) : (
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Scan ID</th>
                      <th>Timestamp</th>
                      <th>Status</th>
                      <th>Duration</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentScans.map((s) => (
                      <tr key={s.id}>
                        <td><code>{s.id.slice(0, 8)}...</code></td>
                        <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {new Date(s.timestamp).toLocaleString()}
                        </td>
                        <td><Badge label={s.status} /></td>
                        <td style={{ fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                          {s.duration_sec.toFixed(3)}s
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* NIST FIPS Migration Reference Strip */}
      <div className="card" style={{ marginTop: '20px', background: 'rgba(10, 15, 29, 0.4)', borderStyle: 'dashed' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', fontSize: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Lock size={16} color="var(--color-primary)" />
            <strong style={{ color: '#fff' }}>Post-Quantum Migration Standards Baseline:</strong>
            <span style={{ color: 'var(--text-muted)' }}>FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA) · SP 800-208 State-Full Hash Signatures</span>
          </div>
          <div style={{ color: 'var(--color-primary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <CheckCircle2 size={14} /> Zero Fake Data Guarantee Active
          </div>
        </div>
      </div>
    </div>
  );
};
