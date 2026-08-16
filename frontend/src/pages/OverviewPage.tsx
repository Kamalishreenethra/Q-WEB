import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { StatCard } from '../components/StatCard';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert } from '../components/FeedbackComponents';
import { KeyRound, AlertTriangle, Zap, GitPullRequest, Layers } from 'lucide-react';
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
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [artRes, certRes, certVulnRes, pqcRes, migP1Res, migAllRes, scansRes] = await Promise.all([
        api.getArtifacts(1, 10),
        api.getCertificates(1, 10),
        api.getCertificates(1, 10, { quantum_status: 'VULNERABLE' }),
        api.getPQCReadiness(1, 10, 'PQC_READY'),
        api.getMigrationAssessments(1, 10, { priority: 'P1' }),
        api.getMigrationAssessments(1, 5),
        api.getScans(1, 5),
      ]);

      setTotalArtifacts(artRes.total);
      setTotalCertificates(certRes.total);
      setVulnerableCount(certVulnRes.total);
      setPQCReadyCount(pqcRes.total);
      setP1Count(migP1Res.total);
      setTopMigrations(migAllRes.items);
      setRecentScans(scansRes.items);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard overview');
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <LoadingSpinner message="Aggregating supply chain cryptographic posture..." />;
  if (error) return <ErrorAlert message={error} onRetry={loadData} />;

  return (
    <div>
      <h1 className="page-title">Post-Quantum Cryptographic Posture Overview</h1>
      <p className="page-subtitle">
        Continuous cryptographic discovery, quantum vulnerability classification, and migration roadmap intelligence across software supply chains.
      </p>

      {/* Metric Cards Grid */}
      <div className="stat-grid">
        <StatCard
          label="Total Scanned Assets"
          value={totalArtifacts}
          subtext="Binaries, certificates, containers, bundles"
          icon={<Layers size={18} />}
        />
        <StatCard
          label="Signing Certificates"
          value={totalCertificates}
          subtext="Unique cryptographic identities"
          icon={<KeyRound size={18} />}
        />
        <StatCard
          label="Quantum Vulnerable"
          value={vulnerableCount}
          subtext="Classical RSA / ECC signing keys"
          icon={<AlertTriangle size={18} />}
          variant="critical"
        />
        <StatCard
          label="PQC-Ready Assets"
          value={pqcReadyCount}
          subtext="FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)"
          icon={<Zap size={18} />}
          variant="success"
        />
        <StatCard
          label="Critical Migration Targets"
          value={p1Count}
          subtext="Tier P1: Immediate migration priority"
          icon={<GitPullRequest size={18} />}
          variant="critical"
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '20px' }}>
        {/* Top Migration Targets */}
        <div className="card">
          <div className="card-title">
            <span>Prioritized Migration Targets</span>
            <Link to="/migration" className="btn" style={{ fontSize: '11px', padding: '4px 8px' }}>
              View All
            </Link>
          </div>
          {topMigrations.length === 0 ? (
            <div className="state-box" style={{ padding: '24px' }}>No migration targets registered.</div>
          ) : (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Priority</th>
                    <th>Score</th>
                    <th>Status</th>
                    <th>Recommended Action</th>
                  </tr>
                </thead>
                <tbody>
                  {topMigrations.map((m) => (
                    <tr key={m.id}>
                      <td><Badge label={m.priority_code} /></td>
                      <td style={{ fontWeight: 600 }}>{m.priority_score.toFixed(1)}</td>
                      <td><Badge label={m.migration_status} /></td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{m.recommended_action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Recent Scan History */}
        <div className="card">
          <div className="card-title">
            <span>Recent Discovery Scans</span>
            <Link to="/scans" className="btn" style={{ fontSize: '11px', padding: '4px 8px' }}>
              View All Scans
            </Link>
          </div>
          {recentScans.length === 0 ? (
            <div className="state-box" style={{ padding: '24px' }}>No scans recorded in database.</div>
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
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{new Date(s.timestamp).toLocaleString()}</td>
                      <td><Badge label={s.status} /></td>
                      <td style={{ fontSize: '12px' }}>{s.duration_sec.toFixed(3)}s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
