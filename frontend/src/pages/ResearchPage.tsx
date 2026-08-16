import React from 'react';
import { FlaskConical } from 'lucide-react';

export const ResearchPage: React.FC = () => {
  return (
    <div>
      <h1 className="page-title">Research Evaluation Framework</h1>
      <p className="page-subtitle">
        Comparative analysis of flat cryptographic inventory vs. SignChain dependency-aware topological migration prioritization.
      </p>

      {/* Research Hypotheses Card */}
      <div className="card">
        <div className="card-title">
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FlaskConical size={18} color="var(--color-primary)" /> Evaluated Research Hypotheses
          </span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px', fontSize: '13px' }}>
          <div style={{ padding: '12px', backgroundColor: 'var(--bg-main)', borderRadius: '6px' }}>
            <strong style={{ color: 'var(--color-primary)' }}>H1: Discovery Coverage</strong>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '12px' }}>
              SignChain discovers more hidden signing dependencies across supply chain formats than manual inventories.
            </p>
          </div>
          <div style={{ padding: '12px', backgroundColor: 'var(--bg-main)', borderRadius: '6px' }}>
            <strong style={{ color: 'var(--color-primary)' }}>H2: Deterministic Accuracy</strong>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '12px' }}>
              Deterministic X.509/ASN.1 parsing achieves 0% false positives for supported cryptographic signatures.
            </p>
          </div>
          <div style={{ padding: '12px', backgroundColor: 'var(--bg-main)', borderRadius: '6px' }}>
            <strong style={{ color: 'var(--color-primary)' }}>H3: Dependency-Aware Prioritization</strong>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '12px' }}>
              Graph centrality identifies high-impact root migration targets that flat inventories rank as low priority.
            </p>
          </div>
          <div style={{ padding: '12px', backgroundColor: 'var(--bg-main)', borderRadius: '6px' }}>
            <strong style={{ color: 'var(--color-primary)' }}>H4: Planning Efficiency</strong>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '12px' }}>
              Dependency-aware migration sequencing significantly reduces manual roadmap synthesis effort.
            </p>
          </div>
        </div>
      </div>

      {/* Model Comparison */}
      <div className="card">
        <div className="card-title">
          <span>Architectural Comparison: Baseline vs. SignChain Pipeline</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          {/* Baseline Approach */}
          <div style={{ border: '1px solid var(--border-color)', borderRadius: '6px', padding: '16px', backgroundColor: 'var(--bg-main)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <span className="badge badge-unknown">Baseline Model</span>
              <strong style={{ color: '#fff' }}>Flat Cryptographic Inventory</strong>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '14px' }}>
              Sorts assets purely by classical algorithm strength (e.g. RSA-1024 before RSA-2048).
            </p>

            <div style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ padding: '8px', border: '1px solid var(--border-color)', borderRadius: '4px' }}>
                1. Standalone test binary (RSA-1024) &rarr; <strong>Priority 1</strong> (0 downstream dependents)
              </div>
              <div style={{ padding: '8px', border: '1px solid var(--border-color)', borderRadius: '4px' }}>
                2. Internal Root CA (RSA-4096) &rarr; <strong>Priority 4</strong> (400 downstream dependents missed)
              </div>
            </div>
            <div style={{ marginTop: '12px', fontSize: '11px', color: 'var(--status-critical)' }}>
              ⚠ Fails to account for transitive blast radius or root dependency blockers.
            </div>
          </div>

          {/* SignChain Approach */}
          <div style={{ border: '1px solid var(--border-color)', borderRadius: '6px', padding: '16px', backgroundColor: 'var(--bg-main)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <span className="badge badge-ready">SignChain Model</span>
              <strong style={{ color: '#fff' }}>Dependency-Aware Topological Engine</strong>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '14px' }}>
              Dynamic scoring: Risk = w_c &middot; R_crypto + w_a &middot; C_asset + w_e &middot; E + w_h &middot; H + w_d &middot; I_dep + w_m &middot; M_comp.
            </p>

            <div style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ padding: '8px', border: '1px solid rgba(56,189,248,0.3)', borderRadius: '4px', backgroundColor: 'rgba(56,189,248,0.05)' }}>
                1. Internal Root CA &rarr; <strong>Priority P1</strong> (Centrality: 0.85, 400 dependents unblocked)
              </div>
              <div style={{ padding: '8px', border: '1px solid var(--border-color)', borderRadius: '4px' }}>
                2. Standalone test binary &rarr; <strong>Priority P3</strong> (Centrality: 0.00, Routine upgrade)
              </div>
            </div>
            <div style={{ marginTop: '12px', fontSize: '11px', color: 'var(--status-low)' }}>
              ✓ Resolves topological dependencies first to prevent migration deadlock.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
