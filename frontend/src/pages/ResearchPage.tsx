import React from 'react';
import { FlaskConical, ShieldAlert, Layers, Activity } from 'lucide-react';

export const ResearchPage: React.FC = () => {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <FlaskConical size={22} color="var(--color-primary)" />
            Empirical Research Evaluation Framework
          </h1>
          <p className="page-subtitle">
            Formal hypothesis evaluation comparing baseline flat cryptographic inventories against SignChain dependency-aware topological migration sequencing.
          </p>
        </div>
      </div>

      {/* Research Hypotheses Grid */}
      <div className="card">
        <div className="card-title">
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={16} color="var(--color-primary)" />
            Evaluated Research Hypotheses (H1 – H5)
          </span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px', fontSize: '13px' }}>
          <div style={{ padding: '14px', backgroundColor: 'var(--bg-base)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <strong style={{ color: 'var(--color-primary)' }}>H1: Discovery Coverage</strong>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '12px' }}>
              SignChain discovers transitive signing dependencies across heterogeneous supply chain formats that flat inventories miss.
            </p>
          </div>

          <div style={{ padding: '14px', backgroundColor: 'var(--bg-base)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <strong style={{ color: 'var(--color-primary)' }}>H2: Deterministic Classification</strong>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '12px' }}>
              Deterministic X.509/ASN.1 parsing achieves 0% false positives for supported cryptographic signatures without heuristic guesswork.
            </p>
          </div>

          <div style={{ padding: '14px', backgroundColor: 'var(--bg-base)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <strong style={{ color: 'var(--color-primary)' }}>H3: Priority Inversion Reduction</strong>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '12px' }}>
              Dependency-aware topological ordering significantly reduces migration priority inversions compared to flat risk models.
            </p>
          </div>

          <div style={{ padding: '14px', backgroundColor: 'var(--bg-base)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <strong style={{ color: 'var(--color-primary)' }}>H4: Planning Effort Reduction</strong>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '12px' }}>
              Automated topological sequencing provides an actionable roadmap, reducing manual post-quantum planning cycles.
            </p>
          </div>

          <div style={{ padding: '14px', backgroundColor: 'var(--bg-base)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <strong style={{ color: 'var(--color-primary)' }}>H5: Computational Scalability</strong>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '12px' }}>
              SignChain execution overhead scales linearly ($O(V + E)$) with artifact volume across supply chain dependency graphs.
            </p>
          </div>
        </div>
      </div>

      {/* Phase Separation Reference */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(440px, 1fr))', gap: '20px' }}>
        <div className="card">
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Layers size={16} color="var(--color-primary)" />
              Track A: Synthetic Ground-Truth Benchmarks
            </span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
            Automated synthetic workload benchmarks evaluated across varying graph sizes (10 to 500 nodes) with controlled cryptographic vulnerability mixtures and deterministic seeds.
          </p>
        </div>

        <div className="card">
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldAlert size={16} color="var(--color-violet)" />
              Track B: Real-World Open-Source Corpus
            </span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
            Real-world static analysis corpus comprising authentic Windows PE binaries, Linux packages, PGP release signatures, Sigstore cosign attestations, and container manifests.
          </p>
        </div>
      </div>
    </div>
  );
};
