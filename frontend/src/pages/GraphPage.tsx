import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { LiveGraph3D } from '../components/LiveGraph3D';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert } from '../components/FeedbackComponents';
import { GraphResponse, DependencyNodeResponse, ScanResponse } from '../types/api';
import {
  Network,
  RefreshCw,
  Info,
  ShieldAlert,
  ArrowRight,
  Layers,
} from 'lucide-react';

export const GraphPage: React.FC = () => {
  const [scansList, setScansList] = useState<ScanResponse[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<DependencyNodeResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [explainMode, setExplainMode] = useState<boolean>(false);
  const [explainStep, setExplainStep] = useState<number>(0);
  const [lastSync, setLastSync] = useState<Date>(new Date());

  useEffect(() => {
    loadScansAndGraph();
  }, []);

  async function loadScansAndGraph(targetScanId?: string) {
    setLoading(true);
    setError(null);
    try {
      const scans = await api.getScans(1, 50);
      setScansList(scans.items);

      const activeScanId = targetScanId || (scans.items.length > 0 ? scans.items[0].id : '');
      setSelectedScanId(activeScanId);

      if (activeScanId) {
        const data = await api.getGraphForScan(activeScanId);
        setGraphData(data);
        if (data.nodes.length > 0) {
          setSelectedNode(data.nodes[0]);
        } else {
          setSelectedNode(null);
        }
      } else {
        setGraphData({ nodes: [], edges: [] });
        setSelectedNode(null);
      }
      setLastSync(new Date());
    } catch (err: any) {
      setError(err.message || 'Failed to construct 3D dependency graph');
    } finally {
      setLoading(false);
    }
  }

  async function handleScanChange(scanId: string) {
    setSelectedScanId(scanId);
    setLoading(true);
    setError(null);
    try {
      const data = await api.getGraphForScan(scanId);
      setGraphData(data);
      if (data.nodes.length > 0) {
        setSelectedNode(data.nodes[0]);
      } else {
        setSelectedNode(null);
      }
      setLastSync(new Date());
    } catch (err: any) {
      setError(err.message || 'Failed to load graph for selected scan');
    } finally {
      setLoading(false);
    }
  }

  if (loading && !graphData) return <LoadingSpinner message="Constructing 3D cryptographic dependency graph topology..." />;
  if (error && !graphData) return <ErrorAlert message={error} onRetry={() => loadScansAndGraph()} />;

  const nodes = graphData?.nodes || [];
  const edges = graphData?.edges || [];

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Network size={24} color="var(--color-primary)" />
            3D Cryptographic Dependency Intelligence Graph
          </h1>
          <p className="page-subtitle">
            WebGL topological model representing transitive signing relationships: Artifacts $\rightarrow$ Signers $\rightarrow$ Certificate Authorities $\rightarrow$ Downstream Dependents.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Scan Selector Dropdown */}
          {scansList.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Layers size={14} color="var(--color-primary)" />
              <select
                className="select-input"
                value={selectedScanId}
                onChange={(e) => handleScanChange(e.target.value)}
                style={{ padding: '6px 10px', fontSize: '12px', minWidth: '220px' }}
              >
                {scansList.map((s, idx) => (
                  <option key={s.id} value={s.id}>
                    Scan #{scansList.length - idx} ({s.id.slice(0, 8)}... - {new Date(s.timestamp).toLocaleTimeString()})
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Mode Toggle */}
          <div style={{ background: 'var(--bg-card)', padding: '3px', borderRadius: '6px', border: '1px solid var(--border-card)', display: 'flex' }}>
            <button
              className="btn"
              onClick={() => { setExplainMode(false); setExplainStep(0); }}
              style={{
                background: !explainMode ? 'var(--color-primary)' : 'transparent',
                color: !explainMode ? '#060913' : 'var(--text-muted)',
                fontWeight: !explainMode ? 700 : 500,
                padding: '4px 10px',
                fontSize: '12px',
                border: 'none',
              }}
            >
              GRAPH
            </button>
            <button
              className="btn"
              onClick={() => { setExplainMode(true); setExplainStep(1); }}
              style={{
                background: explainMode ? 'var(--color-violet)' : 'transparent',
                color: explainMode ? '#fff' : 'var(--text-muted)',
                fontWeight: explainMode ? 700 : 500,
                padding: '4px 10px',
                fontSize: '12px',
                border: 'none',
              }}
            >
              EXPLAIN
            </button>
          </div>

          <button className="btn" onClick={() => loadScansAndGraph(selectedScanId)} style={{ padding: '6px 12px' }}>
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>
      </div>

      {/* Metrics Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', gap: '8px' }}>
          <span className="badge badge-info">Nodes: {nodes.length}</span>
          <span className="badge badge-info">Relationships: {edges.length}</span>
          {nodes.length > 0 && <span className="badge badge-low">WebGL Active</span>}
        </div>
        <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
          Synchronized: {lastSync.toLocaleTimeString()}
        </span>
      </div>

      {/* Main Graph Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: '20px', alignItems: 'start' }}>
        {/* 3D WebGL Canvas */}
        <div>
          <LiveGraph3D
            nodes={nodes}
            edges={edges}
            selectedNodeId={selectedNode?.node_id}
            onSelectNode={(n) => setSelectedNode(n)}
            explainStep={explainStep}
          />
        </div>

        {/* Intelligence Side Panel */}
        <div className="card" style={{ padding: '20px' }}>
          <div className="card-title">
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldAlert size={16} color="var(--color-primary)" />
              Cryptographic Intelligence
            </span>
          </div>

          {selectedNode ? (
            <div>
              <div style={{ marginBottom: '14px' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Selected Entity
                </span>
                <div style={{ fontSize: '16px', fontWeight: 700, color: '#fff', marginTop: '2px' }}>
                  {selectedNode.name}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', marginBottom: '14px' }}>
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Type:</span>
                  <div style={{ marginTop: '2px' }}><Badge label={selectedNode.node_type} /></div>
                </div>
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Status:</span>
                  <div style={{ marginTop: '2px' }}>
                    <Badge label={selectedNode.metadata_json?.quantum_status || 'ANALYZED'} />
                  </div>
                </div>
              </div>

              <div style={{ marginBottom: '14px' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Node Identifier:</span>
                <div style={{ marginTop: '2px', background: 'var(--bg-input)', padding: '6px 8px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                  <code style={{ fontSize: '11px', color: 'var(--color-primary)', wordBreak: 'break-all' }}>
                    {selectedNode.node_id}
                  </code>
                </div>
              </div>

              {/* Explain Mode Walkthrough */}
              {explainMode && (
                <div className="explain-stepper">
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-violet)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <Info size={12} /> GUIDED REASONING CHAIN
                  </div>

                  <div className={`explain-step ${explainStep >= 1 ? 'active' : ''}`}>
                    <div className="explain-step-dot" />
                    <div>
                      <div style={{ fontWeight: 600, color: '#fff', fontSize: '12px' }}>1. Cryptographic Identity</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        Asset discovered with verified signature and identity chain.
                      </div>
                    </div>
                  </div>

                  <div className={`explain-step ${explainStep >= 2 ? 'active' : ''}`}>
                    <div className="explain-step-dot" />
                    <div>
                      <div style={{ fontWeight: 600, color: '#fff', fontSize: '12px' }}>2. Quantum Vulnerability</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        Identified classical algorithm vulnerable to Shor's factorization.
                      </div>
                    </div>
                  </div>

                  <div className={`explain-step ${explainStep >= 3 ? 'active' : ''}`}>
                    <div className="explain-step-dot" />
                    <div>
                      <div style={{ fontWeight: 600, color: '#fff', fontSize: '12px' }}>3. Downstream Blast Radius</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        Graph centrality models transitive impact on downstream dependents.
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', marginTop: '10px' }}>
                    <button
                      className="btn"
                      disabled={explainStep <= 1}
                      onClick={() => setExplainStep((s) => Math.max(1, s - 1))}
                      style={{ padding: '3px 8px', fontSize: '11px' }}
                    >
                      Prev Step
                    </button>
                    <button
                      className="btn btn-primary"
                      disabled={explainStep >= 3}
                      onClick={() => setExplainStep((s) => Math.min(3, s + 1))}
                      style={{ padding: '3px 8px', fontSize: '11px' }}
                    >
                      Next Step <ArrowRight size={11} />
                    </button>
                  </div>
                </div>
              )}

              {/* Node Metadata Key-Value */}
              {selectedNode.metadata_json && Object.keys(selectedNode.metadata_json).length > 0 && (
                <div style={{ marginTop: '14px' }}>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Evidence Metadata:</span>
                  <div style={{ backgroundColor: 'var(--bg-base)', padding: '10px', borderRadius: '4px', marginTop: '4px', fontSize: '11px', border: '1px solid var(--border-subtle)' }}>
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text-muted)' }}>
                      {JSON.stringify(selectedNode.metadata_json, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
              Click on any 3D node in the graph to inspect cryptographic attributes and dependency blast radius.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
