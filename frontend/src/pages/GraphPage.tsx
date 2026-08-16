import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LoadingSpinner, ErrorAlert } from '../components/FeedbackComponents';
import { GraphResponse, DependencyNodeResponse } from '../types/api';
import { Network, ZoomIn, ZoomOut, RefreshCw } from 'lucide-react';

export const GraphPage: React.FC = () => {
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<DependencyNodeResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [zoom, setZoom] = useState<number>(1);

  useEffect(() => {
    loadGraph();
  }, []);

  async function loadGraph() {
    setLoading(true);
    setError(null);
    try {
      const scans = await api.getScans(1, 1);
      if (scans.items.length > 0) {
        const data = await api.getGraphForScan(scans.items[0].id);
        setGraphData(data);
        if (data.nodes.length > 0) {
          setSelectedNode(data.nodes[0]);
        }
      } else {
        setGraphData({ nodes: [], edges: [] });
      }
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve dependency graph');
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <LoadingSpinner message="Building dependency graph topology..." />;
  if (error) return <ErrorAlert message={error} onRetry={loadGraph} />;
  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="state-box">
        <Network size={36} style={{ margin: '0 auto 12px', color: 'var(--text-dim)' }} />
        <p>No dependency graph data available. Ingest a scan to view cryptographic relationships.</p>
      </div>
    );
  }

  const nodes = graphData.nodes;
  const edges = graphData.edges;

  // Simple deterministic circular layout for visualization
  const width = 800;
  const height = 500;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) * 0.38;

  const nodePositions = new Map<string, { x: number; y: number }>();
  nodes.forEach((node, idx) => {
    const angle = (idx / nodes.length) * 2 * Math.PI;
    nodePositions.set(node.node_id, {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    });
  });

  return (
    <div>
      <h1 className="page-title">Cryptographic Dependency Graph</h1>
      <p className="page-subtitle">
        Interactive visualization of transitive signing relationships: Artifacts $\rightarrow$ Certificates $\rightarrow$ Signers $\rightarrow$ CAs.
      </p>

      {/* Stats summary bar */}
      <div style={{ display: 'flex', gap: '16px', marginBottom: '16px' }}>
        <span className="badge badge-info">Nodes: {nodes.length}</span>
        <span className="badge badge-info">Edges: {edges.length}</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '20px' }}>
        {/* Graph Canvas Card */}
        <div className="card" style={{ padding: '16px', position: 'relative', overflow: 'hidden' }}>
          <div style={{ position: 'absolute', top: '16px', right: '16px', display: 'flex', gap: '6px', zIndex: 10 }}>
            <button className="btn" onClick={() => setZoom((z) => Math.min(z + 0.2, 2.0))}>
              <ZoomIn size={14} />
            </button>
            <button className="btn" onClick={() => setZoom((z) => Math.max(z - 0.2, 0.5))}>
              <ZoomOut size={14} />
            </button>
            <button className="btn" onClick={loadGraph}>
              <RefreshCw size={14} />
            </button>
          </div>

          <svg
            viewBox={`0 0 ${width} ${height}`}
            style={{
              width: '100%',
              height: '480px',
              backgroundColor: '#070b12',
              borderRadius: '6px',
              transform: `scale(${zoom})`,
              transition: 'transform 0.2s ease',
            }}
          >
            {/* Edges */}
            {edges.map((e, idx) => {
              const src = nodePositions.get(e.source_id);
              const tgt = nodePositions.get(e.target_id);
              if (!src || !tgt) return null;

              const isConnected = selectedNode && (selectedNode.node_id === e.source_id || selectedNode.node_id === e.target_id);

              return (
                <line
                  key={idx}
                  x1={src.x}
                  y1={src.y}
                  x2={tgt.x}
                  y2={tgt.y}
                  stroke={isConnected ? 'var(--color-primary)' : '#1e293b'}
                  strokeWidth={isConnected ? 2.5 : 1}
                  strokeDasharray={e.edge_type === 'DEPENDS_ON' ? '4 4' : 'none'}
                />
              );
            })}

            {/* Nodes */}
            {nodes.map((n) => {
              const pos = nodePositions.get(n.node_id);
              if (!pos) return null;

              const isSelected = selectedNode?.node_id === n.node_id;
              const nodeColor =
                n.node_type === 'CERTIFICATE' ? '#ef4444' :
                n.node_type === 'CA' ? '#f59e0b' :
                n.node_type === 'CONTAINER' ? '#06b6d4' :
                n.node_type === 'SIGNER' ? '#a855f7' : '#38bdf8';

              return (
                <g
                  key={n.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  style={{ cursor: 'pointer' }}
                  onClick={() => setSelectedNode(n)}
                >
                  <circle
                    r={isSelected ? 16 : 12}
                    fill={nodeColor}
                    stroke="#fff"
                    strokeWidth={isSelected ? 3 : 1}
                  />
                  <text
                    y={22}
                    textAnchor="middle"
                    fill={isSelected ? '#fff' : '#94a3b8'}
                    fontSize="10"
                    fontFamily="var(--font-sans)"
                    fontWeight={isSelected ? 700 : 500}
                  >
                    {n.name.length > 16 ? `${n.name.slice(0, 14)}...` : n.name}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Node Details Panel */}
        <div className="card">
          <div className="card-title">Node Properties</div>
          {selectedNode ? (
            <div style={{ fontSize: '13px' }}>
              <div style={{ marginBottom: '12px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Node Name:</span>
                <div style={{ fontWeight: 600, color: '#fff', fontSize: '15px' }}>{selectedNode.name}</div>
              </div>

              <div style={{ marginBottom: '12px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Type:</span>
                <div><Badge label={selectedNode.node_type} /></div>
              </div>

              <div style={{ marginBottom: '12px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Identifier:</span>
                <div style={{ color: 'var(--color-primary)' }}>
                  <code>{selectedNode.node_id}</code>
                </div>
              </div>

              {selectedNode.metadata_json && Object.keys(selectedNode.metadata_json).length > 0 && (
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Metadata:</span>
                  <div style={{ backgroundColor: 'var(--bg-main)', padding: '8px', borderRadius: '4px', marginTop: '4px', fontSize: '11px' }}>
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      {JSON.stringify(selectedNode.metadata_json, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)' }}>Select a node in the graph to inspect properties.</p>
          )}
        </div>
      </div>
    </div>
  );
};
