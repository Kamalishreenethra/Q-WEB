import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as THREE from 'three';
import {
  DependencyNodeResponse,
  DependencyEdgeResponse,
} from '../types/api';
import {
  Maximize2,
  Minimize2,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  Play,
  Pause,
  Search,
  Layers,
  Terminal,
} from 'lucide-react';

interface LiveGraph3DProps {
  nodes: DependencyNodeResponse[];
  edges: DependencyEdgeResponse[];
  selectedNodeId?: string | null;
  onSelectNode?: (node: DependencyNodeResponse | null) => void;
  explainStep?: number; // For guided explain mode
}

interface Node3DData {
  node: DependencyNodeResponse;
  mesh: THREE.Mesh;
  halo: THREE.Mesh;
  position: THREE.Vector3;
  color: number;
}

export const LiveGraph3D: React.FC<LiveGraph3DProps> = ({
  nodes,
  edges,
  selectedNodeId,
  onSelectNode,
  explainStep,
}) => {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);
  const [autoRotate, setAutoRotate] = useState<boolean>(true);
  const [hoveredNode, setHoveredNode] = useState<{ node: DependencyNodeResponse; x: number; y: number } | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');

  // Three.js internal refs
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const nodeMapRef = useRef<Map<string, Node3DData>>(new Map());
  const edgeLinesRef = useRef<THREE.LineSegments | null>(null);
  const pulseParticlesRef = useRef<THREE.Points | null>(null);
  const pulsePositionsRef = useRef<Float32Array | null>(null);
  const pulseProgressRef = useRef<number[]>([]);
  const animFrameRef = useRef<number | null>(null);

  // Camera control state
  const isDraggingRef = useRef<boolean>(false);
  const prevMouseRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const cameraRadiusRef = useRef<number>(55);
  const cameraThetaRef = useRef<number>(Math.PI / 4);
  const cameraPhiRef = useRef<number>(Math.PI / 3);
  const targetLookAtRef = useRef<THREE.Vector3>(new THREE.Vector3(0, 0, 0));
  const currentLookAtRef = useRef<THREE.Vector3>(new THREE.Vector3(0, 0, 0));

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return nodes.filter((n) => {
      const matchType = typeFilter === 'ALL' || n.node_type.toUpperCase() === typeFilter;
      const matchQuery = !searchQuery || n.name.toLowerCase().includes(searchQuery.toLowerCase()) || n.node_id.toLowerCase().includes(searchQuery.toLowerCase());
      return matchType && matchQuery;
    });
  }, [nodes, typeFilter, searchQuery]);

  // Map of connected neighbor node IDs for the selected node
  const connectedNodeIds = useMemo(() => {
    if (!selectedNodeId) return new Set<string>();
    const set = new Set<string>();
    set.add(selectedNodeId);
    edges.forEach((e) => {
      if (e.source_id === selectedNodeId) set.add(e.target_id);
      if (e.target_id === selectedNodeId) set.add(e.source_id);
    });
    return set;
  }, [selectedNodeId, edges]);

  // Initialize Three.js Scene
  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth;
    const height = container.clientHeight;

    // Scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x060913);
    scene.fog = new THREE.FogExp2(0x060913, 0.012);
    sceneRef.current = scene;

    // Camera
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    cameraRef.current = camera;
    updateCameraPosition();

    // Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: 'high-performance' });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.innerHTML = '';
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // Ambient & Directional Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
    scene.add(ambientLight);

    const dirLight1 = new THREE.DirectionalLight(0x38bdf8, 1.5);
    dirLight1.position.set(30, 40, 30);
    scene.add(dirLight1);

    const dirLight2 = new THREE.DirectionalLight(0xa855f7, 1.2);
    dirLight2.position.set(-30, -20, -30);
    scene.add(dirLight2);

    // Ambient Particle Starfield
    const starCount = 300;
    const starGeo = new THREE.BufferGeometry();
    const starCoords = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount * 3; i += 3) {
      starCoords[i] = (Math.random() - 0.5) * 160;
      starCoords[i + 1] = (Math.random() - 0.5) * 160;
      starCoords[i + 2] = (Math.random() - 0.5) * 160;
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(starCoords, 3));
    const starMat = new THREE.PointsMaterial({
      color: 0x38bdf8,
      size: 0.8,
      transparent: true,
      opacity: 0.3,
    });
    const starPoints = new THREE.Points(starGeo, starMat);
    scene.add(starPoints);

    // Ambient Radar Grid on floor
    const gridHelper = new THREE.GridHelper(80, 40, 0x1e293b, 0x0f172a);
    gridHelper.position.y = -15;
    scene.add(gridHelper);

    // Mouse Interaction Handlers
    const onMouseDown = (e: MouseEvent) => {
      isDraggingRef.current = true;
      prevMouseRef.current = { x: e.clientX, y: e.clientY };
    };

    const onMouseMove = (e: MouseEvent) => {
      if (isDraggingRef.current) {
        const deltaX = e.clientX - prevMouseRef.current.x;
        const deltaY = e.clientY - prevMouseRef.current.y;
        prevMouseRef.current = { x: e.clientX, y: e.clientY };

        cameraThetaRef.current -= deltaX * 0.006;
        cameraPhiRef.current = Math.max(0.1, Math.min(Math.PI - 0.1, cameraPhiRef.current - deltaY * 0.006));
        updateCameraPosition();
      }

      // Raycasting for Hover Tooltip
      if (!isDraggingRef.current && cameraRef.current && sceneRef.current) {
        const rect = renderer.domElement.getBoundingClientRect();
        const mouse = new THREE.Vector2(
          ((e.clientX - rect.left) / rect.width) * 2 - 1,
          -((e.clientY - rect.top) / rect.height) * 2 + 1
        );
        const raycaster = new THREE.Raycaster();
        raycaster.setFromCamera(mouse, cameraRef.current);

        const meshes: THREE.Object3D[] = [];
        nodeMapRef.current.forEach((d) => meshes.push(d.mesh));
        const intersects = raycaster.intersectObjects(meshes);

        if (intersects.length > 0) {
          const hitMesh = intersects[0].object as THREE.Mesh;
          const found = Array.from(nodeMapRef.current.values()).find((d) => d.mesh === hitMesh);
          if (found) {
            setHoveredNode({
              node: found.node,
              x: e.clientX - rect.left + 15,
              y: e.clientY - rect.top - 10,
            });
            renderer.domElement.style.cursor = 'pointer';
            return;
          }
        }
        setHoveredNode(null);
        renderer.domElement.style.cursor = 'grab';
      }
    };

    const onMouseUp = () => {
      isDraggingRef.current = false;
    };

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      cameraRadiusRef.current = Math.max(15, Math.min(130, cameraRadiusRef.current + e.deltaY * 0.06));
      updateCameraPosition();
    };

    const onClick = (e: MouseEvent) => {
      if (!cameraRef.current || !sceneRef.current) return;
      const rect = renderer.domElement.getBoundingClientRect();
      const mouse = new THREE.Vector2(
        ((e.clientX - rect.left) / rect.width) * 2 - 1,
        -((e.clientY - rect.top) / rect.height) * 2 + 1
      );
      const raycaster = new THREE.Raycaster();
      raycaster.setFromCamera(mouse, cameraRef.current);

      const meshes: THREE.Object3D[] = [];
      nodeMapRef.current.forEach((d) => meshes.push(d.mesh));
      const intersects = raycaster.intersectObjects(meshes);

      if (intersects.length > 0) {
        const hitMesh = intersects[0].object as THREE.Mesh;
        const found = Array.from(nodeMapRef.current.values()).find((d) => d.mesh === hitMesh);
        if (found && onSelectNode) {
          onSelectNode(found.node);
          targetLookAtRef.current.copy(found.position);
          return;
        }
      }
    };

    const dom = renderer.domElement;
    dom.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
    dom.addEventListener('wheel', onWheel, { passive: false });
    dom.addEventListener('click', onClick);

    // Animation Loop
    let clock = new THREE.Clock();
    const animate = () => {
      const delta = clock.getDelta();
      const time = clock.getElapsedTime();

      // Slow Auto-Rotation
      if (autoRotate && !isDraggingRef.current) {
        cameraThetaRef.current += delta * 0.08;
        updateCameraPosition();
      }

      // Smooth Camera Look-At Interpolation
      currentLookAtRef.current.lerp(targetLookAtRef.current, 0.06);
      if (cameraRef.current) {
        cameraRef.current.lookAt(currentLookAtRef.current);
      }

      // Animate Selected Node Halos and Idle Pulsing
      nodeMapRef.current.forEach((d) => {
        d.halo.rotation.z += delta * 1.5;
        const scalePulse = 1 + Math.sin(time * 3 + d.position.x) * 0.05;
        d.mesh.scale.set(scalePulse, scalePulse, scalePulse);
      });

      // Animate Edge Energy Flow Particles
      if (pulseParticlesRef.current && pulsePositionsRef.current && pulseProgressRef.current.length > 0) {
        const coords = pulsePositionsRef.current;
        edges.forEach((e, idx) => {
          const src = nodeMapRef.current.get(e.source_id);
          const tgt = nodeMapRef.current.get(e.target_id);
          if (src && tgt && idx < pulseProgressRef.current.length) {
            pulseProgressRef.current[idx] = (pulseProgressRef.current[idx] + delta * 0.4) % 1.0;
            const progress = pulseProgressRef.current[idx];
            coords[idx * 3] = THREE.MathUtils.lerp(src.position.x, tgt.position.x, progress);
            coords[idx * 3 + 1] = THREE.MathUtils.lerp(src.position.y, tgt.position.y, progress);
            coords[idx * 3 + 2] = THREE.MathUtils.lerp(src.position.z, tgt.position.z, progress);
          }
        });
        pulseParticlesRef.current.geometry.attributes.position.needsUpdate = true;
      }

      // Starfield slow rotation
      starPoints.rotation.y = time * 0.02;

      renderer.render(scene, camera);
      animFrameRef.current = requestAnimationFrame(animate);
    };
    animFrameRef.current = requestAnimationFrame(animate);

    // Resize Observer
    const resizeObserver = new ResizeObserver(() => {
      if (!container || !rendererRef.current || !cameraRef.current) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      cameraRef.current.aspect = w / h;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(w, h);
    });
    resizeObserver.observe(container);

    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      resizeObserver.disconnect();
      dom.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      dom.removeEventListener('wheel', onWheel);
      dom.removeEventListener('click', onClick);
      renderer.dispose();
    };
  }, [autoRotate]);

  function updateCameraPosition() {
    if (!cameraRef.current) return;
    const r = cameraRadiusRef.current;
    const theta = cameraThetaRef.current;
    const phi = cameraPhiRef.current;

    cameraRef.current.position.x = r * Math.sin(phi) * Math.sin(theta);
    cameraRef.current.position.y = r * Math.cos(phi);
    cameraRef.current.position.z = r * Math.sin(phi) * Math.cos(theta);
    cameraRef.current.lookAt(currentLookAtRef.current);
  }

  // Populate Nodes and Edges into Three.js Scene
  useEffect(() => {
    const scene = sceneRef.current;
    if (!scene) return;

    // Clean old nodes
    nodeMapRef.current.forEach((d) => {
      scene.remove(d.mesh);
      scene.remove(d.halo);
    });
    nodeMapRef.current.clear();

    if (edgeLinesRef.current) {
      scene.remove(edgeLinesRef.current);
      edgeLinesRef.current = null;
    }
    if (pulseParticlesRef.current) {
      scene.remove(pulseParticlesRef.current);
      pulseParticlesRef.current = null;
    }

    if (filteredNodes.length === 0) return;

    // Deterministic 3D Force/Sphere Layout
    const count = filteredNodes.length;
    const goldenRatio = (1 + Math.sqrt(5)) / 2;
    const radius = Math.min(32, Math.max(14, count * 3.2));

    filteredNodes.forEach((node, i) => {
      // Fibonacci sphere distribution
      const theta = (2 * Math.PI * i) / goldenRatio;
      const phi = Math.acos(1 - (2 * (i + 0.5)) / count);

      const x = radius * Math.cos(theta) * Math.sin(phi);
      const y = (radius * 0.7) * Math.cos(phi);
      const z = radius * Math.sin(theta) * Math.sin(phi);
      const pos = new THREE.Vector3(x, y, z);

      // Node Color by Type & Security Status
      const type = node.node_type.toUpperCase();
      let colorHex = 0x38bdf8; // Default Cyan (Artifact)
      let geometry: THREE.BufferGeometry = new THREE.SphereGeometry(1.6, 24, 24);

      if (type === 'CERTIFICATE') {
        colorHex = 0xf43f5e; // Critical Red
        geometry = new THREE.IcosahedronGeometry(1.8, 1);
      } else if (type === 'SIGNER' || type === 'SIGNING_IDENTITY') {
        colorHex = 0xa855f7; // Violet Diamond
        geometry = new THREE.OctahedronGeometry(1.7);
      } else if (type === 'CA' || type === 'CERTIFICATE_AUTHORITY') {
        colorHex = 0xfbbf24; // Amber Gold Dodecahedron
        geometry = new THREE.DodecahedronGeometry(2.0);
      } else if (type === 'CONTAINER' || type === 'PACKAGE') {
        colorHex = 0x06b6d4; // Teal Box
        geometry = new THREE.BoxGeometry(2.2, 2.2, 2.2);
      }

      const isDimmed = selectedNodeId && !connectedNodeIds.has(node.node_id);
      const isSelected = selectedNodeId === node.node_id;

      const material = new THREE.MeshStandardMaterial({
        color: colorHex,
        roughness: 0.2,
        metalness: 0.8,
        emissive: colorHex,
        emissiveIntensity: isSelected ? 0.8 : isDimmed ? 0.05 : 0.25,
        transparent: true,
        opacity: isDimmed ? 0.2 : 1.0,
      });

      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.copy(pos);
      scene.add(mesh);

      // Halo Ring for Selected or PQC/Critical Nodes
      const haloGeo = new THREE.RingGeometry(2.4, 2.8, 32);
      const haloMat = new THREE.MeshBasicMaterial({
        color: isSelected ? 0x38bdf8 : colorHex,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: isSelected ? 0.9 : isDimmed ? 0.0 : 0.4,
      });
      const halo = new THREE.Mesh(haloGeo, haloMat);
      halo.position.copy(pos);
      scene.add(halo);

      nodeMapRef.current.set(node.node_id, {
        node,
        mesh,
        halo,
        position: pos,
        color: colorHex,
      });
    });

    // Build 3D Edges
    if (edges.length > 0) {
      const linePositions: number[] = [];
      const lineColors: number[] = [];

      edges.forEach((e) => {
        const src = nodeMapRef.current.get(e.source_id);
        const tgt = nodeMapRef.current.get(e.target_id);
        if (src && tgt) {
          linePositions.push(src.position.x, src.position.y, src.position.z);
          linePositions.push(tgt.position.x, tgt.position.y, tgt.position.z);

          const isEdgeConnected = selectedNodeId && (e.source_id === selectedNodeId || e.target_id === selectedNodeId);
          const edgeColor = new THREE.Color(
            isEdgeConnected ? 0x38bdf8 : e.edge_type === 'ISSUED_BY' ? 0xfbbf24 : e.edge_type === 'DEPENDS_ON' ? 0xa855f7 : 0x1e293b
          );
          lineColors.push(edgeColor.r, edgeColor.g, edgeColor.b);
          lineColors.push(edgeColor.r, edgeColor.g, edgeColor.b);
        }
      });

      const edgeGeo = new THREE.BufferGeometry();
      edgeGeo.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3));
      edgeGeo.setAttribute('color', new THREE.Float32BufferAttribute(lineColors, 3));

      const edgeMat = new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        opacity: 0.6,
        linewidth: 1.5,
      });
      const lineSegments = new THREE.LineSegments(edgeGeo, edgeMat);
      scene.add(lineSegments);
      edgeLinesRef.current = lineSegments;

      // Pulse Particles along edges
      const edgeCount = edges.length;
      pulsePositionsRef.current = new Float32Array(edgeCount * 3);
      pulseProgressRef.current = Array.from({ length: edgeCount }, () => Math.random());

      const pulseGeo = new THREE.BufferGeometry();
      pulseGeo.setAttribute('position', new THREE.BufferAttribute(pulsePositionsRef.current, 3));
      const pulseMat = new THREE.PointsMaterial({
        color: 0x38bdf8,
        size: 1.8,
        transparent: true,
        opacity: 0.9,
      });
      const pulsePoints = new THREE.Points(pulseGeo, pulseMat);
      scene.add(pulsePoints);
      pulseParticlesRef.current = pulsePoints;
    }
  }, [filteredNodes, edges, selectedNodeId, connectedNodeIds, explainStep]);

  // Focus Camera onto Selected Node
  useEffect(() => {
    if (selectedNodeId && nodeMapRef.current.has(selectedNodeId)) {
      const d = nodeMapRef.current.get(selectedNodeId)!;
      targetLookAtRef.current.copy(d.position);
    }
  }, [selectedNodeId]);

  function resetCamera() {
    targetLookAtRef.current.set(0, 0, 0);
    cameraRadiusRef.current = 55;
    cameraThetaRef.current = Math.PI / 4;
    cameraPhiRef.current = Math.PI / 3;
    updateCameraPosition();
  }

  return (
    <div
      className="graph-container"
      style={isFullscreen ? { position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', zIndex: 9999, borderRadius: 0 } : {}}
    >
      {/* 3D WebGL Canvas Mount */}
      <div ref={mountRef} style={{ width: '100%', height: '100%' }} />

      {/* Floating HUD Controls */}
      <div className="graph-hud">
        {/* Search */}
        <div className="search-box">
          <Search size={13} />
          <input
            type="text"
            className="search-input"
            placeholder="Search graph node / ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ width: '180px', padding: '5px 10px 5px 28px', fontSize: '12px' }}
          />
        </div>

        {/* Type Filter */}
        <select
          className="select-input"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={{ padding: '5px 8px', fontSize: '12px' }}
        >
          <option value="ALL">All Node Types</option>
          <option value="ARTIFACT">Artifacts</option>
          <option value="CERTIFICATE">Certificates</option>
          <option value="SIGNER">Signing Identities</option>
          <option value="CA">Certificate Authorities</option>
          <option value="CONTAINER">Containers</option>
        </select>
      </div>

      {/* Camera & View Controls */}
      <div className="graph-controls">
        <button
          className="btn"
          onClick={() => setAutoRotate(!autoRotate)}
          title={autoRotate ? 'Pause Auto-Rotation' : 'Resume Auto-Rotation'}
          style={{ padding: '5px 8px' }}
        >
          {autoRotate ? <Pause size={13} /> : <Play size={13} />}
        </button>

        <button
          className="btn"
          onClick={() => {
            cameraRadiusRef.current = Math.max(15, cameraRadiusRef.current - 8);
            updateCameraPosition();
          }}
          title="Zoom In"
          style={{ padding: '5px 8px' }}
        >
          <ZoomIn size={13} />
        </button>

        <button
          className="btn"
          onClick={() => {
            cameraRadiusRef.current = Math.min(130, cameraRadiusRef.current + 8);
            updateCameraPosition();
          }}
          title="Zoom Out"
          style={{ padding: '5px 8px' }}
        >
          <ZoomOut size={13} />
        </button>

        <button
          className="btn"
          onClick={resetCamera}
          title="Reset Camera Target"
          style={{ padding: '5px 8px' }}
        >
          <RotateCcw size={13} />
        </button>

        <button
          className="btn"
          onClick={() => setIsFullscreen(!isFullscreen)}
          title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen Graph'}
          style={{ padding: '5px 8px' }}
        >
          {isFullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
        </button>
      </div>

      {/* Floating Legend */}
      <div className="graph-legend">
        <div style={{ fontWeight: 700, color: '#fff', marginBottom: '6px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '5px' }}>
          <Layers size={12} color="var(--color-primary)" />
          <span>CRYPTOGRAPHIC TOPOLOGY</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '4px 12px', fontSize: '11px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#38bdf8' }} />
            <span>Artifact</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f43f5e' }} />
            <span>Certificate</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#a855f7' }} />
            <span>Signer Identity</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#fbbf24' }} />
            <span>Certificate Auth (CA)</span>
          </div>
        </div>
      </div>

      {/* Hover Tooltip */}
      {hoveredNode && (
        <div
          className="graph-tooltip"
          style={{ left: `${hoveredNode.x}px`, top: `${hoveredNode.y}px` }}
        >
          <div style={{ fontWeight: 700, color: '#fff' }}>{hoveredNode.node.name}</div>
          <div style={{ fontSize: '11px', color: 'var(--color-primary)' }}>{hoveredNode.node.node_type}</div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            ID: {hoveredNode.node.node_id.slice(0, 16)}...
          </div>
        </div>
      )}

      {/* Empty State Ambient Overlay */}
      {nodes.length === 0 && (
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'rgba(6, 9, 19, 0.75)',
            backdropFilter: 'blur(4px)',
            pointerEvents: 'auto',
          }}
        >
          <div className="radar-pulse">
            <Layers size={22} color="var(--color-primary)" />
          </div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff', marginBottom: '4px' }}>
            3D Cryptographic Dependency Graph
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '12px', maxWidth: '440px', textAlign: 'center', lineHeight: 1.5 }}>
            No cryptographic entities currently ingested in database. Ingest a signed binary, X.509 certificate, Sigstore bundle, or container to view live 3D dependency topology.
          </p>
          <div className="terminal-box" style={{ marginTop: '16px' }}>
            <Terminal size={14} />
            <code>signchain store /path/to/signed-artifact.exe</code>
          </div>
        </div>
      )}
    </div>
  );
};
