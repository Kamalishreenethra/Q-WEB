# SignChain — Frontend Phase Modernization Report

## 1. Executive Summary
The SignChain React frontend has been modernized from a basic prototype into a **Cybersecurity Intelligence Platform**. The platform provides an executive command center for post-quantum cryptographic discovery, vulnerability classification, and dependency-aware migration roadmap planning across software supply chains.

---

## 2. Visual Design System & Aesthetics
- **Color Architecture:**
  - Background: Deep Obsidian (`#060810`) and Midnight Navy (`#0a0f1d`)
  - Panels: Glassmorphism (`rgba(15, 23, 42, 0.75)`) with subtle glowing borders (`--border-card: #1e2d4a`)
  - Primary Brand: Electric Cyan (`#38bdf8`) with atmospheric glow
  - Security Semantics:
    - `CRITICAL` / `P1`: Vivid Red (`#f43f5e`)
    - `HIGH` / `P2`: Orange (`#fb923c`)
    - `MEDIUM` / `P3`: Amber (`#fbbf24`)
    - `LOW` / `P4`: Emerald (`#34d399`)
    - `PQC_READY`: Quantum Violet (`#a78bfa`)
- **Atmospheric Background:** Dynamic subtle dot/grid matrix with radial gradients and low-contrast scanlines.
- **Typography:** Inter for headings/body, monospace (`JetBrains Mono`/`Fira Code`) for fingerprints, serial numbers, algorithms, and node identifiers.

---

## 3. Interactive WebGL Live 3D Cryptographic Dependency Graph
- **Component:** [`src/components/LiveGraph3D.tsx`](file:///C:/Users/HP/SignChain-RealWorld/frontend/src/components/LiveGraph3D.tsx)
- **3D Engine:** Three.js WebGL renderer with OrbitControls, directional lighting, and particle starfield.
- **3D Topologies:**
  - `ARTIFACT`: Cyan glowing sphere with orbital pulse
  - `CERTIFICATE`: Red/Amber faceted icosahedron representing cryptographic identity
  - `SIGNER`: Violet octahedron
  - `CA`: Golden dodecahedron
  - `CONTAINER`: Teal rounded cube
- **Animated Relationships & Data Flow:**
  - `SIGNED_BY`: Solid glowing cyan line with moving energy particles
  - `ISSUED_BY`: Amber dashed lines
  - `DEPENDS_ON`: Violet supply chain dependency lines
  - `CONTAINS`: Emerald sub-package links
- **Interactive Capabilities:**
  - Raycaster hover tooltips & click selection
  - Smooth camera focus interpolation onto selected nodes
  - Neighbor highlighting (unconnected nodes dim to 20% opacity)
  - Fullscreen toggle, zoom in/out, auto-rotation toggle, camera reset
  - Search & node type filters operating live in 3D
- **Explain Mode (`[GRAPH] [EXPLAIN]`):** Sequential guided reasoning chain stepping through cryptographic identity, Shor algorithm vulnerability, downstream blast radius, and topological migration assignment.
- **Ambient Empty State:** 3D scanning radar grid with instructional terminal prompt when 0 artifacts exist.

---

## 4. Upgraded Pages & Intelligence Views
1. **Overview Dashboard (`OverviewPage.tsx`):**
   - 5 KPI StatCards (Total Assets, Signing Identities, Quantum Vulnerable Keys, PQC-Ready Assets, P1 Migration Targets)
   - Topological Migration Targets Ladder
   - Recent Discovery Scans Feed
   - NIST FIPS 204/205 Baseline Reference Strip
2. **Asset Inventory (`ArtifactsPage.tsx` & `ArtifactDetailPage.tsx`):**
   - Search by name/path, filter by ecosystem (PE, X509, Sigstore, PGP, Container)
   - Pagination with custom page size selector
   - Deep inspection view with 3-pillar summary (Risk, PQC, Migration) and signature chain table
3. **Certificate Intelligence (`CertificatesPage.tsx`):**
   - Monospace SHA-256 fingerprints with one-click copy-to-clipboard
   - Quantum status classification, CA root flags, subject/issuer hierarchies
4. **Quantum Risk Analytics (`RiskPage.tsx`):**
   - Transparent 6-factor mathematical weighting breakdown formula
   - Multi-factor breakdown per artifact (Crypto, Criticality, Exposure, Horizon, Dependency, Complexity)
5. **PQC Readiness Engine (`PQCReadinessPage.tsx`):**
   - Readiness tier classification (`NOT_READY`, `PARTIALLY_READY`, `HYBRID_READY`, `PQC_READY`)
   - Candidate algorithm identification (ML-DSA, SLH-DSA) and architectural blocker analysis
6. **Migration Roadmap (`MigrationPage.tsx`):**
   - Dependency-aware topological migration sequencing (`P1` to `P4`) resolving priority inversions
   - Action plans and rationale explanations
7. **Scan History (`ScansPage.tsx`):**
   - Execution duration benchmarks, artifact counts, error counts, scanner versions
8. **Research Evaluation (`ResearchPage.tsx`):**
   - Formal evaluation of H1-H5 research hypotheses and track separation (Track A Synthetic vs Track B Real-World)

---

## 5. Resilient Error Handling & Live State
- **API Status Indicator:** Navbar live pulse detecting `ONLINE`, `OFFLINE`, or `CHECKING`.
- **Non-JSON / HTML Fallback Protection:** Centralized `ApiError` handler converts `<!DOCTYPE html>` Vite/proxy routing failures into clear `"Backend route unavailable"` banners rather than raw JSON parse exceptions.
- **Empty States:** Polished empty states with terminal CLI instructions (`signchain store ...`).
- **Zero Fake Data Guarantee:** All UI elements render authentic backend data or clear empty states without simulated numbers.

---

## 6. Build & Test Validation Results

### Backend Pytest Suite
```
======================= 182 passed, 1 warning in 7.38s ========================
```
- **Zero Database Contamination:** Contaminated records archived and cleaned; tests execute in isolated SQLite instances.

### Frontend Production Build
```
✓ 1588 modules transformed.
dist/index.html                   1.22 kB
dist/assets/index-BfrMxYfY.css   13.98 kB
dist/assets/index-G3KJil5H.js   772.51 kB
✓ built in 4.81s with 0 TypeScript errors and 0 Vite errors.
```

---

## 7. How to Run the Application

### Terminal 1: FastAPI Backend
```powershell
cd C:\Users\HP\SignChain-RealWorld
python -m uvicorn signchain.api.app:app --host 127.0.0.1 --port 8000 --reload
```

### Terminal 2: React/Vite Frontend
```powershell
cd C:\Users\HP\SignChain-RealWorld\frontend
npm run dev
```

- **Frontend Dashboard:** `http://127.0.0.1:3000`
- **Backend API Docs:** `http://127.0.0.1:8000/docs`
