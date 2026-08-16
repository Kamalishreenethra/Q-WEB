# Dependency Graph Engine Documentation - SignChain

## 1. Executive Overview

Software supply chains are complex directed networks. Traditional Software Bill of Materials (SBOM) and flat cryptographic inventories analyze artifacts in isolation:

$$\text{Artifact A} \rightarrow \text{RSA-2048}$$
$$\text{Artifact B} \rightarrow \text{ECDSA-P256}$$
$$\text{Artifact C} \rightarrow \text{RSA-2048}$$

While a flat inventory identifies which algorithms are present, it cannot answer critical post-quantum security questions:
- Which root Certificate Authority or intermediate signing key affects the largest number of downstream artifacts?
- If Certificate $X$ is compromised or requires post-quantum migration, which software distributions will be disrupted?
- How should an organization sequence key migrations to minimize supply chain disruption?

**SignChain** addresses this gap by implementing a graph-aware dependency analysis engine powered by **NetworkX**.

> [!NOTE]
> *Research Significance Statement*: Dependency-aware analysis is a proposed research component whose usefulness in post-quantum code signing migration will be evaluated experimentally.

---

## 2. Graph Engine Architecture

SignChain uses a directed graph $G = (V, E)$ implemented in NetworkX (`nx.DiGraph`).

### 2.1 Node Schema ($V$)

Every node represents an identity or software asset:

```json
{
  "id": "cert:8756393aba558adc",
  "type": "CERTIFICATE",
  "name": "CN=SignChain Release Cert, O=Org",
  "metadata": {
    "algorithm": "RSA-2048",
    "quantum_status": "VULNERABLE",
    "fingerprint": "8756393aba558adc0f702398e6512c0fadeb851fae1c9f6d0681db917b61e948"
  }
}
```

#### Supported Node Types
- `ARTIFACT`: Executable binaries, packages, code archives, or release builds.
- `CERTIFICATE`: Leaf X.509 digital certificates or signing keys.
- `SIGNER`: Developer identity or signing authority.
- `CA`: Root or Intermediate Certificate Authority.

---

### 2.2 Edge Schema ($E$)

Edges represent directional trust or operational relationships:

```
  ┌────────────┐     SIGNED_BY     ┌─────────────┐     ISSUED_BY     ┌──────┐
  │  Artifact  │ ────────────────> │ Certificate │ ────────────────> │  CA  │
  └────────────┘                   └─────────────┘                   └──────┘
```

#### Supported Edge Types
- `SIGNED_BY`: Connects an `ARTIFACT` to its signing `CERTIFICATE` or `SIGNER`.
- `ISSUED_BY`: Connects a `CERTIFICATE` to its issuing `CA`.
- `DEPENDS_ON`: Connects an `ARTIFACT` to another `ARTIFACT` or package dependency.

---

## 3. Centrality & Downstream Impact

To quantify the downstream impact of each signing key or Certificate Authority, SignChain evaluates two complementary graph metrics:

### 3.1 Transitive Downstream Reachability Count

For any node $v \in V$, the downstream dependency count $N_{\text{downstream}}(v)$ is defined as the number of unique `ARTIFACT` nodes reachable in the reverse graph $G^{T}$:

$$N_{\text{downstream}}(v) = \left| \{ a \in V_{\text{ARTIFACT}} \mid \text{path}(a \rightarrow v) \text{ exists in } G \} \right|$$

Example:
- `Cert-1` signs 2 artifacts $\rightarrow N_{\text{downstream}}(\text{Cert-1}) = 2$.
- `Cert-2` signs 3 artifacts $\rightarrow N_{\text{downstream}}(\text{Cert-2}) = 3$.
- `Root-CA` issued both certificates $\rightarrow N_{\text{downstream}}(\text{Root-CA}) = 5$.

`Root-CA` and `Cert-2` are identified as high-impact migration targets.

### 3.2 Degree & Betweenness Centrality

- **Degree Centrality**: Measures direct inbound and outbound connectivity.
- **Betweenness Centrality**: Measures how frequently a node acts as a bridge along the shortest path between other nodes in the network:
  $$C_B(v) = \sum_{s \neq v \neq t} \frac{\sigma_{st}(v)}{\sigma_{st}}$$
  High betweenness centrality highlights key **Intermediate CAs** through which multiple code signing trust chains flow.

---

## 4. Transparent Dependency Impact Normalization

In the Phase 4 Quantum Risk Engine, `dependency_impact` ($I_{\text{dep}}$) is a factor score on a scale of $[0.0, 100.0]$.

SignChain maps the raw downstream artifact count $N_{\text{downstream}}$ to $I_{\text{dep}}$ using a transparent, logarithmic scaling function:

$$I_{\text{dep}} = \min\left(100.0, \frac{\ln(1 + N_{\text{downstream}})}{\ln(1 + N_{\text{target\_max}})} \times 100.0\right)$$

*(Default $N_{\text{target\_max}} = 50.0$)*

### Rationale for Logarithmic Scaling
1. **Diminishing Marginal Increase**: Moving from 1 to 5 dependent artifacts represents a dramatic shift in operational risk ($\sim 17.7 \rightarrow 45.6$), while moving from 45 to 50 artifacts represents a smaller incremental shift ($\sim 96.5 \rightarrow 100.0$).
2. **Smooth Saturation**: Prevents extremely large repositories from blowing past upper bounds while giving high-impact signers appropriate risk weight.

| Downstream Artifacts ($N_{\text{downstream}}$) | Normalized $I_{\text{dep}}$ Score |
|---|---|
| 0 | 0.00 |
| 1 | 17.67 |
| 5 | 45.65 |
| 10 | 61.08 |
| 25 | 83.18 |
| 50+ | 100.00 |

---

## 5. Graph Query API

The `DependencyGraph` class provides Python methods:

```python
from signchain.graph import DependencyGraph

g = DependencyGraph()
g.build_from_scan_result(scan_result)

# Query downstream artifacts
affected_artifacts = g.find_artifacts_signed_by("cert:8756393aba558adc")

# Query certificates for an artifact
certs = g.find_certificates_for_artifact("my_app.exe")

# Summary stats & top signers
stats = g.get_graph_statistics()
```

---

## 6. Serialization & Frontend Export

SignChain exports graph data in two formats:
1. **JSON Format** (`export_json()` / `to_dict()`): Standardized schema containing nodes, edges, statistics, and centrality dictionary. Can be consumed directly by React/TypeScript graph visualizers (e.g. Cytoscape.js or D3.js in Phase 13).
2. **GraphML Format** (`export_graphml()`): Standard XML format for external graph analysis tools (e.g., Gephi).

---

## 7. Performance & Benchmarking

SignChain includes a non-fabricated runtime benchmarking method:

```python
bench = g.benchmark_graph_construction(node_count=100)
```

It records exact runtime execution duration (in seconds) using high-resolution performance counters (`time.perf_counter()`) for:
- Node & edge construction time
- Downstream reachability traversal time
- Centrality calculation time

---

## 8. Security Boundaries & Limits

- **Untrusted Data Handling**: Node IDs, names, and metadata from scanned certificates are treated as untrusted strings and sanitized during JSON serialization.
- **Resource Limits**: Memory growth is protected by bounding max file parsing size (10 MB per cert) and max node allocation limits during bulk directory scanning.
