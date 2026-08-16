"""
NetworkX Dependency Graph Engine for SignChain.
"""
import time
import json
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx


class NodeType:
    ARTIFACT = "ARTIFACT"
    CERTIFICATE = "CERTIFICATE"
    SIGNER = "SIGNER"
    CA = "CA"
    PACKAGE = "PACKAGE"
    CONTAINER = "CONTAINER"
    PGP_KEY = "PGP_KEY"
    SIGSTORE_BUNDLE = "SIGSTORE_BUNDLE"
    TRANSPARENCY_ENTRY = "TRANSPARENCY_ENTRY"


class EdgeType:
    SIGNED_BY = "SIGNED_BY"
    ISSUED_BY = "ISSUED_BY"
    DEPENDS_ON = "DEPENDS_ON"
    CONTAINS = "CONTAINS"
    DERIVED_FROM = "DERIVED_FROM"
    BELONGS_TO = "BELONGS_TO"
    RECORDED_IN = "RECORDED_IN"


class DependencyGraph:
    """
    Graph-aware dependency engine driven by NetworkX for software supply chain digital signatures.
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_node(
        self,
        node_id: str,
        node_type: str,
        name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Adds or updates a typed node in the dependency graph.
        """
        if not node_id:
            raise ValueError("node_id cannot be empty.")

        display_name = name or node_id
        meta = metadata if metadata is not None else {}

        if self.graph.has_node(node_id):
            # Update attributes without losing existing data
            self.graph.nodes[node_id]["type"] = node_type
            self.graph.nodes[node_id]["name"] = display_name
            self.graph.nodes[node_id]["metadata"].update(meta)
        else:
            self.graph.add_node(
                node_id,
                type=node_type,
                name=display_name,
                metadata=meta,
            )
        return node_id

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str = EdgeType.SIGNED_BY,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str]:
        """
        Adds a directed edge between two nodes.
        Auto-creates placeholder nodes if missing.
        """
        if not source_id or not target_id:
            raise ValueError("source_id and target_id must be non-empty.")

        if not self.graph.has_node(source_id):
            self.add_node(source_id, NodeType.ARTIFACT, name=source_id)

        if not self.graph.has_node(target_id):
            self.add_node(target_id, NodeType.CERTIFICATE, name=target_id)

        meta = metadata if metadata is not None else {}
        self.graph.add_edge(source_id, target_id, type=edge_type, metadata=meta)
        return source_id, target_id

    def remove_node(self, node_id: str) -> bool:
        """Removes a node and its edges from the graph."""
        if self.graph.has_node(node_id):
            self.graph.remove_node(node_id)
            return True
        return False

    def remove_edge(self, source_id: str, target_id: str) -> bool:
        """Removes a directed edge between source and target."""
        if self.graph.has_edge(source_id, target_id):
            self.graph.remove_edge(source_id, target_id)
            return True
        return False

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Returns metadata dictionary for a single node, or None if missing."""
        if not self.graph.has_node(node_id):
            return None
        data = self.graph.nodes[node_id]
        return {
            "id": node_id,
            "type": data.get("type", "UNKNOWN"),
            "name": data.get("name", node_id),
            "metadata": dict(data.get("metadata", {})),
        }

    def get_neighbors(self, node_id: str) -> List[Dict[str, Any]]:
        """Returns direct successors and predecessors for a node."""
        if not self.graph.has_node(node_id):
            return []

        neighbors = set(self.graph.successors(node_id)).union(set(self.graph.predecessors(node_id)))
        return [self.get_node(nid) for nid in neighbors if nid is not None]

    def find_artifacts_signed_by(self, certificate_id: str) -> List[str]:
        """
        Finds all artifact node IDs directly or transitively downstream of certificate_id.
        """
        if not self.graph.has_node(certificate_id):
            return []

        # Reverse traversal from certificate_id back to connected artifacts
        reverse_g = self.graph.reverse(copy=False)
        reachable = nx.descendants(reverse_g, certificate_id)
        
        artifacts = [
            nid for nid in reachable
            if self.graph.nodes[nid].get("type") == NodeType.ARTIFACT
        ]
        return sorted(artifacts)

    def find_certificates_for_artifact(self, artifact_id: str) -> List[str]:
        """Finds all certificate node IDs directly signed by artifact_id."""
        if not self.graph.has_node(artifact_id):
            return []

        succs = self.graph.successors(artifact_id)
        certs = [
            nid for nid in succs
            if self.graph.nodes[nid].get("type") in (NodeType.CERTIFICATE, NodeType.CA)
        ]
        return sorted(certs)

    def find_downstream_dependencies(self, node_id: str) -> List[str]:
        """
        Finds all reachable downstream artifact nodes that depend on / are signed by node_id.
        """
        return self.find_artifacts_signed_by(node_id)

    def get_dependency_count(self, node_id: str) -> int:
        """Returns count of downstream artifact dependencies affected by node_id."""
        return len(self.find_downstream_dependencies(node_id))

    def get_graph_statistics(self) -> Dict[str, Any]:
        """Returns summary statistics for nodes, edges, types, and top impact signers."""
        node_type_counts = {}
        for _, data in self.graph.nodes(data=True):
            ntype = data.get("type", "UNKNOWN")
            node_type_counts[ntype] = node_type_counts.get(ntype, 0) + 1

        edge_type_counts = {}
        for _, _, data in self.graph.edges(data=True):
            etype = data.get("type", "UNKNOWN")
            edge_type_counts[etype] = edge_type_counts.get(etype, 0) + 1

        # Calculate top certificates and CAs by downstream impact
        cert_impacts = []
        for nid, data in self.graph.nodes(data=True):
            ntype = data.get("type")
            if ntype in (NodeType.CERTIFICATE, NodeType.CA):
                impact = self.get_dependency_count(nid)
                cert_impacts.append({
                    "id": nid,
                    "name": data.get("name", nid),
                    "type": ntype,
                    "downstream_artifacts_count": impact,
                })

        cert_impacts.sort(key=lambda x: x["downstream_artifacts_count"], reverse=True)

        highest_cert = cert_impacts[0] if cert_impacts else None

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "artifacts_count": node_type_counts.get(NodeType.ARTIFACT, 0),
            "certificates_count": node_type_counts.get(NodeType.CERTIFICATE, 0),
            "signers_count": node_type_counts.get(NodeType.SIGNER, 0),
            "cas_count": node_type_counts.get(NodeType.CA, 0),
            "node_type_counts": node_type_counts,
            "edge_type_counts": edge_type_counts,
            "top_signing_dependencies": cert_impacts[:10],
            "highest_downstream_impact": highest_cert,
        }

    def calculate_centrality(self) -> Dict[str, Any]:
        """
        Calculates degree and betweenness centrality measures across the graph.
        
        Note on Betweenness Centrality:
        Betweenness centrality measures how often a node acts as a bridge along the shortest 
        path between other nodes. In digital signature dependency graphs, high betweenness 
        centrality highlights root CAs or intermediate CAs through which multiple signing chains flow.
        """
        if self.graph.number_of_nodes() == 0:
            return {"degree_centrality": {}, "betweenness_centrality": {}}

        deg_centrality = nx.degree_centrality(self.graph)
        in_deg_centrality = nx.in_degree_centrality(self.graph)
        out_deg_centrality = nx.out_degree_centrality(self.graph)

        try:
            btw_centrality = nx.betweenness_centrality(self.graph)
        except Exception:
            btw_centrality = {}

        return {
            "degree_centrality": {k: round(v, 4) for k, v in deg_centrality.items()},
            "in_degree_centrality": {k: round(v, 4) for k, v in in_deg_centrality.items()},
            "out_degree_centrality": {k: round(v, 4) for k, v in out_deg_centrality.items()},
            "betweenness_centrality": {k: round(v, 4) for k, v in btw_centrality.items()},
            "explanation": (
                "Degree centrality measures direct connected links. Betweenness centrality identifies "
                "key bridge nodes (e.g. Intermediate CAs) carrying cryptographic trust chains."
            ),
        }

    def build_from_scan_result(self, scan_result: Dict[str, Any], artifact_id: Optional[str] = None) -> None:
        """
        Populates dependency graph from actual X509Scanner scan outputs.
        """
        if scan_result.get("status") != "SUCCESS":
            return

        file_path = scan_result.get("file_path", "unknown_artifact")
        art_id = artifact_id or file_path

        is_container = scan_result.get("ecosystem") == "CONTAINER" or (
            isinstance(scan_result.get("artifact"), dict) and scan_result.get("artifact", {}).get("type") == "OCI_IMAGE"
        )
        art_node_type = NodeType.CONTAINER if is_container else NodeType.ARTIFACT
        art_name = scan_result.get("artifact_name") or (
            scan_result.get("artifact", {}).get("image_name") if is_container else scan_result.get("artifact", art_id)
        )

        # 1. Add Artifact / Container Node
        self.add_node(
            node_id=art_id,
            node_type=art_node_type,
            name=art_name or art_id,
            metadata={
                "file_path": file_path,
                "is_container": is_container,
                "container_digest": scan_result.get("artifact", {}).get("digest") if is_container else None,
            },
        )

        # If container, add CONTAINS edges for layers
        if is_container:
            for layer_digest in scan_result.get("artifact", {}).get("layer_digests", []):
                if layer_digest:
                    layer_id = f"layer:{layer_digest[:16]}"
                    self.add_node(
                        node_id=layer_id,
                        node_type=NodeType.PACKAGE,
                        name=f"Layer {layer_digest[:12]}",
                        metadata={"digest": layer_digest},
                    )
                    self.add_edge(art_id, layer_id, edge_type=EdgeType.CONTAINS)

        certs = scan_result.get("certificates", [])
        for cert in certs:
            cert_fp = cert.get("sha256_fingerprint")
            if not cert_fp:
                continue

            cert_id = f"cert:{cert_fp[:16]}"
            is_pgp = "OpenPGP" in cert.get("format", "") or cert.get("key_id") is not None
            is_ca = cert.get("is_ca", False)
            node_type = NodeType.PGP_KEY if is_pgp else (NodeType.CA if is_ca else NodeType.CERTIFICATE)

            # 2. Add Certificate / CA / PGP Key Node
            self.add_node(
                node_id=cert_id,
                node_type=node_type,
                name=cert.get("subject", cert_id),
                metadata={
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "algorithm": cert.get("canonical_algorithm"),
                    "quantum_status": cert.get("quantum_status"),
                    "fingerprint": cert_fp,
                    "key_id": cert.get("key_id"),
                },
            )

            # 3. Add SIGNED_BY Edge (Artifact -> Cert/Key)
            self.add_edge(art_id, cert_id, edge_type=EdgeType.SIGNED_BY)

            # 4. For PGP Keys with User IDs: Add SIGNER Node (BELONGS_TO)
            for uid in cert.get("user_ids", []):
                signer_id = f"signer:{hash(uid) & 0xFFFFFFFF:08x}"
                self.add_node(
                    node_id=signer_id,
                    node_type=NodeType.SIGNER,
                    name=uid,
                    metadata={"user_id": uid},
                )
                self.add_edge(cert_id, signer_id, edge_type=EdgeType.BELONGS_TO)

            # 5. For Sigstore signing identity: Add SIGNER Node (BELONGS_TO)
            sig_identity = cert.get("sigstore_identity")
            if sig_identity and sig_identity != "UNKNOWN":
                signer_id = f"signer:{hash(sig_identity) & 0xFFFFFFFF:08x}"
                self.add_node(
                    node_id=signer_id,
                    node_type=NodeType.SIGNER,
                    name=sig_identity,
                    metadata={
                        "identity": sig_identity,
                        "identity_type": cert.get("sigstore_identity_type"),
                        "oidc_issuer": cert.get("sigstore_oidc_issuer"),
                    },
                )
                self.add_edge(cert_id, signer_id, edge_type=EdgeType.BELONGS_TO)

            # 6. Add Issuer CA Node if Issuer != Subject
            issuer_str = cert.get("issuer")
            if issuer_str and issuer_str != cert.get("subject") and not is_pgp:
                ca_id = f"ca:{hash(issuer_str) & 0xFFFFFFFF:08x}"
                self.add_node(
                    node_id=ca_id,
                    node_type=NodeType.CA,
                    name=issuer_str,
                    metadata={"issuer_dn": issuer_str},
                )
                self.add_edge(cert_id, ca_id, edge_type=EdgeType.ISSUED_BY)

        # 7. Add Transparency Log (Rekor) Node if present in Sigstore scan
        tlog = scan_result.get("transparency", {})
        for entry in tlog.get("entries", []):
            log_idx = entry.get("log_index")
            if log_idx and log_idx != "UNKNOWN":
                tlog_id = f"tlog:{log_idx}"
                self.add_node(
                    node_id=tlog_id,
                    node_type=NodeType.TRANSPARENCY_ENTRY,
                    name=f"Rekor Entry #{log_idx}",
                    metadata=entry,
                )
                self.add_edge(art_id, tlog_id, edge_type=EdgeType.RECORDED_IN)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes graph to a clean dictionary format suitable for JSON export or frontend rendering."""
        nodes = []
        for nid, data in self.graph.nodes(data=True):
            nodes.append({
                "id": nid,
                "type": data.get("type", "UNKNOWN"),
                "name": data.get("name", nid),
                "metadata": dict(data.get("metadata", {})),
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "type": data.get("type", EdgeType.SIGNED_BY),
                "metadata": dict(data.get("metadata", {})),
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "statistics": self.get_graph_statistics(),
            "centrality": self.calculate_centrality(),
        }

    def export_json(self, indent: int = 2) -> str:
        """Exports deterministic JSON representation of graph."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def export_graphml(self) -> str:
        """Exports graph in standard GraphML format."""
        # Convert metadata to string for GraphML compatibility
        g_copy = self.graph.copy()
        for _, data in g_copy.nodes(data=True):
            if "metadata" in data:
                data["metadata"] = json.dumps(data["metadata"])
        for _, _, data in g_copy.edges(data=True):
            if "metadata" in data:
                data["metadata"] = json.dumps(data["metadata"])

        return "".join(nx.generate_graphml(g_copy))

    def benchmark_graph_construction(self, node_count: int = 100) -> Dict[str, Any]:
        """
        Measures real runtime performance for node addition, edge creation, traversal, and centrality.
        """
        g_test = DependencyGraph()

        t0 = time.perf_counter()
        for i in range(node_count):
            g_test.add_node(f"bench_art_{i}", NodeType.ARTIFACT, name=f"Artifact {i}")
            g_test.add_node(f"bench_cert_{i % 5}", NodeType.CERTIFICATE, name=f"Cert {i % 5}")
            g_test.add_edge(f"bench_art_{i}", f"bench_cert_{i % 5}", EdgeType.SIGNED_BY)
        t_construct = time.perf_counter() - t0

        t1 = time.perf_counter()
        deps = g_test.find_artifacts_signed_by("bench_cert_0")
        t_traverse = time.perf_counter() - t1

        t2 = time.perf_counter()
        cent = g_test.calculate_centrality()
        t_centrality = time.perf_counter() - t2

        return {
            "benchmark_nodes": g_test.graph.number_of_nodes(),
            "benchmark_edges": g_test.graph.number_of_edges(),
            "construction_time_sec": round(t_construct, 6),
            "traversal_time_sec": round(t_traverse, 6),
            "centrality_time_sec": round(t_centrality, 6),
            "sample_traversal_count": len(deps),
        }
