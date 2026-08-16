"""
Main Typer CLI application for SignChain.
"""
import sys
import json
from pathlib import Path
from typing import Optional

import typer

from signchain.scanners.x509_scanner import X509Scanner
from signchain.scanners.pe_scanner import PEScanner
from signchain.scanners.pgp_scanner import PGPScanner
from signchain.scanners.sigstore_scanner import SigstoreScanner
from signchain.scanners.container_scanner import ContainerScanner

# Reconfigure stdout/stderr for Windows UTF-8 console compatibility
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

app = typer.Typer(
    name="signchain",
    help="SignChain: Automated Discovery and Migration Planning for Post-Quantum Code Signing in Software Supply Chains.",
    add_completion=False,
    rich_markup_mode=None,
)


def get_available_scanners():
    """Returns initialized list of supported scanner plugins."""
    return [PEScanner(), PGPScanner(), SigstoreScanner(), ContainerScanner(), X509Scanner()]


def find_scanner_for_file(file_path: str):
    """Finds first scanner plugin that can process the given artifact path."""
    for scanner in get_available_scanners():
        if scanner.can_handle(file_path):
            return scanner
    return None


@app.callback()
def main_callback():
    """
    SignChain CLI: Post-Quantum Code Signing Security & Migration Tool.
    """
    pass


@app.command(name="scan")
def scan_command(
    path: str = typer.Argument(..., help="Path to certificate or artifact file to scan."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output results in JSON format."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Write scan results to a file."),
):
    """
    Scan a software artifact or certificate for digital signatures and cryptographic parameters.
    """
    file_path = Path(path)

    if not file_path.exists():
        err_msg = f"Error: Path '{path}' does not exist."
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg}))
        else:
            typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    scanner = find_scanner_for_file(str(file_path))
    if not scanner:
        err_msg = f"Error: No available scanner plugin can process '{path}'."
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg}))
        else:
            typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    raw_result = scanner.scan(str(file_path))
    normalized_results = scanner.normalize_result(raw_result)

    if raw_result.get("status") == "ERROR":
        err_msg = raw_result.get("error_message", "Scan failed.")
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg, "file_path": str(file_path)}, indent=2))
        else:
            typer.secho(f"Scan Error: {err_msg}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # Prepare JSON string
    result_json = json.dumps(
        {
            "artifact": str(file_path),
            "status": "SUCCESS",
            "certificate_count": len(normalized_results),
            "certificates": normalized_results,
        },
        indent=2,
    )

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result_json)
            typer.secho(f"Results written to {output_file}", fg=typer.colors.GREEN)
        except Exception as e:
            typer.secho(f"Failed to write output file: {e}", fg=typer.colors.RED, err=True)

    if json_output:
        print(result_json)
    else:
        # Formatted human-readable output
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.secho("              SIGNCHAIN DISCOVERY SCAN            ", fg=typer.colors.CYAN, bold=True)
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"Artifact File : {file_path.name}")
        typer.echo(f"Full Path     : {file_path.resolve()}")
        typer.echo(f"Cert Count    : {len(normalized_results)}")
        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)

        for idx, cert in enumerate(normalized_results, 1):
            status = cert.get("quantum_status", "UNKNOWN")
            status_color = typer.colors.RED if status in ("VULNERABLE", "WEAK_CLASSICAL") else typer.colors.GREEN

            risk_lvl = cert.get("risk_level", "UNKNOWN")
            if risk_lvl in ("CRITICAL", "HIGH"):
                risk_color = typer.colors.RED
            elif risk_lvl == "MEDIUM":
                risk_color = typer.colors.YELLOW
            else:
                risk_color = typer.colors.GREEN

            typer.secho(f"Certificate #{idx}:", fg=typer.colors.YELLOW, bold=True)
            typer.echo(f"  Format             : {cert.get('format')}")
            typer.echo(f"  Subject            : {cert.get('subject')}")
            typer.echo(f"  Issuer             : {cert.get('issuer')}")
            typer.echo(f"  Serial Number      : {cert.get('serial_number')}")
            typer.echo(f"  Not Before (UTC)   : {cert.get('not_before')}")
            typer.echo(f"  Not After (UTC)    : {cert.get('not_after')}")
            typer.echo(f"  Public Key Alg     : {cert.get('public_key_algorithm')} ({cert.get('canonical_algorithm')})")
            typer.echo(f"  Algorithm Family   : {cert.get('algorithm_family')}")
            typer.echo(f"  Classical Sec Bits : {cert.get('classical_security_bits')}")
            if cert.get("key_size"):
                typer.echo(f"  Key Size (bits)    : {cert.get('key_size')}")
            if cert.get("curve"):
                typer.echo(f"  Elliptic Curve     : {cert.get('curve')}")
            typer.echo(f"  Signature Algorithm: {cert.get('signature_algorithm')}")
            typer.echo(f"  SHA-256 Fingerprint: {cert.get('sha256_fingerprint')}")
            typer.echo(f"  Is CA              : {cert.get('is_ca')}")
            typer.secho(f"  Quantum Status     : {status}", fg=status_color, bold=True)
            typer.echo(f"  Reason             : {cert.get('quantum_reason')}")
            typer.echo(f"  Confidence Source  : {cert.get('confidence_source')}")
            typer.secho(f"  Quantum Risk Level : {risk_lvl} (Score: {cert.get('risk_score')}/100)", fg=risk_color, bold=True)
            typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)


@app.command(name="graph")
def graph_command(
    path: str = typer.Argument(..., help="Path to scan result JSON or certificate file."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output graph structure in JSON format."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save graph output to file (JSON or GraphML)."),
):
    """
    Construct and query the NetworkX dependency graph for a scan result.
    """
    from signchain.graph.dependency_graph import DependencyGraph

    file_path = Path(path)
    if not file_path.exists():
        err_msg = f"Error: Path '{path}' does not exist."
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg}))
        else:
            typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    graph_engine = DependencyGraph()

    # Attempt parsing as JSON scan result or JSON graph export
    scan_data = None
    if file_path.suffix.lower() == ".json":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                scan_data = json.load(f)
        except Exception as e:
            typer.secho(f"Error parsing JSON file '{path}': {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    if scan_data and "nodes" in scan_data and "edges" in scan_data:
        # Load from graph export format
        for n in scan_data.get("nodes", []):
            graph_engine.add_node(n["id"], n["type"], name=n.get("name"), metadata=n.get("metadata"))
        for e in scan_data.get("edges", []):
            graph_engine.add_edge(e["source"], e["target"], edge_type=e.get("type", "SIGNED_BY"), metadata=e.get("metadata"))
    elif scan_data:
        # Load from scan result object
        graph_engine.build_from_scan_result(scan_data, artifact_id=file_path.name)
    else:
        # Fallback: attempt running matching scanner on artifact file
        scanner = find_scanner_for_file(str(file_path))
        if scanner:
            raw_res = scanner.scan(str(file_path))
            graph_engine.build_from_scan_result(raw_res, artifact_id=file_path.name)
        else:
            err_msg = f"Error: File '{path}' is not a valid scan result, PE binary, or X.509 certificate."
            if json_output:
                print(json.dumps({"status": "ERROR", "error_message": err_msg}))
            else:
                typer.secho(err_msg, fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    stats = graph_engine.get_graph_statistics()
    graph_json = graph_engine.export_json()

    if output_file:
        try:
            out_path = Path(output_file)
            if out_path.suffix.lower() == ".graphml":
                out_content = graph_engine.export_graphml()
            else:
                out_content = graph_json
            out_path.write_text(out_content, encoding="utf-8")
            typer.secho(f"Graph exported to {output_file}", fg=typer.colors.GREEN)
        except Exception as e:
            typer.secho(f"Failed to export graph file: {e}", fg=typer.colors.RED, err=True)

    if json_output:
        print(graph_json)
    else:
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.secho("           SIGNCHAIN DEPENDENCY GRAPH             ", fg=typer.colors.CYAN, bold=True)
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"Total Nodes : {stats['total_nodes']}")
        typer.echo(f"  Artifacts : {stats['artifacts_count']}")
        typer.echo(f"  Certs     : {stats['certificates_count']}")
        typer.echo(f"  CAs       : {stats['cas_count']}")
        typer.echo(f"Total Edges : {stats['total_edges']}")
        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho("Top Signing Dependencies (Downstream Impact):", fg=typer.colors.YELLOW, bold=True)

        top_signers = stats.get("top_signing_dependencies", [])
        if not top_signers:
            typer.echo("  No signing dependencies found.")
        else:
            for idx, item in enumerate(top_signers, 1):
                typer.echo(f" {idx}. {item['id']} ({item['name']})")
                typer.echo(f"    Type: {item['type']} | Downstream Artifacts: {item['downstream_artifacts_count']}")

        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)


@app.command(name="pqc")
def pqc_command(
    path: str = typer.Argument(..., help="Path to scan result JSON or certificate file."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output readiness assessment in JSON format."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save PQC assessment JSON to file."),
):
    """
    Evaluate PQC readiness, candidate algorithms, blockers, and migration phases.
    """
    from signchain.pqc.readiness_engine import PQCReadinessEngine
    from signchain.graph.dependency_graph import DependencyGraph

    file_path = Path(path)
    if not file_path.exists():
        err_msg = f"Error: Path '{path}' does not exist."
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg}))
        else:
            typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    scan_data = None
    if file_path.suffix.lower() == ".json":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                scan_data = json.load(f)
        except Exception as e:
            typer.secho(f"Error parsing JSON file '{path}': {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    if not scan_data:
        scanner = find_scanner_for_file(str(file_path))
        if scanner:
            scan_data = scanner.scan(str(file_path))
        else:
            err_msg = f"Error: File '{path}' is not a valid scan result, PE binary, or certificate."
            if json_output:
                print(json.dumps({"status": "ERROR", "error_message": err_msg}))
            else:
                typer.secho(err_msg, fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    # Build graph engine for dependency reachability count if available
    graph_engine = DependencyGraph()
    graph_engine.build_from_scan_result(scan_data, artifact_id=file_path.name)

    engine = PQCReadinessEngine()
    assessment = engine.evaluate_readiness(scan_data, graph_engine=graph_engine)
    result_json = json.dumps(assessment, indent=2)

    if output_file:
        try:
            Path(output_file).write_text(result_json, encoding="utf-8")
            typer.secho(f"PQC Assessment saved to {output_file}", fg=typer.colors.GREEN)
        except Exception as e:
            typer.secho(f"Failed to write output file: {e}", fg=typer.colors.RED, err=True)

    if json_output:
        print(result_json)
    else:
        state = assessment["readiness"]["state"]
        state_color = typer.colors.GREEN if state == "PQC_READY" else (typer.colors.YELLOW if state in ("HYBRID_READY", "PARTIALLY_READY") else typer.colors.RED)

        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.secho("         SIGNCHAIN PQC READINESS ASSESSMENT       ", fg=typer.colors.CYAN, bold=True)
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"Artifact          : {assessment['artifact_id']}")
        typer.echo(f"Current Algorithm : {assessment['current_cryptography']['algorithm']}")
        typer.echo(f"Algorithm Family  : {assessment['current_cryptography'].get('family', 'UNKNOWN')}")
        typer.echo(f"Quantum Status    : {assessment['current_cryptography']['quantum_status']}")
        typer.secho(f"PQC Readiness     : {state}", fg=state_color, bold=True)
        typer.echo(f"Migration Phase   : {assessment['readiness']['migration_phase']}")

        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho("Candidate PQC Algorithms:", fg=typer.colors.YELLOW, bold=True)
        cands = assessment.get("candidate_algorithms", [])
        if not cands:
            typer.echo("  No migration candidates (already PQC or unknown).")
        else:
            for cand in cands:
                typer.echo(f"  - {cand['name']} ({cand.get('recommendation_type', 'CANDIDATE')}) - {cand.get('standard_status', '')}")

        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho("Compatibility Assessment:", fg=typer.colors.YELLOW, bold=True)
        compat = assessment.get("compatibility", {})
        for dim_key, dim_val in compat.items():
            label = dim_key.replace("_", " ").title()
            dim_color = typer.colors.GREEN if dim_val == "SUPPORTED" else (typer.colors.YELLOW if dim_val == "PARTIAL" else typer.colors.WHITE)
            typer.secho(f"  {label:30s}: {dim_val}", fg=dim_color)

        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho("Evidence Classification:", fg=typer.colors.YELLOW, bold=True)
        for ev in assessment.get("evidence", []):
            lvl = ev.get("level", "UNKNOWN")
            lvl_color = typer.colors.GREEN if lvl == "OBSERVED" else (typer.colors.YELLOW if lvl == "INFERRED" else typer.colors.WHITE)
            typer.secho(f"  [{lvl:8s}] {ev.get('description', '')}", fg=lvl_color)

        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho("Migration Blockers:", fg=typer.colors.RED, bold=True)
        blockers = assessment.get("blockers", [])
        if not blockers:
            typer.echo("  None identified.")
        else:
            for b in blockers:
                typer.echo(f"  - {b}")

        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho("Readiness Reasons:", fg=typer.colors.YELLOW, bold=True)
        for idx, reason in enumerate(assessment.get("reasons", []), 1):
            typer.echo(f"  {idx}. {reason}")

        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.echo(f"Downstream Impact : {assessment['dependency_impact']['downstream_artifacts']} artifact(s) ({assessment['dependency_impact'].get('impact_level', 'UNKNOWN')})")
        typer.echo(f"Recommended Next  : {assessment['recommended_next_step']}")
        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho(f"Disclaimer: {assessment.get('disclaimer', '')}", fg=typer.colors.BRIGHT_BLACK)
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)


@app.command(name="migration")
def migration_command(
    path: str = typer.Argument(..., help="Path to scan result JSON or certificate file."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output migration plan in JSON format."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save migration plan JSON to file."),
    baseline: bool = typer.Option(False, "--baseline", "-b", help="Run flat baseline comparison."),
):
    """
    Generate dependency-aware PQC migration prioritization, roadmap, and conflict analysis.
    """
    from signchain.migration.migration_engine import MigrationPrioritizationEngine, BaselinePrioritizer
    from signchain.graph.dependency_graph import DependencyGraph

    file_path = Path(path)
    if not file_path.exists():
        err_msg = f"Error: Path '{path}' does not exist."
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg}))
        else:
            typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    scan_data = None
    if file_path.suffix.lower() == ".json":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                scan_data = json.load(f)
        except Exception as e:
            typer.secho(f"Error parsing JSON file '{path}': {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    if not scan_data:
        scanner = find_scanner_for_file(str(file_path))
        if scanner:
            scan_data = scanner.scan(str(file_path))
        else:
            err_msg = f"Error: File '{path}' is not a valid scan result, PE binary, or certificate."
            if json_output:
                print(json.dumps({"status": "ERROR", "error_message": err_msg}))
            else:
                typer.secho(err_msg, fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    # Build dependency graph
    graph_engine = DependencyGraph()
    graph_engine.build_from_scan_result(scan_data, artifact_id=file_path.name)

    records = scan_data.get("certificates", [])
    if not records:
        records = [scan_data]

    if baseline:
        flat_results = BaselinePrioritizer.prioritize_flat(records)
        if json_output:
            print(json.dumps({"baseline_plan": flat_results}, indent=2))
        else:
            typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
            typer.secho("        RESEARCH BASELINE — FLAT RISK ORDERING    ", fg=typer.colors.CYAN, bold=True)
            typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
            for item in flat_results:
                typer.echo(f"Rank {item['baseline_rank']}: {item['artifact_id']} | Risk: {item['risk_score']} | Alg: {item['algorithm']}")
            typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        return

    engine = MigrationPrioritizationEngine()
    plan = engine.prioritize_all(records, graph_engine=graph_engine)
    result_json = json.dumps(plan, indent=2)

    if output_file:
        try:
            Path(output_file).write_text(result_json, encoding="utf-8")
            typer.secho(f"Migration plan saved to {output_file}", fg=typer.colors.GREEN)
        except Exception as e:
            typer.secho(f"Failed to write output file: {e}", fg=typer.colors.RED, err=True)

    if json_output:
        print(result_json)
    else:
        summary = plan["summary"]
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.secho("         SIGNCHAIN PQC MIGRATION ROADMAP          ", fg=typer.colors.CYAN, bold=True)
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"Total Targets    : {summary['total_targets']}")
        typer.secho(f"Priority Tiers   : P1={summary['priority_counts']['P1']} | P2={summary['priority_counts']['P2']} | P3={summary['priority_counts']['P3']} | P4={summary['priority_counts']['P4']}", fg=typer.colors.YELLOW, bold=True)
        typer.echo(f"Blocked Targets  : {summary['blocked_count']}")
        typer.echo(f"Conflicts Found  : {summary['conflict_count']}")

        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho("Prioritized Migration Targets:", fg=typer.colors.YELLOW, bold=True)
        for idx, t in enumerate(plan["targets"], 1):
            p_code = t["priority_code"]
            p_color = typer.colors.RED if p_code == "P1" else (typer.colors.YELLOW if p_code == "P2" else typer.colors.GREEN)
            typer.secho(f"  {idx}. {t['artifact_id']} [{t['priority_level']}] (Score: {t['priority_score']})", fg=p_color, bold=True)
            typer.echo(f"     Algorithm: {t['algorithm']} | Risk: {t['risk_score']} | Status: {t['migration_status']}")
            typer.echo(f"     Action   : {t['recommended_action']}")

        if plan["conflicts"]:
            typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
            typer.secho("Dependency Conflicts Detected:", fg=typer.colors.RED, bold=True)
            for c in plan["conflicts"]:
                typer.echo(f"  - {c['asset']} -> {c['depends_on']}: {c['reason']}")

        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho(f"Disclaimer: {plan['model']['disclaimer']}", fg=typer.colors.BRIGHT_BLACK)
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)


@app.command(name="sigstore")
def sigstore_command(
    path: str = typer.Argument(..., help="Path to Sigstore bundle or envelope (.json, .bundle, .sigstore, .dsse)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output results in JSON format."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Write scan results to a file."),
):
    """
    Perform dedicated Sigstore signing, certificate, identity, and transparency analysis.
    """
    file_path = Path(path)

    if not file_path.exists():
        err_msg = f"Error: Path '{path}' does not exist."
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg}))
        else:
            typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    scanner = SigstoreScanner()
    raw_result = scanner.scan(str(file_path))

    if raw_result.get("status") == "ERROR":
        err_msg = raw_result.get("error_message", "Sigstore analysis failed.")
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg, "file_path": str(file_path)}, indent=2))
        else:
            typer.secho(f"Sigstore Error: {err_msg}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    result_json = json.dumps(raw_result, indent=2)

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result_json)
            typer.secho(f"Results written to {output_file}", fg=typer.colors.GREEN)
        except Exception as e:
            typer.secho(f"Failed to write output file: {e}", fg=typer.colors.RED, err=True)

    if json_output:
        print(result_json)
    else:
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.secho("           SIGNCHAIN SIGSTORE ANALYSIS            ", fg=typer.colors.CYAN, bold=True)
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"Artifact File : {file_path.name}")
        typer.echo(f"Media Type    : {raw_result.get('media_type')}")
        
        # Digest
        d = raw_result.get("artifact", {}).get("digest", {})
        typer.echo(f"Artifact Digest: {d.get('algorithm', 'UNKNOWN')} / {d.get('value', 'UNKNOWN')[:32]}...")

        # Identity
        ident = raw_result.get("identity", {})
        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho(f"Signing Identity: {ident.get('value')}", fg=typer.colors.YELLOW, bold=True)
        typer.echo(f"  Identity Type : {ident.get('type')}")
        typer.echo(f"  OIDC Issuer   : {ident.get('issuer')}")

        # Certificate
        cert = raw_result.get("certificate")
        if cert:
            typer.echo(f"  Certificate   : {cert.get('subject')}")
            typer.echo(f"  Algorithm     : {cert.get('canonical_algorithm')}")
            
            q_status = cert.get("quantum_status", "UNKNOWN")
            q_color = typer.colors.RED if q_status == "VULNERABLE" else typer.colors.GREEN
            typer.secho(f"  Quantum Status: {q_status}", fg=q_color, bold=True)
            typer.echo(f"  Risk Score    : {cert.get('risk_score')} ({cert.get('risk_level')})")

        # Transparency
        tlog = raw_result.get("transparency", {})
        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.echo(f"Transparency Evidence : {tlog.get('status')}")
        typer.echo(f"Rekor Verification    : {tlog.get('verification')}")
        typer.echo(f"Signature Verification: {raw_result.get('signing', {}).get('verification_status')}")
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)


@app.command(name="container")
def container_command(
    path: str = typer.Argument(..., help="Path to OCI/Docker container manifest or metadata (.json, .manifest.json, .oci.json)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output results in JSON format."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Write scan results to a file."),
):
    """
    Perform dedicated OCI/Docker container image manifest, Cosign, and Notary signature analysis.
    """
    file_path = Path(path)

    if not file_path.exists():
        err_msg = f"Error: Path '{path}' does not exist."
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg}))
        else:
            typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    scanner = ContainerScanner()
    raw_result = scanner.scan(str(file_path))

    if raw_result.get("status") == "ERROR":
        err_msg = raw_result.get("error_message", "Container scan failed.")
        if json_output:
            print(json.dumps({"status": "ERROR", "error_message": err_msg, "file_path": str(file_path)}, indent=2))
        else:
            typer.secho(f"Container Error: {err_msg}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    result_json = json.dumps(raw_result, indent=2)

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result_json)
            typer.secho(f"Results written to {output_file}", fg=typer.colors.GREEN)
        except Exception as e:
            typer.secho(f"Failed to write output file: {e}", fg=typer.colors.RED, err=True)

    if json_output:
        print(result_json)
    else:
        art = raw_result.get("artifact", {})
        sig = raw_result.get("signature", {})
        cert = raw_result.get("certificate")

        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.secho("           SIGNCHAIN CONTAINER ANALYSIS           ", fg=typer.colors.CYAN, bold=True)
        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"Image Name    : {art.get('image_name')}")
        typer.echo(f"Media Type    : {art.get('media_type')}")
        typer.echo(f"Digest        : {art.get('digest')}")
        typer.echo(f"Architecture  : {art.get('architecture')} / {art.get('os')}")
        typer.echo(f"Layer Count   : {art.get('layer_count')}")

        typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
        typer.secho(f"Signature Status: {sig.get('status')}", fg=typer.colors.YELLOW, bold=True)
        typer.echo(f"  Ecosystem     : {sig.get('ecosystem')}")
        typer.echo(f"  Verification  : {sig.get('verification')}")

        if cert:
            typer.secho("--------------------------------------------------", fg=typer.colors.CYAN)
            typer.echo(f"Signing Cert  : {cert.get('subject')}")
            typer.echo(f"Issuer CA     : {cert.get('issuer')}")
            typer.echo(f"Algorithm     : {cert.get('canonical_algorithm')}")
            
            q_status = cert.get("quantum_status", "UNKNOWN")
            q_color = typer.colors.RED if q_status == "VULNERABLE" else typer.colors.GREEN
            typer.secho(f"Quantum Status: {q_status}", fg=q_color, bold=True)
            typer.echo(f"Risk Score    : {cert.get('risk_score')} ({cert.get('risk_level')})")
        else:
            typer.echo(f"Quantum Status: {raw_result.get('quantum_status')}")

        typer.secho("==================================================", fg=typer.colors.CYAN, bold=True)


@app.command(name="serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host address (defaults strictly to 127.0.0.1)."),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port number."),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development."),
):
    """
    Start the SignChain FastAPI REST API backend server.
    """
    import uvicorn
    from signchain.db.session import init_db

    # Ensure tables exist
    init_db()

    typer.secho(f"Starting SignChain API Server on http://{host}:{port} ...", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"Interactive API Docs: http://{host}:{port}/docs")
    uvicorn.run("signchain.api.app:app", host=host, port=port, reload=reload)


@app.command(name="store")
def store_command(
    path: str = typer.Argument(..., help="Path to a scan result JSON file or an artifact to scan and store."),
    scanner_version: str = typer.Option("0.1.0", "--scanner-version", help="Scanner version tag."),
):
    """
    Store and persist a scan result into the SignChain database.
    """
    from signchain.db.session import SessionLocal, init_db
    from signchain.api.services.ingestion_service import IngestionService

    init_db()
    file_path = Path(path)

    if not file_path.exists():
        typer.secho(f"Error: File '{path}' does not exist.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # Check if this is already a JSON scan result or a raw artifact to scan first
    raw_result = None
    if file_path.suffix.lower() == ".json":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "status" in data and ("certificates" in data or "artifact" in data or "signature" in data):
                raw_result = data
        except Exception:
            pass

    if raw_result is None:
        scanner = find_scanner_for_file(str(file_path))
        if not scanner:
            typer.secho(f"Error: No suitable scanner plugin found for '{file_path}'.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        raw_result = scanner.scan(str(file_path))

    db = SessionLocal()
    try:
        service = IngestionService(db)
        scan = service.ingest_scan_result(raw_result, scanner_version=scanner_version)
        typer.secho(f"Successfully stored scan record: ID={scan.id}, Status={scan.status}, Artifacts={scan.artifact_count}", fg=typer.colors.GREEN, bold=True)
    except Exception as e:
        typer.secho(f"Failed to store scan: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    finally:
        db.close()


if __name__ == "__main__":
    app()




