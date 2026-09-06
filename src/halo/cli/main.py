"""Project HALO - Command Line Interface.

Provides developer-friendly CLI commands wiring together all four pipeline stages:
SAST route/handler discovery, business intent mining & pruning, DAST dynamic probing,
and empirical verification & reporting.
"""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path

import httpx
import typer
from rich.console import Console

from halo.cli.ui import (
    print_banner,
    print_scan_summary,
    render_candidates_table,
    render_findings_table,
    render_routes_table,
)
from halo.dast.probes.base import ProbeResult
from halo.dast.probes.bfla import BFLAProbe
from halo.dast.probes.bola import BOLAProbe
from halo.dast.probes.mass_assignment import MassAssignmentProbe
from halo.dast.probes.race import RaceConditionProbe
from halo.dast.probes.workflow import WorkflowProbe, WorkflowStep
from halo.dast.sandbox import SandboxManager
from halo.dast.vault import SessionVault
from halo.intent.extractor import IntentExtractor
from halo.intent.hypothesis import (
    FLAW_CLASS_NORMALIZATION,
    HypothesisGenerator,
    HypothesisResult,
)
from halo.intent.pruner import CandidatePruner, SuspectCandidate
from halo.llm.governor import TokenGovernor
from halo.llm.provider import get_llm_provider
from halo.static.export import export_ckg_to_cytoscape_file
from halo.static.graph import (
    CodeKnowledgeGraph,
    EdgeType,
    HandlerNode,
    MiddlewareNode,
    RouteNode,
    SinkNode,
)
from halo.static.parser import CodeParser, HandlerDefinition, RouteDefinition
from halo.validation.cvss import CVSSCalculator
from halo.validation.models import FindingRecord
from halo.validation.patcher import RemediationPatcher
from halo.validation.poc_builder import PoCBuilder
from halo.validation.repair import PoCRepairLoop
from halo.validation.report import ReportGenerator

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="halo",
    help="AI-Native Hybrid Application Security Testing for Business Logic Flaws.",
    add_completion=False,
)
console = Console()

__all__ = [
    "BFLAProbe",
    "BOLAProbe",
    "CandidatePruner",
    "CodeKnowledgeGraph",
    "CodeParser",
    "HypothesisGenerator",
    "IntentExtractor",
    "MassAssignmentProbe",
    "PoCBuilder",
    "ProbeResult",
    "RaceConditionProbe",
    "RemediationPatcher",
    "ReportGenerator",
    "SandboxManager",
    "SessionVault",
    "SuspectCandidate",
    "WorkflowProbe",
    "app",
    "build_ckg_from_repo",
    "discover_repo_files",
    "parse_file_routes_and_handlers",
]


def discover_repo_files(repo_path: str | Path) -> list[Path]:
    """Recursively collect supported source files in target repository."""
    path = Path(repo_path)
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []

    ignored_directories = {
        ".git",
        "node_modules",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".pytest_cache",
        ".superpowers",
        ".halo",
    }
    supported_extensions = set(CodeParser.EXT_TO_LANG.keys())
    matched_files: list[Path] = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignored_directories and not d.startswith(".")]
        for f in files:
            ext = Path(f).suffix.lower()
            if ext in supported_extensions:
                matched_files.append(Path(root) / f)

    return sorted(matched_files)


def parse_file_routes_and_handlers(
    file_path: Path, parser: CodeParser | None = None
) -> tuple[list[RouteDefinition], list[HandlerDefinition]]:
    """Parse a source file and extract route definitions and handler signatures."""
    parser_inst = parser or CodeParser()
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        routes = parser_inst.extract_routes(str(file_path), code=content)
        handlers = parser_inst.extract_handlers(str(file_path), code=content)
        return routes, handlers
    except Exception as exc:  # noqa: BLE001
        logger.debug("Failed to parse file %s: %s", file_path, exc)
        return [], []


def build_ckg_from_repo(
    repo_path: str | Path,
) -> tuple[CodeKnowledgeGraph, list[RouteNode], list[HandlerNode]]:
    """Build a complete Code Knowledge Graph from discovered routes, handlers, and sinks."""
    ckg = CodeKnowledgeGraph()
    parser = CodeParser()
    files = discover_repo_files(repo_path)

    all_routes: list[RouteNode] = []
    all_handlers: list[HandlerNode] = []

    route_counter = 0
    handler_counter = 0
    sink_counter = 0

    for file_path in files:
        routes, handlers = parse_file_routes_and_handlers(file_path, parser=parser)

        file_handler_nodes: dict[str, HandlerNode] = {}
        for h in handlers:
            handler_counter += 1
            h_node = HandlerNode(
                id=f"handler_{handler_counter}_{h.name}",
                name=h.name,
                signature=h.signature,
                line_span=h.line_span,
                arguments=h.arguments,
                file_path=str(file_path),
                line_number=h.line_span[0] if h.line_span[0] > 0 else 1,
            )
            ckg.add_node(h_node)
            all_handlers.append(h_node)
            file_handler_nodes[h.name] = h_node
            if "::" in h.name:
                short_name = h.name.split("::")[-1]
                file_handler_nodes[short_name] = h_node

        for r in routes:
            route_counter += 1
            r_node = RouteNode(
                id=f"route_{route_counter}_{r.method}_{r.path}",
                method=r.method,
                path=r.path,
                param_constraints=r.param_constraints,
                file_path=str(file_path),
                line_number=r.line_number,
            )
            r_node.handler_name = r.handler_name
            ckg.add_node(r_node)
            all_routes.append(r_node)

            # Link route to handler
            matched_handler = file_handler_nodes.get(r.handler_name)
            if matched_handler:
                ckg.add_edge(r_node.id, matched_handler.id, EdgeType.ROUTES_TO)

            # Link route to middleware
            if r.middleware:
                for mid_idx, mid_name in enumerate(r.middleware):
                    is_guard = any(
                        token in mid_name.lower()
                        for token in (
                            "auth",
                            "guard",
                            "role",
                            "perm",
                            "owner",
                            "check",
                            "deny",
                            "reject",
                            "block",
                            "forbidden",
                        )
                    )
                    m_node = MiddlewareNode(
                        id=f"mid_{route_counter}_{mid_idx}_{mid_name}",
                        name=mid_name,
                        type="AUTHZ" if is_guard else "AUTHN",
                        is_auth_guard=is_guard,
                        file_path=str(file_path),
                    )
                    ckg.add_node(m_node)
                    ckg.add_edge(r_node.id, m_node.id, EdgeType.PROTECTED_BY)

            # Infer data sinks for parameterized endpoints or mutating actions
            has_param = any(token in r.path for token in ("{", ":", "<"))
            is_write = r.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
            if has_param or is_write:
                sink_counter += 1
                entity_part = r.path.strip("/").split("/")[0] or "Entity"
                entity_name = entity_part.capitalize()
                s_node = SinkNode(
                    id=f"sink_{sink_counter}_{entity_name}",
                    operation="WRITE" if is_write else "READ",
                    entity=entity_name,
                    query_params=["id"] if has_param else [],
                    file_path=str(file_path),
                    line_number=r.line_number,
                )
                ckg.add_node(s_node)
                source_id = matched_handler.id if matched_handler else r_node.id
                ckg.add_edge(source_id, s_node.id, EdgeType.CALLS)

    return ckg, all_routes, all_handlers


def _execute_dynamic_probes(
    suspects: list[SuspectCandidate],
    target_url: str,
    vault: SessionVault,
    client: httpx.Client,
    hypotheses: list[HypothesisResult] | None = None,
    safe_mode: bool = True,
) -> list[FindingRecord]:
    """Execute dynamic probes against suspect candidates and return verified findings."""
    verified_findings: list[FindingRecord] = []
    finding_counter = 0

    calc = CVSSCalculator()
    sandbox_mgr = SandboxManager(safe_mode=safe_mode)

    def _canon(name: str) -> str:
        clean = name.strip().upper().replace("-", "_")
        return FLAW_CLASS_NORMALIZATION.get(clean, clean)

    # Index hypotheses by candidate route ID, candidate ID, and flaw class
    hypo_map: dict[tuple[str, str], HypothesisResult] = {}
    if hypotheses:
        for h in hypotheses:
            c_cls = _canon(h.flaw_class)
            hypo_map[(h.route_id, c_cls)] = h
            if h.candidate_id:
                hypo_map[(h.candidate_id, c_cls)] = h
            hypo_map[(h.route_id, "*")] = h

    for cand in suspects:
        cand_route_id = cand.route.id if cand.route else ""
        cand_id = getattr(cand, "candidate_id", getattr(cand, "id", ""))
        flaw_set: set[str] = set()
        merged_flaws: list[str] = []
        for f in cand.candidate_flaws or []:
            cf = _canon(f)
            if cf not in flaw_set:
                flaw_set.add(cf)
                merged_flaws.append(cf)

        if hypotheses:
            for (r_id, f_cls), h in hypo_map.items():
                if f_cls == "*":
                    continue
                if r_id == cand_route_id or (cand_id and r_id == cand_id):
                    cf = _canon(h.flaw_class)
                    if cf not in flaw_set:
                        flaw_set.add(cf)
                        merged_flaws.append(cf)
        flaws = merged_flaws or ["BOLA_IDOR"]

        for flaw in flaws:
            norm_flaw = flaw.upper()
            probe_result: ProbeResult | None = None
            endpoint_path = cand.route.path if cand.route else "/api"
            method_str = cand.route.method if cand.route else "GET"

            # Enforce safe mode guardrails before attempting mutations
            is_mutation = method_str.upper() in {"POST", "PUT", "PATCH", "DELETE"}
            allowed, safe_reason = sandbox_mgr.check_safe_mode_guardrails(
                target_url=target_url,
                method=method_str,
                path=endpoint_path,
                identity="halo_user_a",
            )
            if not allowed:
                logger.warning(
                    "Safe mode guardrail: probe on %s %s blocked (%s)",
                    method_str,
                    endpoint_path,
                    safe_reason,
                )
                continue

            hypo = (
                hypo_map.get((cand_route_id, norm_flaw))
                or (hypo_map.get((cand_id, norm_flaw)) if cand_id else None)
                or hypo_map.get((cand_route_id, "*"))
            )
            recipe = hypo.probing_recipe if hypo else None

            try:
                if "BOLA" in norm_flaw or "IDOR" in norm_flaw:
                    probe = BOLAProbe()
                    create_ep = None
                    if recipe and recipe.extra_params.get("create_endpoint"):
                        create_ep = recipe.extra_params["create_endpoint"]
                    is_mutation = method_str.upper() in {"POST", "PUT", "PATCH", "DELETE"}
                    probe_result = probe.execute(
                        client=client,
                        target_url=target_url,
                        vault=vault,
                        recipe=recipe,
                        create_endpoint=create_ep,
                        read_endpoint_template=endpoint_path,
                        test_write=is_mutation,
                        write_method=method_str.upper() if is_mutation else "PUT",
                        write_endpoint_template=endpoint_path if is_mutation else None,
                    )
                elif "BFLA" in norm_flaw:
                    probe = BFLAProbe()
                    probe_result = probe.execute(
                        client=client,
                        target_url=target_url,
                        vault=vault,
                        recipe=recipe,
                        endpoint=endpoint_path,
                        method=method_str,
                    )
                elif "RACE" in norm_flaw:
                    probe = RaceConditionProbe()
                    probe_result = probe.execute(
                        client=client,
                        target_url=target_url,
                        vault=vault,
                        recipe=recipe,
                        endpoint=endpoint_path,
                        method=method_str,
                    )
                elif "WORKFLOW" in norm_flaw:
                    probe = WorkflowProbe()
                    wf_steps = []
                    if recipe and recipe.extra_params.get("workflow_steps"):
                        wf_steps = recipe.extra_params["workflow_steps"]
                    if not wf_steps:
                        base_match = re.match(
                            r"^(.*?)(?:/(?::\w+|\{\w+\}))?/(?:ship|checkout|confirm|approve|complete|pay|deliver|cancel)(?:/.*)?$",
                            endpoint_path,
                            re.IGNORECASE,
                        )
                        if base_match:
                            wf_steps = [
                                WorkflowStep(name="action_step", endpoint=base_match.group(1), method="POST"),
                                WorkflowStep(name="terminal_step", endpoint=endpoint_path, method=method_str),
                            ]
                        else:
                            wf_steps = [
                                WorkflowStep(name="action_step", endpoint=endpoint_path, method=method_str)
                            ]
                    probe_result = probe.execute(
                        client=client,
                        target_url=target_url,
                        vault=vault,
                        recipe=recipe,
                        workflow_steps=wf_steps,
                    )
                elif "MASS" in norm_flaw:
                    probe = MassAssignmentProbe()
                    probe_result = probe.execute(
                        client=client,
                        target_url=target_url,
                        vault=vault,
                        recipe=recipe,
                        endpoint=endpoint_path,
                        method=method_str,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "Probe execution error for %s on %s: %s", norm_flaw, endpoint_path, exc
                )

            if probe_result and probe_result.vulnerable:
                finding_counter += 1
                clean_type = probe_result.flaw_type.upper().replace("_", "-")
                finding_id = f"HALO-{clean_type[:4]}-{finding_counter:02d}"

                is_write = method_str.upper() in {"POST", "PUT", "PATCH", "DELETE"}
                cvss_score, cvss_sev, cvss_vec = calc.calculate_for_finding(
                    flaw_type=probe_result.flaw_type,
                    is_write=is_write,
                )

                file_path = cand.route.file_path if cand.route else ""
                line_start = cand.route.line_number if cand.route else 1

                finding_rec = FindingRecord(
                    id=finding_id,
                    flaw_type=probe_result.flaw_type,
                    endpoint=probe_result.endpoint or endpoint_path,
                    target_url=target_url,
                    method=method_str,
                    severity=cvss_sev,
                    confidence=probe_result.confidence,
                    reproduction_steps=probe_result.reproduction_steps,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_start,
                    details=probe_result.details
                    or f"Verified {probe_result.flaw_type} vulnerability.",
                )
                finding_rec.cvss_score = cvss_score
                finding_rec.cvss_severity = cvss_sev
                finding_rec.cvss_vector = cvss_vec
                verified_findings.append(finding_rec)
                console.print(
                    f"  [bold red]⚡ Verified Vulnerability:[/bold red] [{cvss_sev}] {probe_result.flaw_type} on [cyan]{method_str} {endpoint_path}[/cyan]"
                )

    return verified_findings


@app.command()
def scan(
    repo: str = typer.Option(..., "--repo", "-r", help="Path to repository to scan"),
    url: str | None = typer.Option(
        None, "--url", "-u", help="Live target URL (e.g. http://localhost:3000)"
    ),
    docker: bool = typer.Option(
        False, "--docker", "-d", help="Automatically manage Docker container lifecycle"
    ),
    safe_mode: bool = typer.Option(
        True,
        "--safe-mode/--force-destructive",
        help="Enforce read-only mutations on foreign entities",
    ),
    output_dir: str = typer.Option(
        ".", "--out", "--output-dir", "-o", help="Output directory for reports and PoCs"
    ),
    token_budget: int = typer.Option(150000, "--token-budget", help="LLM token budget limit"),
    llm_provider_name: str = typer.Option(
        os.environ.get("HALO_LLM_PROVIDER", "mock"),
        "--llm-provider",
        help="LLM provider name (mock, openai, anthropic, gemini, ollama, nvidia, auto)",
    ),
    verify_pocs: bool = typer.Option(
        False,
        "--verify-pocs/--no-verify-pocs",
        help="Verify and repair generated PoCs against target URL",
    ),
) -> None:
    """Run full end-to-end hybrid security audit (SAST + Intent + DAST + PoC Verification)."""
    start_time = time.time()
    print_banner(console)

    console.print(f"[bold green]Starting Halo Hybrid Scan on:[/bold green] {repo}")
    if url:
        console.print(f"[cyan]Target Live URL:[/cyan] {url} (Safe Mode: {safe_mode})")
    if docker:
        console.print("[cyan]Docker Sandbox Mode:[/cyan] Enabled")

    # -------------------------------------------------------------------------
    # Stage 1: SAST - Route & Handler Discovery and CKG Construction
    # -------------------------------------------------------------------------
    console.print(
        "\n[bold cyan]Stage 1: Discovering Routes & Building Code Knowledge Graph...[/bold cyan]"
    )
    ckg, routes, _ = build_ckg_from_repo(repo)
    render_routes_table(routes, console=console)

    # -------------------------------------------------------------------------
    # Stage 2: Intent Ingestion, Pruning & Hypothesis Generation
    # -------------------------------------------------------------------------
    console.print(
        "\n[bold yellow]Stage 2: Mining Business Policies & Pruning Candidates...[/bold yellow]"
    )
    intent_extractor = IntentExtractor()
    policies = intent_extractor.extract_policies(repo, ckg=ckg)

    pruner = CandidatePruner()
    suspects = pruner.prune_candidates(ckg, policies=policies)
    render_candidates_table(suspects, console=console)

    governor = TokenGovernor(max_budget=token_budget)
    llm_provider = get_llm_provider(llm_provider_name, governor=governor)
    hypothesis_gen = HypothesisGenerator(llm_provider=llm_provider)
    model_name = getattr(llm_provider, "model", llm_provider_name)
    console.print(
        f"[bold yellow]Reasoning with LLM ({model_name}) across {len(suspects)} suspect candidates...[/bold yellow]"
    )
    hypotheses = []
    for idx, cand in enumerate(suspects, start=1):
        r_path = cand.route.path if cand.route else "endpoint"
        r_method = cand.route.method if cand.route else "ANY"
        console.print(
            f"  [dim]• [{idx}/{len(suspects)}][/dim] Analyzing [cyan]{r_method} {r_path}[/cyan]..."
        )
        hypo = hypothesis_gen.generate_hypothesis(candidate=cand, ckg=ckg, llm_provider=llm_provider)
        hypotheses.append(hypo)

    console.print(f"[bold green]✓ Generated {len(hypotheses)} probing hypotheses.[/bold green]")

    # -------------------------------------------------------------------------
    # Stage 3: DAST - Dynamic Active Verification
    # -------------------------------------------------------------------------
    verified_findings: list[FindingRecord] = []
    if url or docker:
        console.print("\n[bold blue]Stage 3: Running Autonomous DAST Probing...[/bold blue]")
        sandbox: SandboxManager | None = None
        target_url = url

        if docker:
            sandbox = SandboxManager(safe_mode=safe_mode)
            try:
                sandbox.boot_sandbox(repo)
                target_url = sandbox.container_url or f"http://localhost:{sandbox.default_port}"
            except Exception as e:  # noqa: BLE001
                console.print(f"[bold yellow]Warning:[/bold yellow] Sandbox boot failed: {e}")
                target_url = url or "http://localhost:8000"

        if not target_url:
            target_url = "http://localhost:8000"

        vault = SessionVault()
        try:
            vault.provision_personas(target_url, repo_path=repo)
        except Exception as e:  # noqa: BLE001
            logger.debug("Identity provisioning exception: %s", e)

        with httpx.Client(base_url=target_url, timeout=10.0) as client:
            try:
                verified_findings = _execute_dynamic_probes(
                    suspects=suspects,
                    target_url=target_url,
                    vault=vault,
                    client=client,
                    hypotheses=hypotheses,
                    safe_mode=safe_mode,
                )
            finally:
                if sandbox:
                    sandbox.cleanup()

    # -------------------------------------------------------------------------
    # Stage 4: PoC Builder, Remediation & Multi-format Reporting
    # -------------------------------------------------------------------------
    console.print(
        "\n[bold magenta]Stage 4: Generating PoCs, Remediations & Reports...[/bold magenta]"
    )
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    poc_builder = PoCBuilder()
    patcher = RemediationPatcher()

    for finding in verified_findings:
        # Generate standalone PEP 723 PoC
        poc_code = poc_builder.generate_pep723_script(finding)
        if verify_pocs and (url or (docker and target_url)):
            t_url = finding.target_url or target_url or url or ""
            repair_loop = PoCRepairLoop(llm_provider=llm_provider)
            _, poc_code = repair_loop.repair_and_verify(
                script_content=poc_code,
                target_url=t_url,
            )
        poc_filename = f"repro_{finding.id.lower().replace('-', '_')}.py"
        (out_path / poc_filename).write_text(poc_code, encoding="utf-8")

        # Generate AST remediation block
        orig_code = ""
        if finding.file_path and Path(finding.file_path).is_file():
            try:
                orig_code = Path(finding.file_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        patch_code = patcher.generate_role_aware_patch(
            finding=finding,
            handler_node=None,
            original_code=orig_code,
            llm_provider=llm_provider,
        )
        finding.remediation_patch = patch_code
        patch_filename = f"patch_{finding.id.lower().replace('-', '_')}.md"
        (out_path / patch_filename).write_text(patch_code, encoding="utf-8")

    # Multi-format report exports
    report_json_path = out_path / "halo_report.json"
    report_sarif_path = out_path / "halo_report.sarif"
    report_md_path = out_path / "halo_report.md"

    stats = governor.get_stats()
    duration = time.time() - start_time
    scan_meta = {
        "duration_seconds": round(duration, 2),
        "total_routes": len(routes),
        "total_candidates": len(suspects),
        "llm_provider": llm_provider_name,
        "llm_model": getattr(llm_provider, "model", llm_provider_name),
        "token_usage": stats.model_dump(),
    }

    ReportGenerator.export_json(verified_findings, report_json_path, metadata=scan_meta)
    ReportGenerator.export_sarif(verified_findings, report_sarif_path)
    ReportGenerator.export_markdown(verified_findings, report_md_path, metadata=scan_meta)

    render_findings_table(verified_findings, console=console)

    reports_map = {
        "JSON Report": str(report_json_path),
        "SARIF Report": str(report_sarif_path),
        "Markdown Executive Summary": str(report_md_path),
    }
    print_scan_summary(
        total_routes=len(routes),
        total_candidates=len(suspects),
        total_findings=len(verified_findings),
        duration_secs=duration,
        report_paths=reports_map,
        console=console,
        token_stats=stats,
    )


@app.command()
def sast(
    repo: str = typer.Option(..., "--repo", "-r", help="Path to repository to scan"),
    out: str = typer.Option("ckg.json", "--out", "-o", help="Output file for Code Knowledge Graph"),
) -> None:
    """Run static analysis, prune flaw candidates, and export Code Knowledge Graph (CKG)."""
    start_time = time.time()
    print_banner(console)
    console.print(f"[bold blue]Running Static Extraction on:[/bold blue] {repo}")

    # Discover and build CKG
    ckg, routes, _ = build_ckg_from_repo(repo)
    render_routes_table(routes, console=console)

    # Ingest documentation and policies
    extractor = IntentExtractor()
    policies = extractor.extract_policies(repo, ckg=ckg)

    # Prune candidates
    pruner = CandidatePruner()
    candidates = pruner.prune_candidates(ckg, policies=policies)
    render_candidates_table(candidates, console=console)

    # Export CKG Cytoscape JSON
    out_file = export_ckg_to_cytoscape_file(ckg, out)
    console.print(f"[bold green]CKG exported to:[/bold green] {out_file}")

    duration = time.time() - start_time
    print_scan_summary(
        total_routes=len(routes),
        total_candidates=len(candidates),
        total_findings=0,
        duration_secs=duration,
        report_paths={"CKG Knowledge Graph": str(out_file)},
        console=console,
    )


@app.command()
def dast(
    url: str = typer.Option(..., "--url", "-u", help="Target URL"),
    repo: str | None = typer.Option(
        None, "--repo", "-r", help="Optional path to repo for CKG-guided probing"
    ),
    safe_mode: bool = typer.Option(
        True,
        "--safe-mode/--force-destructive",
        help="Enforce read-only mutations on foreign entities",
    ),
    output_dir: str = typer.Option(
        ".", "--out", "--output-dir", "-o", help="Output directory for reports and PoCs"
    ),
    verify_pocs: bool = typer.Option(
        False,
        "--verify-pocs/--no-verify-pocs",
        help="Verify and repair generated PoCs against target URL",
    ),
) -> None:
    """Run autonomous DAST active verification against a live target."""
    start_time = time.time()
    print_banner(console)
    console.print(
        f"[bold yellow]Starting Autonomous DAST on:[/bold yellow] {url} (Safe Mode: {safe_mode})"
    )

    suspects: list[SuspectCandidate] = []
    if repo:
        console.print(f"[cyan]Using repository context from:[/cyan] {repo}")
        ckg, _, _ = build_ckg_from_repo(repo)
        pruner = CandidatePruner()
        suspects = pruner.prune_candidates(ckg)
    else:
        # Default probe candidates when scanning without repository source
        suspects = [
            SuspectCandidate(
                route=RouteNode(
                    id="r_admin",
                    method="GET",
                    path="/api/v1/admin/settings",
                    file_path="api.py",
                ),
                candidate_flaws=["BFLA"],
                reasoning="Administrative route potentially missing authorization guard",
            ),
            SuspectCandidate(
                route=RouteNode(
                    id="r_bola",
                    method="GET",
                    path="/api/v1/resources/{id}",
                    file_path="api.py",
                ),
                candidate_flaws=["BOLA"],
                reasoning="Resource route with ID parameter",
            ),
        ]

    vault = SessionVault()
    try:
        vault.provision_personas(url, repo_path=repo)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Identity provisioning exception: %s", exc)

    verified_findings: list[FindingRecord] = []
    with httpx.Client(base_url=url, timeout=10.0) as client:
        verified_findings = _execute_dynamic_probes(
            suspects=suspects,
            target_url=url,
            vault=vault,
            client=client,
            safe_mode=safe_mode,
        )

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    poc_builder = PoCBuilder()
    patcher = RemediationPatcher()
    for finding in verified_findings:
        poc_code = poc_builder.generate_pep723_script(finding)
        if verify_pocs and url:
            repair_loop = PoCRepairLoop()
            _, poc_code = repair_loop.repair_and_verify(
                script_content=poc_code,
                target_url=finding.target_url or url,
            )
        poc_filename = f"repro_{finding.id.lower().replace('-', '_')}.py"
        (out_path / poc_filename).write_text(poc_code, encoding="utf-8")

        patch_code = patcher.generate_role_aware_patch(
            finding=finding,
            handler_node=None,
            original_code="",
        )
        finding.remediation_patch = patch_code
        patch_filename = f"patch_{finding.id.lower().replace('-', '_')}.md"
        (out_path / patch_filename).write_text(patch_code, encoding="utf-8")

    report_json_path = out_path / "halo_report.json"
    report_sarif_path = out_path / "halo_report.sarif"
    report_md_path = out_path / "halo_report.md"

    ReportGenerator.export_json(verified_findings, report_json_path)
    ReportGenerator.export_sarif(verified_findings, report_sarif_path)
    ReportGenerator.export_markdown(verified_findings, report_md_path)

    render_findings_table(verified_findings, console=console)

    duration = time.time() - start_time
    reports_map = {
        "JSON Report": str(report_json_path),
        "SARIF Report": str(report_sarif_path),
        "Markdown Executive Summary": str(report_md_path),
    }
    print_scan_summary(
        total_routes=len(suspects),
        total_candidates=len(suspects),
        total_findings=len(verified_findings),
        duration_secs=duration,
        report_paths=reports_map,
        console=console,
    )


@app.command()
def daemon(
    host: str = typer.Option("127.0.0.1", "--host", help="Daemon host"),
    port: int = typer.Option(8787, "--port", help="Daemon port"),
    db: str | None = typer.Option(None, "--db", help="Path to SQLite database file"),
) -> None:
    """Start background Halo daemon service for CLI and future GUI integration."""
    print_banner(console)
    console.print(f"[bold magenta]Starting Halo Daemon on {host}:{port}[/bold magenta]")

    import uvicorn

    from halo.daemon.db import Database
    from halo.daemon.server import create_app

    database = Database(db) if db else Database()
    daemon_app = create_app(db=database)
    daemon_app.state.db = database

    uvicorn.run(daemon_app, host=host, port=port)


if __name__ == "__main__":
    app()
