"""Project HALO - Rich Terminal UI Components.

Provides styled ASCII banners, data tables, color-coded severity badges,
and formatted summary panels for CLI feedback.
"""

from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from halo.intent.pruner import SuspectCandidate
from halo.static.graph import RouteNode
from halo.validation.cvss import CVSSCalculator
from halo.validation.models import FindingData, FindingRecord

BANNER_ASCII = r"""
[bold cyan] _   _    _    _     ___  [/bold cyan]
[bold cyan]| | | |  / \  | |   / _ \ [/bold cyan]
[bold cyan]| |_| | / _ \ | |  | | | |[/bold cyan]
[bold cyan]|  _  |/ ___ \| |__| |_| |[/bold cyan]
[bold cyan]|_| |_/_/   \_\_____\___/ [/bold cyan]
"""

BRANDING_SUBTITLE = (
    "[bold white]Project HALO[/bold white] [dim]v0.1.0[/dim] - "
    "[italic green]AI-Native Hybrid Application Security Testing for Business Logic Flaws[/italic green]"
)

SEVERITY_BADGES: dict[str, str] = {
    "CRITICAL": "[bold red]🔴 CRITICAL[/bold red]",
    "HIGH": "[bold color(208)]🟠 HIGH[/bold color(208)]",
    "MEDIUM": "[bold yellow]🟡 MEDIUM[/bold yellow]",
    "LOW": "[bold blue]🔵 LOW[/bold blue]",
    "INFO": "[dim white]⚪ INFO[/dim white]",
}

METHOD_COLORS: dict[str, str] = {
    "GET": "bold green",
    "POST": "bold blue",
    "PUT": "bold yellow",
    "PATCH": "bold magenta",
    "DELETE": "bold red",
    "OPTIONS": "dim cyan",
    "HEAD": "dim green",
}


def print_banner(console: Console | None = None) -> None:
    """Display styled ASCII banner and version/branding."""
    con = console or Console()
    con.print(BANNER_ASCII)
    con.print(BRANDING_SUBTITLE)
    con.print()


def render_routes_table(
    routes: list[dict[str, Any] | RouteNode],
    console: Console | None = None,
) -> Table:
    """Render a Rich table showing method, endpoint, handler, and source location."""
    con = console or Console()
    table = Table(
        title="Discovered Routes & Handlers",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Method", style="bold", justify="center", no_wrap=True)
    table.add_column("Endpoint", style="bold white")
    table.add_column("Handler", style="magenta")
    table.add_column("Location", style="blue")

    if not routes:
        table.add_row("-", "[dim]No routes discovered[/dim]", "-", "-")
        con.print(table)
        return table

    for r in routes:
        if isinstance(r, RouteNode):
            method = r.method.upper()
            path = r.path
            handler = getattr(r, "handler_name", "-") or "-"
            loc = f"{r.file_path}:{r.line_number}" if r.file_path else "-"
        elif isinstance(r, dict):
            method = str(r.get("method", "GET")).upper()
            path = str(r.get("path") or r.get("endpoint") or "/")
            handler = str(r.get("handler") or r.get("handler_name") or "-")
            if r.get("location"):
                loc = str(r["location"])
            elif r.get("file_path"):
                loc = f"{r['file_path']}:{r.get('line_number', 1)}"
            else:
                loc = "-"
        else:
            method = getattr(r, "method", "GET")
            path = getattr(r, "path", "/")
            handler = getattr(r, "handler_name", "-")
            loc = f"{getattr(r, 'file_path', '')}:{getattr(r, 'line_number', 1)}"

        method_color = METHOD_COLORS.get(method, "white")
        styled_method = f"[{method_color}]{method}[/{method_color}]"

        table.add_row(styled_method, path, handler, loc)

    con.print(table)
    return table


def render_candidates_table(
    candidates: list[dict[str, Any] | SuspectCandidate],
    console: Console | None = None,
) -> Table:
    """Render a Rich table showing suspect candidate flaws, endpoint, and pruning reasoning."""
    con = console or Console()
    table = Table(
        title="Suspect Flaw Candidates (Pruned & Prioritized)",
        box=box.ROUNDED,
        header_style="bold yellow",
    )
    table.add_column("Flaw Type", style="bold red", no_wrap=True)
    table.add_column("Endpoint", style="bold cyan")
    table.add_column("Pruning Reasoning", style="white")

    if not candidates:
        table.add_row("-", "[green]All routes verified safe / pruned[/green]", "-")
        con.print(table)
        return table

    for c in candidates:
        if isinstance(c, SuspectCandidate):
            flaws_str = ", ".join(c.candidate_flaws) if c.candidate_flaws else "UNKNOWN"
            route_str = f"{c.route.method} {c.route.path}" if c.route else "-"
            reasoning = c.reasoning or "-"
        elif isinstance(c, dict):
            raw_flaws = c.get("candidate_flaws") or c.get("flaw_type") or "UNKNOWN"
            flaws_str = ", ".join(raw_flaws) if isinstance(raw_flaws, list) else str(raw_flaws)
            if c.get("endpoint"):
                route_str = str(c["endpoint"])
            elif isinstance(c.get("route"), dict):
                r_dict = c["route"]
                route_str = f"{r_dict.get('method', '')} {r_dict.get('path', '')}".strip()
            elif isinstance(c.get("route"), RouteNode):
                route_str = f"{c['route'].method} {c['route'].path}"
            else:
                route_str = "-"
            reasoning = str(c.get("reasoning", "-"))
        else:
            flaws_str = str(getattr(c, "candidate_flaws", "UNKNOWN"))
            route_str = str(getattr(c, "endpoint", "-"))
            reasoning = str(getattr(c, "reasoning", "-"))

        table.add_row(flaws_str, route_str, reasoning)

    con.print(table)
    return table


def render_findings_table(
    findings: list[FindingRecord | dict[str, Any]],
    console: Console | None = None,
) -> Table:
    """Render a Rich table with color-coded severity badges (🔴, 🟠, 🟡, 🔵), flaw type, endpoint, CVSS, and source location."""
    con = console or Console()
    table = Table(
        title="Project HALO - Verified Vulnerability Findings",
        box=box.ROUNDED,
        header_style="bold magenta",
    )
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Flaw Type", style="bold")
    table.add_column("CVSS", justify="right", style="bold yellow")
    table.add_column("Endpoint", style="green")
    table.add_column("Location", style="blue")

    if not findings:
        table.add_row(
            "-", "[green]CLEAN[/green]", "None", "0.0", "-", "No vulnerabilities detected"
        )
        con.print(table)
        return table

    calc = CVSSCalculator()

    for f in findings:
        if isinstance(f, (FindingRecord, FindingData)):
            f_id = f.id
            sev_key = f.severity.upper()
            flaw_type = f.flaw_type or f.rule_id or "UNKNOWN"
            endpoint = f"{f.method} {f.endpoint}".strip() if f.endpoint else "-"
            loc = f"{f.file_path}:{f.line_start}" if f.file_path else "-"
            score = getattr(f, "cvss_score", None)
            if score is None:
                is_write = (f.method or "GET").upper() in {"POST", "PUT", "PATCH", "DELETE"}
                calc_score, _, _ = calc.calculate_for_finding(
                    flaw_type=flaw_type, is_write=is_write
                )
                score = calc_score
        elif isinstance(f, dict):
            f_id = str(f.get("id", "HALO-FINDING"))
            sev_key = str(f.get("severity", "HIGH")).upper()
            flaw_type = str(f.get("flaw_type") or f.get("rule_id") or "UNKNOWN")
            method = str(f.get("method", "GET")).upper()
            ep = str(f.get("endpoint", ""))
            endpoint = f"{method} {ep}".strip() if ep else "-"
            if f.get("location"):
                loc = str(f["location"])
            elif f.get("file_path"):
                loc = f"{f['file_path']}:{f.get('line_start', f.get('line_number', 1))}"
            else:
                loc = "-"
            score = f.get("cvss_score")
            if score is None:
                is_write = method in {"POST", "PUT", "PATCH", "DELETE"}
                calc_score, _, _ = calc.calculate_for_finding(
                    flaw_type=flaw_type, is_write=is_write
                )
                score = calc_score
        else:
            f_id = str(getattr(f, "id", "HALO-FINDING"))
            sev_key = str(getattr(f, "severity", "HIGH")).upper()
            flaw_type = str(getattr(f, "flaw_type", "UNKNOWN"))
            endpoint = str(getattr(f, "endpoint", "-"))
            loc = str(getattr(f, "file_path", "-"))
            score = getattr(f, "cvss_score", 7.5)

        badge = SEVERITY_BADGES.get(sev_key, f"[white]{sev_key}[/white]")
        table.add_row(
            f_id,
            badge,
            flaw_type,
            f"{float(score):.1f}",
            endpoint,
            loc,
        )

    con.print(table)
    return table


def print_scan_summary(
    total_routes: int,
    total_candidates: int,
    total_findings: int,
    duration_secs: float,
    report_paths: dict[str, str] | None = None,
    console: Console | None = None,
    token_stats: Any = None,
) -> Panel:
    """Format and display a structured summary panel."""
    con = console or Console()

    lines: list[str] = [
        f"[bold]Total Routes Discovered:[/bold]      [cyan]{total_routes}[/cyan]",
        f"[bold]Suspect Flaw Candidates:[/bold]      [yellow]{total_candidates}[/yellow]",
        f"[bold]Verified Vulnerabilities:[/bold]    [red]{total_findings}[/red]",
        f"[bold]Scan Duration:[/bold]               [white]{duration_secs:.2f}s[/white]",
    ]

    if token_stats is not None:
        consumed = getattr(token_stats, "total_tokens", None)
        if consumed is None and isinstance(token_stats, dict):
            consumed = token_stats.get("total_tokens", 0)
            reqs = token_stats.get("request_count", 0)
            in_tok = token_stats.get("total_input_tokens", 0)
            out_tok = token_stats.get("total_output_tokens", 0)
        else:
            reqs = getattr(token_stats, "request_count", 0)
            in_tok = getattr(token_stats, "total_input_tokens", 0)
            out_tok = getattr(token_stats, "total_output_tokens", 0)
            consumed = consumed or 0

        lines.append(f"[bold]LLM API Invocations:[/bold]      [cyan]{reqs}[/cyan]")
        lines.append(f"[bold]Tokens Consumed:[/bold]           [magenta]{consumed:,} tokens[/magenta] (in: {in_tok:,}, out: {out_tok:,})")

    if report_paths:
        lines.append("")
        lines.append("[bold underline]Generated Artifacts & Reports:[/bold underline]")
        for label, path in report_paths.items():
            lines.append(f"  • [bold]{label}:[/bold] [green]{path}[/green]")

    content = "\n".join(lines)
    panel = Panel(
        content,
        title="[bold green]Scan Summary[/bold green]",
        box=box.ROUNDED,
        expand=False,
    )
    con.print(panel)
    return panel
