"""Project HALO - Command Line Interface."""

import typer
from rich.console import Console

app = typer.Typer(
    name="halo",
    help="AI-Native Hybrid Application Security Testing for Business Logic Flaws.",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    repo: str = typer.Option(..., "--repo", "-r", help="Path to repository to scan"),
    url: str = typer.Option(None, "--url", "-u", help="Live target URL (e.g. http://localhost:3000)"),
    docker: bool = typer.Option(False, "--docker", "-d", help="Automatically manage Docker container lifecycle"),
    safe_mode: bool = typer.Option(True, "--safe-mode/--force-destructive", help="Enforce read-only mutations on foreign entities"),
):
    """Run full end-to-end hybrid security audit (SAST + DAST + PoC Verification)."""
    console.print(f"[bold green]Starting Halo Hybrid Scan on:[/bold green] {repo}")
    if url:
        console.print(f"[cyan]Target Live URL:[/cyan] {url} (Safe Mode: {safe_mode})")
    if docker:
        console.print("[cyan]Docker Sandbox Mode:[/cyan] Enabled")


@app.command()
def sast(
    repo: str = typer.Option(..., "--repo", "-r", help="Path to repository to scan"),
    out: str = typer.Option("ckg.json", "--out", "-o", help="Output file for Code Knowledge Graph"),
):
    """Run static analysis and export Code Knowledge Graph (CKG)."""
    console.print(f"[bold blue]Running Static Extraction on:[/bold blue] {repo}")


@app.command()
def dast(
    url: str = typer.Option(..., "--url", "-u", help="Target URL"),
    repo: str = typer.Option(None, "--repo", "-r", help="Optional path to repo for CKG-guided probing"),
):
    """Run autonomous DAST active verification against a live target."""
    console.print(f"[bold yellow]Starting Autonomous DAST on:[/bold yellow] {url}")


@app.command()
def daemon(
    host: str = typer.Option("127.0.0.1", "--host", help="Daemon host"),
    port: int = typer.Option(8787, "--port", help="Daemon port"),
):
    """Start background Halo daemon service for CLI and future GUI integration."""
    console.print(f"[bold magenta]Starting Halo Daemon on {host}:{port}[/bold magenta]")


if __name__ == "__main__":
    app()
