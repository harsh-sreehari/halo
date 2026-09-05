"""Unit test for Halo CLI initialization."""

from typer.testing import CliRunner

from halo.cli.main import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AI-Native Hybrid Application Security Testing" in result.output
