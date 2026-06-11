"""Tests for MCPSafe CLI."""

from click.testing import CliRunner

from mcpsafe.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "PATH" in result.output
    assert "--format" in result.output
    assert "--min-severity" in result.output
    assert "--exclude" in result.output
    assert "--version" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output
