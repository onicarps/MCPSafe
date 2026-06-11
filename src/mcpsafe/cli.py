"""Click CLI entry point for MCPSafe."""

from pathlib import Path

import click

from mcpsafe import __version__
from mcpsafe.formatters import format_json, format_sarif, format_text
from mcpsafe.parser import scan_directory
from mcpsafe.rules import scan_tool

FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


@click.command()
@click.argument("path", required=False)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    help="Output format.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    default="LOW",
    help="Minimum severity to report.",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Glob pattern(s) to exclude.",
)
@click.version_option(version=__version__, prog_name="mcpsafe")
@click.pass_context
def main(ctx, path, fmt, min_severity, exclude):
    """Scan MCP server source code for security vulnerabilities."""
    if path is None:
        raise click.UsageError("PATH is required.")

    path_obj = Path(path)
    if not path_obj.exists():
        raise click.BadParameter(f"Path does not exist: {path}")

    if not exclude:
        exclude = ("node_modules/*", ".git/*", "__pycache__/*", "*.egg-info/*")

    tools = scan_directory(path, exclude=exclude)

    all_findings = []
    for tool in tools:
        all_findings.extend(scan_tool(tool))

    # Filter by min_severity
    min_level = SEVERITY_ORDER[min_severity]
    filtered = [
        f for f in all_findings
        if SEVERITY_ORDER.get(f["severity"], 99) <= min_level
    ]

    server_name = path_obj.name or str(path_obj.resolve())

    formatter = FORMATTERS[fmt]
    output = formatter(filtered, server_name)
    click.echo(output)

    # Exit 1 if any filtered finding is CRITICAL or HIGH
    if any(f["severity"] in ("CRITICAL", "HIGH") for f in filtered):
        ctx.exit(1)
