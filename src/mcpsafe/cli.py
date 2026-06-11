"""Click CLI entry point for MCPSafe."""

import click

from mcpsafe import __version__


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
def main(path, fmt, min_severity, exclude):
    """Scan MCP server source code for security vulnerabilities."""
    if path is None:
        raise click.UsageError("PATH is required.")
    click.echo(f"Scanning {path}...")
