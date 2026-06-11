"""Output formatters — text, JSON, and SARIF output for scan findings."""

import json
from datetime import datetime, timezone

from mcpsafe.rules import RULES as ALL_RULES


# ---------------------------------------------------------------------------
# Severity ordering + emoji mapping
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

_SEVERITY_EMOJI = {
    "CRITICAL": "\U0001F534",  # 🔴
    "HIGH": "\U0001F7E0",      # 🟠
    "MEDIUM": "\U0001F7E1",    # 🟡
    "LOW": "\U0001F535",       # 🔵
}


# ---------------------------------------------------------------------------
# Text formatter
# ---------------------------------------------------------------------------


def format_text(findings: list[dict], server_name: str) -> str:
    """Format findings as human-readable text with emoji severity indicators."""
    lines = [f"MCPSafe Scan: {server_name}"]

    if not findings:
        lines.append("✅ No security issues found")
        return "\n".join(lines)

    # Group findings by severity in canonical order
    grouped: dict[str, list[dict]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        sev = f["severity"]
        if sev in grouped:
            grouped[sev].append(f)

    for severity in _SEVERITY_ORDER:
        group = grouped.get(severity, [])
        if not group:
            continue
        emoji = _SEVERITY_EMOJI.get(severity, "")
        lines.append(f"\n{emoji} {severity}")
        for f in group:
            lines.append(f"- [{f['category']}] {f['description']}")
            lines.append(f"  File: {f['file']}:{f['line']}")

    lines.append(f"\nTotal: {len(findings)} finding(s)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


def format_json(findings: list[dict], server_name: str) -> str:
    """Format findings as a JSON string."""
    output = {
        "server": server_name,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "findings_count": len(findings),
        "findings": findings,
    }
    return json.dumps(output, indent=2)


# ---------------------------------------------------------------------------
# SARIF formatter
# ---------------------------------------------------------------------------

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
    "/master/Schemata/sarif-schema-2.1.0.json"
)


def _build_sarif_rules() -> list[dict]:
    """Build SARIF rule metadata from ALL_RULES."""
    rules = []
    for rule in ALL_RULES:
        # Map severity to SARIF level
        if rule.severity == "CRITICAL":
            level = "error"
        elif rule.severity == "HIGH":
            level = "warning"
        elif rule.severity == "MEDIUM":
            level = "warning"
        else:
            level = "note"

        rules.append({
            "id": rule.rule_id,
            "name": rule.category,
            "shortDescription": {"text": f"{rule.category} detection rule"},
            "fullDescription": {
                "text": f"Detects {rule.category} patterns: {', '.join(rule.patterns[:2])}..."
            },
            "defaultConfiguration": {"level": level},
        })
    return rules


def _severity_to_sarif_level(severity: str) -> str:
    """Map internal severity to SARIF result level."""
    if severity == "CRITICAL":
        return "error"
    return "warning"


def format_sarif(findings: list[dict], server_name: str) -> str:
    """Format findings as a SARIF 2.1.0 JSON string."""
    results = []
    for f in findings:
        results.append({
            "ruleId": f["rule"],
            "level": _severity_to_sarif_level(f["severity"]),
            "message": {"text": f["description"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]},
                }
            }],
        })

    output = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MCPSafe",
                    "version": "0.1.0",
                    "rules": _build_sarif_rules(),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(output, indent=2)
