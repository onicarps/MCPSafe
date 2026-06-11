"""Security rule engine - 6 categories of detection rules.

Uses regex-based pattern matching against tool name + description.
"""

import re
from dataclasses import dataclass, field
from typing import List

from mcpsafe.parser import ToolDefinition


@dataclass
class Rule:
    """A single security detection rule."""

    rule_id: str
    category: str
    severity: str
    patterns: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

RULES: List[Rule] = [
    # 1. TOOL_POISONING (CRITICAL)
    Rule(
        rule_id="tool_poisoning_instructions",
        category="TOOL_POISONING",
        severity="CRITICAL",
        patterns=[
            r"ignore\s+(?:previous|prior|all)\s+(?:instructions|rules|commands|prompts)",
            r"you\s+are\s+now\s+in\s+(?:admin|developer|debug|root|system)\s+mode",
            r"override\s+(?:previous|prior|system)\s+(?:all\s+)?(?:instructions|rules|behavior)",
            r"disregard\s+(?:previous|prior|all)\s+(?:the\s+)?(?:instructions|rules|prompt|system)",
            r"new\s+instructions\s*:",
        ],
    ),
    # 2. HIDDEN_BEHAVIOR (HIGH)
    Rule(
        rule_id="hidden_behavior",
        category="HIDDEN_BEHAVIOR",
        severity="HIGH",
        patterns=[
            r"secretly\s+(?:send|copy|read|exfiltrate|embed|hide|bcc)",
            r"without\s+(?:notifying|informing)\s+(?:the\s+)?user",
            r"hidden\s+(?:instruction|directive|command|behavior|parameter)",
            r"(?:must\s+not|shouldn'?t|don'?t)\s+(?:know|notice|see|detect|be\s+aware)",
        ],
    ),
    # 3. DATA_EXFILTRATION (HIGH)
    Rule(
        rule_id="data_exfiltration",
        category="DATA_EXFILTRATION",
        severity="HIGH",
        patterns=[
            r"(?:send|exfiltrate|copy|upload|post|transmit)\s+(?:all|every|any)\s+(?:data|files|credentials|tokens|secrets)\s+(?:to|at)",
            r"(?:secretly|silently|covertly|hiddenly)\s+(?:send|copy|read|upload)",
        ],
    ),
    # 4. EXTERNAL_URL (MEDIUM)
    Rule(
        rule_id="external_url",
        category="EXTERNAL_URL",
        severity="MEDIUM",
        patterns=[
            r"https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)(?:[/:]|\Z))",
        ],
    ),
    # 5. BEHAVIORAL_MISMATCH (HIGH)
    Rule(
        rule_id="behavioral_mismatch",
        category="BEHAVIORAL_MISMATCH",
        severity="HIGH",
        patterns=[
            r"(?:secretly|silently|covertly|hiddenly)",
            r"(?:ignore|override|bypass)\s+(?:the\s+)?(?:user|their|them)",
        ],
    ),
    # 6. PARAMETER_SMUGGLING (MEDIUM)
    Rule(
        rule_id="parameter_smuggling",
        category="PARAMETER_SMUGGLING",
        severity="MEDIUM",
        patterns=[
            r"(?:hidden|secret|undocumented)\s+(?:parameter|field|input|argument)",
            r"also\s+(?:embed|include|add)\s+(?:in|to)\s+(?:response|output|metadata|header)",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Compiled regex cache
# ---------------------------------------------------------------------------

_compiled_rules: List = []


def _get_compiled_rules() -> List:
    """Lazily compile and cache all rule patterns."""
    if not _compiled_rules:
        for rule in RULES:
            compiled = [re.compile(p, re.IGNORECASE) for p in rule.patterns]
            _compiled_rules.append((rule, compiled))
    return _compiled_rules


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_tool(tool: ToolDefinition) -> List[dict]:
    """Scan a tool definition against all security rules.

    Returns a list of finding dicts with keys:
        severity, category, tool, description, file, line, rule
    One match per rule is enough (break after first match within a rule).
    """
    findings: List[dict] = []
    text_to_scan = f"{tool.name} {tool.description}"

    for rule, compiled_patterns in _get_compiled_rules():
        for pattern in compiled_patterns:
            if pattern.search(text_to_scan):
                findings.append({
                    "severity": rule.severity,
                    "category": rule.category,
                    "tool": tool.name,
                    "description": tool.description,
                    "file": tool.source_file,
                    "line": tool.line_number,
                    "rule": rule.rule_id,
                })
                break  # one match per rule is enough

    return findings
