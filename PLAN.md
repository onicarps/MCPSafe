# MCPCheck Implementation Plan

> **For Hermes:** Dispatch each task via `delegate_task` subagents + Factory Droid (`droid exec`). Follow strict TDD: write failing test first, watch it fail, implement minimal code, watch it pass, commit. Use `ctx.exit(1)` not `sys.exit(1)`.

**Goal:** Build mcpcheck — CLI tool that scans MCP server source code for security vulnerabilities. Ships as PyPI package `mcp-scan-safe` with CI/CD integration.

**Architecture:** Python CLI using AST parsing + regex. Two parsing strategies: decorator-based (`@mcp.tool()`) and explicit (`types.Tool()`). Rule-based detection engine. Output in text, JSON, SARIF formats.

**Tech Stack:** Python 3.11+, Click, Rich, pytest, pyproject.toml, GitHub Actions

**Spike Results:** ALL PASS (3/3) — parsing, detection, CLI ergonomics validated.

**Package:** `mcp-scan-safe` on PyPI, CLI command: `mcpcheck`

---

## File Organization

```
workspace/
  pyproject.toml
  README.md
  action.yml
  AGENTS.md
  src/mcpsafe/
    __init__.py          # version only: __version__ = "0.1.0"
    cli.py               # Click CLI entry point (command: mcpcheck)
    parser.py            # MCP tool definition parser (AST + regex)
    rules.py             # Security rule engine (6 categories)
    formatters.py        # Output formatters: text, json, sarif
  tests/
    conftest.py
    fixtures/            # Synthetic MCP servers for testing
    test_cli.py
    test_parser.py
    test_rules.py
    test_formatters.py
    test_action.py
  .github/
    workflows/
      ci.yml
```

---

## Data Models

```python
@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: list[str]
    source_file: str
    source_type: str       # "decorator" | "explicit"
    line_number: int
```

## Detection Rules (6 categories)

| Rule ID | Category | Severity | Patterns |
|---------|----------|----------|----------|
| tool_poisoning_instructions | TOOL_POISONING | CRITICAL | "ignore previous instructions", "you are now in admin mode", "override previous", "disregard", "new instructions:" |
| hidden_behavior | HIDDEN_BEHAVIOR | HIGH | "secretly send/copy/read", "without notifying", "hidden instruction/directive", "must not know/notice" |
| data_exfiltration | DATA_EXFILTRATION | HIGH | "send all data to", "exfiltrate", "secretly send/copy" |
| external_url | EXTERNAL_URL | MEDIUM | Any external URL (excluding localhost/127.0.0.1) |
| behavioral_mismatch | BEHAVIORAL_MISMATCH | HIGH | "secretly send/copy/read", "silently", "covertly", "ignore the user" |
| parameter_smuggling | PARAMETER_SMUGGLING | MEDIUM | "hidden/secret parameter", "embed in response/output" |

## CLI Interface

```
mcpcheck PATH [--format text|json|sarif] [--min-severity CRITICAL|HIGH|MEDIUM|LOW] [--exclude GLOB...] [--version]
```

Exit codes: 0 = clean, 1 = CRITICAL/HIGH findings detected

## Build Rules
1. TDD — write failing test first, watch it fail, implement, watch it pass
2. Type hints everywhere, dataclasses for data models
3. AST parsing via `ast` module (not just regex)
4. Handle both sync and async tool defs
5. Top-level functions only (no nested)
6. SARIF output must include `driver.rules` array with all rule metadata
7. `ctx.exit(1)` not `sys.exit(1)` in Click
8. No hardcoded secrets
9. 90%+ test coverage
