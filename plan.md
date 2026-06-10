# MCPSafe Implementation Plan

**Goal:** Build a CLI tool that scans MCP server source code for security vulnerabilities — tool poisoning, prompt injection via descriptions, data exfiltration patterns, and toxic tool call chains. Ships as a PyPI package with CI/CD integration.

**Architecture:** Python CLI using AST parsing + regex pattern matching. Two parsing strategies: decorator-based (`@mcp.tool()`) and explicit (`types.Tool()`). Rule-based detection engine with severity ratings. Output in text, JSON, and SARIF formats.

**Tech Stack:** Python 3.11+, Click, Rich, pytest, pyproject.toml, GitHub Actions

## Input Schema

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
1. TOOL_POISONING (CRITICAL) — prompt injection patterns
2. DATA_EXFILTRATION (HIGH) — hidden data sending
3. HIDDEN_BEHAVIOR (HIGH) — secret actions
4. BEHAVIORAL_MISMATCH (HIGH) — description contradicts purpose
5. EXTERNAL_URL (MEDIUM) — external URLs in descriptions
6. PARAMETER_SMUGGLING (MEDIUM) — hidden parameters

## Tasks

### Task 1: Project Scaffolding
- Create pyproject.toml, CLI skeleton, test infrastructure
- Verify: `pip install -e ".[dev]"` works, `mcpsafe --help` works, 2 tests pass

### Task 2: MCP Tool Parser
- Decorator pattern: `@mcp.tool()` / @app.tool()`, sync + async, no nested functions
- Explicit pattern: `types.Tool(name=..., description=...)`

### Task 3: Security Rule Engine
- 6 rule categories, regex-based pattern matching
- All tests pass

### Task 4: Output Formatters
- Text (emoji + file:line), JSON (structured), SARIF (CI/CD with rule metadata)

### Task 5: Wire CLI to Pipeline
- CLI → parser → rules → formatters
- Exit code 0 (clean), exit code 1 (CRITICAL/HIGH)
- Exclude patterns, symlink handling

### Task 6: GitHub Actions Integration
- action.yml with version-pinned install

### Task 7: README and Documentation
- Install, usage, severity table, exit codes, CI/CD example

### Task 8: End-to-End Verification
- Synthetic malicious server, verify detection, all tests pass

## Exit Codes
- 0: No findings above severity threshold
- 1: CRITICAL or HIGH findings detected
