# MCPSafe — Project Spec

## Goal
MCP supply chain security scanner. CLI tool that scans MCP server Python source files
for security vulnerabilities: tool poisoning, prompt injection, data exfiltration.

## Tech Stack
- Python 3.11+
- click (CLI framework)
- rich (terminal output)
- pytest (testing)
- pyproject.toml (setuptools build)

## Project Structure
```
src/mcpsafe/
  __init__.py     # Version only
  cli.py          # Click CLI entry point
  parser.py       # MCP tool definition parser (AST + regex)
  rules.py        # Security rule engine
  formatters.py   # Output formatters (text, json, sarif)
tests/
  conftest.py
  test_cli.py
  test_parser.py
  test_rules.py
  test_formatters.py
  test_action.py
pyproject.toml
action.yml
README.md
```

## Conventions
- TDD: write failing test → implement → verify pass → commit
- Each task = one commit
- Use dataclasses for data models
- Use `ast` module for Python source parsing (not just regex)
- Handle both sync and async function definitions
- Only parse top-level functions (not nested)
- SARIF output must include rule metadata in `driver.rules`
- Exit code 1 for CRITICAL/HIGH findings, 0 otherwise
- Use `ctx.exit(1)` not `sys.exit(1)` in Click commands

## Detection Rules (6 categories)
1. TOOL_POISONING (CRITICAL) — prompt injection patterns in descriptions
2. DATA_EXFILTRATION (HIGH) — hidden data sending
3. HIDDEN_BEHAVIOR (HIGH) — secret actions, concealed from user
4. BEHAVIORAL_MISMATCH (HIGH) — description contradicts tool purpose
5. EXTERNAL_URL (MEDIUM) — any external URL in tool descriptions
6. PARAMETER_SMUGGLING (MEDIUM) — hidden parameters

## Output Formats
- text (default): human-readable with emoji severity indicators
- json: machine-parseable
- sarif: GitHub Code Scanning compatible (with rule metadata)

## CLI Interface
```
mcpsafe PATH [--format text|json|sarif] [--min-severity CRITICAL|HIGH|MEDIUM|LOW]
            [--exclude GLOB...] [--version]
```

## Testing
- pytest with CliRunner for CLI tests
- Synthetic test servers in tmpdir for e2e tests
- Each module has its own test file
- 90%+ coverage target

## Git
- Repo: https://github.com/onicarps/MCPSafe
- Branch naming: mcpsafe/ONI-XX-description
- Linear project: MCPSafe (ONI), issues ONI-84 to ONI-109
