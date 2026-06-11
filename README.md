# MCPCheck 🔒

[![PyPI version](https://img.shields.io/pypi/v/mcp-scan-safe)](https://pypi.org/project/mcp-scan-safe/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-brightgreen.svg)](https://python.org)

**MCP supply chain security scanner.** Detect tool poisoning, prompt injection, data exfiltration, and other attacks in MCP server definitions.

## Installation

```bash
pip install mcp-scan-safe
```

## Usage

### Basic scan

```bash
mcpcheck ./my-mcp-server
```

### JSON output

```bash
mcpcheck ./my-mcp-server --format json
```

### SARIF for CI/CD

```bash
mcpcheck ./my-mcp-server --format sarif > results.sarif
```

### Severity filter

```bash
mcpcheck ./my-mcp-server --min-severity HIGH
```

### Exclude patterns

```bash
mcpcheck ./my-mcp-server --exclude "vendor/*" --exclude "node_modules/*"
```

## Detected Vulnerabilities

| Rule ID | Category | Severity | Description |
|---------|----------|----------|-------------|
| `tool_poisoning_instructions` | TOOL_POISONING | CRITICAL | Detects prompt injection patterns such as "ignore previous instructions", "you are now in admin mode", "override previous", "disregard", and "new instructions:" in tool names and descriptions. |
| `hidden_behavior` | HIDDEN_BEHAVIOR | HIGH | Detects hidden actions and concealed behaviors like "secretly send/copy/read", "without notifying the user", hidden instructions/directives, and directives that the user must not notice. |
| `data_exfiltration` | DATA_EXFILTRATION | HIGH | Detects hidden data sending patterns such as "send all data to", "exfiltrate", and covert data exfiltration in tool descriptions. |
| `behavioral_mismatch` | BEHAVIORAL_MISMATCH | HIGH | Detects when tool descriptions contradict their stated purpose — e.g. tools described as benign but containing keywords like "secretly", "silently", "covertly", or "ignore the user". |
| `external_url` | EXTERNAL_URL | MEDIUM | Flags any external URL in tool descriptions (excluding localhost/127.0.0.1) that could indicate callback or data exfiltration endpoints. |
| `parameter_smuggling` | PARAMETER_SMUGGLING | MEDIUM | Detects hidden or undocumented parameters and attempts to embed secret data in responses or metadata. |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no CRITICAL or HIGH findings detected |
| `1` | One or more CRITICAL or HIGH findings were detected |

## CI/CD Integration

MCPCheck includes a GitHub Action (`action.yml`) for seamless CI/CD integration. It
runs a scan, uploads results as a SARIF artifact, and integrates with GitHub Code
Scanning.

```yaml
name: MCPCheck Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  mcpcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run MCPCheck
        uses: onicarps/mcpcheck@main
        with:
          path: "."
          severity: "LOW"
          version: "0.1.0"

      # The action automatically uploads SARIF results to GitHub Code Scanning.
      # Findings will appear under the "Security" tab in your repository.
```

You can also invoke MCPCheck directly in any CI pipeline:

```bash
pip install mcp-scan-safe
mcpcheck ./my-mcp-server --format sarif > results.sarif
```

## License

MIT
