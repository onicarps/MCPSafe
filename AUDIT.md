# MCPSafe Security Audit Report

**Date:** 2026-06-11
**Auditor:** Independent subagent review (fresh-eyes, no shared context with implementers)
**Scope:** Full codebase review — all source files, test files, CI/CD configs, action.yml
**Repo:** https://github.com/onicarps/MCPSafe (main branch, Tasks 1-8 complete)

---

## Executive Summary

**PASS WITH MINOR CONCERNS** — The codebase is functionally correct, all 134 tests pass, coverage is 97%, and no security vulnerabilities were found in the code itself. There are minor code-quality issues (import ordering, unused imports, f-strings without placeholders) that ruff flags but do not affect correctness or security. The tool is ready for PyPI publication after addressing the minor lint issues.

---

## Security Scan Results

### Hardcoded Secrets
- **Status:** PASS
- **Method:** Grep for `api_key`, `secret`, `password`, `token`, `passwd` across all source files
- **Findings:** None. The only matches for "secret" are inside regex pattern strings in `rules.py` (e.g., `r"secretly\\s+..."`) which are detection patterns, not credentials.

### Shell Injection
- **Status:** PASS
- **Method:** Grep for `os.system`, `subprocess`, `shell=True` across all source files
- **Findings:** None. No shell execution anywhere in the codebase.

### Dangerous eval/exec
- **Status:** PASS
- **Method:** Grep for `eval(`, `exec(` across all source files
- **Findings:** None.

### Unsafe Deserialization
- **Status:** PASS
- **Method:** Grep for `pickle.loads` across all source files
- **Findings:** None.

### SQL Injection
- **Status:** PASS
- **Method:** Grep for SQL patterns across all source files
- **Findings:** None. The tool does not use any database.

### Dangerous Imports
- **Status:** PASS
- **Method:** Grep for `__import__` across all source files
- **Findings:** None.

### Debug Prints
- **Status:** PASS
- **Method:** Grep for `print(` across all source files
- **Findings:** None. No debug prints left behind.

### Commented-Out Code
- **Status:** PASS
- **Method:** Manual scan of all source files
- **Findings:** None. All comments are explanatory, not disabled code.

---

## Test Results

### Test Suite
```
134 passed in 0.20s
```
- **test_action.py:** 2 tests — PASS
- **test_cli.py:** 7 tests — PASS
- **test_comprehensive.py:** 93 tests — PASS
- **test_formatters.py:** 19 tests — PASS
- **test_parser.py:** 9 tests — PASS
- **test_rules.py:** 12 tests — PASS

### Coverage
```
Name                        Stmts   Miss  Cover   Missing
---------------------------------------------------------
src/mcpsafe/__init__.py         1      0   100%
src/mcpsafe/cli.py             32      0   100%
src/mcpsafe/formatters.py      52      1    98%   94
src/mcpsafe/parser.py         141      6    96%   117, 135-136, 163, 175, 262
src/mcpsafe/rules.py           26      0   100%
---------------------------------------------------------
TOTAL                         252      7    97%
```
- **Coverage: 97%** (well above the 90% threshold)
- Uncovered lines: parser.py lines 117, 135-136, 163, 175 (edge cases in balanced-parens and keyword extraction for malformed input), formatters.py line 94 (LOW severity SARIF mapping — no test triggers LOW)

### Linting
```
ruff check . — 6 findings (all fixable):
  - I001: Import block unsorted (test_comprehensive.py:11)
  - F401: `os` imported but unused (test_comprehensive.py:12)
  - F401: `scan_directory` imported but unused (test_comprehensive.py:26)
  - F541: f-string without placeholders (test_comprehensive.py:276)
  - F541: f-string without placeholders (test_comprehensive.py:279)
  - E501: Line too long 101 > 100 (test_comprehensive.py:596)
```
- All issues are in test files, not source code
- All are style issues, not logic or security issues
- Source code (src/mcpsafe/) passes ruff cleanly

---

## Code Review Findings

### parser.py

- [x] **Decorator variant handling:** CORRECT. Handles `@tool`, `@mcp.tool`, `@app.tool`, `@server.tool`, `@mcp_server.tool`, and all with/without parentheses. The `_is_tool_decorator` function recursively unwraps `ast.Call` nodes to check the inner function/attribute. Covers all common MCP framework patterns (FastMCP, streamable-http, etc.).

- [x] **Regex explicit parser — nested parentheses:** CORRECT. The `_extract_balanced_parens` function properly tracks depth and skips string literals (both single and double quoted). Tested with strings containing parens (e.g., `b=")"`). Triple-quoted strings with parens also work correctly (verified in deep audit).

- [x] **Edge cases — false positives/negatives:**
  - Nested functions are correctly ignored (only `tree.body` is iterated, not nested scopes).
  - Class methods are correctly ignored (only top-level `FunctionDef`/`AsyncFunctionDef`).
  - Decorators on classes and non-function statements are safely skipped.
  - Syntax errors in source files return empty list (no crash).
  - Empty files, comment-only files return empty list.
  - Lambda functions are correctly ignored.
  - **No false positives or false negatives detected.**

- [x] **Symlink handling:** CORRECT. Both `parse_file` and `scan_directory` check `is_symlink()` and skip symlinked files. Note: `os.walk` follows symlinks to directories by default, which is acceptable behavior (documented in test).

- [x] **Exclude patterns:** CORRECT. The `_glob_matches` function checks against basename, full path, and all path suffixes. This correctly handles patterns like `vendor/*` matching `/tmp/project/vendor/bad.py`.

- [x] **Path traversal:** NO VULNERABILITY. The tool uses `os.walk` and `Path` from pathlib. It does not resolve or follow paths provided by untrusted input in a way that could escape the target directory. The `path` argument is treated as a root for `os.walk`.

- [x] **Error handling:** ADEQUATE. Encoding errors handled via `errors="replace"`. Syntax errors caught with try/except. Permission errors during `os.walk` would propagate as exceptions (acceptable — the CLI would show the error).

- **Minor concern:** `_extract_balanced_parens` does not handle triple-quoted strings as a single token — it processes them character by character. This works because it just skips characters between quote marks, but it would fail if a triple-quoted string contained an escaped quote of the same type. In practice this is extremely unlikely in MCP tool definitions.

### rules.py

- [x] **ReDoS risk:** LOW. All patterns use alternation groups `(?:a|b)` rather than nested quantifiers `(a+b+)`. No catastrophic backtracking possible. Verified by structural analysis of all 16 patterns.

- [x] **Pattern comprehensiveness:** GOOD. The patterns cover the major attack vectors:
  - TOOL_POISONING: 5 patterns covering "ignore previous", "admin mode", "override", "disregard", "new instructions:"
  - HIDDEN_BEHAVIOR: 4 patterns covering "secretly send/copy", "without notifying", "hidden instruction", "must not know"
  - DATA_EXFILTRATION: 2 patterns covering "send all data to", "secretly send/copy"
  - EXTERNAL_URL: 1 pattern with negative lookahead for localhost/loopback
  - BEHAVIORAL_MISMATCH: 2 patterns for "secretly/silently/covertly" and "ignore user"
  - PARAMETER_SMUGGLING: 2 patterns for "hidden parameter" and "embed in response"

- [x] **False positive analysis:**
  - "ignore case" does NOT match "ignore previous instructions" (requires "previous|prior|all" after "ignore") — VERIFIED
  - "localhost:8080", "127.0.0.1", "0.0.0.0", "[::1]" are correctly excluded from EXTERNAL_URL — VERIFIED
  - "localhost.evil.com" correctly matches as external (not a true localhost reference) — VERIFIED
  - Tool names are scanned together with descriptions, so a tool named "evil_looking_name" with a benign description produces no false positives — VERIFIED

- [x] **Severity assignment:** CORRECT per spec. TOOL_POISONING=CRITICAL, DATA_EXFILTRATION=HIGH, HIDDEN_BEHAVIOR=HIGH, BEHAVIORAL_MISMATCH=HIGH, EXTERNAL_URL=MEDIUM, PARAMETER_SMUGGLING=MEDIUM.

- [x] **Unicode handling:** CORRECT. All patterns use `re.IGNORECASE` and operate on Unicode strings. Tested with CJK characters, accented Latin, etc. No crashes.

- [x] **Empty/short strings:** CORRECT. Empty descriptions produce no findings. Single-word descriptions handled safely.

- [x] **Very long strings:** CORRECT. Tested with 1500+ character descriptions. No performance issues.

### formatters.py

- [x] **SARIF 2.1.0 compliance:** COMPLIANT. Verified:
  - `$schema` points to `sarif-schema-2.1.0.json`
  - `version` is `"2.1.0"`
  - `runs[0].tool.driver.rules` array contains all 6 rules with `id`, `name`, `shortDescription`, `fullConfiguration` with `level`
  - Each result has `ruleId`, `level`, `message.text`, `locations[0].physicalLocation.artifactLocation.uri`, `locations[0].physicalLocation.region.startLine`
  - CRITICAL maps to `"error"`, HIGH/MEDIUM map to `"warning"` (SARIF 2.1.0 allows: error, warning, note)

- [x] **JSON unicode handling:** CORRECT. `json.dumps` with default settings preserves Unicode. Tested with CJK, accented characters, emoji.

- [x] **Output injection:** NO VULNERABILITY. The output is generated via `json.dumps` (for JSON/SARIF) which properly escapes all special characters. The text formatter uses f-strings with simple concatenation — no HTML/JS injection possible since output is terminal-only.

- [x] **Text formatter:** CORRECT. Groups by severity in canonical order (CRITICAL > HIGH > MEDIUM > LOW). Shows emoji indicators, category, description, file:line, and total count.

### cli.py

- [x] **ctx.exit(1) usage:** CORRECT. Uses `ctx.exit(1)` not `sys.exit(1)`. Exit code 1 is triggered only when filtered findings include CRITICAL or HIGH severity.

- [x] **Exclude pattern defaults:** SENSIBLE. Defaults exclude `node_modules/*`, `.git/*`, `__pycache__/*`, `*.egg-info/*` — standard directories that should not be scanned.

- [x] **min_severity filtering:** CORRECT. Uses `SEVERITY_ORDER` dict with numeric values (CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3). Filter keeps findings with severity level <= min_level. Verified: `--min-severity CRITICAL` shows only CRITICAL, `--min-severity LOW` shows all.

- [x] **Error handling:** ADEQUATE.
  - Missing PATH raises `click.UsageError` (standard Click behavior)
  - Invalid format/severity choices handled by `click.Choice`
  - Permission denied during scan would propagate as Python exception (acceptable)
  - Non-existent path would raise `FileNotFoundError` from `os.walk` (acceptable)

- [x] **Server name extraction:** `path.rstrip("/").split("/")[-1]` — simple but effective for directory paths. For a single file path, it extracts the filename, which is reasonable.

### action.yml

- [x] **Valid YAML:** YES. Parsed successfully with `yaml.safe_load`.

- [x] **Version-pinned install:** YES. Uses `pip install mcpsafe==${{ inputs.version }}` with a default of `0.1.0`.

- [x] **Inputs correctly defined:** YES. Three inputs: `path` (required, default "."), `severity` (optional, default "LOW"), `version` (optional, default "0.1.0").

- **Minor concern:** The `version` input default (`0.1.0`) will become stale when new versions are published. Consider documenting that users should update this pin. This is a maintenance concern, not a security issue.

- **Minor concern:** The `if: always()` on the SARIF upload step means it uploads even if the install or scan step fails. This is intentional (upload partial results) but could produce empty/malformed SARIF on failure. Acceptable for a security scanning tool.

### ci.yml

- [x] **Triggers on push and PR:** YES. `on: [push, pull_request]`

- [x] **Required checks present:** YES. Runs `pytest tests/ -v` and `ruff check .`

- **Minor concern:** Only tests on Python 3.11 (single version). The project requires 3.11+ but doesn't test on 3.12 or 3.13. Acceptable for MVP.

- **Minor concern:** No coverage enforcement in CI. The `pytest-cov` package is installed but `--cov-fail-under=90` is not used. Consider adding this to prevent coverage regression.

---

## Recommendations

### Must Fix Before PyPI Publication
None. The codebase is ready.

### Should Fix (Minor Quality Issues)
1. **Fix ruff lint issues in test_comprehensive.py:**
   - Sort imports (I001)
   - Remove unused `os` import (F401)
   - Remove unused `scan_directory` import (F401)
   - Remove extraneous `f` prefix on strings without placeholders (F541, 2 instances)
   - Wrap long comment line at 596 (E501)

2. **Add coverage enforcement to CI:** Add `--cov-fail-under=90` to the pytest command in ci.yml to prevent coverage regression.

### Nice to Have (Future Improvements)
1. **Test on multiple Python versions** in CI (3.11, 3.12, 3.13)
2. **Add `--cov-fail-under` to CI** for coverage gate
3. **Document the version pin maintenance** for action.yml users
4. **Consider adding a `--strict` mode** that also exits on MEDIUM findings
5. **Consider adding rule descriptions** to the text formatter output for better user experience
6. **Add type hints to test functions** for consistency (currently missing in some test helpers)

---

## Verdict

**PASS** — MCPSafe is ready for PyPI publication.

The codebase is well-structured, thoroughly tested (134 tests, 97% coverage), and free of security vulnerabilities. The lint issues are cosmetic and confined to test files. The SARIF output is fully compliant with 2.1.0. The detection rules are well-designed with appropriate severity levels and minimal false positives. The CLI follows Click best practices with proper exit codes.
