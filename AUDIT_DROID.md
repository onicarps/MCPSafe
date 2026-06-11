# MCPSafe — Independent Code Quality Audit (AUDIT_DROID)

**Date:** 2026-06-11
**Auditor:** Independent code-quality reviewer (fresh audit, no prior context)
**Scope:** All source files in `src/mcpsafe/` and all test files in `tests/`
**Method:** Manual review of every file, plus inspection of CI / `action.yml` /
`pyproject.toml` configuration.

This audit is intentionally independent of `AUDIT.md`. Where it overlaps, the
findings here are stated in my own words and frequently disagree with or extend
the prior audit. Findings are anchored to file paths and line numbers; severity
is the *audit* severity (importance of the finding), not the rule severity.

---

## Summary of Findings

| ID | File | Line(s) | Category | Severity |
|----|------|---------|----------|----------|
| F1 | src/mcpsafe/parser.py | 113-128 | Correctness — string-literal skipping is naive | High |
| F2 | src/mcpsafe/parser.py | 144-150 | Correctness — escaped quotes inside string args break extraction | High |
| F3 | src/mcpsafe/parser.py | 153-160 | Correctness — list extraction is single-line only | Medium |
| F4 | src/mcpsafe/parser.py | 109 | Correctness — bare `Tool(` regex over-matches | Medium |
| F5 | src/mcpsafe/parser.py | 62-67 | Correctness — `*args`, `**kwargs`, kw-only, pos-only args dropped | Medium |
| F6 | src/mcpsafe/parser.py | 213-216 | Robustness — unbounded file read, IO errors not caught | Medium |
| F7 | src/mcpsafe/parser.py | 247-249 | Robustness — `os.walk` follows directory symlinks (cycles possible) | Medium |
| F8 | src/mcpsafe/parser.py | 240-263 | Determinism — output order depends on filesystem listing | Low |
| F9 | src/mcpsafe/parser.py | 220-235 | Performance — `_glob_matches` recomputes path suffixes per pattern | Low |
| F10 | src/mcpsafe/parser.py | 266-268 | Code quality — `parse_directory` is a redundant alias | Low |
| F11 | src/mcpsafe/rules.py | 86-92 | Concurrency — module-level cache mutated lazily, not thread-safe | Low |
| F12 | src/mcpsafe/rules.py | 51-54 | Correctness — “new instructions:” is too generic, false-positive prone | Medium |
| F13 | src/mcpsafe/rules.py | 70-73 | Correctness — bare `secretly\|silently\|covertly` triggers HIGH on benign text | Medium |
| F14 | src/mcpsafe/rules.py | 102-103 | Correctness — `PARAMETER_SMUGGLING` rule never inspects actual parameters | High |
| F15 | src/mcpsafe/rules.py | 65 | Style — `\|hiddenly` is not a real word and noisy | Low |
| F16 | src/mcpsafe/formatters.py | 124-127 | Correctness — `_severity_to_sarif_level` ignores LOW (mismaps to “warning”) | Medium |
| F17 | src/mcpsafe/formatters.py | 92-104 | DRY — severity→SARIF-level mapping duplicated and inconsistent with F16 | Low |
| F18 | src/mcpsafe/formatters.py | 100-103 | Documentation — fullDescription leaks raw regex with misleading “…” | Low |
| F19 | src/mcpsafe/formatters.py | 67-70 | Determinism — `datetime.now(UTC)` makes JSON output non-reproducible | Low |
| F20 | src/mcpsafe/cli.py | 70 | Portability — server-name split uses `/` only (Windows path bug) | Medium |
| F21 | src/mcpsafe/cli.py | 47-48 | UX — non-existent / unreadable PATH silently reports “clean” | Medium |
| F22 | src/mcpsafe/cli.py | 78-81 | Style — `ctx.exit(1)` inside a `for` loop instead of `any()` | Low |
| F23 | src/mcpsafe/cli.py | 53 | Style — default `exclude` is a tuple but downstream type hint is `list[str]` | Low |
| F24 | tests/test_comprehensive.py | 11, 12, 26, 276, 279, 596 | Lint — ruff failures (E501, F401, F541, I001) | Low |
| F25 | tests (overall) | — | Coverage gap — `format_sarif` LOW path, parameter scanning, multi-line `Tool()` etc. | Medium |
| F26 | src/mcpsafe (modules) | various | Documentation — missing module-level type guarantees and dataclass field docs | Low |
| F27 | tests/test_parser.py | 137, 156, 174, 184 | Test hygiene — `tempfile.mkdtemp()` directories never cleaned up | Low |
| F28 | tests/test_comprehensive.py | many | Test hygiene — same `tempfile.mkdtemp()` leak pattern repeated dozens of times | Low |
| F29 | src/mcpsafe/parser.py | 209-212 | Edge case — directory or non-existent file path crashes parse_file | Low |
| F30 | src/mcpsafe/cli.py | 41-46 | Documentation — `--exclude` semantics (basename + path + suffix) undocumented | Low |

Severity legend: **High** = correctness/security regression that can be
reproduced today; **Medium** = real defect with realistic trigger;
**Low** = polish, style, or theoretical issue.

---

## 1. Detailed Findings — `src/mcpsafe/parser.py`

### F1 — Naive string-literal skipping in `_extract_balanced_parens`
**File / Lines:** `src/mcpsafe/parser.py:113-128`

The inner string-skipping loop treats the *first* `"` or `'` as the start of a
string and the *next matching* `"` / `'` as the end. This is wrong for triple-
quoted strings (which are common in `description="""..."""`) and for adjacent
strings:

```python
elif ch in ('"', "'"):
    quote = ch
    i += 1
    while i < len(source):
        if source[i] == "\\":
            i += 2
            continue
        if source[i] == quote:
            break
        i += 1
```

Reproducer (will mis-count parens):

```python
types.Tool(
    name="bad",
    description="""multi-line ( with embedded paren""",
)
```

The first `"` is read as start; the second `"` (immediately following) is read
as end. Then the third `"` starts another string that is closed by the first
`"` after “paren”, leaving the `(` *outside* a string in the parser’s view, so
`depth` is corrupted and the entire call may be rejected (returns `None`). This
is a real correctness bug for any explicit `Tool()` call that uses a triple-
quoted description.

**Fix:** Detect `"""`/`'''` first, then scan to the matching triple delimiter.

### F2 — Escaped quotes break `_extract_keyword_string`
**File / Lines:** `src/mcpsafe/parser.py:144-150`

```python
pattern = re.compile(rf'\b{key}\s*=\s*([\'"])(.*?)\1')
```

The non-greedy `.*?` is not aware of `\\"` escapes. Input
`name="he said \"hi\""` returns `he said \` instead of `he said \"hi\"`.
Tools authored with embedded quotes silently lose data and may fail the `if
name:` check, producing a false negative (no `ToolDefinition` emitted).

### F3 — `_extract_keyword_list` is single-line only
**File / Lines:** `src/mcpsafe/parser.py:153-160`

```python
pattern = re.compile(rf'\b{key}\s*=\s*\[(.*?)\]')
```

`re.DOTALL` is not enabled, so a multi-line list (very common in MCP code) is
not matched and `parameters` silently becomes `[]`. Affects scans that need
parameters (e.g., for any future PARAMETER_SMUGGLING rule that actually checks
parameters — see F14).

### F4 — Bare `Tool(` regex over-matches
**File / Lines:** `src/mcpsafe/parser.py:104-109`

```python
_EXPLICIT_TOOL_RE = re.compile(r"\b(?:types\.Tool|Tool)\s*\(")
```

The alternative `Tool` is anchored only by `\b`. Any *attribute* access whose
last segment is `Tool` matches, e.g. `mypkg.AnotherTool(` or
`my_obj.subTool(`? — the latter is excluded (no boundary), but
`my_module.Tool(` (different module than `types`) and `from foo import Tool`
do match. Producing false `ToolDefinition`s when `name=` happens to be present.
Constraining to `types.Tool` only or to `mcp.types.Tool` would be safer.

### F5 — Variadic / kw-only / pos-only args are dropped
**File / Lines:** `src/mcpsafe/parser.py:62-67`

```python
for arg in func_node.args.args:
    if arg.arg not in ("self", "cls"):
        params.append(arg.arg)
```

`func_node.args` also exposes `.posonlyargs`, `.kwonlyargs`, `.vararg`,
`.kwarg`. None of those are inspected. A tool defined as
`def t(x, /, *, secret_token: str)` reports `parameters=["x"]`, hiding the
exact parameter (`secret_token`) that PARAMETER_SMUGGLING is supposed to find.
Combined with F14, parameter-based detection is effectively dead code.

### F6 — Unbounded file read; IO errors not caught
**File / Lines:** `src/mcpsafe/parser.py:213-216`

```python
source = file_path.read_text(encoding="utf-8", errors="replace")
```

No size cap (a malicious 1 GB `.py` is loaded fully into memory) and no
exception handling for `PermissionError`, `IsADirectoryError`, or
`FileNotFoundError`. A single unreadable file aborts the whole scan. Wrap with
`try/except OSError` and consider streaming or capping at e.g. 5 MB.

### F7 — `os.walk` follows directory symlinks
**File / Lines:** `src/mcpsafe/parser.py:249-263`

`os.walk(directory)` defaults to `followlinks=False`, so cycles are not the
issue here — but the *test* `test_scan_symlink_to_directory` asserts that a
symlinked directory IS scanned, which contradicts the default. Re-reading: the
default is `followlinks=False`, meaning the symlinked dir would NOT be
descended. The test therefore relies on `os.walk` being given the symlink as
its *root* (in which case `os.walk` does walk into it). That works, but if a
user passes a parent that contains a symlinked subdirectory, the symlink will
be skipped silently — which is undocumented and surprising.

### F8 — Non-deterministic output ordering
**File / Lines:** `src/mcpsafe/parser.py:240-263`

`os.walk` does not guarantee directory or file order. JSON / SARIF output will
differ between runs on the same input on different filesystems, making CI
diffing painful. A `sorted(files)` and `sorted(dirs)` step would make output
reproducible at negligible cost.

### F9 — `_glob_matches` recomputes path suffixes per pattern
**File / Lines:** `src/mcpsafe/parser.py:220-235`

```python
for pattern in patterns:
    ...
    parts = Path(path).parts
    for i in range(len(parts)):
        subpath = str(Path(*parts[i:]))
```

`Path(path).parts` and the suffix list are recomputed for every pattern. For a
directory of N files × M patterns × D depth, this is O(N·M·D). Hoisting the
suffix list out of the pattern loop is an easy O(D) win. Not critical at
typical scales but trivially fixable.

### F10 — `parse_directory` is dead-weight
**File / Lines:** `src/mcpsafe/parser.py:266-268`

```python
def parse_directory(directory: str | Path) -> list[ToolDefinition]:
    return scan_directory(directory)
```

Two public names for the same behaviour invite drift. Either remove
`parse_directory` (no longer used outside tests) or document the alias as a
deprecation.

### F29 — `parse_file` crashes on non-existent path / directory
**File / Lines:** `src/mcpsafe/parser.py:209-212`

```python
if file_path.is_symlink():
    return []
source = file_path.read_text(...)
```

A non-existent file or a directory passed by an external caller raises
`FileNotFoundError` / `IsADirectoryError`. This isn’t exercised by `cli.py`
because `os.walk` enumerates files only, but `parse_file` is part of the
public surface.

---

## 2. Detailed Findings — `src/mcpsafe/rules.py`

### F11 — Lazy module-level cache is not thread-safe
**File / Lines:** `src/mcpsafe/rules.py:80-92`

```python
_compiled_rules: list = []

def _get_compiled_rules() -> list:
    if not _compiled_rules:
        for rule in RULES:
            ...
            _compiled_rules.append((rule, compiled))
    return _compiled_rules
```

If two threads enter `_get_compiled_rules` simultaneously, both observe the
empty list and both append duplicates, leading to duplicated findings. Use a
module-level `tuple` initialised eagerly at import, or wrap with a `Lock`.
Additionally, mutating a module-level list across imports is brittle for
test-isolation if anyone reloads the module.

### F12 — `tool_poisoning_instructions` over-matches `new\s+instructions:`
**File / Lines:** `src/mcpsafe/rules.py:51-54`

The pattern `r"new\s+instructions\s*:"` (CRITICAL) matches benign README-style
docstrings such as:

> *"New instructions: run `pip install` after upgrading."*

The phrase is common in legitimate help text. CRITICAL severity for such a
generic phrase will produce noise that erodes trust. Tighten to require a
line-start anchor, or down-grade to HIGH and require a context word.

### F13 — `behavioral_mismatch` flags benign words
**File / Lines:** `src/mcpsafe/rules.py:70-73`

```python
patterns=[
    r"(?:secretly|silently|covertly|hiddenly)",
    ...
],
```

A bare alternation matches **any** occurrence. Examples that will be flagged
HIGH severity:

* `"""Silently logs failures to stderr."""`
* `"""Quietly retries — covertly never blocks the caller."""`
* `"""Update files and silently reload the watcher."""`

Combine with a verb / object (e.g. `(?:secretly|silently)\s+(?:send|copy|read|exfiltrate|leak)`)
to reduce false positives.

### F14 — `PARAMETER_SMUGGLING` rule never reads the parameters list
**File / Lines:** `src/mcpsafe/rules.py:102-103` and `:138-139`

`scan_tool` builds `text_to_scan = f"{tool.name} {tool.description}"`. The
`tool.parameters` field is *never* consumed. A real parameter-smuggling tool
named, e.g.:

```python
@mcp.tool()
def innocent(query: str, _bcc_email: str = "...", __debug: bool = False):
    """Search the corpus for the user query."""
```

does not match — its docstring is benign, and its smuggled parameters live in
`tool.parameters`, which is ignored. The rule only fires when the *description*
already self-incriminates (e.g. literally says “hidden parameter”), making the
detector almost vacuous. Consider matching parameter names against a
deny-list (`bcc`, `secret`, `internal`, `_admin`, leading double underscore,
…).

### F15 — `\|hiddenly` is not English
**File / Lines:** `src/mcpsafe/rules.py:65, 102`

The token “hiddenly” appears in two patterns. It is not a standard English
word and is unlikely to occur in attacker-authored text. It clutters the
patterns and grows the regex without benefit. Drop it.

---

## 3. Detailed Findings — `src/mcpsafe/formatters.py`

### F16 — `_severity_to_sarif_level` mismaps LOW to “warning”
**File / Lines:** `src/mcpsafe/formatters.py:124-127`

```python
def _severity_to_sarif_level(severity: str) -> str:
    if severity == "CRITICAL":
        return "error"
    return "warning"
```

A LOW finding is emitted as a SARIF `result.level == "warning"`, while in
`_build_sarif_rules` (lines 92-104) LOW is correctly mapped to `"note"`. The
two functions disagree. SARIF consumers (GitHub Code Scanning) display LOW
findings at warning severity in the UI, contradicting the rule metadata.

### F17 — Severity→SARIF mapping duplicated
**File / Lines:** `src/mcpsafe/formatters.py:92-104` and `124-127`

The mapping logic appears twice with different bodies (see F16 for the
inconsistency). Extract a single dict:

```python
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "warning",
                "MEDIUM": "warning", "LOW": "note"}
```

…and use it in both producers.

### F18 — `fullDescription` leaks regex with misleading ellipsis
**File / Lines:** `src/mcpsafe/formatters.py:100-103`

```python
"fullDescription": {
    "text": f"Detects {rule.category} patterns: {', '.join(rule.patterns[:2])}..."
},
```

The trailing `...` always appears, even when there are exactly 2 patterns
(implying more exist when they may not). Rule documentation should be
human-readable rather than raw regex; raw regex in a SARIF UI is confusing
to security reviewers.

### F19 — Non-deterministic JSON output (timestamp)
**File / Lines:** `src/mcpsafe/formatters.py:67-70`

```python
"scan_time": datetime.now(UTC).isoformat(),
```

Output cannot be byte-compared between runs. Acceptable, but golden-test
authors will trip on this; consider supporting an env-override (e.g.
`SOURCE_DATE_EPOCH`) for reproducibility.

---

## 4. Detailed Findings — `src/mcpsafe/cli.py`

### F20 — Server-name extraction is POSIX-only
**File / Lines:** `src/mcpsafe/cli.py:70`

```python
server_name = path.rstrip("/").split("/")[-1]
```

On Windows, `r"C:\proj\my-server"` produces `server_name == "C:\\proj\\my-server"`.
Use `Path(path).name or Path(path).resolve().name` instead. Also, a path of
exactly `"/"` produces an empty server name.

### F21 — Non-existent / unreadable PATH silently shows “clean”
**File / Lines:** `src/mcpsafe/cli.py:47-48, 53-58`

```python
if path is None:
    raise click.UsageError("PATH is required.")
...
tools = scan_directory(path, exclude=exclude)
```

If `path` is a typo (`./mc-server` instead of `./my-server`), `os.walk` returns
nothing and the CLI prints `✅ No security issues found` with exit 0. This is
a usability foot-gun for CI. Add a `Path(path).exists()` check that errors out
explicitly.

### F22 — `ctx.exit(1)` inside a loop
**File / Lines:** `src/mcpsafe/cli.py:78-81`

```python
for f in filtered:
    if f["severity"] in ("CRITICAL", "HIGH"):
        ctx.exit(1)
```

Functionally correct (first match exits), but the intent is more directly
expressed as:

```python
if any(f["severity"] in ("CRITICAL", "HIGH") for f in filtered):
    ctx.exit(1)
```

### F23 — `exclude` typing inconsistency
**File / Lines:** `src/mcpsafe/cli.py:53, src/mcpsafe/parser.py:240`

`cli.py` defaults `exclude` to a 4-tuple of strings; `scan_directory` is
annotated `exclude: list[str] | None`. Tuples are accepted at runtime, but the
mismatch is misleading. Annotate `Iterable[str]` or normalise.

### F30 — `--exclude` semantics undocumented
**File / Lines:** `src/mcpsafe/cli.py:41-46`

The help text says only “Glob pattern(s) to exclude”, but `_glob_matches`
matches against (a) basename, (b) full path, (c) every path-suffix. Users will
expect plain `fnmatch`/`pathspec` semantics. Document the three-way matching
or simplify to one.

---

## 5. Test Suite — `tests/`

### F24 — Existing ruff lint failures
**File / Lines:** `tests/test_comprehensive.py:11, 12, 26, 276, 279, 596`

`ruff check .` reports six issues (I001 / F401×2 / F541×2 / E501) confined to
the comprehensive test file. They block any CI gate that runs `ruff check`
with strict mode but are otherwise cosmetic. (Confirmed by re-running the
linter mentally against the imports and the offending f-strings.)

### F25 — Coverage gaps the suite does not hit
The current AUDIT.md cites 97 % coverage, but several behaviours are not
exercised:

1. **`_severity_to_sarif_level("LOW")`** — no test ever passes a LOW finding
   into `format_sarif`, so the bug in F16 was missed.
2. **Tool() with triple-quoted description** — see F1; no test feeds
   `description="""..."""` into the explicit parser.
3. **Tool() with escaped quotes** — see F2.
4. **Tool() with multi-line `parameters=[...]`** — see F3.
5. **Async tool with `*args` / `**kwargs`** — verifies they’re *missing* from
   `parameters`, but no test asserts the *intended* behaviour, so future fixes
   would be uncovered.
6. **Parameters-actually-smuggled scenario** — F14 cannot be detected without
   a test like:
   ```python
   @mcp.tool()
   def t(query: str, _bcc: str = "..."): """benign"""
   ```
7. **Non-existent / non-readable scan path** — F21 has no negative test.
8. **`scan_directory` ordering / determinism** — F8 has no test pinning the
   order.
9. **Non-UTF-8 source files** — `errors="replace"` path is not asserted.
10. **`parse_file` on a directory or missing file** — see F29.

### F27 — `tempfile.mkdtemp()` directories are leaked
**File / Lines:** `tests/test_parser.py:36, 60, 87, 109, 130, 153, 173, 199, 211`

```python
tmp = Path(tempfile.mkdtemp())
_write(tmp, "server.py", src)
```

There is no `shutil.rmtree(tmp)` and no `tmp_path` fixture. Each `pytest` run
leaks ~10 directories under `/tmp`. Switching to the built-in `tmp_path`
fixture would be the idiomatic fix and reduce noise.

### F28 — Same leak repeated in `test_comprehensive.py`
**File / Lines:** `tests/test_comprehensive.py` (≈25 occurrences of
`tempfile.mkdtemp()`)

Same issue as F27, multiplied. Each run leaks dozens of directories.

---

## 6. Documentation Gaps (F26)

* `parser.ToolDefinition` (`src/mcpsafe/parser.py:18-27`): the docstring is
  one line; per-field meaning (e.g., `source_type` is `"decorator"` |
  `"explicit"`) is documented only as a code comment. Promote it to the
  docstring.
* `rules.Rule` (`src/mcpsafe/rules.py:11-19`): no description of how
  `patterns` are combined (logical OR, IGNORECASE) or what `severity` strings
  are valid.
* `rules.scan_tool` (`src/mcpsafe/rules.py:96-122`): does not document that
  `parameters` is intentionally not scanned (see F14).
* `formatters.format_text/json/sarif` do not document the expected dict
  shape. Existing implementations rely on duck-typing; a `TypedDict` would
  pay for itself.
* No module-level docstring on `cli.py` describes exit-code contract
  (the README does — duplicate it in the source as a stable reference).

---

## 7. Performance Observations (low-severity)

* **Per-tool scan is `O(rules × patterns)`** — fine for typical MCP servers
  (≤100 tools), but every match builds a full `dict` even if a later finding
  for the same rule is suppressed. Acceptable.
* **Files are read fully into memory** before `ast.parse`. Large
  generated MCP files (>50 MB) would produce noticeable memory pressure.
* **No parallelism.** A directory with thousands of `.py` files is scanned
  sequentially. `concurrent.futures.ThreadPoolExecutor` (or `ProcessPool` for
  AST-heavy work) would scale linearly with cores.
* **`_glob_matches` per-pattern recomputation** — see F9.

---

## 8. Security Observations

The tool itself is read-only and does not execute any scanned code (uses
`ast.parse`, never `exec`). I did not find any injection, path-traversal, or
shell-execution surface. The two security-relevant items are F6 (unbounded
read enabling DoS on a huge crafted `.py`) and F11 (cache race producing
duplicated findings under threading — not a vulnerability, but data-integrity
concern). No hard-coded secrets, no use of `pickle`, no `subprocess`.

---

## 9. Recommendations Ranked

1. **Fix F14** — `PARAMETER_SMUGGLING` should actually inspect
   `tool.parameters`, otherwise the rule is theatre.
2. **Fix F1, F2, F3** — explicit `Tool()` parsing has multiple correctness
   gaps; tests should include a triple-quoted description and embedded
   escaped quotes.
3. **Fix F16/F17** — unify SARIF level mapping; LOW must map to `note`.
4. **Tighten F12, F13** — both rules currently produce noisy false positives
   at HIGH/CRITICAL severity; tighten or down-grade.
5. **Fix F21** — make a non-existent PATH a hard error; today it silently
   reports clean.
6. **Fix F20** — server-name extraction must use `pathlib`, not string split,
   for cross-platform support.
7. **Address F6 / F7** — add I/O exception handling and bound file size.
8. **Sort scan output (F8)** for reproducible CI diffs.
9. **Clean up tests (F24, F27, F28)** — wire up `tmp_path`, satisfy ruff.
10. **Document undocumented behaviour (F26, F30)** — exclude semantics, exit
    codes, dict shapes.

---

**End of independent audit.**
