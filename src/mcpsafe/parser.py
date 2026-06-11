"""MCP tool definition parser — AST + regex strategies.

Two parsing strategies:
1. Decorator-based: @mcp.tool() / @app.tool() decorated functions
2. Explicit: types.Tool(name=..., description=...) calls
"""

import ast
import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class ToolDefinition:
    """Represents a parsed MCP tool definition."""

    name: str
    description: str
    parameters: List[str]
    source_file: str
    source_type: str  # "decorator" | "explicit"
    line_number: int


# ---------------------------------------------------------------------------
# Decorator-based parsing (AST)
# ---------------------------------------------------------------------------

# Decorator names we recognise as MCP tool decorators
_TOOL_DECORATOR_NAMES = {"tool"}
_TOOL_DECORATOR_ATTRS = {"mcp.tool", "app.tool", "server.tool", "mcp_server.tool"}


def _is_tool_decorator(node: ast.expr) -> bool:
    """Check if an AST decorator node is an MCP tool decorator."""
    # Plain name: @tool or @tool()
    if isinstance(node, ast.Name) and node.id in _TOOL_DECORATOR_NAMES:
        return True
    # Attribute: @mcp.tool or @mcp.tool()
    if isinstance(node, ast.Attribute) and node.attr == "tool":
        return True
    # Call: @mcp.tool() or @app.tool() — unwrap to check the func
    if isinstance(node, ast.Call):
        return _is_tool_decorator(node.func)
    return False


def _has_tool_decorator(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if any decorator on the function is a tool decorator."""
    for dec in func_node.decorator_list:
        if _is_tool_decorator(dec):
            return True
    return False


def _extract_parameters(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> List[str]:
    """Extract argument names from a function definition (skip 'self', 'cls')."""
    params = []
    for arg in func_node.args.args:
        if arg.arg not in ("self", "cls"):
            params.append(arg.arg)
    return params


def _extract_description(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Extract the docstring from a function definition."""
    return ast.get_docstring(func_node) or ""


def _parse_decorator_tools(source: str, source_file: str) -> List[ToolDefinition]:
    """Parse decorator-based tool definitions from source code."""
    tree = ast.parse(source)
    tools: List[ToolDefinition] = []

    # Only iterate top-level statements
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _has_tool_decorator(node):
                tools.append(
                    ToolDefinition(
                        name=node.name,
                        description=_extract_description(node),
                        parameters=_extract_parameters(node),
                        source_file=source_file,
                        source_type="decorator",
                        line_number=node.lineno,
                    )
                )

    return tools


# ---------------------------------------------------------------------------
# Explicit types.Tool() parsing (regex with balanced parens)
# ---------------------------------------------------------------------------

# Regex to find types.Tool( or similar explicit Tool() calls
# We look for patterns like: types.Tool( ... ) or Tool( ... )
_EXPLICIT_TOOL_RE = re.compile(
    r"\b(?:types\.Tool|Tool)\s*\(",
)


def _extract_balanced_parens(source: str, start: int) -> Optional[str]:
    """Extract content inside balanced parentheses starting at position `start`.

    `start` should point to the opening '(' character.
    Returns the content between the parens (exclusive), or None if unbalanced.
    """
    if start >= len(source) or source[start] != "(":
        return None

    depth = 0
    i = start
    while i < len(source):
        ch = source[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return source[start + 1 : i]
        elif ch in ('"', "'"):
            # Skip string literals to avoid counting parens inside strings
            quote = ch
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == quote:
                    break
                i += 1
        i += 1
    return None


def _extract_keyword_string(content: str, key: str) -> Optional[str]:
    """Extract a string value for a keyword argument like name="foo"."""
    # Match key="value" or key='value'
    pattern = re.compile(rf'\b{key}\s*=\s*([\'"])(.*?)\1')
    m = pattern.search(content)
    if m:
        return m.group(2)
    return None


def _extract_keyword_list(content: str, key: str) -> Optional[List[str]]:
    """Extract a list value for a keyword argument like parameters=["a", "b"]."""
    pattern = re.compile(rf'\b{key}\s*=\s*\[(.*?)\]')
    m = pattern.search(content)
    if m:
        inner = m.group(1)
        # Extract all string items
        items = re.findall(r'[\'"]([^\'"]+)[\'"]', inner)
        return items
    return None


def _parse_explicit_tools(source: str, source_file: str) -> List[ToolDefinition]:
    """Parse explicit types.Tool() definitions from source code using regex."""
    tools: List[ToolDefinition] = []

    for m in _EXPLICIT_TOOL_RE.finditer(source):
        # Find the opening paren position
        paren_start = source.index("(", m.start())
        content = _extract_balanced_parens(source, paren_start)
        if content is None:
            continue

        name = _extract_keyword_string(content, "name")
        description = _extract_keyword_string(content, "description")
        parameters = _extract_keyword_list(content, "parameters")

        if name:
            # Compute line number
            line_number = source[: m.start()].count("\n") + 1
            tools.append(
                ToolDefinition(
                    name=name,
                    description=description or "",
                    parameters=parameters or [],
                    source_file=source_file,
                    source_type="explicit",
                    line_number=line_number,
                )
            )

    return tools


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_file(file_path: str | Path) -> List[ToolDefinition]:
    """Parse a single Python file for MCP tool definitions.

    Returns a list of ToolDefinition objects found in the file.
    Skips symlinked files (returns empty list).
    """
    file_path = Path(file_path)

    # Skip symlinks
    if file_path.is_symlink():
        return []

    source = file_path.read_text(encoding="utf-8", errors="replace")
    source_file = str(file_path)

    tools = []
    tools.extend(_parse_decorator_tools(source, source_file))
    tools.extend(_parse_explicit_tools(source, source_file))
    return tools


def _glob_matches(path: str, patterns: List[str]) -> bool:
    """Check if a path matches any of the given glob patterns."""
    name = os.path.basename(path)
    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path, pattern):
            return True
    return False


def scan_directory(
    directory: str | Path,
    exclude: Optional[List[str]] = None,
) -> List[ToolDefinition]:
    """Walk a directory, find .py files, and parse each for tool definitions.

    Skips symlinked files and files matching any exclude glob patterns.
    """
    if exclude is None:
        exclude = []

    directory = Path(directory)
    tools: List[ToolDefinition] = []

    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if not fname.endswith(".py"):
                continue

            full_path = Path(root) / fname

            # Skip symlinks
            if full_path.is_symlink():
                continue

            # Check exclude patterns
            if _glob_matches(str(full_path), exclude):
                continue

            tools.extend(parse_file(full_path))

    return tools


def parse_directory(directory: str | Path) -> List[ToolDefinition]:
    """Alias for scan_directory with no exclude patterns."""
    return scan_directory(directory)
