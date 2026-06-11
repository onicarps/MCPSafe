"""Tests for MCPSafe MCP tool definition parser."""

import tempfile
from pathlib import Path

import pytest

from mcpsafe.parser import parse_directory, parse_file, scan_directory

# ---------------------------------------------------------------------------
# Helpers: write temp .py files
# ---------------------------------------------------------------------------

def _write(tmpdir: Path, name: str, content: str) -> Path:
    p = tmpdir / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Decorator pattern — sync
# ---------------------------------------------------------------------------

def test_sync_decorator_tool():
    src = '''
import mcp

@mcp.tool()
def my_tool(x: int, y: str) -> str:
    """My tool description."""
    return f"{x} {y}"
'''
    tmp = Path(tempfile.mkdtemp())
    _write(tmp, "server.py", src)
    tools = parse_file(tmp / "server.py")
    assert len(tools) == 1
    t = tools[0]
    assert t.name == "my_tool"
    assert t.description == "My tool description."
    assert t.parameters == ["x", "y"]
    assert t.source_type == "decorator"
    assert t.source_file == str(tmp / "server.py")
    assert t.line_number == 5


# ---------------------------------------------------------------------------
# Decorator pattern — async
# ---------------------------------------------------------------------------

def test_async_decorator_tool():
    src = '''
from mcp import Server

app = Server("test")

@app.tool()
async def async_tool(query: str, limit: int = 10):
    """Async tool description."""
    pass
'''
    tmp = Path(tempfile.mkdtemp())
    _write(tmp, "server.py", src)
    tools = parse_file(tmp / "server.py")
    assert len(tools) == 1
    t = tools[0]
    assert t.name == "async_tool"
    assert t.description == "Async tool description."
    assert t.parameters == ["query", "limit"]
    assert t.source_type == "decorator"
    assert t.line_number == 7


# ---------------------------------------------------------------------------
# Mixed sync + async
# ---------------------------------------------------------------------------

def test_mixed_sync_and_async():
    src = '''
import mcp

@mcp.tool()
def sync_one(a: int):
    """Sync one."""
    pass

@mcp.tool()
async def async_one(b: str):
    """Async one."""
    pass

@mcp.tool()
def sync_two(c: float, d: bool):
    """Sync two."""
    pass
'''
    tmp = Path(tempfile.mkdtemp())
    _write(tmp, "server.py", src)
    tools = parse_file(tmp / "server.py")
    assert len(tools) == 3
    names = [t.name for t in tools]
    assert names == ["sync_one", "async_one", "sync_two"]
    for t in tools:
        assert t.source_type == "decorator"


# ---------------------------------------------------------------------------
# No tools in file
# ---------------------------------------------------------------------------

def test_no_tools():
    src = '''
def helper(x):
    return x + 1

class Foo:
    pass
'''
    tmp = Path(tempfile.mkdtemp())
    _write(tmp, "utils.py", src)
    tools = parse_file(tmp / "utils.py")
    assert tools == []


# ---------------------------------------------------------------------------
# Nested functions ignored
# ---------------------------------------------------------------------------

def test_nested_functions_ignored():
    src = '''
import mcp

@mcp.tool()
def outer():
    """Outer tool."""
    @mcp.tool()
    def inner():
        """Inner tool."""
        pass
    pass
'''
    tmp = Path(tempfile.mkdtemp())
    _write(tmp, "server.py", src)
    tools = parse_file(tmp / "server.py")
    assert len(tools) == 1
    assert tools[0].name == "outer"


# ---------------------------------------------------------------------------
# Explicit types.Tool() pattern
# ---------------------------------------------------------------------------

def test_explicit_tool_pattern():
    src = '''
import types

tool = types.Tool(
    name="explicit_tool",
    description="An explicit tool.",
    parameters=["param1", "param2"],
)
'''
    tmp = Path(tempfile.mkdtemp())
    _write(tmp, "tools.py", src)
    tools = parse_file(tmp / "tools.py")
    assert len(tools) == 1
    t = tools[0]
    assert t.name == "explicit_tool"
    assert t.description == "An explicit tool."
    assert t.parameters == ["param1", "param2"]
    assert t.source_type == "explicit"


# ---------------------------------------------------------------------------
# Symlink handling
# ---------------------------------------------------------------------------

def test_symlink_skipped():
    tmp = Path(tempfile.mkdtemp())
    real = tmp / "real.py"
    real.write_text(
        'import mcp\n\n@mcp.tool()\ndef real_tool():\n    """Real."""\n    pass\n'
    )
    link = tmp / "link.py"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("Symlinks not supported on this platform")
    tools = parse_file(link)
    # Symlinked files should be skipped (return empty)
    assert tools == []


# ---------------------------------------------------------------------------
# Exclude patterns
# ---------------------------------------------------------------------------

def test_exclude_patterns():
    tmp = Path(tempfile.mkdtemp())
    _write(tmp, "good.py", '@mcp.tool()\ndef good():\n    """Good."""\n    pass\n')
    _write(tmp, "bad.py", '@mcp.tool()\ndef bad():\n    """Bad."""\n    pass\n')
    _write(tmp, "test_server.py", '@mcp.tool()\ndef test_tool():\n    """Test."""\n    pass\n')
    tools = scan_directory(str(tmp), exclude=["test_*.py", "bad.py"])
    names = [t.name for t in tools]
    assert "good" in names
    assert "bad" not in names
    assert "test_tool" not in names


# ---------------------------------------------------------------------------
# scan_directory returns tools from multiple files
# ---------------------------------------------------------------------------

def test_scan_directory_multiple_files():
    tmp = Path(tempfile.mkdtemp())
    _write(tmp, "a.py", '@mcp.tool()\ndef tool_a(x):\n    """A."""\n    pass\n')
    _write(tmp, "b.py", '@mcp.tool()\ndef tool_b(y):\n    """B."""\n    pass\n')
    tools = parse_directory(str(tmp))
    names = [t.name for t in tools]
    assert "tool_a" in names
    assert "tool_b" in names
    assert len(tools) == 2
