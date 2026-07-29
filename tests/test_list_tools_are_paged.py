"""Every list tool is paged, discovered rather than enumerated.

``tests/test_typed_reader_paging.py`` names the tools it drives, because each
one needs a different filter argument. A named roster cannot fail for a tool
nobody thought to add to it: ``firewall_policy_list``,
``monitor_firewall_session_list``, ``monitor_endpoint_record_list`` and
``monitor_wifi_client_list`` all shipped unpaged while that roster was green,
and the last of the four bounded its response by nothing at all.

So this guard discovers its subjects. It walks the tool modules and holds
every ``*_list`` tool to the paging contract, which makes the failure mode a
new unpaged tool rather than a forgotten roster entry.

``_list``/``_get`` is the codebase's own signal for collection-versus-object,
so the name is what selects a tool here. The log family is out of scope by
design: it pages on the FortiOS log API's own ``rows``/``start`` vocabulary
(see ``log_traffic_forward``), not on ``paging.py``.

Duplicates ``_tool_functions`` from ``tests/test_tools_have_instance_param.py``
rather than importing it, following that file's note: a structural guard should
not depend on another guard's internals.
"""

from __future__ import annotations

import ast
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

#: ``fortigate_list`` answers from the loaded instance config without touching
#: a device, so its length is the operator's fleet size and there is no page to
#: fetch. It is also the one tool with no ``instance`` parameter.
TOOLS_WITHOUT_PAGING = {"fortigate_list"}


def _tool_functions(path: Path) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    """Every function in ``path`` registered as an MCP tool.

    Counts both ``@mcp.tool(...)`` decoration and the explicit
    ``mcp.tool(...)(name)`` call that a runtime-built description forces.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    by_name: dict[str, ast.AsyncFunctionDef | ast.FunctionDef] = {}
    decorated: list[ast.AsyncFunctionDef | ast.FunctionDef] = []
    registered_by_call: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            by_name[node.name] = node
            if any("mcp.tool" in ast.unparse(d) for d in node.decorator_list):
                decorated.append(node)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Call)
            and "mcp.tool" in ast.unparse(node.func)
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
        ):
            registered_by_call.add(node.args[0].id)

    decorated_names = {fn.name for fn in decorated}
    found = list(decorated)
    found.extend(
        by_name[name]
        for name in sorted(registered_by_call)
        if name in by_name and name not in decorated_names
    )
    return found


def _list_tools() -> list[tuple[Path, ast.AsyncFunctionDef | ast.FunctionDef]]:
    """Every ``*_list`` tool that owes the paging contract."""
    found = []
    for path in sorted(p for p in TOOLS_DIR.glob("*.py") if p.name != "__init__.py"):
        for fn in _tool_functions(path):
            if fn.name.endswith("_list") and fn.name not in TOOLS_WITHOUT_PAGING:
                found.append((path, fn))
    return found


def _annotation_of(fn: ast.AsyncFunctionDef | ast.FunctionDef, arg: str) -> str | None:
    for candidate in fn.args.args + fn.args.kwonlyargs:
        if candidate.arg == arg:
            return (
                ast.unparse(candidate.annotation)
                if candidate.annotation is not None
                else ""
            )
    return None


def test_the_guard_discovers_the_list_tools() -> None:
    """A discovery bug would empty the roster and pass everything below."""
    names = {fn.name for _, fn in _list_tools()}

    assert "firewall_policy_list" in names
    assert "monitor_wifi_client_list" in names
    assert len(names) >= 6


def test_the_exemption_list_has_not_grown() -> None:
    assert TOOLS_WITHOUT_PAGING == {"fortigate_list"}


def test_every_list_tool_takes_the_shared_paging_parameters() -> None:
    """``start``/``count`` must be the shared aliases, not bare ints.

    A tool declaring its own ``count: int = 200`` skips ``normalise``, so a
    negative ``start`` or a zero ``count`` reaches the device instead of
    raising ``PageError``.
    """
    offenders: list[str] = []
    for path, fn in _list_tools():
        for arg, expected in (("start", "StartParam"), ("count", "CountParam")):
            if _annotation_of(fn, arg) != expected:
                offenders.append(f"{path.name}:{fn.lineno} {fn.name} ({arg})")

    assert offenders == [], (
        f"list tools not using the shared paging params: {offenders}"
    )


def test_every_list_tool_pages_its_response() -> None:
    """Taking the parameters is not enough; the payload must be trimmed."""
    offenders: list[str] = []
    for path, fn in _list_tools():
        body = ast.unparse(fn)
        if "paginate(" not in body or "normalise(" not in body:
            offenders.append(f"{path.name}:{fn.lineno} {fn.name}")

    assert offenders == [], f"list tools not routed through paging.py: {offenders}"
