"""Structural guards over the tool modules.

These protect the multi-instance invariant for tools added in future: every
tool must accept an `instance` parameter and resolve its client through the
registry.
"""

from __future__ import annotations

import ast
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

# Fleet meta tools describe the server's own inventory rather than proxying a
# FortiOS endpoint, so they take no `instance` parameter.
MODULES_WITHOUT_INSTANCE_PARAM = {"fleet.py"}


def _tool_functions(path: Path) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    """Every function in ``path`` registered as an MCP tool.

    Most tools use ``@mcp.tool(...)`` decorator syntax. A tool whose
    description is built at runtime (a generated resource table appended to
    ``__doc__``) cannot use it -- a docstring must be a literal -- so it is
    defined undecorated and registered by an explicit ``mcp.tool(...)(name)``
    call instead (see ``user_read`` in ``tools/user.py``). This counts both
    forms, so the guards below still see a tool registered the second way.

    Duplicates the helper of the same name in
    ``tests/test_tool_annotations.py`` rather than importing it, so this
    file's structural guard does not depend on that file's internals.
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


def _tool_modules() -> list[Path]:
    return sorted(p for p in TOOLS_DIR.glob("*.py") if p.name != "__init__.py")


def test_the_exemption_list_has_not_grown() -> None:
    assert MODULES_WITHOUT_INSTANCE_PARAM == {"fleet.py"}


def test_every_tool_accepts_an_instance_parameter() -> None:
    missing: list[str] = []
    for path in _tool_modules():
        if path.name in MODULES_WITHOUT_INSTANCE_PARAM:
            continue
        for fn in _tool_functions(path):
            if "instance" not in [a.arg for a in fn.args.args]:
                missing.append(f"{path.name}:{fn.lineno} {fn.name}")

    assert missing == [], f"tools missing an 'instance' parameter: {missing}"


def test_instance_immediately_precedes_vdom() -> None:
    misordered: list[str] = []
    for path in _tool_modules():
        if path.name in MODULES_WITHOUT_INSTANCE_PARAM:
            continue
        for fn in _tool_functions(path):
            args = [a.arg for a in fn.args.args]
            if "instance" in args and "vdom" in args:
                if args.index("instance") != args.index("vdom") - 1:
                    misordered.append(f"{path.name}:{fn.lineno} {fn.name}")

    assert misordered == [], (
        f"'instance' must sit immediately before 'vdom': {misordered}"
    )


def test_no_tool_still_reads_the_legacy_client_key() -> None:
    offenders = [
        path.name
        for path in _tool_modules()
        if 'lifespan_context["client"]' in path.read_text(encoding="utf-8")
    ]

    assert offenders == [], f"modules still using the legacy client key: {offenders}"


def test_expected_number_of_tools_is_registered() -> None:
    total = sum(len(_tool_functions(p)) for p in _tool_modules())

    # 104 FortiOS tools + fortigate_list, since the collapse folded 145
    # pure-alias tools into nine `*_read` tools (see
    # tests/test_tool_annotations.py's EXPECTED_TOOL_COUNT for the running
    # total across the collapse: 241 -> 232 -> 105 -> 91).
    assert total == 105
