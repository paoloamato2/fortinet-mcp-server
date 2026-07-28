"""The ``instance`` and ``vdom`` descriptions live in exactly one place.

Before this, the full prose for both parameters was inlined at all 241 tool
sites -- 103,144 characters, 45.4% of everything the server advertises, to
say the same two things 241 times. The prose now lives in ``tool_params.py``;
these tests keep it from creeping back into the tool modules.
"""

from __future__ import annotations

from pathlib import Path

from server import mcp

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

#: Fragments that only ever appeared inside the duplicated descriptions.
BANNED_FRAGMENTS = (
    "Target FortiGate name; see fortigate_list",
    "Target VDOM name. Defaults to the server default VDOM",
)


def _tool_modules() -> list[Path]:
    return sorted(p for p in TOOLS_DIR.glob("*.py") if p.name != "__init__.py")


def test_no_tool_module_inlines_the_descriptions() -> None:
    offenders: list[str] = []
    for path in _tool_modules():
        text = path.read_text(encoding="utf-8")
        for fragment in BANNED_FRAGMENTS:
            if fragment in text:
                offenders.append(f"{path.name}: {fragment!r}")
    assert offenders == [], (
        f"inlined parameter prose found; use tool_params.py instead: {offenders}"
    )


async def test_the_descriptions_still_reach_the_client() -> None:
    """Deduplicating must not mean deleting -- both params stay documented."""
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    schema = tools["cmdb_list"].inputSchema["properties"]
    assert schema["instance"]["description"].strip()
    assert schema["vdom"]["description"].strip()
    assert "fortigate_list" in schema["instance"]["description"]
    assert "*" in schema["vdom"]["description"]


def test_the_one_off_migration_script_is_gone() -> None:
    """``add_instance_param.py`` existed only because no alias did."""
    script = Path(__file__).resolve().parent.parent / "add_instance_param.py"
    assert not script.exists(), (
        "add_instance_param.py is superseded by tool_params.py; delete it"
    )
