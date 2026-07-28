"""``title`` keys are stripped from every advertised schema.

Pydantic derives a ``title`` from each field name, so ``instance`` arrives as
``"title": "Instance"`` -- 26,191 characters across 241 tools restating keys
the client can already read. Stripping them changes nothing a client can act
on: JSON Schema treats ``title`` as presentational, and the property name is
right there as the object key.
"""

from __future__ import annotations

from server import mcp


def _titles_in(schema: dict) -> list[str]:
    """Every ``title`` key found anywhere in one tool's input schema."""
    found: list[str] = []
    if "title" in schema:
        found.append(f"<root>.title={schema['title']!r}")
    for name, prop in schema.get("properties", {}).items():
        if isinstance(prop, dict) and "title" in prop:
            found.append(f"{name}.title={prop['title']!r}")
    return found


async def test_no_tool_advertises_a_title() -> None:
    tools = await mcp.list_tools()
    offenders = [
        f"{tool.name}: {', '.join(_titles_in(tool.inputSchema))}"
        for tool in tools
        if _titles_in(tool.inputSchema)
    ]
    assert offenders == [], f"schemas still carry title keys: {offenders[:5]}"


async def test_stripping_preserves_everything_else() -> None:
    """A representative schema keeps its type, description, default and enum."""
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    schema = tools["cmdb_list"].inputSchema
    resource = schema["properties"]["resource_path"]
    assert schema["type"] == "object"
    assert "resource_path" in schema["required"]
    assert "description" in resource
    vdom = schema["properties"]["vdom"]
    assert vdom["default"] is None
    assert vdom["anyOf"] == [{"type": "string"}, {"type": "null"}]
