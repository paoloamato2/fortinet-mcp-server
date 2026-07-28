"""Shared dispatch for the per-domain read tools.

The nine ``<domain>_read`` tools differ only in which slice of
``READ_RESOURCES`` they expose and which ``Literal`` types their ``resource``
parameter. The logic -- look the row up, decide whether a key is allowed,
build the path, pick the API family, convert ``FortiOSError`` into a dict --
is identical, so it lives here once.

Underscore-prefixed because it registers no tools of its own; ``server.py``
does not import it.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import Context

from fortios_client import FortiOSError
from instances import FortiOSAPI
from resources import READ_RESOURCES


def resource_table_doc(domain: str) -> str:
    """Render a domain's rows as the markdown list shown to the model.

    The summaries are the docstrings of the tools this table replaced, so the
    per-resource semantics survive the collapse into one enum.
    """
    rows = READ_RESOURCES[domain]
    return "\n".join(f"- `{value}` — {rows[value].summary}" for value in sorted(rows))


async def read_resource(
    ctx: Context,
    domain: str,
    resource: str,
    name: str | None,
    instance: str | None,
    vdom: str | None,
) -> dict[str, Any]:
    """Read one FortiOS resource, listing it or fetching a single object.

    Args:
        ctx: MCP request context, carrying the instance registry.
        domain: Key into ``READ_RESOURCES`` -- the calling tool's domain.
        resource: Enum value naming the row to read.
        name: Object key. ``None`` lists every object. Rejected for
            singletons and for monitor endpoints, which take no path key.
        instance: Target FortiGate name, or ``"*"`` to fan out.
        vdom: Target VDOM, or ``None`` for the client default.

    Returns:
        The FortiOS response, or ``{"error": ..., "status_code": ...}``.
    """
    row = READ_RESOURCES.get(domain, {}).get(resource)
    if row is None:
        known = ", ".join(sorted(READ_RESOURCES.get(domain, {})))
        return {"error": f"unknown {domain} resource {resource!r}. Known: {known}"}

    if name is not None and not row.keyed:
        reason = (
            "a monitor endpoint, which takes no object key"
            if row.api == "monitor"
            else "a singleton"
        )
        return {"error": (f"resource {resource!r} is {reason}; omit name to read it.")}

    path = f"{row.path}/{name}" if name is not None else row.path
    params = dict(row.params) if row.params else None
    client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
        instance
    )
    try:
        if row.api == "cmdb":
            return await client.cmdb_get(path, params, vdom=vdom)
        return await client.monitor_get(path, params, vdom=vdom)
    except FortiOSError as exc:
        return {"error": str(exc), "status_code": exc.status_code}
