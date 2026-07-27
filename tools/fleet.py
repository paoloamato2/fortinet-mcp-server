"""Fleet meta tools — inspect the configured FortiGates themselves.

Unlike every other tool module these tools describe the server's own instance
inventory rather than proxying a FortiOS endpoint, so they take no ``instance``
parameter.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from instances import InstanceRegistry
from tool_annotations import READ_ONLY


def register(mcp: FastMCP) -> None:
    """Register the fleet meta tools onto the FastMCP instance."""

    @mcp.tool(annotations=READ_ONLY)
    async def fortigate_list(
        ctx: Context,
        check_health: Annotated[
            bool,
            Field(
                default=False,
                description=(
                    "When true, query each FortiGate's system status to report "
                    "reachability, firmware version and serial number. Adds one "
                    "HTTP request per instance."
                ),
            ),
        ] = False,
    ) -> dict[str, Any]:
        """List the FortiGates this server manages.

        Returns each instance's name, description, host, default VDOM and
        read-only status. Pass the returned name as the `instance` parameter on
        any other tool. API tokens are never returned.
        """
        registry: InstanceRegistry = ctx.request_context.lifespan_context["registry"]
        instances: list[dict[str, Any]] = [
            {
                "name": cfg.name,
                "description": cfg.description,
                "host": cfg.host,
                "vdom": cfg.vdom,
                "read_only": cfg.read_only,
            }
            for cfg in registry.configs
        ]

        if check_health:
            names = [entry["name"] for entry in instances]
            results = await asyncio.gather(
                *(
                    registry.clients[name].monitor_get("system/status")
                    for name in names
                ),
                return_exceptions=True,
            )
            for entry, result in zip(instances, results):
                if isinstance(result, BaseException):
                    entry["reachable"] = False
                    entry["error"] = str(result)
                    continue
                entry["reachable"] = True
                # FortiOS puts version/serial at the top level of the monitor
                # envelope, not inside results (which holds hostname/model).
                entry["version"] = result.get("version")
                entry["serial"] = result.get("serial")

        return {"count": len(instances), "instances": instances}
