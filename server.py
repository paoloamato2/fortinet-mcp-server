"""FortiOS 7.6.6 MCP Server — Complete REST API implementation.

This server exposes the entire Fortinet FortiOS 7.6.6 REST API
(1536 endpoints across CMDB, Monitor, Log, and Service sections)
as Model Context Protocol tools.

Architecture:
- Generic CRUD tools (cover all 1536 endpoints directly)
- Specific typed tools (cover the most important 150+ operations)
- Async HTTP client with Bearer-token authentication

Configuration (environment variables or .env file):
    FORTIOS_HOST       — FortiGate URL (e.g. https://192.168.1.1)
    FORTIOS_API_TOKEN  — API Bearer token
    FORTIOS_VDOM       — VDOM (default: root)
    FORTIOS_VERIFY_SSL — true/false (default: false for self-signed)
    FORTIOS_TIMEOUT    — HTTP timeout in seconds (default: 30)
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from typing import AsyncGenerator

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from instances import InstanceRegistry, load_instances, roster_text

# ── Tool modules ──────────────────────────────────────────────────────
from tools import (
    generic,
    system,
    firewall,
    vpn,
    router,
    user,
    monitor,
    log,
    security,
    wireless,
    fleet,
)

# Load .env if present
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("fortios_mcp")


# ─────────────────────────────────────────────────────────────────────
# Fleet roster for the instructions block
#
# Loaded tolerantly at import so `import server` keeps working with no
# environment set (tests/test_server.py relies on this). The lifespan below
# repeats the load strictly and refuses to start on any error.
# ─────────────────────────────────────────────────────────────────────

_IMPORT_INSTANCES, _ = load_instances()


# ─────────────────────────────────────────────────────────────────────
# Lifespan — one FortiOS client per configured FortiGate
# ─────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncGenerator[dict, None]:
    """Create and manage one FortiOS API client per configured FortiGate."""
    instances, errors = load_instances()
    if errors:
        raise EnvironmentError(
            "FortiGate instance configuration is invalid:\n  - " + "\n  - ".join(errors)
        )
    if not instances:
        raise EnvironmentError(
            "No FortiGate instances configured. Set FORTIOS_INSTANCES_FILE to a "
            "JSON file, or FORTIOS_HOST and FORTIOS_API_TOKEN for a single device."
        )

    registry = InstanceRegistry(instances)
    for cfg in instances:
        logger.info(
            "FortiGate '%s' → %s (vdom=%s, ssl-verify=%s, read-only=%s)",
            cfg.name,
            cfg.host,
            cfg.vdom,
            cfg.verify_ssl,
            cfg.read_only,
        )

    async with AsyncExitStack() as stack:
        for client in registry.clients.values():
            await stack.enter_async_context(client)
        logger.info("%d FortiGate client(s) initialized.", len(instances))
        yield {"registry": registry}
    logger.info("FortiGate clients closed.")


# ─────────────────────────────────────────────────────────────────────
# FastMCP application
# ─────────────────────────────────────────────────────────────────────

mcp = FastMCP(
    name="FortiOS MCP Server",
    host=os.environ.get("MCP_HOST", "127.0.0.1"),
    port=int(os.environ.get("MCP_PORT", "8000")),
    instructions=(
        "You are connected to one or more Fortinet FortiGates running "
        "FortiOS 7.6.6. "
        "This server exposes the complete FortiOS REST API as MCP tools. "
        "\n\n" + roster_text(_IMPORT_INSTANCES) + "\n\n"
        "Tool categories:\n"
        "- **Generic**: cmdb_list/get/create/update/delete, monitor_get/action, log_get, service_call\n"
        "    → These cover ALL 1536 FortiOS API endpoints directly.\n"
        "- **System**: interfaces, DNS, NTP, admins, DHCP, SNMP, certificates, VDOMs\n"
        "- **Firewall**: policies, addresses, services, VIPs, IP pools, schedules, sessions\n"
        "- **VPN**: IPsec Phase 1/2, SSL VPN portals/settings, tunnel control, certificates\n"
        "- **Router**: static routes, OSPF, BGP, RIP, prefix lists, route maps, SD-WAN\n"
        "- **User**: local users, groups, RADIUS, LDAP, TACACS+, SAML, session management\n"
        "- **Monitor**: ARP, FortiView, license, endpoint, IPS, switch controller, config backup\n"
        "- **Log**: traffic/event/virus/webfilter/IPS logs, FortiAnalyzer config\n"
        "- **Security**: IPS, AV, webfilter, app control, DLP, email filter, DNS filter, WAF, ZTNA\n"
        "- **Wireless**: APs, SSIDs, Hotspot 2.0, connected clients, rogue AP detection\n"
        "\n"
        "Always use specific typed tools when available. "
        "Fall back to generic cmdb_list/cmdb_get/monitor_get for unlisted resources. "
        "For destructive operations (delete, policy changes), confirm with the user first."
    ),
    lifespan=lifespan,
)

# ─────────────────────────────────────────────────────────────────────
# Register all tool modules
# ─────────────────────────────────────────────────────────────────────

generic.register(mcp)
system.register(mcp)
firewall.register(mcp)
vpn.register(mcp)
router.register(mcp)
user.register(mcp)
monitor.register(mcp)
log.register(mcp)
security.register(mcp)
wireless.register(mcp)
fleet.register(mcp)

logger.info("All 11 tool modules registered (205+ tools).")


# ─────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server using stdio transport (default for Claude Desktop)."""
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        host = os.environ.get("MCP_HOST", "127.0.0.1")
        port = int(os.environ.get("MCP_PORT", "8000"))
        logger.info("Starting FortiOS MCP Server on %s:%d (HTTP)", host, port)
        mcp.run(transport="streamable-http")
    else:
        logger.info("Starting FortiOS MCP Server on stdio")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
