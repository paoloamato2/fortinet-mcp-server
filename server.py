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
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from fortios_client import FortiOSClient

# ── Tool modules ──────────────────────────────────────────────────────
from tools import generic, system, firewall, vpn, router, user, monitor, log, security, wireless

# Load .env if present
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("fortios_mcp")


# ─────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────

def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set. "
            f"Copy .env.example to .env and fill in your values."
        )
    return value


def _get_config() -> dict:
    return {
        "host": _required_env("FORTIOS_HOST"),
        "api_token": _required_env("FORTIOS_API_TOKEN"),
        "vdom": os.environ.get("FORTIOS_VDOM", "root").strip(),
        "verify_ssl": os.environ.get("FORTIOS_VERIFY_SSL", "false").lower() in ("1", "true", "yes"),
        "timeout": float(os.environ.get("FORTIOS_TIMEOUT", "30")),
    }


# ─────────────────────────────────────────────────────────────────────
# Lifespan — shared FortiOS client
# ─────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncGenerator[dict, None]:
    """Create and manage the FortiOS API client lifecycle."""
    cfg = _get_config()
    logger.info(
        "Connecting to FortiGate %s (vdom=%s, ssl-verify=%s)",
        cfg["host"],
        cfg["vdom"],
        cfg["verify_ssl"],
    )
    client = FortiOSClient(
        host=cfg["host"],
        api_token=cfg["api_token"],
        vdom=cfg["vdom"],
        verify_ssl=cfg["verify_ssl"],
        timeout=cfg["timeout"],
    )
    async with client:
        logger.info("FortiOS client initialized.")
        yield {"client": client}
    logger.info("FortiOS client closed.")


# ─────────────────────────────────────────────────────────────────────
# FastMCP application
# ─────────────────────────────────────────────────────────────────────

mcp = FastMCP(
    name="FortiOS MCP Server",
    instructions=(
        "You are connected to a Fortinet FortiGate running FortiOS 7.6.6. "
        "This server exposes the complete FortiOS REST API as MCP tools. "
        "\n\n"
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

logger.info("All 10 tool modules registered (204+ tools).")


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
        mcp.run(transport="streamable-http", host=host, port=port)
    else:
        logger.info("Starting FortiOS MCP Server on stdio")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
