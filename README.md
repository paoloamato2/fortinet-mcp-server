# FortiOS 7.6.6 MCP Server

A complete **Model Context Protocol (MCP)** server for Fortinet FortiOS 7.6.6, exposing the entire REST API (1536 endpoints) as typed MCP tools usable from Claude Desktop, Cursor, or any MCP-compatible client.

## Features

- **150+ specific typed tools** organized by functional area
- **5 generic pass-through tools** that cover all 1536 FortiOS API endpoints
- Async HTTP client with Bearer-token authentication
- Full support for CMDB, Monitor, Log, and Service API sections
- Safe against self-signed certificates (configurable)
- Compatible with multi-VDOM environments

## Tool Categories

| Module | Tools | Description |
|--------|-------|-------------|
| **Generic** | 5 | `cmdb_list/get/create/update/delete`, `monitor_get/action`, `log_get`, `service_call` — cover ALL endpoints |
| **System** | 27 | Interfaces, DNS, NTP, admins, DHCP, SNMP, certificates, VDOMs, syslog |
| **Firewall** | 32 | Policies (IPv4/IPv6), addresses, address groups, services, VIPs, IP pools, schedules, sessions |
| **VPN** | 22 | IPsec Phase 1/2, SSL VPN portals/settings, tunnel up/down, VPN certificates |
| **Router** | 17 | Static routes, OSPF, BGP, RIP, prefix lists, route maps, SD-WAN health |
| **User** | 18 | Local users, groups, RADIUS, LDAP, TACACS+, SAML, authenticated sessions |
| **Monitor** | 18 | ARP, FortiView top talkers, endpoint control, IPS stats, switch controller, config backup |
| **Log** | 18 | Traffic, event, VPN, user, virus, webfilter, IPS, app-ctrl, DNS logs + log config |
| **Security** | 29 | IPS, AV, webfilter, app control, DLP, email filter, DNS filter, WAF, ICAP, ssh-filter, ZTNA |
| **Wireless** | 18 | AP profiles, WTPs, SSIDs (VAPs), Hotspot 2.0, connected clients, rogue APs |

**Total: 204+ tools**

## Requirements

- Python 3.11+
- `uv` package manager (or `pip`)
- Fortinet FortiGate with FortiOS 7.6.x
- A REST API admin account on the FortiGate

## Setup

### 1. Create API Token on FortiGate

1. Go to **System > Administrators**
2. Create a new **REST API Admin**
3. Set appropriate admin profile (e.g. `super_admin` for full access or restrict as needed)
4. Copy the generated API token

### 2. Install dependencies

```bash
cd fortinet/mcp-server

# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env with your FortiGate details:
#   FORTIOS_HOST=https://192.168.1.1
#   FORTIOS_API_TOKEN=your-token-here
#   FORTIOS_VDOM=root
#   FORTIOS_VERIFY_SSL=false
```

### 4. Test with MCP Inspector

```bash
uv run mcp dev server.py
```

### 5. Install in Claude Desktop

```bash
uv run mcp install server.py --name "FortiOS 7.6.6"
```

Or manually add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "fortios": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/fortinet/mcp-server", "python", "server.py"],
      "env": {
        "FORTIOS_HOST": "https://192.168.1.1",
        "FORTIOS_API_TOKEN": "your-api-token",
        "FORTIOS_VDOM": "root",
        "FORTIOS_VERIFY_SSL": "false"
      }
    }
  }
}
```

## HTTP Mode (optional)

To run as a remote HTTP server instead of stdio:

```bash
MCP_TRANSPORT=streamable-http MCP_PORT=8000 uv run server.py
```

Connect via `http://localhost:8000/mcp`.

## Usage Examples

### Via Claude Desktop

Once installed, ask Claude:

- "Show me all firewall policies that deny traffic"
- "What IPsec tunnels are currently down?"
- "List interfaces with their IPs"
- "Look up which route would be used to reach 8.8.8.8"
- "Show top 20 traffic sources in FortiView"
- "Are there any failed admin login attempts in the logs?"

### Direct Tool Invocations

```python
# List firewall policies
firewall_policy_list(filter_action="deny")

# Get system status
system_status()

# Check VPN tunnels
monitor_vpn_ipsec()

# Query forward traffic logs for a specific IP
log_traffic_forward(srcip="10.10.1.100", rows=50)

# Generic: list any resource
cmdb_list("casb/profile")
cmdb_list("wireless-controller.hotspot20/hs-profile")

# Generic: get any monitor data
monitor_get("registration/forticloud")
```

## Project Structure

```
├── server.py              # FastMCP entry point, lifespan, tool registration
├── fortios_client.py      # Async HTTP client (CMDB/Monitor/Log/Service)
├── pyproject.toml         # Project metadata and dependencies
├── .env.example           # Environment variable template
├── README.md              # This file
└── tools/
    ├── __init__.py
    ├── generic.py          # Generic pass-through tools (all 1536 endpoints)
    ├── system.py           # System config + monitoring
    ├── firewall.py         # Firewall policies, addresses, VIPs, sessions
    ├── vpn.py              # IPsec + SSL VPN config and monitoring
    ├── router.py           # Static routes, OSPF, BGP, SD-WAN
    ├── user.py             # Local users, groups, RADIUS, LDAP, sessions
    ├── monitor.py          # Network monitoring, FortiView, endpoint control
    ├── log.py              # Log retrieval and configuration
    ├── security.py         # IPS, AV, webfilter, DLP, WAF, ZTNA profiles
    └── wireless.py         # WiFi APs, SSIDs, clients, rogue APs
```

## Security Notes

- The API token provides the same level of access as the admin profile it was assigned to. Use the **principle of least privilege**.
- Set `FORTIOS_VERIFY_SSL=true` in production and install a valid certificate on your FortiGate.
- This server runs locally on stdio by default — it is not exposed over the network unless you use HTTP mode.
- Never commit your `.env` file or expose your API token.

## FortiOS API Reference

The full FortiOS 7.6.6 REST API is documented in the official Fortinet documentation.

You can explore any available path at runtime using the generic `cmdb_list` tool:

```python
# Discover resources using generic tools
cmdb_list("casb/profile")
cmdb_list("wireless-controller.hotspot20/hs-profile")
monitor_get("registration/forticloud")
```
