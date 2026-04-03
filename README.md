# FortiOS 7.6.x MCP Server

<p align="center">
  <img src="https://img.shields.io/badge/FortiOS-7.6.x-EE3124?style=for-the-badge&logo=fortinet&logoColor=white" alt="FortiOS version">
  <img src="https://img.shields.io/badge/MCP-Model_Context_Protocol-5A67D8?style=for-the-badge" alt="MCP">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/github/license/paoloamato2/fortinet-mcp-server?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/stars/paoloamato2/fortinet-mcp-server?style=for-the-badge" alt="Stars">
</p>

<p align="center">
  <strong>A complete <a href="https://modelcontextprotocol.io">Model Context Protocol (MCP)</a> server for Fortinet FortiOS 7.6.x — exposing the entire REST API (1536 endpoints) as typed MCP tools usable from Claude Desktop, Cursor, or any MCP-compatible client.</strong>
</p>

---

## Table of Contents

- [Features](#features)
- [Tool Categories](#tool-categories)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
  - [1. Create API Token on FortiGate](#1-create-api-token-on-fortigate)
  - [2. Install dependencies](#2-install-dependencies)
  - [3. Configure environment](#3-configure-environment)
  - [4. Run with MCP Inspector](#4-run-with-mcp-inspector)
  - [5. Install in Claude Desktop](#5-install-in-claude-desktop)
- [HTTP Mode](#http-mode)
- [Usage Examples](#usage-examples)
- [Project Structure](#project-structure)
- [Security Notes](#security-notes)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **204+ typed MCP tools** organized by functional area (system, firewall, VPN, router, user, monitor, log, security, wireless)
- **5 generic pass-through tools** that cover all 1,536 FortiOS API endpoints
- Async HTTP client with Bearer-token authentication via `httpx`
- Full support for **CMDB, Monitor, Log, and Service** API sections
- Configurable SSL verification (self-signed certificates supported)
- Compatible with **multi-VDOM** environments
- Runs as **stdio** (Claude Desktop) or **HTTP** server (remote/cloud use)

---

## Tool Categories

| Module | # Tools | Description |
|--------|--------:|-------------|
| **Generic** | 5 | `cmdb_list/get/create/update/delete`, `monitor_get/action`, `log_get`, `service_call` — cover **ALL** endpoints |
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

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.11+ |
| Package manager | `uv` (recommended) or `pip` |
| FortiGate | FortiOS 7.6.x |
| Auth | REST API admin account with Bearer token |

---

## Quick Start

### 1. Create API Token on FortiGate

1. Log into your FortiGate Web UI
2. Navigate to **System > Administrators**
3. Click **Create New > REST API Admin**
4. Assign an admin profile (`super_admin` for full access, or a restricted profile following least-privilege)
5. Copy the generated **API token** — it is shown only once

### 2. Install dependencies

```bash
git clone https://github.com/paoloamato2/fortinet-mcp-server.git
cd fortinet-mcp-server

# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

### 3. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```dotenv
FORTIOS_HOST=https://192.168.1.1
FORTIOS_API_TOKEN=your-token-here
FORTIOS_VDOM=root
FORTIOS_VERIFY_SSL=false
FORTIOS_TIMEOUT=30
```

### 4. Run with MCP Inspector

```bash
uv run mcp dev server.py
```

### 5. Install in Claude Desktop

```bash
uv run mcp install server.py --name "FortiOS"
```

Or manually add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "fortios": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "/absolute/path/to/fortinet-mcp-server",
        "python", "server.py"
      ],
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

> On **macOS**, `claude_desktop_config.json` is at `~/Library/Application Support/Claude/claude_desktop_config.json`.  
> On **Windows**, it is at `%APPDATA%\Claude\claude_desktop_config.json`.

---

## HTTP Mode

To run as a remote HTTP server instead of stdio:

```bash
MCP_TRANSPORT=streamable-http MCP_PORT=8000 uv run server.py
```

Connect via `http://localhost:8000/mcp`.

This mode is useful for shared team setups or cloud-hosted deployments.

---

## Usage Examples

### Via Claude Desktop

Once installed, you can ask Claude natural-language questions such as:

- *"Show me all firewall policies that deny traffic"*
- *"Which IPsec tunnels are currently down?"*
- *"List all interfaces with their IP addresses"*
- *"Which route would be used to reach 8.8.8.8?"*
- *"Show the top 20 traffic sources in FortiView"*
- *"Are there any failed admin login attempts in the logs?"*

### Direct Tool Invocations

```python
# List firewall policies filtered by action
firewall_policy_list(filter_action="deny")

# Get system status
system_status()

# Check IPsec VPN tunnels
monitor_vpn_ipsec()

# Query forward traffic logs for a specific source IP
log_traffic_forward(srcip="10.10.1.100", rows=50)

# Generic: list any CMDB resource (full API coverage)
cmdb_list("casb/profile")
cmdb_list("wireless-controller.hotspot20/hs-profile")

# Generic: get any monitor data
monitor_get("registration/forticloud")
```

---

## Project Structure

```
fortinet-mcp-server/
├── server.py              # FastMCP entry point, lifespan, tool registration
├── fortios_client.py      # Async HTTP client (CMDB/Monitor/Log/Service)
├── pyproject.toml         # Project metadata and dependencies
├── .env.example           # Environment variable template
├── README.md              # This file
└── tools/
    ├── __init__.py
    ├── generic.py         # Generic pass-through tools (all 1536 endpoints)
    ├── system.py          # System config + monitoring
    ├── firewall.py        # Firewall policies, addresses, VIPs, sessions
    ├── vpn.py             # IPsec + SSL VPN config and monitoring
    ├── router.py          # Static routes, OSPF, BGP, SD-WAN
    ├── user.py            # Local users, groups, RADIUS, LDAP, sessions
    ├── monitor.py         # Network monitoring, FortiView, endpoint control
    ├── log.py             # Log retrieval and configuration
    ├── security.py        # IPS, AV, webfilter, DLP, WAF, ZTNA profiles
    └── wireless.py        # WiFi APs, SSIDs, clients, rogue APs
```

---

## Security Notes

- The API token grants the same access level as its associated admin profile. Follow the **principle of least privilege** — create a restricted profile if you only need read access.
- Set `FORTIOS_VERIFY_SSL=true` in production and ensure your FortiGate has a valid TLS certificate.
- The server runs **locally over stdio** by default — it is not exposed over the network unless HTTP mode is enabled.
- **Never commit your `.env` file or expose your API token** in logs, issues, or code.
- Rotate your API token regularly and revoke it immediately if compromised.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

- Bug reports and feature requests → [open an issue](https://github.com/paoloamato2/fortinet-mcp-server/issues)
- Security vulnerabilities → see [SECURITY.md](SECURITY.md)
- Code of conduct → [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

> **Disclaimer:** This project is not affiliated with or endorsed by Fortinet, Inc. FortiOS and FortiGate are trademarks of Fortinet, Inc.
