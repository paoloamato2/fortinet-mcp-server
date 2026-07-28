#!/usr/bin/env python3
"""Generate ``resources.py`` from the tool modules that are about to be removed.

Every pure-alias tool -- a body that is one client call wrapped in
``try/except FortiOSError`` -- reduces to ``(client_method, path,
docstring_first_line)``. This script reads those tuples out of ``tools/*.py``
by AST and emits the table, so the 125 read rows and 15 delete rows are
derived from the code being replaced rather than retyped.

Run BEFORE removing any tool:

    uv run python scripts/generate_resources.py > resources.py
    uv run ruff format resources.py

It is idempotent and safe to re-run while the old tools still exist. Once
they are gone it will emit an empty table, which is why
``tests/test_resource_tables.py`` pins the committed output rather than
regenerating it.
"""

from __future__ import annotations

import ast
import collections
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

READ_METHODS = {"cmdb_get", "monitor_get"}

#: Generic pass-through tools. They take a caller-supplied path, so they have
#: no fixed row in the table and are not being removed.
GENERIC = {
    "cmdb_get",
    "cmdb_delete",
    "cmdb_list",
    "cmdb_create",
    "cmdb_update",
    "monitor_get",
    "monitor_action",
    "log_get",
    "service_call",
}

#: Their ``_list`` siblings carry real filter logic and survive the collapse,
#: so these ``_get`` tools stay with them rather than folding into a read
#: tool -- otherwise there would be two ways to list the same resource.
KEEP_GET = {"firewall_policy_get", "firewall_address_get", "system_interface_get"}

#: ``system_fortiguard_status`` and ``monitor_license_status`` issue the
#: identical call to ``license/status``. Keep the monitor one.
DROP = {"system_fortiguard_status"}

#: FortiOS configuration singletons: one object, no per-object key, so
#: ``name=`` is meaningless and is rejected rather than silently 404ing.
SINGLETON_PATHS = frozenset(
    {
        "system/global",
        "system/dns",
        "system/ntp",
        "system/time",
        "system/sdwan",
        "system.snmp/sysinfo",
        "system.autoupdate/schedule",
        "antivirus/settings",
        "automation/setting",
        "router/ospf",
        "router/ospf6",
        "router/bgp",
        "router/rip",
        "log.disk/filter",
        "log.disk/setting",
        "log.memory/setting",
        "log.fortianalyzer/setting",
        "log.syslogd/setting",
        "vpn.ssl/settings",
        "wireless-controller/setting",
        "wireless-controller/rf-analysis",
    }
)

#: The stripping rule would leave a bare ``ip``; its path says ``iplist``.
NAME_OVERRIDES = {"monitor_firewall_ip_list": "iplist"}

DOMAIN_ALIAS = {
    "firewall": "FirewallResource",
    "log": "LogResource",
    "monitor": "MonitorResource",
    "router": "RouterResource",
    "security": "SecurityResource",
    "system": "SystemResource",
    "user": "UserResource",
    "vpn": "VpnResource",
    "wireless": "WirelessResource",
}


def enum_name(domain: str, tool_name: str) -> str:
    """Strip the redundant prefixes and suffix from a tool name."""
    if tool_name in NAME_OVERRIDES:
        return NAME_OVERRIDES[tool_name]
    name = tool_name
    if name.startswith("monitor_") and domain != "monitor":
        name = name[len("monitor_") :]
    name = name.removeprefix(f"{domain}_")
    if domain == "wireless":
        name = name.removeprefix("wifi_")
    name = name.removesuffix("_list")
    return name.removesuffix("_get")


def scan() -> list[dict]:
    """Every ``@mcp.tool`` function, with the facts needed to classify it."""
    out: list[dict] = []
    for path in sorted(TOOLS_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            if not any("mcp.tool" in ast.unparse(d) for d in node.decorator_list):
                continue
            own = [
                a.arg
                for a in node.args.args
                if a.arg not in ("ctx", "instance", "vdom")
            ]
            body = [
                s
                for s in node.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
            ]
            stmts = [
                s
                for s in body
                if not (isinstance(s, ast.AnnAssign) and "resolve" in ast.unparse(s))
            ]
            pure = len(stmts) == 1 and "json.loads" not in ast.unparse(node)
            method = call_path = None
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                attr = getattr(inner.func, "attr", "")
                if attr in READ_METHODS | {"cmdb_delete"} and inner.args:
                    method = attr
                    first = inner.args[0]
                    call_path = (
                        first.value
                        if isinstance(first, ast.Constant)
                        else ast.unparse(first)
                    )
            doc = (ast.get_docstring(node) or "").split("\n")[0].strip()
            out.append(
                {
                    "domain": path.stem,
                    "name": node.name,
                    "own": own,
                    "pure": pure,
                    "method": method,
                    "path": call_path,
                    "summary": doc,
                }
            )
    return out


def strip_key(path: str) -> str:
    """``f'firewall/address/{name}'`` -> ``firewall/address``."""
    head = path.split("/{")[0]
    for prefix in ("f'", 'f"'):
        if head.startswith(prefix):
            return head[len(prefix) :]
    return head.strip("'\"")


def main() -> None:
    rows = scan()
    reads = collections.defaultdict(dict)
    deletes: dict[str, tuple[str, str, str, bool]] = {}

    for row in rows:
        if row["name"] in GENERIC or not row["pure"]:
            continue
        if row["name"] in DROP:
            continue
        if not row["own"] and row["method"] in READ_METHODS:
            value = enum_name(row["domain"], row["name"])
            api = "cmdb" if row["method"] == "cmdb_get" else "monitor"
            path = row["path"]
            keyed = api == "cmdb" and path not in SINGLETON_PATHS
            reads[row["domain"]][value] = (api, path, row["summary"], keyed)
        elif len(row["own"]) == 1 and row["method"] == "cmdb_delete":
            value = enum_name(row["domain"], row["name"].removesuffix("_delete"))
            if row["name"] == "wifi_wtp_deauthorize":
                value = "wifi_wtp"
            deletes[value] = ("cmdb", strip_key(row["path"]), row["summary"], True)

    print(HEADER)
    print("SINGLETON_PATHS: frozenset[str] = frozenset({")
    for path in sorted(SINGLETON_PATHS):
        print(f'    "{path}",')
    print("})\n\n")

    for domain in sorted(reads):
        alias = DOMAIN_ALIAS[domain]
        print(f"{alias}: TypeAlias = Literal[")
        for value in sorted(reads[domain]):
            print(f'    "{value}",')
        print("]\n")

    print("DeletableResource: TypeAlias = Literal[")
    for value in sorted(deletes):
        print(f'    "{value}",')
    print("]\n\n")

    print("READ_RESOURCES: dict[str, dict[str, Resource]] = {")
    for domain in sorted(reads):
        print(f'    "{domain}": {{')
        for value in sorted(reads[domain]):
            api, path, summary, keyed = reads[domain][value]
            print(
                f'        "{value}": Resource("{api}", "{path}", '
                f"{summary!r}, keyed={keyed}),"
            )
        print("    },")
    print("}\n\n")

    print("DELETE_RESOURCES: dict[str, Resource] = {")
    for value in sorted(deletes):
        api, path, summary, keyed = deletes[value]
        print(
            f'    "{value}": Resource("{api}", "{path}", {summary!r}, keyed={keyed}),'
        )
    print("}")


HEADER = '''"""The FortiOS resource table behind the per-domain read tools.

Each row is one FortiOS endpoint: which API family serves it, its path, a
one-line summary shown to the model, and whether it accepts a per-object key.
Nine ``<domain>_read`` tools and ``fortios_delete`` dispatch through these
rows, replacing 160 tools whose bodies were a single client call with a
hardcoded path.

GENERATED by ``scripts/generate_resources.py`` from the tool modules this
table replaced -- the summaries are those tools' docstrings, carried over
verbatim. Edit this file directly when adding a resource; the generator
cannot re-derive rows for tools that no longer exist.

Imports nothing from this project, so every layer can use it with no cycle.
"""

from __future__ import annotations

from typing import Literal, NamedTuple, TypeAlias


class Resource(NamedTuple):
    """One readable FortiOS endpoint."""

    api: Literal["cmdb", "monitor"]
    path: str
    summary: str
    keyed: bool = False


'''

if __name__ == "__main__":
    main()
