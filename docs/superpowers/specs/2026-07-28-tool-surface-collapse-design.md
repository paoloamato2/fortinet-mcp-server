# Tool Surface Collapse — Design

**Date:** 2026-07-28
**Status:** Approved for planning

## Problem

The server advertises 241 tools. Serialised as the client receives them —
name, description, `inputSchema`, `annotations` — that surface is **227,145
characters, roughly 56,800 tokens**, sent on every request before the model
does any work. Two thirds of it buys nothing.

An AST walk over `tools/*.py` shows **179 of 241 tool bodies are a single
client call wrapped in `try/except FortiOSError`** — no payload parsing, no
filter building, no post-processing. Their entire contribution is a hardcoded
path string. Of those:

- **126 tools accept no parameters at all** beyond `instance` and `vdom`.
  They cost **94,477 chars (≈23,600 tokens)** to advertise what is, in
  substance, a lookup table of 126 URL paths. 93 are `cmdb_get`, 33 are
  `monitor_get`.
- **22 more** are `<resource>_get(key)` aliases (≈4,900 tokens).
- **15 more** are `<resource>_delete(key)` aliases (≈3,400 tokens), each
  fully covered by the existing generic `cmdb_delete`.

Independently, the `instance` and `vdom` parameters are declared with their
full prose descriptions inlined on all 241 tools: **103,144 chars — 45.4% of
the entire surface** — restating the same two sentences 241 times, while
`server.py`'s `instructions` block already explains `instance` once. The
source side mirrors this: the `Annotated[...]` block is copy-pasted at 241
sites with no shared alias, which is why the one-off codegen script
`add_instance_param.py` exists at repo root.

## Goal

Cut the advertised surface by more than half without losing a single
reachable FortiOS path, without weakening any `ToolAnnotations` hint, and
with the reduction held in place by a test rather than by reviewer attention.

## Enabling constraint

The collapse is mechanically derivable, not a matter of taste. For each of
the 179 pure aliases the AST yields the tuple that fully determines its
behaviour: `(client_method, path_literal, docstring_first_line)`. Nothing
else in the body varies. A tool is therefore replaceable by a row in a table
plus a dispatcher, and the replacement can be proved complete by re-deriving
the tuple set and diffing it — the same technique the annotations work used
to freeze the write surface.

Two facts fell out of building that table, both of which would otherwise have
been found at runtime:

- **`license/status` is served by two tools.** `monitor_license_status` and
  `system_fortiguard_status` issue the identical call. A uniqueness assertion
  over the table surfaced it.
- **Three `_get(key)` tools have list siblings that survive.**
  `firewall_policy_list`, `firewall_address_list` and `system_interface_list`
  carry real filter logic (`filter_srcintf`, `filter_type`, `include_vlan`)
  and are not pure aliases, so they stay. Folding only their `_get` halves
  would leave two ways to list addresses — one filtered, one not. Those three
  `_get` tools therefore stay with their siblings, and the get-by-name fold
  covers 19 tools, not 22.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Backward compatibility | **Break it.** The 160 names are removed outright, no deprecation window and no legacy profile | A deprecation release would *add* the new tools while keeping the old, pushing the surface to ~60k tokens for a release — paying a cost to defer the benefit. A dual profile means maintaining and testing two surfaces forever. |
| Replacement shape | **One read tool per domain**, nine total, enum spanning both `cmdb` and `monitor` paths | Keeps the count minimal while leaving exactly one obvious choice per domain. Alternatives measured: split cmdb/monitor = 14 tools; catalog-only = 1 tool but adds a round-trip before any read and degrades tool-selection accuracy. |
| Delete replacement | **One global `fortios_delete`** with a 15-value `resource` enum | Verified: FastMCP enforces `Literal` server-side, rejecting invalid values before the body runs — including path-traversal strings that `cmdb_delete(resource_path=...)` accepts. The enum is a genuine narrowing, not just a rename. Per-domain deletes cost ~2.2k tokens for allowlist granularity nobody asked for. |
| Enum value naming | Strip a leading `monitor_`, then the `<domain>_` prefix, then a trailing `_list` or `_get`: `user_local_list` → `local` | The domain is already in the tool name. `user_read(resource="local")` reads better than `user_read(resource="user_local_list")` and costs fewer tokens. Verified collision-free across all nine domains. Two exceptions: the `wireless` domain also strips a `wifi_` prefix (`wifi_vap_list` → `vap`), and `monitor_firewall_ip_list` → `iplist` rather than the bare `ip` the rule would give, matching its `firewall/iplist` path. |
| `system_status` | **Folded**, no exception | Becomes `system_read(resource="status")`. It is the tool `instructions` names first, so that text changes in the same commit; a standalone exception would cost ~250 tokens and invite more exceptions. |
| `license/status` duplicate | Keep `monitor_read(resource="license_status")`, drop the `system` twin | Identical call today. Retaining both would encode a duplicate in the table the uniqueness test forbids. |
| `wifi_wtp_deauthorize` | Folded into `fortios_delete(resource="wifi_wtp")` | It is literally `cmdb_delete` on the WTP entry. Its table `summary` states that removing the entry deauthorises the AP, since that is not guessable from the resource name. |
| Enum documentation | Full first docstring line per value, rendered as a table in the tool description | Costs ≈2,350 tokens across the nine tools. Six-word summaries would save ~1,200 more, but the docstrings are the only per-resource semantics the 126 tools carried and they were written for this audience. |
| Module location | Two new top-level leaves, `resources.py` and `tool_params.py` | Matches the flat layout and the `tool_annotations.py` precedent: data and parameter definitions that import nothing from the project, so every layer can reach them with no cycle. |

## Components

```text
resources.py       NEW  Resource NamedTuple + READ_RESOURCES/DELETE_RESOURCES tables
tool_params.py     NEW  InstanceParam / VdomParam shared Annotated aliases
server.py               + FastMCP subclass overriding list_tools() to strip `title`
                        + instructions text: system_status -> system_read(resource="status")
tools/*.py              -160 tool functions, +9 <domain>_read, 241 param sites -> aliases
tools/generic.py        + fortios_delete
add_instance_param.py  DELETED  its purpose is served by tool_params.py
tests/test_resource_tables.py   NEW  migration completeness, path uniqueness
tests/test_tool_surface_budget.py NEW  serialised-surface ceiling
tests/test_tool_annotations.py  EXPECTED_MUTATING: -15 aliases, +fortios_delete
README.md, CLAUDE.md, CONTRIBUTING.md, tool_annotations.py  tool counts
```

### `resources.py`

```python
class Resource(NamedTuple):
    api: Literal["cmdb", "monitor"]  # selects cmdb_get or monitor_get
    path: str                        # "ips/sensor"
    summary: str                     # inherited verbatim from the tool's docstring
    keyed: bool = False              # accepts name= for a single-object read
    deletable: bool = False          # appears in fortios_delete's enum

READ_RESOURCES: dict[str, dict[str, Resource]]  # domain -> value -> Resource
```

`keyed` is derived by rule, not per-tool judgement: a `cmdb` resource is
keyed unless its path is a FortiOS configuration singleton, and `monitor`
resources are never keyed, as they take query parameters rather than a path
key. The 21 singleton paths, enumerated so the classification is not left to
interpretation:

```text
system/global   system/dns   system/ntp   system/time   system/sdwan
system.snmp/sysinfo          system.autoupdate/schedule
antivirus/settings           automation/setting
router/ospf     router/ospf6 router/bgp   router/rip
log.disk/filter log.disk/setting          log.memory/setting
log.fortianalyzer/setting    log.syslogd/setting
vpn.ssl/settings
wireless-controller/setting  wireless-controller/rf-analysis
```

The nine enums hold 125 values in total — the 126 collapsed resources less the
dropped `license/status` duplicate:

| domain | enum values | cmdb tables | cmdb singletons | monitor |
|---|---|---|---|---|
| `security_read` | 28 | 26 | 2 | 0 |
| `system_read` | 19 | 7 | 7 | 5 |
| `router_read` | 17 | 7 | 5 | 5 |
| `firewall_read` | 15 | 12 | 0 | 3 |
| `vpn_read` | 12 | 8 | 1 | 3 |
| `wireless_read` | 12 | 6 | 2 | 4 |
| `monitor_read` | 11 | 0 | 0 | 11 |
| `user_read` | 7 | 6 | 0 | 1 |
| `log_read` | 4 | 0 | 4 | 0 |

Example rows, `user` domain, showing the docstrings carried across verbatim:

```python
"local":      Resource("cmdb", "user/local",  "List all local user accounts.", keyed=True),
"group":      Resource("cmdb", "user/group",  "List all user groups.", keyed=True),
"tacacs":     Resource("cmdb", "user/tacacs+", "List all TACACS+ authentication server configurations.", keyed=True),
"fortitoken": Resource("monitor", "user/fortitoken", "List FortiToken hardware/software tokens and their status.", keyed=False),
```

### The read tools

```python
@mcp.tool(annotations=READ_ONLY)
async def user_read(
    ctx: Context,
    resource: Annotated[Literal["local", "group", ...], Field(description=...)],
    name: Annotated[str | None, Field(default=None, description=...)] = None,
    instance: InstanceParam = None,
    vdom: VdomParam = None,
) -> dict[str, Any]:
```

Parameter order keeps `instance` immediately before `vdom`, so the existing
`tests/test_tools_have_instance_param.py` ordering guard passes unchanged.

Flow: look up the `Resource` → if `name` was passed to a non-`keyed`
resource, return `{"error": "resource 'global' is a singleton; omit name"}`
→ build `path` or `f"{path}/{name}"` → dispatch to `client.cmdb_get` or
`client.monitor_get` → catch `FortiOSError`, return
`{"error": str(exc), "status_code": exc.status_code}` per the existing
convention.

Two properties come free. `instance="*"` fan-out now works uniformly across
all 126 resources rather than per hand-written tool. And singleton-vs-table,
today tribal knowledge encoded only in which tools were named `_get` versus
`_list`, becomes asserted data.

### `fortios_delete`

```python
@mcp.tool(annotations=DESTRUCTIVE)
async def fortios_delete(
    ctx: Context,
    resource: Annotated[Literal["firewall_address", "firewall_policy", ...], Field(...)],
    name: Annotated[str, Field(description="Object key to delete.")],
    instance: InstanceParam = None,
    vdom: VdomParam = None,
) -> dict[str, Any]:
```

Lives in `tools/generic.py` beside the other cross-cutting tools, reading the
`deletable` slice of the table. `instance="*"` is refused by the existing
`ErrorClient` path, unchanged.

### `title` stripping

`Tool.from_function` exposes no schema hook, and pydantic emits a `title` for
every field. Those keys cost **26,191 chars (≈6,550 tokens, 11.5% of the
surface)** and carry no information a client needs — the field name is
already the JSON key.

`FastMCP._setup_handlers` registers the bound `self.list_tools`, so a
subclass override reaches the wire. Roughly fifteen lines in `server.py`:
strip `title` from `inputSchema` and from each entry in `properties`, leaving
everything else untouched. This is the single point where schemas are
serialised, so nothing else needs to know.

## Accepted limits

- **160 tool names disappear.** Any saved prompt, script or client allowlist
  naming them breaks at once. This is the deliberate choice recorded above.
- **A gating client loses per-name delete granularity.** Allowlisting
  `firewall_address_delete` becomes allowlisting `fortios_delete`, which
  covers 15 object types. Still narrower than `cmdb_delete`, which accepts
  any path at all, but wider than today.
- **Two ways to list three resources remain.** `firewall_policy_list`,
  `firewall_address_list` and `system_interface_list` keep their filter
  parameters and their `_get` siblings; those three resources are absent from
  the read enums. The inconsistency is deliberate and is the lesser of the
  two evils identified in *Enabling constraint*.
- **Response size is not addressed.** The 116 typed `cmdb_get` readers still
  return whole FortiOS envelopes with no field projection, and on a busy
  device a single `firewall_policy_list` can exceed the entire tool surface.
  That is a separate, larger win and deliberately out of scope here.

## Enforcement

1. **Migration completeness** — `tests/test_resource_tables.py` asserts the
   set of `(api, path)` pairs reachable through the nine read tools plus
   `fortios_delete` is a superset of the set reachable through the 160
   removed tools, with the two documented exceptions (`license/status`
   deduplicated; the three surviving `_get` siblings). This is the test that
   proves nothing was silently dropped, and it is written first.
2. **Path uniqueness** — no two table rows share an `(api, path)` pair. This
   is what found the `license/status` duplicate.
3. **Surface budget** — `tests/test_tool_surface_budget.py` serialises every
   registered tool exactly as `list_tools()` emits it and asserts the total
   stays under a committed ceiling (26,000 tokens against a measured 25,103,
   leaving deliberate headroom for a few new tools before the number must be
   re-examined). Without it, 45%-boilerplate regression is a single
   copy-paste away.
4. **Annotations** — `EXPECTED_MUTATING` loses the 15 delete aliases and
   gains `fortios_delete`. The AST write-guard needs no change: the nine read
   tools reach only `cmdb_get`/`monitor_get`, `fortios_delete` reaches
   `cmdb_delete` and advertises `DESTRUCTIVE`.
5. **Instance parameter** — the existing ordering guard covers the ten new
   tools with no modification.

## Consequences

Measured, with enum summaries included and `title` stripped:

| | tools | chars | tokens | |
|---|---|---|---|---|
| today | 241 | 227,145 | 56,786 | |
| boilerplate trim alone | 241 | 170,050 | 42,512 | −25% |
| **trim + collapse** | **91** | **100,415** | **25,103** | **−55%** |

Per-tool cost of the ten additions ranges from 241 tokens
(`fortios_delete`) to 812 (`security_read`, 28 values with summaries).

Documentation touched in the same commit, since all of it states counts that
change: `README.md` (`231 typed`, `Total: 241 tools`, `183 of the 241`,
`the 241-tool set`), `tool_annotations.py`'s module and `READ_ONLY`
docstrings, `CLAUDE.md` (`~200 typed convenience tools`, the annotation
convention), and `CONTRIBUTING.md` (adding a resource now means a table row,
not a new tool function).

The last consequence is the most durable one: after this, adding coverage for
a new FortiOS read endpoint is a one-line table row rather than a
thirty-line copy-pasted tool function, and it costs the surface roughly forty
tokens instead of seven hundred.
