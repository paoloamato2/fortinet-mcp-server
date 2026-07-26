# Multi-FortiGate Instance Support — Design

**Date:** 2026-07-26
**Status:** Approved for planning

## Problem

The server binds to exactly one FortiGate. `lifespan` builds a single `FortiOSClient`
from `FORTIOS_HOST` / `FORTIOS_API_TOKEN` and yields it as `{"client": client}`; all 240
tools read it with `ctx.request_context.lifespan_context["client"]`.

Managing N firewalls therefore means running N server processes. Every process advertises
the same 240 tools, so the LLM's context carries the tool set N times — roughly 100k+
tokens of duplication for a handful of firewalls, and no way for the model to know which
process is which box.

## Goal

One server process, many FortiGates. The LLM picks the target per tool call and can see a
short human-readable description of each firewall to pick correctly.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Targeting | Optional `instance` param on all 240 tools | Stateless; safe under parallel calls; target visible in every call. A stateful "select" tool risks config writes landing on the wrong firewall. |
| `instance` omitted | Use it only if exactly one FortiGate is configured; otherwise error listing valid names | Existing single-firewall setups keep working; multi-firewall setups can never silently hit the wrong box. |
| Config source | JSON file via `FORTIOS_INSTANCES_FILE`, with env-var fallback | Readable descriptions, easy to add a firewall, per-instance settings. Fallback preserves today's setups verbatim. |
| Discovery | Roster in MCP `instructions` + a `fortigate_list` tool | Instructions cost no round-trip; the tool covers clients that drop instructions. Per-tool `instance` description stays terse to limit schema bloat. |
| Extras in scope | Per-instance `read_only` guard; `instance="*"` read fan-out | Both land in the client layer and so cover all 240 tools with no per-tool work. |

## Enabling constraint

All 243 client call sites in `tools/*.py` are bare `return await client.<method>(...)`
with **zero post-processing** (verified by grep: 243 direct returns, 0 assignments). This
is what makes the read-only guard and the fan-out possible in the client layer alone.

Two further verified facts shape the rollout: all 240 tools have a `vdom` parameter, and
in 239 of them it is the last parameter (`wifi_vap_create` in `tools/wireless.py` is the
exception, with two params after `vdom`).

## Architecture

Four pieces. Existing three-layer structure and flat package layout are preserved.

```
server.py          builds registry in lifespan, yields {"registry": registry}
                   roster built into instructions at import
instances.py  NEW  InstanceConfig, load_instances(), InstanceRegistry,
                   FortiOSAPI protocol, FanOutClient, ErrorClient
fortios_client.py  + name, + read_only guard on the 6 write methods
tools/*.py         + instance param x240, resolve via registry
tools/fleet.py NEW fortigate_list
```

### 1. Config format

`FORTIOS_INSTANCES_FILE` points at a JSON **array**:

```json
[
  {
    "name": "hq-fw",
    "description": "HQ perimeter FW, Vienna. Prod internet edge + IPsec hub.",
    "host": "https://10.0.0.1",
    "api_token": "...",
    "vdom": "root",
    "read_only": true
  },
  {
    "name": "dc-edge",
    "description": "Datacenter edge, VDOMs per tenant. Change window Sun 02:00.",
    "host": "https://10.9.0.1",
    "api_token_env": "DC_EDGE_TOKEN",
    "verify_ssl": true
  }
]
```

| Field | Required | Default |
|---|---|---|
| `name` | yes | — must match `^[A-Za-z0-9._-]{1,64}$`; `*` is reserved |
| `description` | yes | — rendered verbatim into MCP instructions; 1–2 lines by convention, not enforced |
| `host` | yes | — |
| `api_token` / `api_token_env` | exactly one | — `api_token_env` names an env var holding the token |
| `vdom` | no | `FORTIOS_VDOM`, else `root` |
| `verify_ssl` | no | `FORTIOS_VERIFY_SSL`, else `false` |
| `timeout` | no | `FORTIOS_TIMEOUT`, else `30` |
| `read_only` | no | `false` |

The existing `FORTIOS_VDOM` / `FORTIOS_VERIFY_SSL` / `FORTIOS_TIMEOUT` variables become
fleet-wide defaults for instances that omit the field. This provides global settings
without wrapping the array in an object.

### 2. Config resolution — deliberately strict

- `FORTIOS_INSTANCES_FILE` set → the file **must** exist, parse, and validate. It never
  falls back to `FORTIOS_HOST`. Silent fallback is the dangerous failure mode here:
  believing five firewalls are configured while talking to one.
- `FORTIOS_INSTANCES_FILE` unset → `FORTIOS_HOST` + `FORTIOS_API_TOKEN` form a single
  instance named `default` with description `"Default FortiGate (configured via
  environment variables)."`. Existing deployments work unchanged, and `instance` may be
  omitted because exactly one instance exists.
- Both set → the file wins; a warning is logged that `FORTIOS_HOST` is ignored.

Rejected at startup: unreadable or unparseable file, non-array JSON, empty array,
duplicate names, names failing the charset rule, the literal name `*`, neither or both of
`api_token`/`api_token_env`, and `api_token_env` naming an unset or empty variable.

**Load timing.** `load_instances()` runs twice, by design:

1. **At import, tolerantly** — returns `(configs, errors)` and never raises. Feeds the
   `instructions` roster. Keeps `import server` working with no environment set, which the
   existing `tests/test_server.py` relies on and CLAUDE.md documents.
2. **In `lifespan`, strictly** — raises `EnvironmentError` on any collected error or an
   empty roster, so a misconfigured server refuses to start with a clear message.

Parsing is a file read plus `json.loads`, so doing it twice is free. This avoids mutating
FastMCP internals to inject instructions after construction.

### 3. `fortios_client.py` changes

Add two constructor params: `name: str` and `read_only: bool = False`. The six write
methods — `cmdb_post`, `cmdb_put`, `cmdb_delete`, `monitor_post`, `log_post`,
`service_post` — check the flag before issuing any request:

```python
if self.read_only:
    raise FortiOSError(
        f"Instance '{self.name}' is configured read-only; write operations are refused.",
        403,
    )
```

Read methods (`cmdb_get`, `monitor_get`, `log_get`, `service_get`) are unaffected. No
other changes to this file.

### 4. `InstanceRegistry` and `resolve()`

The registry holds one `FortiOSClient` per configured instance. Constructing an
`httpx.AsyncClient` performs no network I/O, so all clients are built eagerly in `lifespan`
via `contextlib.AsyncExitStack` at no cost, and no lazy-init path is needed.

**`resolve(instance: str | None)` never raises.** In all 240 tools the client lookup sits
*outside* the `try/except FortiOSError`, so a raising resolver would propagate to the MCP
layer — violating CLAUDE.md's "never let it propagate" rule — and avoiding that would mean
surgically relocating 240 varied `try` blocks.

Instead `resolve()` returns one of three objects satisfying a shared `FortiOSAPI` Protocol
that declares the eight API methods (this keeps `pyright` satisfied at the 240 call sites):

- **`FortiOSClient`** — the real client, for a valid single target.
- **`FanOutClient`** — returned for `instance="*"`. Read methods run every configured
  client concurrently via `asyncio.gather(..., return_exceptions=True)` and return
  `{name: response}` in config order; a failed instance contributes
  `{"error": str(exc), "status_code": <code or 0>}` so the per-instance shape matches a
  normal single-call error. Write methods raise `FortiOSError`. Read-only instances are
  included, since reads are permitted on them. The `vdom` argument is passed through
  unchanged to every instance.
- **`ErrorClient`** — a sentinel whose every method raises `FortiOSError` carrying the
  resolution failure.

Every tool's existing `except FortiOSError` then converts all four failure classes into
the standard `{"error": ..., "status_code": ...}` dict through a single path.

Resolution rules:

| `instance` | Configured | Result |
|---|---|---|
| omitted | exactly 1 | that client |
| omitted | 2 or more | `ErrorClient`: `'instance' is required: 3 FortiGates configured. Choose one of: hq-fw, dc-edge, branch-vie` |
| known name | any | that client |
| unknown name | any | `ErrorClient`: `Unknown instance 'hq-fw2'. Configured: hq-fw, dc-edge, branch-vie` |
| `"*"` | any | `FanOutClient` (including the 1-instance case, which yields a 1-key map) |

`instance` is stripped of surrounding whitespace before matching, and an empty or
whitespace-only string is treated exactly as omitted. This keeps a model that passes `""`
from getting an "unknown instance ''" error.

Other error strings:

```
{"error": "Instance 'hq-fw' is configured read-only; write operations are refused.", "status_code": 403}
{"error": "instance='*' fan-out is read-only. Target a single instance for write operations."}
```

### 5. Tool rollout (240 tools)

Applied by an AST-guided script, not `sed`. Two substitutions per tool:

**a) Insert an `instance` param immediately before `vdom`.** Anchoring before `vdom`
rather than appending at the end means `wifi_vap_create` needs no special case, and every
param from `vdom` onward already has a default so the signature stays legal.

```python
instance: Annotated[
    str | None,
    Field(
        default=None,
        description=(
            "Target FortiGate name; see fortigate_list. "
            "Omit if only one is configured. '*' = all (reads only)."
        ),
    ),
] = None,
```

At roughly 22 tokens x 240 tools this adds about **7k tokens once** — against the 100k+
of advertising the tool set N times by running N servers.

**b) Replace the client lookup:**

```python
# before
client: FortiOSClient = ctx.request_context.lifespan_context["client"]
# after
client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(instance)
```

Plus a per-module import fixup: `FortiOSClient` becomes unused in modules that referenced
it only for that annotation and must be dropped to satisfy `ruff`; `FortiOSError` stays;
`FortiOSAPI` is imported from `instances`.

The insertion shifts positional parameter order. This is irrelevant to MCP — FastMCP
always invokes tools with keyword arguments — and there are no direct positional callers,
since every tool is a closure inside its module's `register()`. New tests use keywords.

After the script: `ruff format`, then the full CI gate (`ruff check`,
`ruff format --check`, `pyright`, `pytest`).

### 6. Discovery

**Roster in `instructions`**, built at import from the tolerant load, with read-only status
marked so the LLM does not attempt doomed writes:

```
Configured FortiGates — pass the name as the `instance` parameter on any tool:
- hq-fw — HQ perimeter FW, Vienna. Prod internet edge + IPsec hub. [READ-ONLY]
- dc-edge — Datacenter edge, VDOMs per tenant. Change window Sun 02:00.
Omit `instance` only if exactly one is configured. instance="*" reads from all at once.
```

When the tolerant load yields no instances (as under test), a single generic sentence
replaces the block. The rest of the existing `instructions` text — the tool-category
listing and the closing guidance — is unchanged, except for its opening line, which becomes
"You are connected to one or more Fortinet FortiGates running FortiOS 7.6.6." in place of
today's singular phrasing.

**`tools/fleet.py`** — a new module imported and registered in `server.py`, exposing one
tool:

`fortigate_list(check_health: bool = False)` returns `name`, `description`, `host`,
`vdom`, and `read_only` per instance. It never returns `api_token` values. With
`check_health=True` it issues a concurrent `monitor_get("system/status")` per instance —
the endpoint already used by `tools/system.py:38` — adding `reachable`, `version`, and
`serial`, or `error` on failure. Health checks are reads, so `read_only` instances are
included.

It takes no `instance` param, being a meta tool over the whole fleet. It reaches the
registry the same way every other tool does —
`ctx.request_context.lifespan_context["registry"]` — but iterates the registry's instances
directly rather than calling `resolve()`.

## Error handling summary

| Condition | Surfaces as |
|---|---|
| Config invalid / file missing when var set | `EnvironmentError` at `lifespan`; server refuses to start |
| `instance` omitted, 2+ configured | error dict listing valid names; no HTTP issued |
| Unknown instance name | error dict listing valid names; no HTTP issued |
| Write on a `read_only` instance | error dict, `status_code: 403`; no HTTP issued |
| Write with `instance="*"` | error dict; no HTTP issued |
| Fan-out, some instances fail | keyed map with per-instance error entries alongside successes |
| FortiOS API error | unchanged from today |

## Testing

- **`load_instances()`** — file happy path; env fallback produces one instance named
  `default`; `FORTIOS_INSTANCES_FILE` set but file missing raises; non-array JSON; empty
  array; duplicate names; invalid name charset; literal `*` as a name; both and neither of
  `api_token`/`api_token_env`; `api_token_env` resolved, and unset variable raises;
  `FORTIOS_*` defaults inherited by instances that omit the field.
- **`resolve()`** — one instance and omitted; three and omitted yields `ErrorClient` with
  the required-param message; unknown name; `"*"` yields `FanOutClient`; known name yields
  the correct client.
- **read-only guard** — each of the six write methods raises with status 403 *and*
  pytest-httpx records zero requests; the four read methods are unaffected.
- **fan-out** — two mocked instances return a keyed map; one failing instance produces a
  partial map with an error entry beside the success; a write method raises.
- **tool level, via pytest-httpx** — `cmdb_list(instance="dc-edge")` reaches only
  dc-edge's host; omitting `instance` with two configured returns an error dict with no
  HTTP issued; `instance="*"` returns a keyed map. The same three assertions against one
  typed firewall tool.
- **`fortigate_list`** — returns descriptions and never leaks a token; `check_health=True`
  marks a mocked-unreachable instance as failed without failing the call.
- **guard test** — AST-walks `tools/*.py` and fails if any `@mcp.tool()` function lacks an
  `instance` param, or if any `lifespan_context["client"]` reference remains. Protects the
  invariant for tools added later. `tools/fleet.py` is exempt from the `instance`-param
  check via an explicit module allow-list in the test, since its tools are fleet-wide
  meta tools by design; the allow-list is asserted to contain only `fleet.py` so a new
  module cannot quietly join it.
- **regression** — `tests/test_server.py::test_mcp_instance_name` keeps passing with no
  environment set.

## Docs

- `README.md` — multi-instance configuration section, the `instance` param, `read_only`,
  and `instance="*"`.
- `.env.example` — `FORTIOS_INSTANCES_FILE`, noting the single-instance variables remain
  supported.
- `fortigates.example.json` — new, a two-instance example.
- `.gitignore` — ignore a real `fortigates.json`, since it holds tokens.
- `CLAUDE.md` — update the tool conventions: new tools take an `instance` param and resolve
  the client via `registry.resolve(instance)`; note the lifespan context key changed from
  `client` to `registry`.

## Out of scope

- Fan-out for write operations. Reads only, by design.
- Credential stores beyond `api_token_env` (Vault, cloud secret managers).
- Per-instance concurrency limits or rate limiting; `asyncio.gather` over the fleet
  unbounded is acceptable at the expected scale of tens of firewalls.
- FortiManager as an aggregation layer.
