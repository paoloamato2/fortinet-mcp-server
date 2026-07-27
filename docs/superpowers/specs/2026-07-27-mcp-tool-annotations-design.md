# MCP Tool Annotations — Design

**Date:** 2026-07-27
**Status:** Approved for planning

## Problem

All 241 tools are declared with a bare `@mcp.tool()`, so none of them ship
`ToolAnnotations`. On the wire that is not neutral. The MCP spec's defaults are
`readOnlyHint=false`, `destructiveHint=true`, `idempotentHint=false` — so today an
unannotated `system_status` advertises *"may modify its environment, possibly
destructively, and is not safe to repeat"*.

A client that gates auto-approval on those hints therefore cannot tell a status read from
`firewall_policy_delete`, and the useful behaviour (approve readers freely, confirm
writers) collapses into confirming everything or confirming nothing. On a server whose
write surface includes deleting firewall policies on a production perimeter device, that
is the wrong failure mode.

## Goal

Every tool advertises what a call will actually do, and the classification is enforced by
a test rather than by reviewer attention.

## Enabling constraint

The write surface is derivable mechanically, not from tool names. `FortiOSClient` exposes
exactly six mutating methods — `cmdb_post`, `cmdb_put`, `cmdb_delete`, `monitor_post`,
`log_post`, `service_post` — and an AST walk over `tools/*.py` shows **59 of 241 tools
reach one of them**. The same walk finds no name/behaviour mismatch in either direction:
no tool whose name implies a write avoids the write methods, and the only three that write
without a writerly name are `monitor_action`, `service_call` and `monitor_network_ping`,
all three handled explicitly below.

Reaching a write method is the starting point, not the classification: **58 of those 59
are classified as writers.** `monitor_network_ping` is the single deliberate exception —
it POSTs but changes nothing — so the frozen non-read-only set in contract 3 below holds
58 names, against 183 readers.

This is what makes the frozen list in the contract test cheap to keep honest: the
classification can be re-derived and diffed at any time.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Read-only line | Stored config **and** live session state left as found | A dropped session is unrecoverable even though no config changed. Verb-based classification would call `monitor_network_ping` a write and `wifi_wtp_deauthorize` a read; both are wrong. |
| `openWorldHint` | `True` on every tool, no exceptions | Every tool reaches a FortiGate over the network. `fortigate_list` opens sockets when `check_health=True`, so no tool qualifies as in-process — hence no `READ_ONLY_LOCAL` category. |
| Category count | 5, all pairwise distinct on the wire | Two names for one hint combination would make the category a comment rather than a contract. |
| All four hints | Set explicitly on all 5 categories | `destructiveHint` defaults to *true*, so omitting it on a reader tells any client reading that field without first checking `readOnlyHint` that `system_status` may destroy things. |
| Enforcement | Frozen non-read-only name set **plus an AST-derived behaviour guard** | The frozen set alone only fails once an *annotation* has already gone wrong — a writer mis-annotated `READ_ONLY`, or an unreviewed name appearing among the writers. It cannot see a tool's body, so it does not by itself fail when a reader's implementation quietly starts calling a write method while its `@mcp.tool(annotations=...)` line is untouched. That gap is closed by re-deriving, via AST, which tools call one of the six write methods and cross-checking that derivation against the registered annotations (see Enforcement below). |
| Module location | Top-level `tool_annotations.py` | Matches the flat layout (`instances.py`, `fortios_client.py`). Imports nothing from the package, so no cycle with `tools/*`. |

## Categories

```text
tool_annotations.py  NEW  five ToolAnnotations constants + CATEGORIES registry
tools/*.py                + import, + annotations=... on 241 decorator sites
tests/test_tool_annotations.py  NEW  contracts, incl. an AST-derived behaviour guard (see Enforcement)
CONTRIBUTING.md           + the convention, under "Adding a new MCP tool"
```

| Category | readOnly | destructive | idempotent | openWorld | n |
|---|---|---|---|---|---|
| `READ_ONLY` | `True` | `False` | `True` | `True` | 183 |
| `CREATES` | `False` | `False` | `False` | `True` | 21 |
| `UPDATES` | `False` | `False` | `True` | `True` | 1 |
| `DESTRUCTIVE` | `False` | `True` | `True` | `True` | 34 |
| `UNCONSTRAINED` | `False` | `True` | `False` | `True` | 2 |

- **`READ_ONLY`** — every `*_list`/`*_get`/`*_status` tool, the log-retrieval tools (all
  GETs; unlike FortiAnalyzer there is no server-side task handle to argue about) —
  17 of the 18 tools named `log_*`; the one that writes is
  `log_fortianalyzer_setting_update`, a `cmdb_put` classified `DESTRUCTIVE` below — and
  `fortigate_list`.
- **`CREATES`** — the 21 `cmdb_post` callers. Additive, so not destructive; a repeat call
  adds a second object or fails on a duplicate key, so not idempotent.
- **`UPDATES`** — reversible operational flip that tears nothing down. Exactly one member.
- **`DESTRUCTIVE`** — removes state, or replaces it with no recovery path.
- **`UNCONSTRAINED`** — dispatches to a caller-chosen endpoint; hints are the union of
  everything reachable.

## Where the lines fall

Six calls a reviewer is most likely to re-open. Each is deliberate.

**`monitor_network_ping` is `READ_ONLY`** despite being the single POST among the readers.
It emits ICMP from the device and returns timings; nothing on the FortiGate changes.
Classifying by HTTP verb instead of by effect would put a diagnostic behind a confirmation
prompt while leaving `wifi_wtp_deauthorize` (below) looking like a read.

The trade-off is worth stating rather than only asserting the device-state side, though.
`READ_ONLY` is also the category most likely to be auto-approved by a client without a
human in the loop, and `monitor_network_ping` gives such a client a caller-directed ICMP
emitter — both `destination` and `count` are caller-supplied arguments — a low-bandwidth
probe primitive reachable from inside the perimeter with no confirmation step. The
classification stands: the device genuinely is unchanged, on every hint MCP defines.
`openWorldHint=true` is the only signal that this "read" reaches past the FortiGate
itself, and it is set on every category, so it does not single this tool out either.

**All 14 `*_update` tools are `DESTRUCTIVE`, not `UPDATES`.** FortiOS `cmdb_put` is
full-object replacement — after the call the prior value is unrecoverable. That is exactly
what the spec means by a destructive update as opposed to an additive one. This is the
decision with the widest blast radius (it makes routine config edits such as
`system_ntp_update` advertise `destructiveHint=true`) and it is accepted: a client cannot
undo a PUT, so it should ask.

**`firewall_policy_move` is `DESTRUCTIVE`.** It is a `cmdb_put` with `action=move` and
changes no object's contents, but on a firewall the policy *order* is the semantics — a
reorder can silently expose or blackhole traffic, and the call carries no way back to the
previous ordering.

**The four teardown actions are `DESTRUCTIVE`** — `monitor_firewall_session_close`,
`monitor_user_disconnect`, `monitor_vpn_ssl_delete_user`, `monitor_vpn_ipsec_tunnel_down`.
No stored config changes, but dropped sessions do not come back, which is the point of the
read-only line above. They are idempotent: closing an already-closed session is a no-op.

**`monitor_vpn_ipsec_tunnel_up` is the sole `UPDATES`** — reversible, idempotent, and the
twin of `tunnel_down`. A one-member category is deliberate rather than an accident of
counting: it is the only tool that flips reversible operational state without tearing
anything down, and collapsing it into `DESTRUCTIVE` would advertise that bringing a tunnel
up destroys something.

**`monitor_action` and `service_call` are `UNCONSTRAINED`, by reachability.** Their bodies
only forward a caller-supplied path, but `monitor_action` reaches `system/os/reboot` and
`service_call(method="POST")` reaches `sniffer/start`. Their hints must be the union of
everything they can dispatch to. Letting either inherit `READ_ONLY` would be the single
most misleading annotation in the server: one tool advertising "changes nothing" while
exposing every mutating endpoint in FortiOS behind a string argument.

**`cmdb_list`, `cmdb_get`, `monitor_get`, and `log_get` stay `READ_ONLY` despite also
taking a caller-supplied path, for the opposite reason.** `FortiOSClient` pins the HTTP
verb per method — each of these four calls `client.get(...)` unconditionally, with no
branch that could turn it into a POST, PUT, or DELETE — so no path or params a caller
supplies can escape GET, and FortiOS exposes no mutating operation behind GET in the
cmdb, monitor, or log sections. That pinned verb is the load-bearing assumption behind
classifying these four `READ_ONLY` instead of `UNCONSTRAINED`; it is what `monitor_action`
and `service_call` (above) lack, since both of *their* bodies choose the verb (or take it
from the caller) rather than have it fixed by the method they call.

**`wifi_wtp_deauthorize` is `DESTRUCTIVE` because it is a `cmdb_delete`** — it removes the
WTP configuration entry rather than performing an operational deauth. The name reads
operational and the behaviour is a config delete, so the declaration site gets a comment
saying so.

## Accepted limits

Three things these hints do not express, recorded so they are not mistaken for oversights:

- **`monitor_system_config_backup` is not the only `READ_ONLY` tool that returns
  credential material.** It returns the entire device configuration, including secrets,
  but it is one of several: `system_admin_list`/`system_admin_get`,
  `user_local_list`/`user_local_get`, `vpn_ipsec_phase1_list`/`vpn_ipsec_phase1_get`
  (`psksecret`), and especially `system_snmp_community_list` — where the community name
  *is* the secret — are all `READ_ONLY` readers that return sensitive values too. Every
  one of these is correct on every hint field — the device is unchanged by any of them —
  but MCP has no hint for "returns sensitive data", so a gating client cannot distinguish
  any of them from `system_time_get`. If that distinction is ever needed it is a new
  category and an update to this spec, not a reinterpretation of the existing hints, and
  not a change scoped to the backup tool alone.
- **Annotations are static per tool and cannot reflect per-instance `read_only: true`.** A
  `DESTRUCTIVE` tool aimed at a read-only instance still advertises destructive, then
  errors via `ErrorClient`. Making the hint dynamic is not possible: annotations are
  published once at registration, before any `instance` argument exists.
- **Fan-out and the annotation are two different definitions of "read-only", and they
  disagree on one tool.** `FanOutClient` refuses all six write methods (verified: every one
  of `cmdb_post`, `cmdb_put`, `cmdb_delete`, `monitor_post`, `log_post`, `service_post` on
  `FanOutClient` calls `_refuse()`), and `FortiOSClient._write_guard()` refuses the same six
  on any instance configured `read_only: true`. It does **not** follow that `instance="*"`
  can only ever reach `READ_ONLY` tools, nor that every `READ_ONLY` tool survives fan-out or
  a read-only instance:
  - `service_call` is `UNCONSTRAINED`, yet `service_call(method="GET", ...)` works under
    `instance="*"` — `FanOutClient.service_get` fans out — because the annotation
    classifies the tool, not any one call it can make.
  - `monitor_network_ping` is `READ_ONLY`, yet it is refused under `instance="*"`
    (`FanOutClient.monitor_post` → `_refuse()`) and on any `read_only: true` instance
    (`FortiOSClient.monitor_post` → `_write_guard()` → HTTP 403), because both guards key
    on the HTTP method the tool calls, not on whether that call changes anything. See
    `tests/test_client_readonly.py:40` and `tests/test_registry_fanout.py:115`, which both
    list `monitor_post` as a write — the codebase's settled position, and the more
    conservative of this server's two definitions of read-only.

  So the annotation is the more permissive of the two: `READ_ONLY` says nothing changes on
  the device, while the write guard and fan-out both say "anything that POSTs is refused,"
  and `monitor_network_ping` is the one tool where those disagree. No behaviour changes
  here — whether the write guard should carve out an exemption for a POST that changes
  nothing is a **known follow-up**, out of scope for this branch. No fan-out-specific
  category either way: reachability under fan-out is not itself a hint MCP defines.

## Enforcement

`tests/test_tool_annotations.py`. `from server import mcp` already works without
`FORTIOS_HOST`/`FORTIOS_API_TOKEN` (validated only at lifespan startup), and this server
has no dynamic tool mode, so the registry is reachable with a plain import — none of
fortianalyzer's module-reload machinery is needed.

Several contracts, deliberately not collapsed into one assertion so a failure names its own
cause:

1. **Every registered tool has annotations with all four fields non-`None`.** Catches a
   new tool added with a bare `@mcp.tool()`.
2. **Every tool's hints are identical to an approved `CATEGORIES` entry.** Catches a
   hand-rolled `ToolAnnotations(...)` combination nobody reviewed.
3. **The set of non-read-only tool names equals a frozen expectation, and each carries its
   expected category.** Fails when a writer is mis-annotated `READ_ONLY`, and equally when
   a tool's *annotation* changes to non-read-only without a matching, reviewed entry being
   added to the frozen list. This contract reads `tool.annotations` only — it does **not**
   read what a tool's body does, so a reader whose implementation starts calling a write
   method while its decorator is left alone passes this contract unchanged. That is a real
   gap the branch shipped with; contract 6 closes it.
4. **`openWorldHint` is `True` on every tool.** No exceptions are permitted, so a future
   in-process tool has to come back to this spec.
5. **The five categories are pairwise distinct, `CATEGORIES` matches `__all__`, the
   registry has exactly five entries, and every category is carried by at least one
   registered tool.** Keeps the registry from drifting behind the module's public
   constants. The count and membership checks exist because `test_mutating_set_is_frozen`
   keys off `readOnlyHint is not True`: a hand-added sixth category that still sets
   `readOnlyHint=True` would never appear in that contract's comparison set, so it could
   sit in `CATEGORIES` unused by any tool and unchecked against `EXPECTED_MUTATING`
   indefinitely without either of these two checks.
6. **An AST-derived behaviour guard.** `tests/test_tool_annotations.py` walks `tools/*.py`
   with `ast`, finds every function decorated `@mcp.tool`, and collects which of the six
   write methods (`WRITE_METHODS`) each one calls via `client.<attr>(...)`. Every tool that
   reaches a write method — except the single exemption `monitor_network_ping`
   (`POSTS_WITHOUT_MUTATING`, pinned by its own test the same way
   `tests/test_tools_have_instance_param.py` pins `MODULES_WITHOUT_INSTANCE_PARAM`) — must
   not be annotated `readOnlyHint=True`; and, conversely, every name in
   `EXPECTED_MUTATING` must actually reach a write method, catching a stale entry left
   behind by a rename or refactor. This is the contract that fails when a reader gains
   write semantics: it does not depend on the annotation having already been touched,
   because it re-derives the write surface from the tool's own source rather than from
   its decorator.

The existing `test_expected_number_of_tools_is_registered` (241) stays as-is and keeps
contract 3 from going vacuous — a frozen write-surface assertion proves nothing if the
tools never registered. Contract 6 carries the equivalent guard for itself: it asserts the
AST walk found all 241 `@mcp.tool` functions before deriving anything from it.

Adding a mutating tool then requires editing the frozen list in the same commit. That edit
is the review prompt, and it is the point.

## Consequences

No tool's behaviour changes; annotations are advertisement only. The cost is one line per
declaration site across 241 sites and a frozen list that must be maintained — accepted,
because a wrong hint is now a safety bug rather than a cosmetic one.

The convention goes in `CONTRIBUTING.md` under the existing "Adding a new MCP tool"
checklist. It deliberately does **not** go in `CLAUDE.md`: that file is untracked in this
repo (listed in `.git/info/exclude`), so a note there would never reach a contributor.
