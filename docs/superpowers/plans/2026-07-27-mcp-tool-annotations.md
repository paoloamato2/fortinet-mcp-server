# MCP Tool Annotations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give all 241 MCP tools accurate `ToolAnnotations`, enforced by a contract test that fails when a writer is mis-annotated as a reader.

**Architecture:** A new top-level `tool_annotations.py` defines five `ToolAnnotations` constants and a `CATEGORIES` registry. Each of the 241 `@mcp.tool()` decorator sites in `tools/*.py` gains an `annotations=` argument naming one constant. `tests/test_tool_annotations.py` freezes the classification with five independent contracts, the load-bearing one being a frozen set of the 58 non-read-only tool names that fails in both directions.

**Tech Stack:** Python 3.11+, `mcp[cli]` (FastMCP, `mcp.types.ToolAnnotations`), pytest, ruff, pyright, uv.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-27-mcp-tool-annotations-design.md`. Read it before Task 1.
- Ruff format: 88-column lines, double quotes. `uv run ruff format .` must leave the tree unchanged (CI runs `ruff format --check .`).
- Ruff lint runs with **default rules**, which include `F401` unused-import. Each `tools/*.py` must import exactly the category constants it uses — no more.
- Full type hints on public functions. Google-style docstrings.
- Conventional Commits: `feat|fix|docs|test|refactor|chore|security(scope): summary`.
- `openWorldHint` is `True` on every category. No exceptions.
- All four hint fields (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) are set explicitly on every category. `ToolAnnotations` also has a `title` field; leave it unset.
- Do **not** stage `CLAUDE.md`, `.claude/`, `.mcp.json`, or `fortigates.local.json`. They are in `.git/info/exclude`. Verify with `git diff --cached --name-only` before every commit.
- Branch: `feat/tool-annotations` (already created, already holds the spec commit).
- Never edit `tests/test_tools_have_instance_param.py`. Its 241-tool count is what keeps Task 2's contracts from going vacuous.

---

### Task 1: The category module

**Files:**
- Create: `tool_annotations.py`
- Test: `tests/test_tool_annotations.py`

**Interfaces:**
- Consumes: `mcp.types.ToolAnnotations` (pydantic model; supports `==`).
- Produces: module `tool_annotations` exporting `READ_ONLY`, `CREATES`, `UPDATES`, `DESTRUCTIVE`, `UNCONSTRAINED` (all `ToolAnnotations`), plus `CATEGORIES: dict[str, ToolAnnotations]` and `__all__`. Tasks 2 and 3 import these by name.

- [ ] **Step 1: Write the failing test**

Create `tests/test_tool_annotations.py` with only the module-level contracts. Registry contracts arrive in Task 2.

```python
"""Contract tests for MCP tool annotations.

Annotations are advertisement: a client reads them to decide what it may
auto-approve, what it must confirm and what it should surface to a human.
A wrong hint is therefore a safety bug -- a tool that reconfigures a
production firewall while advertising ``readOnlyHint=true`` is precisely
the failure a gating client cannot defend against. These tests exist so
that failure has to be made deliberately.

See ``docs/superpowers/specs/2026-07-27-mcp-tool-annotations-design.md``
for where the read-only line falls and why.
"""

from __future__ import annotations

import tool_annotations
from tool_annotations import CATEGORIES, READ_ONLY

#: The four hint fields the MCP spec defines. ``ToolAnnotations`` also has
#: ``title``, which is a display string rather than a safety hint and is
#: deliberately left unset.
HINT_FIELDS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def test_categories_are_pairwise_distinct() -> None:
    """No two named categories may carry the same four hints.

    Two names for one hint combination would make the category a comment
    rather than a contract: the identity check in
    ``test_every_tool_uses_an_approved_category`` could not tell which one
    a tool meant, and a reviewer reading ``UPDATES`` would have no
    guarantee it differs from ``CREATES`` on the wire.
    """
    seen: dict[tuple[object, ...], str] = {}
    for name, ann in CATEGORIES.items():
        key = tuple(getattr(ann, field) for field in HINT_FIELDS)
        assert key not in seen, f"{name} duplicates {seen[key]}: {key}"
        seen[key] = name


def test_every_category_sets_all_four_hints() -> None:
    """Including the two the spec calls meaningful only for writers.

    ``destructiveHint`` defaults to *true* on the wire, so a reader that
    omits it advertises "may perform destructive updates" to any client
    that reads the field without checking ``readOnlyHint`` first.
    """
    for name, ann in CATEGORIES.items():
        for field in HINT_FIELDS:
            assert getattr(ann, field) is not None, f"{name}.{field} is None"


def test_open_world_is_true_everywhere() -> None:
    """Every tool reaches a FortiGate, so no category may claim otherwise.

    This server has no in-process tool: ``fortigate_list`` opens a socket
    per instance when ``check_health=True``. A future closed-world tool
    must come back to the design doc rather than add a category here.
    """
    for name, ann in CATEGORIES.items():
        assert ann.openWorldHint is True, f"{name} does not advertise an open world"


def test_all_exported_categories_are_in_the_registry() -> None:
    """``CATEGORIES`` must not drift behind the module's public constants."""
    exported = {
        name
        for name in tool_annotations.__all__
        if name != "CATEGORIES"
        and isinstance(getattr(tool_annotations, name), type(READ_ONLY))
    }
    assert exported == set(CATEGORIES), (
        f"exported constants {sorted(exported)} != CATEGORIES keys {sorted(CATEGORIES)}"
    )
    # Registry values must be the constants themselves, not copies.
    assert CATEGORIES["READ_ONLY"] is READ_ONLY
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_tool_annotations.py -v`
Expected: FAIL at collection — `ModuleNotFoundError: No module named 'tool_annotations'`

- [ ] **Step 3: Write the implementation**

Create `tool_annotations.py`:

```python
"""MCP tool annotation categories (spec ``ToolAnnotations``).

Every registered tool declares one of the constants below via
``@mcp.tool(annotations=...)``. Annotations are advertisement only -- they
change nothing about how a tool runs, they tell a client what a call is
going to do so it can decide what to auto-approve, what to confirm and
what to surface. A wrong hint is therefore a safety bug, not a cosmetic
one, and ``tests/test_tool_annotations.py`` freezes the classification.

This module sits at package top level next to ``instances.py`` and
``fortios_client.py``, matching the flat layout. It imports nothing from
the project, so ``server.py`` and every module under ``tools/`` can reach
it with no cycle and no side effect.

All four hint fields are set explicitly on every category, including the
two the spec calls meaningful "only when ``readOnlyHint`` is false".
``destructiveHint`` **defaults to true** on the wire, so omitting it on a
reader means a client that reads that field without first checking
``readOnlyHint`` sees "may perform destructive updates" on
``system_status``. Explicit ``False`` costs one line and can only narrow
what a client believes a reader might do.

Where the read-only line falls (recorded in full, with the six boundary
calls, in ``docs/superpowers/specs/2026-07-27-mcp-tool-annotations-design.md``):
a tool is read-only when a call leaves both the FortiGate's stored
configuration *and* its live session state as it found them. Two
consequences worth stating outright:

- **HTTP verb does not decide it.** ``monitor_network_ping`` POSTs and is
  ``READ_ONLY`` -- it emits ICMP and returns timings, changing nothing on
  the device. ``wifi_wtp_deauthorize`` reads operational and is
  ``DESTRUCTIVE`` -- it is a ``cmdb_delete`` that removes the WTP entry.
- **Live state counts as state.** Closing sessions or dropping a tunnel
  changes no stored config, but the dropped sessions are unrecoverable,
  so those tools are ``DESTRUCTIVE`` rather than ``UPDATES``.
"""

from mcp.types import ToolAnnotations

#: Reads a FortiGate and changes nothing on it. The default for this
#: server: 183 of 241 tools, every ``*_list``/``*_get``/``*_status``, all
#: 16 ``log_*`` tools, ``monitor_system_config_backup``,
#: ``monitor_network_ping`` and ``fortigate_list``.
READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

#: Adds new configuration to a FortiGate (``cmdb_post``). Additive, so not
#: destructive; a repeat call adds a second object or fails on a duplicate
#: key, so not idempotent.
CREATES = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

#: Flips reversible operational state without tearing anything down. Not
#: destructive because nothing is lost, and idempotent because repeating
#: it is a no-op. Exactly one member -- ``monitor_vpn_ipsec_tunnel_up``,
#: the twin of ``monitor_vpn_ipsec_tunnel_down``.
UPDATES = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

#: Removes FortiGate state, or replaces it with no recovery path. Deletes
#: obviously; also every ``cmdb_put``, because FortiOS PUT is full-object
#: replacement and the prior value is unrecoverable afterwards, which is
#: what "destructive update" means in the spec as opposed to "additive
#: only"; also ``firewall_policy_move``, because policy order is the
#: firewall's semantics and the call carries no way back; also the four
#: teardown actions, whose dropped sessions do not come back.
DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=True,
)

#: Dispatches to a caller-chosen endpoint, so the hints must be the union
#: of everything reachable. ``monitor_action`` reaches
#: ``system/os/reboot``; ``service_call(method="POST")`` reaches
#: ``sniffer/start``. Inheriting ``READ_ONLY`` here would be the single
#: most misleading annotation in the server: one tool advertising "changes
#: nothing" while exposing every mutating endpoint behind a string.
UNCONSTRAINED = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

#: Every approved category, by name. The annotation contract test asserts
#: each registered tool's annotations equal one of these, so a new tool
#: cannot introduce an unreviewed hint combination by hand.
CATEGORIES: dict[str, ToolAnnotations] = {
    "READ_ONLY": READ_ONLY,
    "CREATES": CREATES,
    "UPDATES": UPDATES,
    "DESTRUCTIVE": DESTRUCTIVE,
    "UNCONSTRAINED": UNCONSTRAINED,
}

__all__ = [
    "CATEGORIES",
    "CREATES",
    "DESTRUCTIVE",
    "READ_ONLY",
    "UNCONSTRAINED",
    "UPDATES",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_tool_annotations.py -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Lint, format and type-check**

Run: `uv run ruff format . && uv run ruff check . && uv run pyright`
Expected: format reports the two new files unchanged or reformats them; check passes; pyright passes.

- [ ] **Step 6: Commit**

```bash
git add tool_annotations.py tests/test_tool_annotations.py
git diff --cached --name-only   # must list exactly those two files
git commit -m "feat(annotations): add MCP tool annotation categories"
```

---

### Task 2: Freeze the classification

Adds the four registry contracts. They fail against the current unannotated tree — that failure is the red for Task 3. A reviewer can reject this frozen list (the classification itself) while accepting Task 3's mechanical edit, which is why they are separate tasks.

**Files:**
- Modify: `tests/test_tool_annotations.py` (append; keep Task 1's tests)

**Interfaces:**
- Consumes: `tool_annotations.{CATEGORIES, CREATES, DESTRUCTIVE, READ_ONLY, UNCONSTRAINED, UPDATES}`; `server.mcp`.
- Produces: `EXPECTED_MUTATING: dict[str, ToolAnnotations]` — 58 entries. Task 3 must make the tree satisfy it exactly.

- [ ] **Step 1: Extend the imports and add the frozen list**

Replace the import block in `tests/test_tool_annotations.py` with:

```python
from __future__ import annotations

from typing import Any

import pytest

import tool_annotations
from server import mcp
from tool_annotations import (
    CATEGORIES,
    CREATES,
    DESTRUCTIVE,
    READ_ONLY,
    UNCONSTRAINED,
    UPDATES,
)
```

Then add below `HINT_FIELDS`:

```python
#: Every tool that changes FortiGate state, and the category it must
#: carry. Adding a mutating tool means adding it here in the same commit;
#: that is the point of the list. ``monitor_network_ping`` is deliberately
#: absent -- it POSTs but changes nothing on the device.
EXPECTED_MUTATING: dict[str, Any] = {
    # firewall.py
    "firewall_address_create": CREATES,
    "firewall_address_delete": DESTRUCTIVE,
    "firewall_address_update": DESTRUCTIVE,
    "firewall_addrgrp_create": CREATES,
    "firewall_addrgrp_delete": DESTRUCTIVE,
    "firewall_ippool_create": CREATES,
    "firewall_policy_create": CREATES,
    "firewall_policy_delete": DESTRUCTIVE,
    "firewall_policy_move": DESTRUCTIVE,
    "firewall_policy_update": DESTRUCTIVE,
    "firewall_service_create": CREATES,
    "firewall_vip_create": CREATES,
    "firewall_vip_delete": DESTRUCTIVE,
    "monitor_firewall_session_close": DESTRUCTIVE,
    # generic.py
    "cmdb_create": CREATES,
    "cmdb_delete": DESTRUCTIVE,
    "cmdb_update": DESTRUCTIVE,
    "monitor_action": UNCONSTRAINED,
    "service_call": UNCONSTRAINED,
    # log.py
    "log_fortianalyzer_setting_update": DESTRUCTIVE,
    # router.py
    "router_bgp_update": DESTRUCTIVE,
    "router_static_create": CREATES,
    "router_static_delete": DESTRUCTIVE,
    "router_static_update": DESTRUCTIVE,
    # security.py
    "antivirus_profile_create": CREATES,
    "ips_sensor_create": CREATES,
    "ips_sensor_delete": DESTRUCTIVE,
    # system.py
    "system_admin_create": CREATES,
    "system_admin_delete": DESTRUCTIVE,
    "system_dhcp_server_create": CREATES,
    "system_dns_update": DESTRUCTIVE,
    "system_global_update": DESTRUCTIVE,
    "system_interface_create": CREATES,
    "system_interface_delete": DESTRUCTIVE,
    "system_interface_update": DESTRUCTIVE,
    "system_ntp_update": DESTRUCTIVE,
    # user.py
    "monitor_user_disconnect": DESTRUCTIVE,
    "user_group_create": CREATES,
    "user_group_delete": DESTRUCTIVE,
    "user_ldap_create": CREATES,
    "user_local_create": CREATES,
    "user_local_delete": DESTRUCTIVE,
    "user_local_update": DESTRUCTIVE,
    "user_radius_create": CREATES,
    # vpn.py
    "monitor_vpn_ipsec_tunnel_down": DESTRUCTIVE,
    "monitor_vpn_ipsec_tunnel_up": UPDATES,
    "monitor_vpn_ssl_delete_user": DESTRUCTIVE,
    "vpn_ipsec_phase1_create": CREATES,
    "vpn_ipsec_phase1_delete": DESTRUCTIVE,
    "vpn_ipsec_phase1_update": DESTRUCTIVE,
    "vpn_ipsec_phase2_create": CREATES,
    "vpn_ipsec_phase2_delete": DESTRUCTIVE,
    "vpn_ssl_portal_create": CREATES,
    "vpn_ssl_portal_delete": DESTRUCTIVE,
    "vpn_ssl_settings_update": DESTRUCTIVE,
    # wireless.py
    "wifi_vap_create": CREATES,
    "wifi_vap_delete": DESTRUCTIVE,
    "wifi_wtp_deauthorize": DESTRUCTIVE,
}
```

- [ ] **Step 2: Add the registry fixture and the four contracts**

Append to `tests/test_tool_annotations.py`:

```python
@pytest.fixture(scope="module")
def tools() -> dict[str, Any]:
    """Every registered tool, by name.

    ``server`` validates ``FORTIOS_HOST``/``FORTIOS_API_TOKEN`` only at
    lifespan startup, so importing it here needs no environment and opens
    no connection. This server has no dynamic tool mode, so one import
    reaches the whole surface.
    """
    return {tool.name: tool for tool in mcp._tool_manager.list_tools()}


def test_the_frozen_list_covers_the_whole_write_surface(
    tools: dict[str, Any],
) -> None:
    """Guard the premise of every assertion below.

    A frozen write-surface test proves nothing if the tools never
    registered, so pin the total. ``tests/test_tools_have_instance_param.py``
    pins the same 241 by AST; this pins it at the registry.
    """
    assert len(tools) == 241, f"registered {len(tools)} tools, expected 241"
    assert len(EXPECTED_MUTATING) == 58, (
        f"EXPECTED_MUTATING holds {len(EXPECTED_MUTATING)} names, expected 58"
    )


def test_every_tool_is_annotated(tools: dict[str, Any]) -> None:
    """Catches a new tool added with a bare ``@mcp.tool()``."""
    for name, tool in tools.items():
        ann = tool.annotations
        assert ann is not None, f"{name} has no annotations (bare @mcp.tool()?)"
        for field in HINT_FIELDS:
            assert getattr(ann, field) is not None, f"{name}.{field} is None"


def test_every_tool_uses_an_approved_category(tools: dict[str, Any]) -> None:
    """Hints must match a reviewed category exactly, not merely be plausible."""
    approved = {
        tuple(getattr(ann, field) for field in HINT_FIELDS): name
        for name, ann in CATEGORIES.items()
    }
    for name, tool in tools.items():
        key = tuple(getattr(tool.annotations, field) for field in HINT_FIELDS)
        assert key in approved, (
            f"{name} carries an unapproved hint combination {key}; add a category "
            f"to tool_annotations.CATEGORIES instead of hand-rolling ToolAnnotations"
        )


def test_mutating_set_is_frozen(tools: dict[str, Any]) -> None:
    """The write surface is exactly EXPECTED_MUTATING -- no more, no less."""
    actual = {
        name for name, tool in tools.items() if tool.annotations.readOnlyHint is not True
    }
    expected = set(EXPECTED_MUTATING)

    unexpected = actual - expected
    assert not unexpected, (
        f"tool(s) {sorted(unexpected)} became non-read-only; if that is intended, "
        f"add them to EXPECTED_MUTATING with a reviewed category"
    )
    missing = expected - actual
    assert not missing, (
        f"tool(s) {sorted(missing)} mutate a FortiGate but no longer advertise it; "
        f"a writer annotated READ_ONLY is the dangerous direction of this bug"
    )


def test_mutating_categories_match(tools: dict[str, Any]) -> None:
    for name, expected in EXPECTED_MUTATING.items():
        assert name in tools, f"{name} is no longer registered"
        assert tools[name].annotations == expected, (
            f"{name}: expected {expected!r}, got {tools[name].annotations!r}"
        )


def test_no_tool_claims_a_closed_world(tools: dict[str, Any]) -> None:
    """Anything that reaches a FortiGate must advertise an open world."""
    closed = sorted(
        name for name, tool in tools.items() if tool.annotations.openWorldHint is False
    )
    assert closed == [], (
        f"tool(s) {closed} claim a closed world; every tool here queries a "
        f"FortiGate and must not claim otherwise"
    )
```

- [ ] **Step 3: Run tests to verify the new contracts fail**

Run: `uv run pytest tests/test_tool_annotations.py -v`
Expected: Task 1's 4 tests PASS. `test_the_frozen_list_covers_the_whole_write_surface` PASSES (241 tools register today; the list has 58 names). The other five FAIL — `test_every_tool_is_annotated` with `cmdb_list has no annotations (bare @mcp.tool()?)`, and the rest with `AttributeError: 'NoneType' object has no attribute 'readOnlyHint'` or the frozen-set message.

This is the intended red. Do not fix it here.

- [ ] **Step 4: Verify the frozen list matches the code, not just itself**

Re-derive the write surface from the source and diff it against `EXPECTED_MUTATING`. This catches a typo'd tool name in the list, which would otherwise only surface in Task 3.

```bash
uv run python - <<'PY'
import ast, pathlib
from tests.test_tool_annotations import EXPECTED_MUTATING
MUT = {"cmdb_post", "cmdb_put", "cmdb_delete", "monitor_post", "log_post", "service_post"}
reaches = set()
for p in sorted(pathlib.Path("tools").glob("*.py")):
    if p.name == "__init__.py":
        continue
    for n in ast.walk(ast.parse(p.read_text())):
        if not isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        if not any("mcp.tool" in ast.unparse(d) for d in n.decorator_list):
            continue
        if any(a.attr in MUT for a in ast.walk(n) if isinstance(a, ast.Attribute)):
            reaches.add(n.name)
listed = set(EXPECTED_MUTATING)
print("reach a write API but not listed:", sorted(reaches - listed))
print("listed but reach no write API   :", sorted(listed - reaches))
PY
```

Expected, exactly:
```
reach a write API but not listed: ['monitor_network_ping']
listed but reach no write API   : []
```

`monitor_network_ping` is the one deliberate exception. Any other name in either line means the frozen list is wrong — fix the list, not the expectation.

- [ ] **Step 5: Commit the red test**

```bash
git add tests/test_tool_annotations.py
git diff --cached --name-only   # must list exactly that one file
git commit -m "test(annotations): freeze the tool write surface"
```

Committing a failing test is deliberate here: the classification is the reviewable artifact, and Task 3 is the mechanical change that satisfies it.

---

### Task 3: Annotate all 241 tools

**Files:**
- Modify: `tools/firewall.py`, `tools/fleet.py`, `tools/generic.py`, `tools/log.py`, `tools/monitor.py`, `tools/router.py`, `tools/security.py`, `tools/system.py`, `tools/user.py`, `tools/vpn.py`, `tools/wireless.py` (241 decorator sites + one import line each)
- Modify: `CONTRIBUTING.md` (the "Adding a new MCP tool" checklist, around line 94)

**Interfaces:**
- Consumes: `EXPECTED_MUTATING` from Task 2 as the source of truth; the five constants from Task 1.
- Produces: no new symbols. The deliverable is a green `tests/test_tool_annotations.py`.

- [ ] **Step 1: Confirm the edit is safe to mechanise**

Every decorator site is byte-identical, which is what lets a script do this deterministically.

Run: `grep -rho "@mcp\.tool([^)]*)" tools/*.py | sort | uniq -c`
Expected: exactly one line, `241 @mcp.tool()`.

If any other form appears, stop and annotate by hand instead — the script below asserts on this and will refuse to run.

- [ ] **Step 2: Apply the annotations**

The script derives every category from `EXPECTED_MUTATING` (Task 2's reviewed list), defaults everything else to `READ_ONLY`, inserts a per-module import of exactly the constants that module uses, and asserts on each line before rewriting it.

```bash
uv run python - <<'PY'
import ast, pathlib
from tests.test_tool_annotations import EXPECTED_MUTATING
import tool_annotations

BY_ID = {id(v): k for k, v in tool_annotations.CATEGORIES.items()}
CATEGORY = {name: BY_ID[id(ann)] for name, ann in EXPECTED_MUTATING.items()}

for path in sorted(pathlib.Path("tools").glob("*.py")):
    if path.name == "__init__.py":
        continue
    src = path.read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    tree = ast.parse(src)

    edits, used = [], set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        decs = [d for d in node.decorator_list if "mcp.tool" in ast.unparse(d)]
        if not decs:
            continue
        assert len(decs) == 1, f"{path.name}:{node.name} has {len(decs)} tool decorators"
        cat = CATEGORY.get(node.name, "READ_ONLY")
        used.add(cat)
        edits.append((decs[0].lineno - 1, cat))

    for index, cat in edits:
        assert lines[index].strip() == "@mcp.tool()", (
            f"{path.name}:{index + 1} is {lines[index].strip()!r}, not '@mcp.tool()'"
        )
        lines[index] = lines[index].replace(
            "@mcp.tool()", f"@mcp.tool(annotations={cat})"
        )

    # Insert the import after the module's last top-level import, so it
    # joins the existing first-party block (fortios_client / instances).
    last = max(
        n.end_lineno
        for n in tree.body
        if isinstance(n, (ast.Import, ast.ImportFrom)) and n.end_lineno is not None
    )
    names = ", ".join(sorted(used))
    lines.insert(last, f"from tool_annotations import {names}\n")

    path.write_text("".join(lines), encoding="utf-8")
    print(f"{path.name:14} {len(edits):3} tools  imports: {names}")
PY
```

Expected output — 241 tools total, and note `monitor.py` and `fleet.py` import `READ_ONLY` alone:

```
firewall.py     37 tools  imports: CREATES, DESTRUCTIVE, READ_ONLY
fleet.py         1 tools  imports: READ_ONLY
generic.py       9 tools  imports: CREATES, DESTRUCTIVE, READ_ONLY, UNCONSTRAINED
log.py          16 tools  imports: DESTRUCTIVE, READ_ONLY
monitor.py      21 tools  imports: READ_ONLY
router.py       24 tools  imports: CREATES, DESTRUCTIVE, READ_ONLY
security.py     35 tools  imports: CREATES, DESTRUCTIVE, READ_ONLY
system.py       33 tools  imports: CREATES, DESTRUCTIVE, READ_ONLY
user.py         19 tools  imports: CREATES, DESTRUCTIVE, READ_ONLY
vpn.py          26 tools  imports: CREATES, DESTRUCTIVE, READ_ONLY, UPDATES
wireless.py     20 tools  imports: CREATES, DESTRUCTIVE, READ_ONLY
```

- [ ] **Step 3: Run the contract tests to verify they pass**

Run: `uv run pytest tests/test_tool_annotations.py -v`
Expected: PASS, 10 tests.

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest -v`
Expected: PASS. `tests/test_tools_have_instance_param.py` still sees 241 tools — the script changed only decorator arguments and added an import, never a signature.

- [ ] **Step 5: Add the comment on the one misleading name**

`wifi_wtp_deauthorize` now reads `@mcp.tool(annotations=DESTRUCTIVE)` while its name suggests an operational action. Add the reason directly above it in `tools/wireless.py`:

```python
    # DESTRUCTIVE, not an operational deauth: this is a cmdb_delete that
    # removes the WTP configuration entry.
    @mcp.tool(annotations=DESTRUCTIVE)
    async def wifi_wtp_deauthorize(
```

- [ ] **Step 6: Document the convention**

In `CONTRIBUTING.md`, under `### Adding a new MCP tool`, replace step 2 and renumber so the list reads:

```markdown
1. Choose the correct module in `tools/` (or propose a new one).
2. Define the tool function with full typing and a clear docstring — the docstring becomes the tool description shown to the LLM.
3. Declare a tool annotation category: `@mcp.tool(annotations=READ_ONLY)`, or `CREATES` / `UPDATES` / `DESTRUCTIVE` / `UNCONSTRAINED` from `tool_annotations.py`. A tool is `READ_ONLY` only when a call leaves both the FortiGate's stored configuration and its live session state as it found them — the HTTP verb does not decide it. If the tool writes, add it to `EXPECTED_MUTATING` in `tests/test_tool_annotations.py` in the same commit; that edit is the review prompt. See `docs/superpowers/specs/2026-07-27-mcp-tool-annotations-design.md`.
4. Register the tool in `server.py` if it requires registration outside the module (check how existing tools are registered).
5. Add at least one test in `tests/` covering the happy path and one error case.
```

- [ ] **Step 7: Lint, format and type-check**

Run: `uv run ruff format . && uv run ruff check . && uv run pyright`
Expected: all pass. If `ruff check` reports `F401` on any `tools/*.py`, the script over-imported for that module — remove the unused name and re-run.

- [ ] **Step 8: Verify the diff is only what was intended**

Run: `git diff --stat && git diff tools/monitor.py | head -40`
Expected: 12 files changed; every `tools/*.py` hunk is either the added import line or a decorator line gaining `annotations=`. No signature, docstring or body changes.

- [ ] **Step 9: Re-run the full suite and commit**

```bash
uv run pytest -v
git add tools/ CONTRIBUTING.md
git diff --cached --name-only   # 11 tools/*.py + CONTRIBUTING.md; no CLAUDE.md, no .claude/, no .mcp.json
git commit -m "feat(tools): annotate all 241 tools with MCP tool annotations"
```

---

## Verification

After Task 3, confirm the contract actually bites — a passing test proves nothing if it cannot fail.

- [ ] **Mutate a reader, confirm the test catches it**

Temporarily change `system_status` in `tools/system.py` to `@mcp.tool(annotations=DESTRUCTIVE)`.

Run: `uv run pytest tests/test_tool_annotations.py::test_mutating_set_is_frozen -v`
Expected: FAIL with `tool(s) ['system_status'] became non-read-only`.

- [ ] **Mutate a writer, confirm the dangerous direction is caught**

Revert that, then change `firewall_policy_delete` to `@mcp.tool(annotations=READ_ONLY)`.

Run: `uv run pytest tests/test_tool_annotations.py::test_mutating_set_is_frozen -v`
Expected: FAIL with `tool(s) ['firewall_policy_delete'] mutate a FortiGate but no longer advertise it`.

- [ ] **Revert both and confirm green**

Run: `git checkout tools/system.py tools/firewall.py && uv run pytest -v`
Expected: PASS, and `git status --short` is clean.
