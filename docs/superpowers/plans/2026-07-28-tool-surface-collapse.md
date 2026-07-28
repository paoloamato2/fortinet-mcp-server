# Tool Surface Collapse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the advertised MCP tool surface from 241 tools / 56,786 tokens to 91 tools / ~25,100 tokens by collapsing 160 pure-alias tools into nine per-domain read tools plus one `fortios_delete`, without losing a single reachable FortiOS path.

**Architecture:** A new dependency-free `resources.py` holds the resource lookup table (125 read rows, 15 delete rows) plus explicit `Literal` type aliases per domain. A shared `_read_resource()` helper in `tools/_read.py` does the dispatch; each `tools/<domain>.py` gains one thin `<domain>_read` tool annotated `READ_ONLY`. A new `tool_params.py` supplies shared `InstanceParam`/`VdomParam` aliases replacing 241 copy-pasted `Annotated` blocks. A `FastMCP` subclass in `server.py` strips pydantic's `title` keys from every schema on the way out.

**Tech Stack:** Python 3.11+, `uv`, FastMCP (`mcp[cli]>=1.9.0`), `httpx`, pydantic, pytest, ruff, pyright.

**Spec:** `docs/superpowers/specs/2026-07-28-tool-surface-collapse-design.md`

## Global Constraints

- Every task must leave `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, and `uv run pytest` all passing. CI runs exactly these four.
- Ruff format: 88-column lines, double quotes. Full type hints on public functions and tool handlers. Google-style docstrings.
- Conventional Commits: `feat|fix|docs|test|refactor|chore|security(scope): summary`.
- **Never** let `FortiOSError` propagate out of a tool. Catch it and return `{"error": str(exc), "status_code": exc.status_code}`.
- Every tool takes an optional `instance` parameter **immediately preceding** an optional `vdom` parameter. `tests/test_tools_have_instance_param.py` enforces both presence and ordering.
- Every tool declares an annotation category from `tool_annotations.py`. A tool is `READ_ONLY` only when a call leaves both the FortiGate's stored config **and** its live session state as it found them.
- Resolve the client inside the tool body: `client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(instance)`.
- `resources.py` and `tool_params.py` must import nothing from this project, so any layer can use them with no cycle.
- Do **not** stage `CLAUDE.md`, `.claude/`, or `.mcp.json` — they are excluded via `.git/info/exclude`. Check `git diff --cached --name-only` before every commit.
- The surface-budget ceiling in `tests/test_tool_surface_budget.py` is a **ratchet**: it only ever decreases. Every task that shrinks the surface tightens it in the same commit.

---

### Task 1: The measuring instrument

Nothing can be verified without a repeatable measurement of the serialised surface. This task builds it and pins today's number.

**Files:**
- Create: `tests/test_tool_surface_budget.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `serialised_surface_chars() -> int` — importable by later tasks, returns the total character count of every registered tool as `list_tools()` emits it. `SURFACE_CEILING_CHARS: int` — the ratchet constant.

- [ ] **Step 1: Write the failing test**

Create `tests/test_tool_surface_budget.py`:

```python
"""A ratchet on the advertised tool surface.

Every tool's name, description, ``inputSchema`` and ``annotations`` are sent
to the client on every request, before the model does any work. At 241 tools
that was 227,145 characters -- roughly 56,800 tokens -- and 45% of it was the
same two parameter descriptions repeated 241 times.

``SURFACE_CEILING_CHARS`` only ever moves down. Raising it is the signal that
a change made the server more expensive for every client on every request,
which is a decision that belongs in review rather than in a passing test.
"""

from __future__ import annotations

import json

import pytest

from server import mcp

#: Measured ceiling. Lower this whenever a change shrinks the surface; never
#: raise it without recording why in the commit message.
SURFACE_CEILING_CHARS = 227_200


async def _tool_payloads() -> list[dict[str, object]]:
    """Every registered tool, shaped exactly as ``list_tools()`` emits it."""
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.inputSchema,
            "annotations": (
                tool.annotations.model_dump() if tool.annotations else None
            ),
        }
        for tool in await mcp.list_tools()
    ]


async def serialised_surface_chars() -> int:
    """Total characters the server advertises across all tools."""
    return sum(len(json.dumps(payload)) for payload in await _tool_payloads())


@pytest.mark.anyio
async def test_surface_stays_under_the_ceiling() -> None:
    total = await serialised_surface_chars()
    assert total <= SURFACE_CEILING_CHARS, (
        f"tool surface grew to {total} chars, ceiling is "
        f"{SURFACE_CEILING_CHARS}. Every client pays this on every request."
    )


@pytest.mark.anyio
async def test_ceiling_is_not_slack() -> None:
    """The ceiling tracks reality, so a big win must tighten it."""
    total = await serialised_surface_chars()
    assert total >= SURFACE_CEILING_CHARS - 20_000, (
        f"surface is {total} chars but the ceiling is still "
        f"{SURFACE_CEILING_CHARS} -- tighten it in this commit."
    )
```

- [ ] **Step 2: Run the test to see how it fails**

```bash
uv run pytest tests/test_tool_surface_budget.py -v
```

Expected: both tests ERROR with a fixture/marker problem — `anyio` is not configured. This tells you whether the repo already has an async-test convention.

- [ ] **Step 3: Match the repo's existing async-test convention**

```bash
grep -rn "anyio\|asyncio_mode\|pytest.mark.asyncio" tests/ pyproject.toml
```

If the repo already configures one (e.g. `asyncio_mode = "auto"` under `[tool.pytest.ini_options]`), delete the `@pytest.mark.anyio` decorators and the `import pytest` if unused, and let the existing config drive it. If nothing is configured, the tests in this repo are all synchronous — in that case replace the two async tests with synchronous ones that drive the coroutine directly:

```python
import asyncio


def test_surface_stays_under_the_ceiling() -> None:
    total = asyncio.run(serialised_surface_chars())
    assert total <= SURFACE_CEILING_CHARS, (
        f"tool surface grew to {total} chars, ceiling is "
        f"{SURFACE_CEILING_CHARS}. Every client pays this on every request."
    )


def test_ceiling_is_not_slack() -> None:
    total = asyncio.run(serialised_surface_chars())
    assert total >= SURFACE_CEILING_CHARS - 20_000, (
        f"surface is {total} chars but the ceiling is still "
        f"{SURFACE_CEILING_CHARS} -- tighten it in this commit."
    )
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
uv run pytest tests/test_tool_surface_budget.py -v
```

Expected: PASS. Today's surface is 227,145 chars, just under the 227,200 ceiling.

- [ ] **Step 5: Print the number so you can see the ratchet move later**

```bash
uv run python -c "
import asyncio, sys; sys.path.insert(0, 'tests')
from test_tool_surface_budget import serialised_surface_chars
print('chars:', asyncio.run(serialised_surface_chars()))
"
```

Expected: `chars: 227145`

- [ ] **Step 6: Lint, type-check, full suite**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add tests/test_tool_surface_budget.py
git diff --cached --name-only   # must show ONLY that file
git commit -m "test(surface): ratchet the advertised tool surface at 227,200 chars"
```

---

### Task 2: Strip pydantic's `title` keys

Pydantic emits a `title` for every field and every schema. Those keys cost **26,191 chars (~6,550 tokens, 11.5% of the surface)** and tell a client nothing the JSON key doesn't already say. This task is fully independent of the collapse.

**Files:**
- Modify: `server.py` (add a `FastMCP` subclass, change the `mcp = FastMCP(...)` construction)
- Create: `tests/test_schema_titles_stripped.py`

**Interfaces:**
- Consumes: `serialised_surface_chars()` from Task 1.
- Produces: `class TrimmedFastMCP(FastMCP)` in `server.py`, overriding `async def list_tools(self) -> list[MCPTool]`. `mcp` remains a module-level name usable as `from server import mcp`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_schema_titles_stripped.py`:

```python
"""``title`` keys are stripped from every advertised schema.

Pydantic derives a ``title`` from each field name, so ``instance`` arrives as
``"title": "Instance"`` -- 26,191 characters across 241 tools restating keys
the client can already read. Stripping them changes nothing a client can act
on: JSON Schema treats ``title`` as presentational, and the property name is
right there as the object key.
"""

from __future__ import annotations

import asyncio

from server import mcp


def _titles_in(schema: dict) -> list[str]:
    """Every ``title`` key found anywhere in one tool's input schema."""
    found: list[str] = []
    if "title" in schema:
        found.append(f"<root>.title={schema['title']!r}")
    for name, prop in schema.get("properties", {}).items():
        if isinstance(prop, dict) and "title" in prop:
            found.append(f"{name}.title={prop['title']!r}")
    return found


def test_no_tool_advertises_a_title() -> None:
    tools = asyncio.run(mcp.list_tools())
    offenders = [
        f"{tool.name}: {', '.join(_titles_in(tool.inputSchema))}"
        for tool in tools
        if _titles_in(tool.inputSchema)
    ]
    assert offenders == [], f"schemas still carry title keys: {offenders[:5]}"


def test_stripping_preserves_everything_else() -> None:
    """A representative schema keeps its type, description, default and enum."""
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    schema = tools["cmdb_list"].inputSchema
    resource = schema["properties"]["resource_path"]
    assert schema["type"] == "object"
    assert "resource_path" in schema["required"]
    assert "description" in resource
    vdom = schema["properties"]["vdom"]
    assert vdom["default"] is None
    assert vdom["anyOf"] == [{"type": "string"}, {"type": "null"}]
```

- [ ] **Step 2: Run it to verify it fails**

```bash
uv run pytest tests/test_schema_titles_stripped.py -v
```

Expected: `test_no_tool_advertises_a_title` FAILS listing offenders like `cmdb_list: <root>.title='cmdb_listArguments', resource_path.title='Resource Path'`. `test_stripping_preserves_everything_else` PASSES already.

- [ ] **Step 3: Add the subclass to `server.py`**

`FastMCP._setup_handlers` registers the *bound* `self.list_tools`, and it runs inside `FastMCP.__init__`, so a subclass override reaches the wire. Insert this immediately above the `mcp = FastMCP(...)` construction:

```python
class TrimmedFastMCP(FastMCP):
    """``FastMCP`` that omits pydantic's ``title`` keys from tool schemas.

    Pydantic derives a ``title`` from every field name and one for the
    argument model itself. Across 241 tools that is 26,191 characters of
    ``"title": "Vdom"`` restating the JSON key beside it -- roughly 6,550
    tokens on every request, for a field JSON Schema defines as
    presentational.

    ``Tool.from_function`` exposes no schema hook, so the trim happens at the
    one point where schemas are serialised: ``list_tools``, which
    ``_setup_handlers`` registers as a bound method.
    """

    async def list_tools(self) -> list[MCPTool]:
        """Every registered tool, with ``title`` keys removed."""
        tools = await super().list_tools()
        for tool in tools:
            schema = tool.inputSchema
            schema.pop("title", None)
            for prop in schema.get("properties", {}).values():
                if isinstance(prop, dict):
                    prop.pop("title", None)
        return tools
```

Add the `MCPTool` import at the top of `server.py`, beside the existing `mcp` imports:

```python
from mcp.types import Tool as MCPTool
```

Then change the construction from `mcp = FastMCP(` to:

```python
mcp = TrimmedFastMCP(
```

leaving every keyword argument exactly as it is.

- [ ] **Step 4: Run the test to verify it passes**

```bash
uv run pytest tests/test_schema_titles_stripped.py -v
```

Expected: both PASS.

- [ ] **Step 5: Measure the win and tighten the ratchet**

```bash
uv run python -c "
import asyncio, sys; sys.path.insert(0, 'tests')
from test_tool_surface_budget import serialised_surface_chars
print('chars:', asyncio.run(serialised_surface_chars()))
"
```

Expected: `chars: 200954` (227,145 − 26,191).

In `tests/test_tool_surface_budget.py`, set:

```python
SURFACE_CEILING_CHARS = 201_000
```

- [ ] **Step 6: Lint, type-check, full suite**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest
```

Expected: all pass. If pyright objects that `list_tools` has an incompatible override, confirm the return annotation is exactly `list[MCPTool]` matching the base signature.

- [ ] **Step 7: Commit**

```bash
git add server.py tests/test_schema_titles_stripped.py tests/test_tool_surface_budget.py
git diff --cached --name-only
git commit -m "perf(schemas): strip pydantic title keys from advertised tool schemas

26,191 chars (~6,550 tokens, 11.5% of the surface) of \"title\": \"Vdom\"
restating the JSON key beside it. Ratchet 227,200 -> 201,000."
```

---

### Task 3: Shared `instance` / `vdom` parameter aliases

The two parameters are declared with full prose at 241 sites: **103,144 chars, 45.4% of the surface**. `server.py`'s `instructions` block already explains `instance` once, to the same audience.

**Files:**
- Create: `tool_params.py`
- Modify: the 10 tool modules under `tools/` that declare the two parameters — every `.py` except `__init__.py` and `fleet.py` (verified: `fleet.py` declares neither, since `fortigate_list` describes the server's own inventory)
- Delete: `add_instance_param.py`
- Create: `tests/test_tool_params_shared.py`

**Interfaces:**
- Consumes: `serialised_surface_chars()` from Task 1.
- Produces: `InstanceParam` and `VdomParam` in `tool_params.py`, both `TypeAlias`es of `Annotated[str | None, Field(...)]`, used as `instance: InstanceParam = None` and `vdom: VdomParam = None`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_tool_params_shared.py`:

```python
"""The ``instance`` and ``vdom`` descriptions live in exactly one place.

Before this, the full prose for both parameters was inlined at all 241 tool
sites -- 103,144 characters, 45.4% of everything the server advertises, to
say the same two things 241 times. The prose now lives in ``tool_params.py``;
these tests keep it from creeping back into the tool modules.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from server import mcp

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

#: Fragments that only ever appeared inside the duplicated descriptions.
BANNED_FRAGMENTS = (
    "Target FortiGate name; see fortigate_list",
    "Target VDOM name. Defaults to the server default VDOM",
)


def _tool_modules() -> list[Path]:
    return sorted(p for p in TOOLS_DIR.glob("*.py") if p.name != "__init__.py")


def test_no_tool_module_inlines_the_descriptions() -> None:
    offenders: list[str] = []
    for path in _tool_modules():
        text = path.read_text(encoding="utf-8")
        for fragment in BANNED_FRAGMENTS:
            if fragment in text:
                offenders.append(f"{path.name}: {fragment!r}")
    assert offenders == [], (
        f"inlined parameter prose found; use tool_params.py instead: {offenders}"
    )


def test_the_descriptions_still_reach_the_client() -> None:
    """Deduplicating must not mean deleting -- both params stay documented."""
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    schema = tools["cmdb_list"].inputSchema["properties"]
    assert schema["instance"]["description"].strip()
    assert schema["vdom"]["description"].strip()
    assert "fortigate_list" in schema["instance"]["description"]
    assert "*" in schema["vdom"]["description"]


def test_the_one_off_migration_script_is_gone() -> None:
    """``add_instance_param.py`` existed only because no alias did."""
    script = Path(__file__).resolve().parent.parent / "add_instance_param.py"
    assert not script.exists(), (
        "add_instance_param.py is superseded by tool_params.py; delete it"
    )
```

- [ ] **Step 2: Run it to verify it fails**

```bash
uv run pytest tests/test_tool_params_shared.py -v
```

Expected: `test_no_tool_module_inlines_the_descriptions` FAILS with ~20 offenders (both fragments in ~10 modules). `test_the_one_off_migration_script_is_gone` FAILS. The middle test PASSES.

- [ ] **Step 3: Create `tool_params.py`**

```python
"""Shared parameter definitions for every MCP tool.

``instance`` and ``vdom`` appear on nearly every tool in this server. Inlined,
their descriptions were 103,144 of the 227,145 characters the server
advertised -- 45.4% of the surface spent restating two sentences 241 times,
to a client that has already read ``server.py``'s ``instructions`` block.

The descriptions here are deliberately terse for that reason: the roster of
configured FortiGates, what ``instance="*"`` means and when to use it are all
covered once in the server instructions. This module imports nothing from the
project, so ``tools/*`` and ``server.py`` can both use it with no cycle.
"""

from __future__ import annotations

from typing import Annotated, TypeAlias

from pydantic import Field

#: Which configured FortiGate to talk to. Full roster and the ``"*"`` fan-out
#: semantics are in ``server.py``'s ``instructions``.
InstanceParam: TypeAlias = Annotated[
    str | None,
    Field(default=None, description="FortiGate name; '*'=all. See fortigate_list."),
]

#: Which VDOM to target. Defaults to the client's configured VDOM.
VdomParam: TypeAlias = Annotated[
    str | None,
    Field(default=None, description="VDOM name; '*'=all VDOMs."),
]
```

- [ ] **Step 4: Confirm which modules to rewrite**

```bash
grep -c "Target FortiGate name" tools/*.py
grep -c "Target VDOM name" tools/*.py
grep -n "vdom\|instance" tools/fleet.py
```

Expected: ten modules carry both fragments (the nine domain modules plus `generic.py`). `fleet.py` carries neither and declares no `instance` or `vdom` parameter at all — `fortigate_list` describes the server's own inventory, which is why `MODULES_WITHOUT_INSTANCE_PARAM` in `tests/test_tools_have_instance_param.py` exempts it. Leave `fleet.py` alone.

- [ ] **Step 5: Rewrite the parameter declarations**

For each of the ten modules, add the import beside the existing `tool_annotations` import:

```python
from tool_params import InstanceParam, VdomParam
```

Then replace every occurrence of this shape:

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
        vdom: Annotated[
            str | None,
            Field(
                default=None,
                description="Target VDOM name. Defaults to the server default VDOM. Use '*' for all VDOMs (super-admin required).",
            ),
        ] = None,
```

with:

```python
        instance: InstanceParam = None,
        vdom: VdomParam = None,
```

Do this module by module, running `uv run pytest` after each — ten small verifiable edits beat one large one. Some tools have parameters *after* `vdom` (e.g. `wifi_vap_create`); preserve their position and their trailing comma. After each module, check nothing else moved:

```bash
uv run pytest tests/test_tools_have_instance_param.py -v
```

Expected: PASS after every module — `instance` must stay immediately before `vdom`.

- [ ] **Step 6: Delete the superseded migration script**

```bash
git rm add_instance_param.py
```

- [ ] **Step 7: Run the new tests and the full suite**

```bash
uv run pytest tests/test_tool_params_shared.py -v
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest
```

Expected: all three tests in the new file PASS; everything else PASSES. If `Annotated` or `Field` becomes unused in a module, ruff will flag it — remove the dead import.

- [ ] **Step 8: Measure and tighten the ratchet**

```bash
uv run python -c "
import asyncio, sys; sys.path.insert(0, 'tests')
from test_tool_surface_budget import serialised_surface_chars
print('chars:', asyncio.run(serialised_surface_chars()))
"
```

Expected: `chars: 170050` (±200 depending on exact description wording).

Set `SURFACE_CEILING_CHARS = 170_200`.

- [ ] **Step 9: Commit**

```bash
git add tool_params.py tools/ tests/test_tool_params_shared.py tests/test_tool_surface_budget.py
git diff --cached --name-only   # must NOT list CLAUDE.md, .claude/, .mcp.json
git commit -m "refactor(tools): share instance/vdom parameter definitions

The two descriptions were inlined at 241 sites -- 103,144 chars, 45.4% of
the advertised surface -- while server instructions already explain both.
Retires add_instance_param.py, whose purpose was the missing alias.
Ratchet 201,000 -> 170,200."
```

---

### Task 4: `resources.py` — the lookup table

The table is **derived, not authored**. Every one of the 160 doomed tools reduces to `(client_method, path_literal, docstring_first_line)`, so a generator reads them out of the current source while those tools still exist. Deriving beats transcribing 125 rows by hand, and the generator doubles as the proof that nothing was invented.

**Files:**
- Create: `resources.py` (generated, then committed)
- Create: `scripts/generate_resources.py`
- Create: `tests/test_resource_tables.py`

**Interfaces:**
- Consumes: nothing.
- Produces, all importable from `resources.py`:
  - `class Resource(NamedTuple)` with fields `api: Literal["cmdb", "monitor"]`, `path: str`, `summary: str`, `keyed: bool = False`
  - `READ_RESOURCES: dict[str, dict[str, Resource]]` — domain → enum value → row; 9 domains, 125 rows
  - `DELETE_RESOURCES: dict[str, Resource]` — 15 rows
  - Nine `Literal` aliases: `FirewallResource`, `LogResource`, `MonitorResource`, `RouterResource`, `SecurityResource`, `SystemResource`, `UserResource`, `VpnResource`, `WirelessResource`
  - One `Literal` alias `DeletableResource` for `fortios_delete`
  - `SINGLETON_PATHS: frozenset[str]` — the 21 non-keyed cmdb paths

- [ ] **Step 1: Write the generator**

Create `scripts/generate_resources.py`:

```python
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
    "cmdb_get", "cmdb_delete", "cmdb_list", "cmdb_create", "cmdb_update",
    "monitor_get", "monitor_action", "log_get", "service_call",
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
SINGLETON_PATHS = frozenset({
    "system/global", "system/dns", "system/ntp", "system/time", "system/sdwan",
    "system.snmp/sysinfo", "system.autoupdate/schedule",
    "antivirus/settings", "automation/setting",
    "router/ospf", "router/ospf6", "router/bgp", "router/rip",
    "log.disk/filter", "log.disk/setting", "log.memory/setting",
    "log.fortianalyzer/setting", "log.syslogd/setting",
    "vpn.ssl/settings",
    "wireless-controller/setting", "wireless-controller/rf-analysis",
})

#: The stripping rule would leave a bare ``ip``; its path says ``iplist``.
NAME_OVERRIDES = {"monitor_firewall_ip_list": "iplist"}

DOMAIN_ALIAS = {
    "firewall": "FirewallResource", "log": "LogResource",
    "monitor": "MonitorResource", "router": "RouterResource",
    "security": "SecurityResource", "system": "SystemResource",
    "user": "UserResource", "vpn": "VpnResource",
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
            out.append({
                "domain": path.stem, "name": node.name, "own": own, "pure": pure,
                "method": method, "path": call_path, "summary": doc,
            })
    return out


def strip_key(path: str) -> str:
    """``f'firewall/address/{name}'`` -> ``firewall/address``."""
    return path.split("/{")[0].strip("f'\"")


def main() -> None:
    rows = scan()
    reads = collections.defaultdict(dict)
    deletes: dict[str, dict] = {}

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
            f'    "{value}": Resource("{api}", "{path}", '
            f"{summary!r}, keyed={keyed}),"
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
```

- [ ] **Step 2: Generate the table and inspect it**

```bash
mkdir -p scripts
uv run python scripts/generate_resources.py > resources.py
uv run ruff format resources.py
uv run python -c "
import resources as r
print('domains:', len(r.READ_RESOURCES))
print('read rows:', sum(len(v) for v in r.READ_RESOURCES.values()))
print('delete rows:', len(r.DELETE_RESOURCES))
for d, rows in sorted(r.READ_RESOURCES.items()):
    print(f'  {d}_read {len(rows)}')
"
```

Expected exactly:

```text
domains: 9
read rows: 125
delete rows: 15
  firewall_read 15
  log_read 4
  monitor_read 11
  router_read 17
  security_read 28
  system_read 19
  user_read 7
  vpn_read 12
  wireless_read 12
```

If any count differs, the generator's classification drifted from the spec — fix the generator, do not hand-edit `resources.py`.

- [ ] **Step 3: Write the table's contract tests**

Create `tests/test_resource_tables.py`:

```python
"""Contracts on the generated resource table.

The table replaced 160 tools. Two things must hold for that to have been
safe: every path those tools could reach is still reachable, and no two rows
claim the same endpoint. The first is migration completeness; the second is
what found that ``system_fortiguard_status`` and ``monitor_license_status``
were the same call.
"""

from __future__ import annotations

import asyncio

from resources import (
    DELETE_RESOURCES,
    READ_RESOURCES,
    SINGLETON_PATHS,
    Resource,
)
from server import mcp

EXPECTED_ROW_COUNTS = {
    "firewall": 15, "log": 4, "monitor": 11, "router": 17, "security": 28,
    "system": 19, "user": 7, "vpn": 12, "wireless": 12,
}


def test_row_counts_are_frozen() -> None:
    """125 read rows across nine domains -- 126 collapsed, less one duplicate."""
    actual = {d: len(rows) for d, rows in READ_RESOURCES.items()}
    assert actual == EXPECTED_ROW_COUNTS
    assert sum(actual.values()) == 125
    assert len(DELETE_RESOURCES) == 15


def test_no_two_rows_claim_the_same_endpoint() -> None:
    """A duplicate row means two enum values issue one identical call."""
    seen: dict[tuple[str, str], str] = {}
    clashes: list[str] = []
    for domain, rows in READ_RESOURCES.items():
        for value, row in rows.items():
            key = (row.api, row.path)
            where = f"{domain}/{value}"
            if key in seen:
                clashes.append(f"{key} claimed by {seen[key]} and {where}")
            seen[key] = where
    assert clashes == [], f"duplicate endpoints: {clashes}"


def test_singletons_are_not_keyed_and_tables_are() -> None:
    """``keyed`` follows the path, not per-row judgement."""
    wrong: list[str] = []
    for domain, rows in READ_RESOURCES.items():
        for value, row in rows.items():
            expected = row.api == "cmdb" and row.path not in SINGLETON_PATHS
            if row.keyed is not expected:
                wrong.append(f"{domain}/{value} keyed={row.keyed}, want {expected}")
    assert wrong == [], f"keyed misclassified: {wrong}"


def test_monitor_rows_are_never_keyed() -> None:
    """Monitor endpoints take query parameters, not a path key."""
    keyed_monitors = [
        f"{d}/{v}"
        for d, rows in READ_RESOURCES.items()
        for v, row in rows.items()
        if row.api == "monitor" and row.keyed
    ]
    assert keyed_monitors == []


def test_spot_check_rows_carry_the_original_docstrings() -> None:
    """The summaries are the replaced tools' docstrings, not paraphrases."""
    assert READ_RESOURCES["user"]["local"] == Resource(
        "cmdb", "user/local", "List all local user accounts.", keyed=True
    )
    assert READ_RESOURCES["system"]["global"] == Resource(
        "cmdb",
        "system/global",
        "Get FortiOS global settings (hostname, admin timeout, language, etc.).",
        keyed=False,
    )
    assert READ_RESOURCES["wireless"]["vap"] == Resource(
        "cmdb",
        "wireless-controller/vap",
        "List all VAPs (Virtual APs / SSIDs).",
        keyed=True,
    )
    assert READ_RESOURCES["monitor"]["license_status"] == Resource(
        "monitor",
        "license/status",
        "Get FortiGuard license and subscription status for all services.",
        keyed=False,
    )
    assert READ_RESOURCES["firewall"]["iplist"] == Resource(
        "monitor",
        "firewall/iplist",
        "List active banned/exempt IPs in the firewall.",
        keyed=False,
    )


def test_the_dropped_duplicate_is_absent() -> None:
    """``license/status`` is reachable once, via monitor_read."""
    assert "fortiguard_status" not in READ_RESOURCES["system"]
    paths = [
        row.path
        for rows in READ_RESOURCES.values()
        for row in rows.values()
    ]
    assert paths.count("license/status") == 1


def test_every_summary_is_present_and_terse() -> None:
    """Summaries reach the model, so an empty or essay-length one is a bug."""
    bad = [
        f"{d}/{v}"
        for d, rows in READ_RESOURCES.items()
        for v, row in rows.items()
        if not row.summary.strip() or len(row.summary) > 120
    ]
    assert bad == [], f"summaries empty or over 120 chars: {bad}"


def test_delete_rows_are_all_keyed_cmdb() -> None:
    """Every deletable object is addressed by key on the cmdb API."""
    wrong = [
        v
        for v, row in DELETE_RESOURCES.items()
        if row.api != "cmdb" or not row.keyed
    ]
    assert wrong == []


def test_migration_completeness_against_the_removed_tools() -> None:
    """Every endpoint the removed tools could reach is still reachable.

    Read from the table rather than the (by now deleted) tool bodies: the
    generator derived these rows from those bodies, and this asserts the
    result covers each path exactly once per API family.
    """
    reachable = {
        (row.api, row.path)
        for rows in READ_RESOURCES.values()
        for row in rows.values()
    } | {("cmdb", row.path) for row in DELETE_RESOURCES.values()}
    # 125 read endpoints; the 15 delete paths all duplicate read paths
    # already in the set, so the union is the read set plus nothing new.
    assert len(reachable) == 125
    for required in (
        ("cmdb", "firewall/addrgrp"),
        ("cmdb", "ips/sensor"),
        ("cmdb", "vpn.ipsec/phase1-interface"),
        ("cmdb", "user/tacacs+"),
        ("monitor", "system/status"),
        ("monitor", "wifi/rogue_ap"),
        ("monitor", "sdwan/health-check"),
        ("cmdb", "log.fortianalyzer/setting"),
    ):
        assert required in reachable, f"{required} became unreachable"


def test_literal_aliases_match_the_table_keys() -> None:
    """A ``Literal`` that drifts from its dict advertises a broken enum."""
    import typing

    import resources

    for domain, alias_name in (
        ("firewall", "FirewallResource"), ("log", "LogResource"),
        ("monitor", "MonitorResource"), ("router", "RouterResource"),
        ("security", "SecurityResource"), ("system", "SystemResource"),
        ("user", "UserResource"), ("vpn", "VpnResource"),
        ("wireless", "WirelessResource"),
    ):
        alias = getattr(resources, alias_name)
        assert set(typing.get_args(alias)) == set(READ_RESOURCES[domain]), (
            f"{alias_name} drifted from READ_RESOURCES[{domain!r}]"
        )
    assert set(typing.get_args(resources.DeletableResource)) == set(
        DELETE_RESOURCES
    )


def test_the_table_does_not_change_the_surface_yet() -> None:
    """This task adds data only -- no tool is added or removed."""
    tools = asyncio.run(mcp.list_tools())
    assert len(tools) == 241
```

- [ ] **Step 4: Run the tests**

```bash
uv run pytest tests/test_resource_tables.py -v
```

Expected: all PASS. If `test_spot_check_rows_carry_the_original_docstrings` fails, the docstring in the source differs from the expected string — copy the actual value from the failure output only after confirming it against the tool's docstring in `tools/`.

- [ ] **Step 5: Lint, type-check, full suite**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest
```

Expected: all pass. The surface ratchet is unchanged — this task adds no tools.

- [ ] **Step 6: Commit**

```bash
git add resources.py scripts/generate_resources.py tests/test_resource_tables.py
git diff --cached --name-only
git commit -m "feat(resources): derive the FortiOS resource table from the alias tools

125 read rows across nine domains plus 15 delete rows, generated by AST from
the 160 tool bodies they replace so the summaries are those docstrings
verbatim. Drops the system_fortiguard_status / monitor_license_status
duplicate, which the uniqueness contract surfaced."
```

---

### Task 5: The read helper and the first domain

`user` is the smallest domain (7 rows), so it proves the pattern end to end at the lowest risk. It removes 10 tools and adds 1.

**Files:**
- Create: `tools/_read.py`
- Modify: `tools/user.py` (add `user_read`; remove `user_local_list`, `user_group_list`, `user_radius_list`, `user_ldap_list`, `user_tacacs_list`, `user_saml_list`, `monitor_user_fortitoken_list`, `user_local_get`, `user_group_get`, `user_radius_get`)
- Create: `tests/test_read_tools.py`

**Interfaces:**
- Consumes: `Resource`, `READ_RESOURCES`, `UserResource` from `resources.py`; `InstanceParam`, `VdomParam` from `tool_params.py`; `serialised_surface_chars()` from Task 1.
- Produces: `async def read_resource(ctx: Context, domain: str, resource: str, name: str | None, instance: str | None, vdom: str | None) -> dict[str, Any]` in `tools/_read.py`. Also `def resource_table_doc(domain: str) -> str`, which renders a domain's rows as the markdown list appended to each read tool's description.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_read_tools.py`:

```python
"""Behaviour of the per-domain read tools.

These replace 145 tools whose bodies were one client call with a hardcoded
path. What has to hold: the right path is built for a list and for a keyed
read, singletons refuse a key rather than 404ing, and FortiOSError still
comes back as a dict instead of propagating.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from fortios_client import FortiOSError
from tools._read import read_resource, resource_table_doc


class FakeClient:
    """Records the calls a tool makes instead of reaching a FortiGate."""

    def __init__(self, raises: FortiOSError | None = None) -> None:
        self.calls: list[tuple[str, str, str | None]] = []
        self._raises = raises

    async def cmdb_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append(("cmdb_get", path, vdom))
        if self._raises:
            raise self._raises
        return {"results": [], "path": path}

    async def monitor_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append(("monitor_get", path, vdom))
        if self._raises:
            raise self._raises
        return {"results": [], "path": path}


class FakeContext:
    """Minimal stand-in for the MCP ``Context`` a tool receives."""

    def __init__(self, client: FakeClient) -> None:
        class _Registry:
            def resolve(self, _instance: str | None) -> FakeClient:
                return client

        class _RequestContext:
            lifespan_context = {"registry": _Registry()}

        self.request_context = _RequestContext()

    async def error(self, _message: str) -> None:
        return None


def test_list_read_builds_the_bare_path() -> None:
    client = FakeClient()
    result = asyncio.run(
        read_resource(FakeContext(client), "user", "local", None, None, None)
    )
    assert client.calls == [("cmdb_get", "user/local", None)]
    assert "error" not in result


def test_keyed_read_appends_the_name() -> None:
    client = FakeClient()
    asyncio.run(
        read_resource(FakeContext(client), "user", "local", "alice", None, None)
    )
    assert client.calls == [("cmdb_get", "user/local/alice", None)]


def test_monitor_resource_dispatches_to_monitor_get() -> None:
    client = FakeClient()
    asyncio.run(
        read_resource(FakeContext(client), "user", "fortitoken", None, None, None)
    )
    assert client.calls == [("monitor_get", "user/fortitoken", None)]


def test_vdom_is_passed_through() -> None:
    client = FakeClient()
    asyncio.run(
        read_resource(FakeContext(client), "user", "local", None, None, "root")
    )
    assert client.calls == [("cmdb_get", "user/local", "root")]


def test_name_on_a_singleton_is_refused_without_calling_the_device() -> None:
    client = FakeClient()
    result = asyncio.run(
        read_resource(FakeContext(client), "system", "global", "anything", None, None)
    )
    assert client.calls == [], "a refused call must not reach the FortiGate"
    assert "error" in result
    assert "singleton" in result["error"]
    assert "global" in result["error"]


def test_name_on_a_monitor_resource_is_refused() -> None:
    client = FakeClient()
    result = asyncio.run(
        read_resource(FakeContext(client), "user", "fortitoken", "x", None, None)
    )
    assert client.calls == []
    assert "error" in result


def test_unknown_resource_is_reported_not_raised() -> None:
    """Pydantic blocks this at the schema, but the helper is defensive."""
    client = FakeClient()
    result = asyncio.run(
        read_resource(FakeContext(client), "user", "nope", None, None, None)
    )
    assert client.calls == []
    assert "error" in result


def test_fortios_error_is_returned_as_a_dict() -> None:
    client = FakeClient(raises=FortiOSError("permission denied", status_code=403))
    result = asyncio.run(
        read_resource(FakeContext(client), "user", "local", None, None, None)
    )
    assert result["status_code"] == 403
    assert "permission denied" in result["error"]


def test_table_doc_lists_every_resource_with_its_summary() -> None:
    doc = resource_table_doc("user")
    assert "`local`" in doc
    assert "List all local user accounts." in doc
    assert doc.count("\n- ") + doc.count("- ") >= 7


@pytest.mark.parametrize(
    "removed",
    [
        "user_local_list", "user_group_list", "user_radius_list",
        "user_ldap_list", "user_tacacs_list", "user_saml_list",
        "monitor_user_fortitoken_list", "user_local_get",
        "user_group_get", "user_radius_get",
    ],
)
def test_the_replaced_user_tools_are_gone(removed: str) -> None:
    from server import mcp

    names = {tool.name for tool in asyncio.run(mcp.list_tools())}
    assert removed not in names, f"{removed} should have folded into user_read"


def test_user_read_is_registered_and_read_only() -> None:
    from server import mcp

    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    assert "user_read" in tools
    tool = tools["user_read"]
    assert tool.annotations is not None
    assert tool.annotations.readOnlyHint is True
    props = tool.inputSchema["properties"]
    assert set(props) == {"resource", "name", "instance", "vdom"}
    assert props["resource"]["enum"] == sorted(props["resource"]["enum"])
    assert len(props["resource"]["enum"]) == 7
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest tests/test_read_tools.py -v
```

Expected: every test FAILS at import — `ModuleNotFoundError: No module named 'tools._read'`.

- [ ] **Step 3: Write `tools/_read.py`**

```python
"""Shared dispatch for the per-domain read tools.

The nine ``<domain>_read`` tools differ only in which slice of
``READ_RESOURCES`` they expose and which ``Literal`` types their ``resource``
parameter. The logic -- look the row up, decide whether a key is allowed,
build the path, pick the API family, convert ``FortiOSError`` into a dict --
is identical, so it lives here once.

Underscore-prefixed because it registers no tools of its own; ``server.py``
does not import it.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import Context

from fortios_client import FortiOSError
from instances import FortiOSAPI
from resources import READ_RESOURCES


def resource_table_doc(domain: str) -> str:
    """Render a domain's rows as the markdown list shown to the model.

    The summaries are the docstrings of the tools this table replaced, so the
    per-resource semantics survive the collapse into one enum.
    """
    rows = READ_RESOURCES[domain]
    return "\n".join(f"- `{value}` — {rows[value].summary}" for value in sorted(rows))


async def read_resource(
    ctx: Context,
    domain: str,
    resource: str,
    name: str | None,
    instance: str | None,
    vdom: str | None,
) -> dict[str, Any]:
    """Read one FortiOS resource, listing it or fetching a single object.

    Args:
        ctx: MCP request context, carrying the instance registry.
        domain: Key into ``READ_RESOURCES`` -- the calling tool's domain.
        resource: Enum value naming the row to read.
        name: Object key. ``None`` lists every object. Rejected for
            singletons and for monitor endpoints, which take no path key.
        instance: Target FortiGate name, or ``"*"`` to fan out.
        vdom: Target VDOM, or ``None`` for the client default.

    Returns:
        The FortiOS response, or ``{"error": ..., "status_code": ...}``.
    """
    row = READ_RESOURCES.get(domain, {}).get(resource)
    if row is None:
        known = ", ".join(sorted(READ_RESOURCES.get(domain, {})))
        return {"error": f"unknown {domain} resource {resource!r}. Known: {known}"}

    if name is not None and not row.keyed:
        reason = (
            "a monitor endpoint, which takes no object key"
            if row.api == "monitor"
            else "a singleton"
        )
        return {
            "error": (
                f"resource {resource!r} is {reason}; omit name to read it."
            )
        }

    path = f"{row.path}/{name}" if name is not None else row.path
    client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
        instance
    )
    try:
        if row.api == "cmdb":
            return await client.cmdb_get(path, vdom=vdom)
        return await client.monitor_get(path, vdom=vdom)
    except FortiOSError as exc:
        return {"error": str(exc), "status_code": exc.status_code}
```

- [ ] **Step 4: Add `user_read` to `tools/user.py`**

Add the imports:

```python
from resources import UserResource
from tools._read import read_resource, resource_table_doc
```

Then add the tool inside `register()`.

**The description is built at runtime, so this tool is not decorated.** A
docstring must be a literal, but each read tool's description ends with its
generated resource table — 125 summaries that should not be pasted into nine
docstrings by hand. FastMCP reads `fn.__doc__` when `mcp.tool(...)` runs, so
the pattern is: define the function undecorated with a placeholder docstring,
assign the real `__doc__`, then register explicitly. Verified: the assigned
text reaches `list_tools()[i].description` and the `Literal` still becomes the
schema `enum`.

```python
    async def user_read(
        ctx: Context,
        resource: Annotated[
            UserResource, Field(description="Which user resource to read.")
        ],
        name: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Object key to fetch. Omit to list every object. "
                    "Rejected for singletons and monitor endpoints."
                ),
            ),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Placeholder replaced below with the generated resource table."""
        return await read_resource(ctx, "user", resource, name, instance, vdom)

    user_read.__doc__ = (
        "Read user, group and authentication-server configuration.\n\n"
        "Omit `name` to list a resource, or pass it to fetch one object by "
        "key.\n\n" + resource_table_doc("user")
    )
    mcp.tool(annotations=READ_ONLY)(user_read)
```

- [ ] **Step 5: Verify the description actually carries the table**

```bash
uv run python -c "
import asyncio
from server import mcp
t = {x.name: x for x in asyncio.run(mcp.list_tools())}['user_read']
print(t.description)
"
```

Expected: the two prose lines followed by seven `- \`value\` — summary` lines. If the description is the placeholder text, the `__doc__` assignment came after registration — reorder.

- [ ] **Step 6: Delete the ten replaced tools from `tools/user.py`**

Remove these functions entirely: `user_local_list`, `user_group_list`, `user_radius_list`, `user_ldap_list`, `user_tacacs_list`, `user_saml_list`, `monitor_user_fortitoken_list`, `user_local_get`, `user_group_get`, `user_radius_get`. Leave every create/update/delete tool untouched.

- [ ] **Step 7: Run the tests**

```bash
uv run pytest tests/test_read_tools.py -v
```

Expected: all PASS.

- [ ] **Step 8: Lint, type-check, full suite**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest
```

Expected: all pass. `tests/test_tool_annotations.py` still passes — `user_read` reaches only `cmdb_get`/`monitor_get`, so the AST write-guard is satisfied and `EXPECTED_MUTATING` is unaffected.

- [ ] **Step 9: Tighten the ratchet**

```bash
uv run python -c "
import asyncio, sys; sys.path.insert(0, 'tests')
from test_tool_surface_budget import serialised_surface_chars
print('chars:', asyncio.run(serialised_surface_chars()))
"
```

Ten tools removed (~7,000 chars) and one added (~1,300), so expect roughly `164,000`. Set `SURFACE_CEILING_CHARS` to the measured value rounded up to the next 100.

- [ ] **Step 10: Commit**

```bash
git add tools/_read.py tools/user.py tests/test_read_tools.py tests/test_tool_surface_budget.py
git diff --cached --name-only
git commit -m "feat(user): collapse ten user tools into user_read

Proves the pattern end to end on the smallest domain: shared dispatch in
tools/_read.py, an enum from resources.py, and the replaced tools'
docstrings carried into the description as the resource table."
```

---

### Task 6: The remaining eight domains

The pattern is proven, so each domain is one small function plus deletions. Each gets its own test-and-commit cycle — a reviewer can reject `security` while approving `log`.

**Files, per domain:**
- Modify: `tools/firewall.py`, `tools/log.py`, `tools/monitor.py`, `tools/router.py`, `tools/security.py`, `tools/system.py`, `tools/vpn.py`, `tools/wireless.py`
- Modify: `tests/test_read_tools.py` (extend the registration test)
- Modify: `tests/test_tool_surface_budget.py` (ratchet, once at the end)

**Interfaces:**
- Consumes: `read_resource`, `resource_table_doc` from `tools/_read.py`; the eight remaining `Literal` aliases from `resources.py`.
- Produces: `firewall_read`, `log_read`, `monitor_read`, `router_read`, `security_read`, `system_read`, `vpn_read`, `wireless_read`, all `READ_ONLY`.

- [ ] **Step 1: Extend the registration test to cover all nine**

Replace `test_user_read_is_registered_and_read_only` in `tests/test_read_tools.py` with:

```python
EXPECTED_ENUM_SIZES = {
    "firewall_read": 15, "log_read": 4, "monitor_read": 11, "router_read": 17,
    "security_read": 28, "system_read": 19, "user_read": 7, "vpn_read": 12,
    "wireless_read": 12,
}


@pytest.mark.parametrize("tool_name", sorted(EXPECTED_ENUM_SIZES))
def test_read_tool_is_registered_and_read_only(tool_name: str) -> None:
    from server import mcp

    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    assert tool_name in tools
    tool = tools[tool_name]
    assert tool.annotations is not None
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.destructiveHint is False
    props = tool.inputSchema["properties"]
    assert set(props) == {"resource", "name", "instance", "vdom"}
    assert len(props["resource"]["enum"]) == EXPECTED_ENUM_SIZES[tool_name]
    assert tool.description is not None
    assert "- `" in tool.description, "resource table missing from description"
```

- [ ] **Step 2: Run it to confirm eight of nine fail**

```bash
uv run pytest tests/test_read_tools.py -k test_read_tool_is_registered -v
```

Expected: `user_read` PASSES, the other eight FAIL on `assert tool_name in tools`.

- [ ] **Step 3: Add each read tool, one domain at a time**

For each domain below, add these imports to its module (`InstanceParam`/`VdomParam` are already there from Task 3):

```python
from resources import <AliasName>
from tools._read import read_resource, resource_table_doc
```

then add inside `register()`, substituting the domain name, alias, and prose:

```python
    async def <domain>_read(
        ctx: Context,
        resource: Annotated[
            <AliasName>, Field(description="Which <domain> resource to read.")
        ],
        name: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Object key to fetch. Omit to list every object. "
                    "Rejected for singletons and monitor endpoints."
                ),
            ),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Placeholder replaced below with the generated resource table."""
        return await read_resource(ctx, "<domain>", resource, name, instance, vdom)

    <domain>_read.__doc__ = (
        "<PROSE>\n\n"
        "Omit `name` to list a resource, or pass it to fetch one object by "
        "key.\n\n" + resource_table_doc("<domain>")
    )
    mcp.tool(annotations=READ_ONLY)(<domain>_read)
```

Domain-by-domain values, and the tools to delete from each module:

| domain | alias | `<PROSE>` | delete from the module |
|---|---|---|---|
| `firewall` | `FirewallResource` | `Read firewall objects, policies and live firewall state.` | `firewall_policy6_list`, `firewall_addrgrp_list`, `firewall_service_list`, `firewall_service_grp_list`, `firewall_vip_list`, `firewall_vipgrp_list`, `firewall_ippool_list`, `firewall_schedule_one_time_list`, `firewall_schedule_recurring_list`, `firewall_central_snat_list`, `firewall_ssl_ssh_profile_list`, `firewall_shaping_policy_list`, `monitor_firewall_policy_stats`, `monitor_firewall_address_dynamic`, `monitor_firewall_ip_list`, `firewall_addrgrp_get`, `firewall_service_get`, `firewall_vip_get` |
| `log` | `LogResource` | `Read log subsystem configuration (disk, memory, FortiAnalyzer).` | `log_disk_filter_get`, `log_disk_setting_get`, `log_memory_setting_get`, `log_fortianalyzer_setting_get` |
| `monitor` | `MonitorResource` | `Read live device, network and security telemetry.` | `monitor_network_arp_list`, `monitor_network_lldp_neighbors`, `monitor_fortiview_top_threat_map`, `monitor_license_status`, `monitor_license_forticare_resellers`, `monitor_endpoint_summary`, `monitor_ips_anomaly`, `monitor_utm_app_categories`, `monitor_switch_controller_managed_switch`, `monitor_security_rating_summary`, `monitor_system_process_list` |
| `router` | `RouterResource` | `Read routing configuration and the live routing table.` | `router_static_list`, `router_static6_list`, `router_policy_list`, `router_ospf_get`, `router_ospf6_get`, `router_bgp_get`, `router_rip_get`, `router_prefix_list_list`, `router_route_map_list`, `router_community_list_list`, `router_access_list_list`, `router_sdwan_get`, `monitor_router_ipv4`, `monitor_router_ipv6`, `monitor_router_statistics`, `monitor_sdwan_health_check`, `monitor_sdwan_members`, `router_static_get` |
| `security` | `SecurityResource` | `Read security profiles: IPS, antivirus, web filter, DLP, WAF, ZTNA.` | `ips_sensor_list`, `ips_custom_list`, `antivirus_profile_list`, `antivirus_settings_get`, `webfilter_profile_list`, `webfilter_urlfilter_list`, `webfilter_override_list`, `webfilter_content_list`, `application_list_profiles`, `application_group_list`, `dlp_sensor_list`, `dlp_dictionary_list`, `dlp_filepattern_list`, `emailfilter_profile_list`, `emailfilter_bwl_list`, `dnsfilter_profile_list`, `dnsfilter_domain_filter_list`, `file_filter_profile_list`, `icap_server_list`, `icap_profile_list`, `ssh_filter_profile_list`, `waf_profile_list`, `waf_signature_list`, `voip_profile_list`, `virtual_patch_profile_list`, `automation_setting_get`, `ztna_server_list`, `ztna_tag_policy_list`, `ips_sensor_get`, `antivirus_profile_get`, `webfilter_profile_get`, `application_list_get` |
| `system` | `SystemResource` | `Read system configuration and device health.` | `system_status`, `system_resource_usage`, `system_performance_status`, `system_ha_status`, `system_firmware_list`, `system_time_get`, `system_global_get`, `system_dns_get`, `system_ntp_get`, `system_admin_list`, `system_dhcp_server_list`, `system_snmp_sysinfo_get`, `system_snmp_community_list`, `system_snmp_user_list`, `system_fortiguard_status`, `system_autoupdate_schedule_get`, `certificate_local_list`, `certificate_ca_list`, `system_vdom_list`, `log_syslogd_get`, `system_admin_get`, `system_dhcp_server_get` |
| `vpn` | `VpnResource` | `Read IPsec and SSL-VPN configuration, certificates and tunnel state.` | `vpn_ipsec_phase1_list`, `vpn_ipsec_phase2_list`, `vpn_ssl_settings_get`, `vpn_ssl_portal_list`, `vpn_ssl_web_host_check_software_list`, `vpn_certificate_ca_list`, `vpn_certificate_local_list`, `vpn_certificate_remote_list`, `vpn_certificate_ocsp_server_list`, `monitor_vpn_ipsec`, `monitor_vpn_ssl_list`, `monitor_vpn_certificate_valid`, `vpn_ipsec_phase1_get`, `vpn_ipsec_phase2_get`, `vpn_ssl_portal_get` |
| `wireless` | `WirelessResource` | `Read wireless controller configuration and live AP/client state.` | `wifi_wtp_profile_list`, `wifi_wtp_list`, `wifi_vap_list`, `wifi_vap_group_list`, `wifi_controller_setting_get`, `wifi_qos_profile_list`, `wifi_rf_analysis_get`, `wifi_hotspot20_profile_list`, `monitor_wifi_managed_ap`, `monitor_wifi_rogue_ap`, `monitor_wifi_spectrum_analysis`, `monitor_wifi_interfering_ap`, `wifi_wtp_profile_get`, `wifi_wtp_get`, `wifi_vap_get` |

**Note on `system`:** `system_fortiguard_status` is deleted with no enum value — it duplicated `monitor_read(resource="license_status")`, which is why `system_read` has 19 values against 20 removed tools.

**Do not delete** `firewall_policy_list`, `firewall_policy_get`, `firewall_address_list`, `firewall_address_get`, `system_interface_list`, `system_interface_get` — the `_list` tools carry filter logic and their `_get` siblings stay with them.

After each domain:

```bash
uv run pytest tests/test_read_tools.py -k "<domain>" -v && uv run pytest
```

Expected: that domain's registration test PASSES and the full suite stays green.

- [ ] **Step 4: Confirm the tool count**

```bash
uv run python -c "
import asyncio
from server import mcp
names = {t.name for t in asyncio.run(mcp.list_tools())}
print('tools:', len(names))
print('read tools:', sorted(n for n in names if n.endswith('_read')))
"
```

Expected: `tools: 105` — 241 less the 145 read-side removals (126 zero-param + 19 get-by-name, of which Task 5 did 10 and this task the remaining 135), plus the 9 read tools. The 15 delete aliases come out in Task 7, taking it to 91. All nine `*_read` names should be listed.

- [ ] **Step 5: Lint, type-check, full suite**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest
```

Expected: all pass. If `tests/test_tool_annotations.py` fails on a count assertion in a docstring, leave it — Task 8 updates the prose. If it fails on `EXPECTED_MUTATING`, something in the deletion list was wrong: no removed read tool is a writer.

- [ ] **Step 6: Tighten the ratchet**

```bash
uv run python -c "
import asyncio, sys; sys.path.insert(0, 'tests')
from test_tool_surface_budget import serialised_surface_chars
print('chars:', asyncio.run(serialised_surface_chars()))
"
```

Expect roughly `112,000`. Set `SURFACE_CEILING_CHARS` to the measured value rounded up to the next 100.

- [ ] **Step 7: Commit**

Commit per domain as you go, then the ratchet last:

```bash
git add tools/<domain>.py tests/test_read_tools.py
git commit -m "feat(<domain>): collapse N pure-alias tools into <domain>_read"
# ... after all eight ...
git add tests/test_tool_surface_budget.py
git diff --cached --name-only
git commit -m "test(surface): ratchet after the nine read tools land"
```

---

### Task 7: `fortios_delete`

Fifteen `<resource>_delete(key)` aliases become one enum-constrained tool. Verified in advance: FastMCP enforces `Literal` server-side, rejecting an unlisted value — including a path-traversal string — before the body runs, which the generic `cmdb_delete(resource_path=...)` cannot do.

**Files:**
- Modify: `tools/generic.py` (add `fortios_delete`)
- Modify: `tools/firewall.py`, `tools/router.py`, `tools/security.py`, `tools/system.py`, `tools/user.py`, `tools/vpn.py`, `tools/wireless.py` (remove the 15 aliases)
- Modify: `tests/test_tool_annotations.py` (`EXPECTED_MUTATING`)
- Create: `tests/test_fortios_delete.py`

**Interfaces:**
- Consumes: `DELETE_RESOURCES`, `DeletableResource` from `resources.py`; `InstanceParam`, `VdomParam` from `tool_params.py`.
- Produces: `fortios_delete` registered `DESTRUCTIVE`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_fortios_delete.py`:

```python
"""Behaviour and safety of the consolidated delete tool.

Replaces 15 aliases that each wrapped one ``cmdb_delete`` call. The enum is
the point: FastMCP validates ``Literal`` before the body runs, so this tool
cannot be pointed at an arbitrary path the way ``cmdb_delete`` can.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from fortios_client import FortiOSError
from resources import DELETE_RESOURCES


class FakeClient:
    def __init__(self, raises: FortiOSError | None = None) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self._raises = raises

    async def cmdb_delete(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append((path, vdom))
        if self._raises:
            raise self._raises
        return {"status": "success", "path": path}


class FakeContext:
    def __init__(self, client: FakeClient) -> None:
        class _Registry:
            def resolve(self, _instance: str | None) -> FakeClient:
                return client

        class _RequestContext:
            lifespan_context = {"registry": _Registry()}

        self.request_context = _RequestContext()

    async def error(self, _message: str) -> None:
        return None


def _delete_tool():
    """The registered ``fortios_delete`` callable, via the tool manager."""
    from server import mcp

    tool = mcp._tool_manager.get_tool("fortios_delete")
    assert tool is not None, "fortios_delete is not registered"
    return tool.fn


def test_builds_the_keyed_path() -> None:
    client = FakeClient()
    result = asyncio.run(
        _delete_tool()(
            FakeContext(client), resource="firewall_address", name="stale-host"
        )
    )
    assert client.calls == [("firewall/address/stale-host", None)]
    assert "error" not in result


def test_vdom_is_passed_through() -> None:
    client = FakeClient()
    asyncio.run(
        _delete_tool()(
            FakeContext(client), resource="user_local", name="bob", vdom="root"
        )
    )
    assert client.calls == [("user/local/bob", "root")]


def test_fortios_error_is_returned_as_a_dict() -> None:
    client = FakeClient(raises=FortiOSError("in use by policy 7", status_code=424))
    result = asyncio.run(
        _delete_tool()(FakeContext(client), resource="firewall_address", name="x")
    )
    assert result["status_code"] == 424
    assert "in use by policy 7" in result["error"]


def test_every_table_row_is_reachable() -> None:
    """Each enum value maps to a row, so none is dead."""
    for value in DELETE_RESOURCES:
        client = FakeClient()
        asyncio.run(
            _delete_tool()(FakeContext(client), resource=value, name="probe")
        )
        assert client.calls, f"{value} issued no call"
        assert client.calls[0][0].endswith("/probe")


def test_the_enum_rejects_an_arbitrary_path() -> None:
    """The safety property: this tool cannot be aimed anywhere it likes."""
    from mcp.server.fastmcp.exceptions import ToolError
    from server import mcp

    with pytest.raises(ToolError) as excinfo:
        asyncio.run(
            mcp.call_tool(
                "fortios_delete",
                {"resource": "system/admin/../../etc", "name": "x"},
            )
        )
    assert "resource" in str(excinfo.value)


def test_it_advertises_destructive() -> None:
    from server import mcp

    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    ann = tools["fortios_delete"].annotations
    assert ann is not None
    assert ann.readOnlyHint is False
    assert ann.destructiveHint is True
    assert len(tools["fortios_delete"].inputSchema["properties"]["resource"]["enum"]) == 15


@pytest.mark.parametrize(
    "removed",
    [
        "firewall_policy_delete", "firewall_address_delete",
        "firewall_addrgrp_delete", "firewall_vip_delete", "router_static_delete",
        "ips_sensor_delete", "system_interface_delete", "system_admin_delete",
        "user_local_delete", "user_group_delete", "vpn_ipsec_phase1_delete",
        "vpn_ipsec_phase2_delete", "vpn_ssl_portal_delete",
        "wifi_wtp_deauthorize", "wifi_vap_delete",
    ],
)
def test_the_replaced_delete_tools_are_gone(removed: str) -> None:
    from server import mcp

    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert removed not in names
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest tests/test_fortios_delete.py -v
```

Expected: all FAIL — `fortios_delete is not registered`, and the removal tests fail because the aliases still exist.

- [ ] **Step 3: Add `fortios_delete` to `tools/generic.py`**

Add the imports:

```python
from resources import DELETE_RESOURCES, DeletableResource
```

and the tool inside `register()`:

```python
    async def fortios_delete(
        ctx: Context,
        resource: Annotated[
            DeletableResource,
            Field(description="Which kind of object to delete."),
        ],
        name: Annotated[
            str, Field(description="Key of the object to delete.")
        ],
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Placeholder replaced below with the generated resource table."""
        row = DELETE_RESOURCES.get(resource)
        if row is None:
            known = ", ".join(sorted(DELETE_RESOURCES))
            return {"error": f"unknown resource {resource!r}. Known: {known}"}
        client: FortiOSAPI = ctx.request_context.lifespan_context[
            "registry"
        ].resolve(instance)
        try:
            return await client.cmdb_delete(f"{row.path}/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    fortios_delete.__doc__ = (
        "Delete a configuration object from a FortiGate.\n\n"
        "`resource` is restricted to the object types this server supports "
        "deleting, so this tool cannot be aimed at an arbitrary API path. "
        "Deletions are not reversible — confirm with the user first.\n\n"
        + "\n".join(
            f"- `{value}` — {DELETE_RESOURCES[value].summary}"
            for value in sorted(DELETE_RESOURCES)
        )
    )
    mcp.tool(annotations=DESTRUCTIVE)(fortios_delete)
```

- [ ] **Step 4: Remove the 15 aliases**

Delete these functions from their modules: `firewall_policy_delete`, `firewall_address_delete`, `firewall_addrgrp_delete`, `firewall_vip_delete` (`firewall.py`); `router_static_delete` (`router.py`); `ips_sensor_delete` (`security.py`); `system_interface_delete`, `system_admin_delete` (`system.py`); `user_local_delete`, `user_group_delete` (`user.py`); `vpn_ipsec_phase1_delete`, `vpn_ipsec_phase2_delete`, `vpn_ssl_portal_delete` (`vpn.py`); `wifi_wtp_deauthorize`, `wifi_vap_delete` (`wireless.py`).

- [ ] **Step 5: Update the frozen writer set**

In `tests/test_tool_annotations.py`, remove those 15 names from `EXPECTED_MUTATING` and add `fortios_delete`. Run:

```bash
uv run pytest tests/test_tool_annotations.py -v
```

Expected: PASS. If the AST write-guard fails, `fortios_delete` reaches `cmdb_delete` and must be `DESTRUCTIVE`, not `READ_ONLY` — check the decorator.

- [ ] **Step 6: Run the new tests and the full suite**

```bash
uv run pytest tests/test_fortios_delete.py -v
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest
```

Expected: all pass.

- [ ] **Step 7: Confirm the final tool count and tighten the ratchet**

```bash
uv run python -c "
import asyncio, sys; sys.path.insert(0, 'tests')
from server import mcp
from test_tool_surface_budget import serialised_surface_chars
print('tools:', len(asyncio.run(mcp.list_tools())))
print('chars:', asyncio.run(serialised_surface_chars()))
"
```

Expected: `tools: 91`, `chars: ~100400`. Set `SURFACE_CEILING_CHARS` to the measured value rounded up to the next 100.

- [ ] **Step 8: Commit**

```bash
git add tools/ tests/test_fortios_delete.py tests/test_tool_annotations.py tests/test_tool_surface_budget.py
git diff --cached --name-only
git commit -m "feat(generic): consolidate 15 delete aliases into fortios_delete

The Literal enum is validated server-side before the body runs, so unlike
cmdb_delete this tool cannot be pointed at an arbitrary path. Frozen writer
set updated: -15 aliases, +fortios_delete."
```

---

### Task 8: Documentation and the final count

Every count stated anywhere in the repo is now wrong. The spec lists them; this task fixes them and pins the final ceiling.

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `tool_annotations.py`, `server.py`
- Modify: `tests/test_tool_surface_budget.py`
- Create: `tests/test_documented_counts.py`

**Interfaces:**
- Consumes: everything above.
- Produces: no new code interfaces.

- [ ] **Step 1: Write the test that pins the counts**

Create `tests/test_documented_counts.py`:

```python
"""The tool counts in prose match the server.

Four documents and one module docstring state how many tools this server has.
They drifted the moment the surface changed, and a stale "241 tools" in the
README is the kind of thing nobody notices for months.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from server import mcp

ROOT = Path(__file__).resolve().parent.parent
DOCS = ("README.md", "CLAUDE.md", "CONTRIBUTING.md")

#: Counts that were true before the collapse and must not survive in prose.
STALE_NUMBERS = ("241", "231", "183 of the 241", "~200 typed")


def test_the_server_registers_the_expected_number_of_tools() -> None:
    assert len(asyncio.run(mcp.list_tools())) == 91


def test_no_document_still_claims_a_pre_collapse_count() -> None:
    offenders: list[str] = []
    for name in DOCS:
        text = (ROOT / name).read_text(encoding="utf-8")
        for stale in STALE_NUMBERS:
            if stale in text:
                offenders.append(f"{name}: {stale!r}")
    annotations = (ROOT / "tool_annotations.py").read_text(encoding="utf-8")
    for stale in ("241", "183 of 241"):
        if stale in annotations:
            offenders.append(f"tool_annotations.py: {stale!r}")
    assert offenders == [], f"stale tool counts in prose: {offenders}"


def test_readme_states_the_current_count() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "91" in text, "README should state the current tool count"


def test_instructions_no_longer_name_a_removed_tool() -> None:
    """``system_status`` folded into ``system_read``."""
    text = (ROOT / "server.py").read_text(encoding="utf-8")
    instructions = text[text.index("instructions=(") :]
    assert "system_status" not in instructions
    assert "system_read" in instructions


def test_annotation_category_counts_match_reality() -> None:
    """The docstring in ``tool_annotations.py`` cites per-category counts."""
    tools = asyncio.run(mcp.list_tools())
    readers = [t for t in tools if t.annotations and t.annotations.readOnlyHint]
    writers = [t for t in tools if t.annotations and not t.annotations.readOnlyHint]
    assert len(readers) + len(writers) == 91
    text = (ROOT / "tool_annotations.py").read_text(encoding="utf-8")
    cited = re.search(r"(\d+) of (\d+) tools", text)
    assert cited is not None, "tool_annotations.py should cite N of M tools"
    assert int(cited.group(2)) == 91
    assert int(cited.group(1)) == len(readers)
```

- [ ] **Step 2: Run it to see what needs changing**

```bash
uv run pytest tests/test_documented_counts.py -v
```

Expected: `test_no_document_still_claims_a_pre_collapse_count` FAILS listing every stale number; `test_instructions_no_longer_name_a_removed_tool` FAILS; the annotation-count test FAILS.

- [ ] **Step 3: Get the real numbers**

```bash
uv run python -c "
import asyncio
from server import mcp
tools = asyncio.run(mcp.list_tools())
readers = [t for t in tools if t.annotations and t.annotations.readOnlyHint]
print('total:', len(tools))
print('read-only:', len(readers))
print('writers:', len(tools) - len(readers))
"
```

Record all three; they go into the prose below.

- [ ] **Step 4: Update `server.py`'s instructions**

In the `instructions=(...)` block, change:

```python
        "one with system_status, or fortigate_list(check_health=True) for the "
```

to:

```python
        "one with system_read(resource=\"status\"), or "
        "fortigate_list(check_health=True) for the "
```

and update the tool-category list so each domain mentions its read tool, e.g.:

```python
        "- **Generic**: cmdb_list/get/create/update/delete, monitor_get/action, log_get, service_call, fortios_delete\n"
        "    → These cover ALL 1536 FortiOS API endpoints directly.\n"
        "- **Per-domain reads**: system_read, firewall_read, vpn_read, router_read,\n"
        "  user_read, monitor_read, log_read, security_read, wireless_read — each takes\n"
        "  a `resource` enum; omit `name` to list, pass it to fetch one object.\n"
```

Also replace the closing guidance line `"Always use specific typed tools when available. "` with wording that reflects the new shape:

```python
        "Prefer a domain read tool or a typed write tool when one covers the "
        "resource; fall back to cmdb_list/cmdb_get/monitor_get for endpoints "
        "no enum lists. For destructive operations, confirm with the user first."
```

- [ ] **Step 5: Update `README.md`**

Replace the four stale claims:
- `- **231 typed MCP tools** organized by functional area …` → the new count of typed tools with the nine read tools described
- `- **9 generic pass-through tools** that cover all 1,536 FortiOS API endpoints` → 10, now including `fortios_delete`
- `confirm writes: 183 of the 241 tools advertise read-only, 58 advertise a write.` → the measured numbers from Step 3
- `**Total: 241 tools**` → `**Total: 91 tools**`
- `so the 241-tool set is loaded into its context once rather than once per device.` → `91-tool`

Add a short migration note so a reader of the old README is not stranded:

```markdown
> **Changed in this release:** 160 single-purpose read and delete tools were
> replaced by nine `<domain>_read` tools and one `fortios_delete`, cutting the
> advertised tool surface by 55%. `ips_sensor_list` is now
> `security_read(resource="ips_sensor")`; `user_local_get(name="alice")` is
> `user_read(resource="local", name="alice")`; `firewall_address_delete` is
> `fortios_delete(resource="firewall_address", name=...)`.
```

- [ ] **Step 6: Update `CLAUDE.md` and `CONTRIBUTING.md`**

In `CLAUDE.md`, revise the `tools/` bullet: the other modules now add typed write tools plus one read tool each, `resources.py` and `tool_params.py` join the leaf modules, and adding a read resource means a table row rather than a tool. Update the `~200 typed convenience tools` figure.

In `CONTRIBUTING.md`, under "Adding a new MCP tool", add that a new *readable* endpoint is a row in `resources.py` and its domain's `Literal`, not a new function — and that `scripts/generate_resources.py` cannot re-derive rows for tools that no longer exist, so the table is edited directly.

- [ ] **Step 7: Update `tool_annotations.py`'s docstrings**

The module docstring and the `READ_ONLY` comment cite `183 of 241 tools`, `every *_list/*_get/*_status`, and `17 of the 18 tools named log_*`. Rewrite with the Step 3 numbers and drop the naming-pattern claims, which no longer describe the surface. Keep the read-only *definition* — it is unchanged and still correct.

- [ ] **Step 8: Set the final ceiling**

```bash
uv run python -c "
import asyncio, sys; sys.path.insert(0, 'tests')
from test_tool_surface_budget import serialised_surface_chars
print('chars:', asyncio.run(serialised_surface_chars()))
"
```

Set `SURFACE_CEILING_CHARS = 104_000` — the spec's committed ceiling, ~4% headroom over the measured ~100,400 for a few new tools before the number must be re-examined. Update that module's docstring to state the new baseline and drop the `test_ceiling_is_not_slack` margin to `10_000` so the headroom is not itself slack.

- [ ] **Step 9: Full verification**

```bash
uv run pytest tests/test_documented_counts.py -v
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest
```

Expected: everything passes.

- [ ] **Step 10: Confirm the headline claim end to end**

```bash
uv run python -c "
import asyncio, sys; sys.path.insert(0, 'tests')
from server import mcp
from test_tool_surface_budget import serialised_surface_chars
n = len(asyncio.run(mcp.list_tools()))
c = asyncio.run(serialised_surface_chars())
print(f'{n} tools, {c} chars, ~{c//4} tokens')
print(f'was 241 tools, 227145 chars, ~56786 tokens')
print(f'reduction: {100*(227145-c)//227145}% chars, {100*(241-n)//241}% tools')
"
```

Expected: approximately `91 tools, 100415 chars, ~25103 tokens` and `reduction: 55% chars, 62% tools`. If either is materially off, find out why before committing — the spec's central claim is this number.

- [ ] **Step 11: Commit**

```bash
git add README.md CONTRIBUTING.md tool_annotations.py server.py tests/
git diff --cached --name-only   # CLAUDE.md is excluded; edit it but expect it absent here
git commit -m "docs: update tool counts and migration notes for the collapse

241 -> 91 tools, 227,145 -> ~100,400 chars of advertised surface (-55%).
Final ratchet set to 104,000 with ~4% headroom."
```

---

## Verification Checklist

Run after Task 8 to confirm the whole plan landed:

- [ ] `uv run pytest` — all green
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run pyright` — all green
- [ ] `uv run python -c "import asyncio; from server import mcp; print(len(asyncio.run(mcp.list_tools())))"` prints `91`
- [ ] `uv run mcp dev server.py` starts, and the Inspector lists nine `*_read` tools plus `fortios_delete`
- [ ] Against a real device: `system_read(resource="status", instance="fw-itd-dc")` returns firmware and serial
- [ ] Against a real device: `user_read(resource="local", instance="fw-itd-dc")` lists accounts, and adding `name=<one of them>` returns that single account
- [ ] `system_read(resource="global", name="x")` returns the singleton error without touching the device
- [ ] `security_read(resource="ips_sensor", instance="*")` fans out across both configured FortiGates
- [ ] `git log --oneline` shows one commit per task, no `CLAUDE.md`/`.claude/`/`.mcp.json` in any of them
