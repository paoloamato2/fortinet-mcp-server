# Multi-FortiGate Instance Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one server process serve many FortiGates, with the target chosen per tool call via an optional `instance` parameter, so the LLM no longer carries the 240-tool set once per firewall.

**Architecture:** A new root-level `instances.py` owns fleet config loading and an `InstanceRegistry` whose `resolve(instance)` returns one of three objects behind a shared `FortiOSAPI` Protocol: the real `FortiOSClient`, a `FanOutClient` for `instance="*"`, or a raising `ErrorClient`. Because `resolve()` never raises and every tool already wraps its call in `except FortiOSError`, resolution failures, read-only violations and fan-out-on-write all become the standard `{"error": ..., "status_code": ...}` payload without relocating a single `try` block. The 240 tools change by exactly two mechanical substitutions each, applied by an AST-guided script.

**Tech Stack:** Python 3.11+, `uv`, FastMCP (`mcp[cli]`), `httpx`, `pydantic`, `pytest`, `pytest-asyncio`, `pytest-httpx`, `ruff`, `pyright`.

**Spec:** `docs/superpowers/specs/2026-07-26-multi-fortigate-instances-design.md`

## Global Constraints

- Ruff format: 88-column lines, double quotes. Run `uv run ruff format .` before every commit.
- Full type hints on all public functions and tool handlers. Google-style docstrings.
- CI gate that must pass before every commit: `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, `uv run pytest -v`.
- Conventional Commits: `feat|fix|docs|test|refactor|chore|security(scope): summary`.
- Tools must catch `FortiOSError` and **return** `{"error": str(exc), "status_code": exc.status_code}` — never let it propagate to the MCP layer.
- `import server` must keep working with **no** environment variables set (`tests/test_server.py` depends on this). Config errors surface at `lifespan`, not at import.
- Instance names must match `^[A-Za-z0-9._-]{1,64}$`. The name `*` is reserved for fan-out.
- Never log or return `api_token` values.
- Branch: `feat/multi-fortigate-instances` (already created, spec already committed). Target branch for the eventual PR is `master`.
- Do **not** commit `CLAUDE.md`, `.claude/`, or `.mcp.json` — they are in `.git/info/exclude`. Verify `git diff --cached --name-only` before every commit.

## Verified facts this plan relies on

Do not re-derive these; they were measured against the current tree.

- 240 `@mcp.tool()` functions across `tools/*.py` (generic 9, firewall 37, security 35, system 33, vpn 26, router 24, monitor 21, wireless 20, user 19, log 16).
- All 243 client call sites are bare `return await client.<method>(...)` — zero post-processing.
- All 240 tools have a `vdom` param. It is the last param in 239; `wifi_vap_create` (`tools/wireless.py:168`) has `broadcast_ssid` and `fast_bss_transition` after it.
- All 240 lookup lines are byte-identical:
  `        client: FortiOSClient = ctx.request_context.lifespan_context["client"]\n` (8-space indent).
- `FortiOSClient` occurs in each module exactly `lookups + 1` times — only in those annotations plus the import, so the import must drop it after migration.
- `pytest-asyncio` currently runs in **STRICT** mode (no config), so async tests need markers until Task 1 adds `asyncio_mode = "auto"`.
- `mcp.shared.memory.create_connected_server_and_client_session` accepts a `FastMCP` instance directly and runs the real lifespan — verified to list 240 tools and call `cmdb_list` against a `pytest-httpx` mock.
- Ruff's default rule set (E4, E7, E9, F) has no import-sorting or unused-argument rules, so import order and unused stub params will not be flagged.

---

### Task 1: Fleet config loading

**Files:**
- Create: `instances.py`
- Create: `tests/conftest.py`
- Create: `tests/test_instances_load.py`
- Modify: `pyproject.toml` (add `[tool.pytest.ini_options]`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `InstanceConfig` frozen dataclass with fields `name: str`, `description: str`, `host: str`, `api_token: str`, `vdom: str = "root"`, `verify_ssl: bool = False`, `timeout: float = 30.0`, `read_only: bool = False`.
  - `load_instances() -> tuple[list[InstanceConfig], list[str]]` — never raises; returns `(instances, errors)`.
  - Module constant `FAN_OUT = "*"`.

- [ ] **Step 1: Add pytest config so async tests run without per-test markers**

Append to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

- [ ] **Step 2: Add the env-isolation fixture**

Create `tests/conftest.py`. `server.py` calls `load_dotenv()` at import, so a developer's real `.env` would otherwise leak into every test.

```python
"""Shared test fixtures."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_fortios_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every FORTIOS_* variable so tests never inherit a real .env."""
    for key in list(os.environ):
        if key.startswith("FORTIOS_"):
            monkeypatch.delenv(key, raising=False)
```

- [ ] **Step 3: Write the failing tests**

Create `tests/test_instances_load.py`:

```python
"""Tests for fleet configuration loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from instances import InstanceConfig, load_instances


def _write(tmp_path: Path, payload: object) -> str:
    path = tmp_path / "fortigates.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_loads_instances_from_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(
        tmp_path,
        [
            {
                "name": "hq-fw",
                "description": "HQ perimeter",
                "host": "https://10.0.0.1",
                "api_token": "tok-a",
                "read_only": True,
            },
            {
                "name": "dc-edge",
                "description": "DC edge",
                "host": "https://10.9.0.1",
                "api_token": "tok-b",
                "vdom": "tenant1",
                "verify_ssl": True,
                "timeout": 12.5,
            },
        ],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)

    instances, errors = load_instances()

    assert errors == []
    assert [i.name for i in instances] == ["hq-fw", "dc-edge"]
    assert instances[0] == InstanceConfig(
        name="hq-fw",
        description="HQ perimeter",
        host="https://10.0.0.1",
        api_token="tok-a",
        vdom="root",
        verify_ssl=False,
        timeout=30.0,
        read_only=True,
    )
    assert instances[1].vdom == "tenant1"
    assert instances[1].verify_ssl is True
    assert instances[1].timeout == 12.5
    assert instances[1].read_only is False


def test_env_fallback_creates_single_default_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORTIOS_HOST", "https://fw.example")
    monkeypatch.setenv("FORTIOS_API_TOKEN", "tok")

    instances, errors = load_instances()

    assert errors == []
    assert len(instances) == 1
    assert instances[0].name == "default"
    assert instances[0].host == "https://fw.example"
    assert instances[0].read_only is False
    assert "environment variables" in instances[0].description


def test_fleet_defaults_apply_to_instances_that_omit_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(
        tmp_path,
        [
            {
                "name": "a",
                "description": "d",
                "host": "https://a",
                "api_token": "t",
            }
        ],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)
    monkeypatch.setenv("FORTIOS_VDOM", "mgmt")
    monkeypatch.setenv("FORTIOS_VERIFY_SSL", "true")
    monkeypatch.setenv("FORTIOS_TIMEOUT", "45")

    instances, errors = load_instances()

    assert errors == []
    assert instances[0].vdom == "mgmt"
    assert instances[0].verify_ssl is True
    assert instances[0].timeout == 45.0


def test_api_token_env_is_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(
        tmp_path,
        [
            {
                "name": "a",
                "description": "d",
                "host": "https://a",
                "api_token_env": "MY_FW_TOKEN",
            }
        ],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)
    monkeypatch.setenv("MY_FW_TOKEN", "resolved-token")

    instances, errors = load_instances()

    assert errors == []
    assert instances[0].api_token == "resolved-token"


def test_missing_file_when_var_set_is_an_error_not_an_env_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", str(tmp_path / "nope.json"))
    monkeypatch.setenv("FORTIOS_HOST", "https://fw.example")
    monkeypatch.setenv("FORTIOS_API_TOKEN", "tok")

    instances, errors = load_instances()

    assert instances == []
    assert len(errors) == 1
    assert "cannot be read" in errors[0]


@pytest.mark.parametrize(
    ("payload", "expected_fragment"),
    [
        ({"name": "a"}, "must contain a JSON array"),
        ([], "empty array"),
        ([{"description": "d", "host": "https://a", "api_token": "t"}], "'name' is required"),
        (
            [{"name": "a", "host": "https://a", "api_token": "t"}],
            "'description' is required",
        ),
        ([{"name": "a", "description": "d", "api_token": "t"}], "'host' is required"),
        (
            [{"name": "a", "description": "d", "host": "https://a"}],
            "exactly one of 'api_token' or 'api_token_env'",
        ),
        (
            [
                {
                    "name": "a",
                    "description": "d",
                    "host": "https://a",
                    "api_token": "t",
                    "api_token_env": "X",
                }
            ],
            "exactly one of 'api_token' or 'api_token_env'",
        ),
        (
            [{"name": "bad name", "description": "d", "host": "https://a", "api_token": "t"}],
            "invalid name",
        ),
        (
            [{"name": "*", "description": "d", "host": "https://a", "api_token": "t"}],
            "reserved for fan-out",
        ),
        (
            [
                {
                    "name": "a",
                    "description": "d",
                    "host": "https://a",
                    "api_token": "t",
                    "timeout": "soon",
                }
            ],
            "'timeout' is not a number",
        ),
        (["not-an-object"], "expected a JSON object"),
    ],
)
def test_invalid_config_is_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    expected_fragment: str,
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write(tmp_path, payload))

    instances, errors = load_instances()

    assert instances == []
    assert any(expected_fragment in e for e in errors), errors


def test_malformed_json_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "fortigates.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", str(path))

    instances, errors = load_instances()

    assert instances == []
    assert any("not valid JSON" in e for e in errors), errors


def test_api_token_env_pointing_at_unset_variable_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    monkeypatch.setenv(
        "FORTIOS_INSTANCES_FILE",
        _write(
            tmp_path,
            [
                {
                    "name": "a",
                    "description": "d",
                    "host": "https://a",
                    "api_token_env": "MISSING_TOKEN",
                }
            ],
        ),
    )

    instances, errors = load_instances()

    assert instances == []
    assert any("MISSING_TOKEN" in e for e in errors), errors


def test_duplicate_names_are_reported_and_first_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "FORTIOS_INSTANCES_FILE",
        _write(
            tmp_path,
            [
                {"name": "a", "description": "first", "host": "https://1", "api_token": "t"},
                {"name": "a", "description": "second", "host": "https://2", "api_token": "t"},
            ],
        ),
    )

    instances, errors = load_instances()

    assert [i.description for i in instances] == ["first"]
    assert any("duplicate name" in e for e in errors), errors


def test_no_configuration_at_all_is_reported() -> None:
    instances, errors = load_instances()

    assert instances == []
    assert any("No FortiGate configured" in e for e in errors), errors
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `uv run pytest tests/test_instances_load.py -v`
Expected: collection error — `ModuleNotFoundError: No module named 'instances'`

- [ ] **Step 5: Write `instances.py`**

Create `instances.py`:

```python
"""FortiGate fleet configuration and instance registry.

Loads the set of managed FortiGates either from a JSON file named by
``FORTIOS_INSTANCES_FILE`` or, as a fallback, from the single-device
environment variables ``FORTIOS_HOST`` / ``FORTIOS_API_TOKEN``.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

FAN_OUT = "*"
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass(frozen=True)
class InstanceConfig:
    """Configuration for one managed FortiGate."""

    name: str
    description: str
    host: str
    api_token: str
    vdom: str = "root"
    verify_ssl: bool = False
    timeout: float = 30.0
    read_only: bool = False


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes")


def _fleet_defaults(errors: list[str]) -> dict[str, Any]:
    """Read the fleet-wide defaults from the legacy FORTIOS_* variables."""
    timeout = 30.0
    raw_timeout = os.environ.get("FORTIOS_TIMEOUT", "").strip()
    if raw_timeout:
        try:
            timeout = float(raw_timeout)
        except ValueError:
            errors.append(f"FORTIOS_TIMEOUT is not a number: {raw_timeout!r}")
    return {
        "vdom": os.environ.get("FORTIOS_VDOM", "").strip() or "root",
        "verify_ssl": _env_bool("FORTIOS_VERIFY_SSL", False),
        "timeout": timeout,
    }


def _parse_instance(
    raw: Any, index: int, defaults: dict[str, Any], errors: list[str]
) -> InstanceConfig | None:
    """Validate one entry from the instances file. Records errors, never raises."""
    where = f"instance #{index}"
    if not isinstance(raw, dict):
        errors.append(f"{where}: expected a JSON object, got {type(raw).__name__}")
        return None

    name = str(raw.get("name", "")).strip()
    if not name:
        errors.append(f"{where}: 'name' is required")
        return None
    where = f"instance {name!r}"
    if name == FAN_OUT:
        errors.append(
            f"{where}: '*' is reserved for fan-out and cannot be an instance name"
        )
        return None
    if not _NAME_RE.match(name):
        errors.append(
            f"{where}: invalid name; must be 1-64 characters from [A-Za-z0-9._-]"
        )
        return None

    description = str(raw.get("description", "")).strip()
    if not description:
        errors.append(f"{where}: 'description' is required")
        return None

    host = str(raw.get("host", "")).strip()
    if not host:
        errors.append(f"{where}: 'host' is required")
        return None

    inline_token = raw.get("api_token")
    token_env = raw.get("api_token_env")
    if bool(inline_token) == bool(token_env):
        errors.append(f"{where}: set exactly one of 'api_token' or 'api_token_env'")
        return None
    if token_env:
        api_token = os.environ.get(str(token_env), "").strip()
        if not api_token:
            errors.append(
                f"{where}: environment variable {str(token_env)!r} named by "
                f"'api_token_env' is unset or empty"
            )
            return None
    else:
        api_token = str(inline_token).strip()
        if not api_token:
            errors.append(f"{where}: 'api_token' is empty")
            return None

    timeout = float(defaults["timeout"])
    if "timeout" in raw:
        try:
            timeout = float(raw["timeout"])
        except (TypeError, ValueError):
            errors.append(f"{where}: 'timeout' is not a number: {raw['timeout']!r}")
            return None

    return InstanceConfig(
        name=name,
        description=description,
        host=host,
        api_token=api_token,
        vdom=str(raw.get("vdom", "")).strip() or str(defaults["vdom"]),
        verify_ssl=bool(raw.get("verify_ssl", defaults["verify_ssl"])),
        timeout=timeout,
        read_only=bool(raw.get("read_only", False)),
    )


def _load_from_file(
    path: str, defaults: dict[str, Any], errors: list[str]
) -> list[InstanceConfig]:
    try:
        raw_text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"FORTIOS_INSTANCES_FILE {path!r} cannot be read: {exc}")
        return []

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors.append(f"FORTIOS_INSTANCES_FILE {path!r} is not valid JSON: {exc}")
        return []

    if not isinstance(payload, list):
        errors.append(
            f"FORTIOS_INSTANCES_FILE {path!r} must contain a JSON array of "
            f"instance objects."
        )
        return []
    if not payload:
        errors.append(
            f"FORTIOS_INSTANCES_FILE {path!r} contains an empty array; "
            f"configure at least one FortiGate."
        )
        return []

    instances: list[InstanceConfig] = []
    seen: set[str] = set()
    for index, item in enumerate(payload, start=1):
        cfg = _parse_instance(item, index, defaults, errors)
        if cfg is None:
            continue
        if cfg.name in seen:
            errors.append(f"instance {cfg.name!r}: duplicate name")
            continue
        seen.add(cfg.name)
        instances.append(cfg)
    return instances


def _load_from_env(
    defaults: dict[str, Any], errors: list[str]
) -> list[InstanceConfig]:
    host = os.environ.get("FORTIOS_HOST", "").strip()
    api_token = os.environ.get("FORTIOS_API_TOKEN", "").strip()

    if not host and not api_token:
        errors.append(
            "No FortiGate configured. Set FORTIOS_INSTANCES_FILE to a JSON file, "
            "or set FORTIOS_HOST and FORTIOS_API_TOKEN for a single device."
        )
        return []
    if not host:
        errors.append("FORTIOS_HOST is not set.")
        return []
    if not api_token:
        errors.append("FORTIOS_API_TOKEN is not set.")
        return []

    return [
        InstanceConfig(
            name="default",
            description="Default FortiGate (configured via environment variables).",
            host=host,
            api_token=api_token,
            vdom=str(defaults["vdom"]),
            verify_ssl=bool(defaults["verify_ssl"]),
            timeout=float(defaults["timeout"]),
        )
    ]


def load_instances() -> tuple[list[InstanceConfig], list[str]]:
    """Load the FortiGate fleet from the environment. Never raises.

    Returns:
        An ``(instances, errors)`` pair. Callers that need a working fleet — the
        server lifespan — must raise when ``errors`` is non-empty or
        ``instances`` is empty. Callers that only need a best-effort roster —
        the MCP instructions block, built at import time — can ignore both.
    """
    errors: list[str] = []
    defaults = _fleet_defaults(errors)
    path = os.environ.get("FORTIOS_INSTANCES_FILE", "").strip()

    if not path:
        return _load_from_env(defaults, errors), errors

    if os.environ.get("FORTIOS_HOST", "").strip():
        logger.warning(
            "Both FORTIOS_INSTANCES_FILE and FORTIOS_HOST are set; "
            "FORTIOS_HOST is ignored."
        )
    return _load_from_file(path, defaults, errors), errors
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_instances_load.py -v`
Expected: PASS (all cases)

- [ ] **Step 7: Run the full gate**

Run: `uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest -v`
Expected: all clean. `test_mcp_instance_name` still passes.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml instances.py tests/conftest.py tests/test_instances_load.py
git diff --cached --name-only   # confirm no CLAUDE.md / .claude / .mcp.json
git commit -m "feat(instances): add fleet configuration loading

JSON file via FORTIOS_INSTANCES_FILE, falling back to the single-device
FORTIOS_HOST/FORTIOS_API_TOKEN variables as an instance named 'default'.
load_instances() never raises; it returns collected errors so the import-time
roster can be tolerant while the lifespan stays strict."
```

---

### Task 2: Read-only guard in `FortiOSClient`

**Files:**
- Modify: `fortios_client.py:44-57` (constructor), and the six write methods
- Create: `tests/test_client_readonly.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `FortiOSClient(host, api_token, vdom="root", verify_ssl=False, timeout=30.0, name="default", read_only=False)`; attributes `self.name`, `self.read_only`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_client_readonly.py`:

```python
"""Tests for the per-instance read-only guard."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from fortios_client import FortiOSClient, FortiOSError


def _client(read_only: bool) -> FortiOSClient:
    return FortiOSClient(
        host="https://fw.example",
        api_token="tok",
        name="hq-fw",
        read_only=read_only,
    )


async def test_reads_are_allowed_on_a_read_only_instance(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://fw.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [], "http_status": 200},
    )
    async with _client(read_only=True) as client:
        assert await client.cmdb_get("firewall/policy") == {
            "results": [],
            "http_status": 200,
        }


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("cmdb_post", ("firewall/policy", {"name": "x"})),
        ("cmdb_put", ("firewall/policy/1", {"name": "x"})),
        ("cmdb_delete", ("firewall/policy/1",)),
        ("monitor_post", ("system/config/restore",)),
        ("log_post", ("forward/raw",)),
        ("service_post", ("security-rating/trigger",)),
    ],
)
async def test_writes_are_refused_without_issuing_a_request(
    httpx_mock: HTTPXMock, method: str, args: tuple[object, ...]
) -> None:
    async with _client(read_only=True) as client:
        with pytest.raises(FortiOSError) as excinfo:
            await getattr(client, method)(*args)

    assert excinfo.value.status_code == 403
    assert "read-only" in str(excinfo.value)
    assert "hq-fw" in str(excinfo.value)
    assert httpx_mock.get_requests() == []


async def test_writes_are_allowed_when_not_read_only(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://fw.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"http_status": 200, "mkey": 7},
    )
    async with _client(read_only=False) as client:
        result = await client.cmdb_post("firewall/policy", {"name": "x"})

    assert result["mkey"] == 7
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_client_readonly.py -v`
Expected: FAIL — `TypeError: FortiOSClient.__init__() got an unexpected keyword argument 'name'`

- [ ] **Step 3: Extend the constructor**

In `fortios_client.py`, replace the `__init__` signature and body:

```python
    def __init__(
        self,
        host: str,
        api_token: str,
        vdom: str = "root",
        verify_ssl: bool = False,
        timeout: float = 30.0,
        name: str = "default",
        read_only: bool = False,
    ) -> None:
        self.host = host.rstrip("/")
        self.api_token = api_token
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.name = name
        self.read_only = read_only
        self._client: httpx.AsyncClient | None = None
```

- [ ] **Step 4: Add the guard helper**

In `fortios_client.py`, directly after `_client_guard`:

```python
    def _write_guard(self) -> None:
        """Refuse write operations on an instance configured read-only."""
        if self.read_only:
            raise FortiOSError(
                f"Instance '{self.name}' is configured read-only; "
                f"write operations are refused.",
                403,
            )
```

- [ ] **Step 5: Call the guard from all six write methods**

Insert `self._write_guard()` as the **first** statement of `cmdb_post`, `cmdb_put`, `cmdb_delete`, `monitor_post`, `log_post`, and `service_post` — before `client = self._client_guard()`, so no request is built. For example `cmdb_post` becomes:

```python
    async def cmdb_post(
        self,
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """POST /api/v2/cmdb/{path} — create a configuration object."""
        self._write_guard()
        client = self._client_guard()
        url = f"{self._BASE}/cmdb/{path.lstrip('/')}"
        resp = await client.post(url, json=body, params=self._vdom_params(params, vdom))
        return self._check_response(resp)
```

Leave the four read methods (`cmdb_get`, `monitor_get`, `log_get`, `service_get`) untouched.

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_client_readonly.py -v`
Expected: PASS (8 cases)

- [ ] **Step 7: Verify the guard count**

Run: `grep -c '_write_guard()' fortios_client.py`
Expected: `7` — one definition plus six call sites.

- [ ] **Step 8: Run the full gate and commit**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest -v
git add fortios_client.py tests/test_client_readonly.py
git diff --cached --name-only
git commit -m "feat(client): add per-instance read-only guard

Write methods refuse before building a request when the instance is
configured read-only, raising FortiOSError(403) that every tool's existing
handler turns into a standard error payload."
```

---

### Task 3: `FortiOSAPI` protocol, `ErrorClient`, and `InstanceRegistry.resolve()`

**Files:**
- Modify: `instances.py` (append)
- Create: `tests/test_registry_resolve.py`

**Interfaces:**
- Consumes: `InstanceConfig`, `FAN_OUT` (Task 1); `FortiOSClient(..., name=, read_only=)` (Task 2).
- Produces:
  - `FortiOSAPI` Protocol declaring all ten API methods.
  - `ErrorClient(message: str, status_code: int = 0)`.
  - `InstanceRegistry(instances: list[InstanceConfig])` with `.configs -> list[InstanceConfig]`, `.clients -> dict[str, FortiOSClient]`, `.names() -> list[str]`, `.resolve(instance: str | None) -> FortiOSAPI`.
  - `roster_text(instances: list[InstanceConfig]) -> str`.

Note: `FanOutClient` arrives in Task 4. Until then `resolve("*")` returns an `ErrorClient` explaining that fan-out is unavailable, which Task 4 replaces.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_registry_resolve.py`:

```python
"""Tests for instance resolution."""

from __future__ import annotations

import pytest

from fortios_client import FortiOSClient, FortiOSError
from instances import ErrorClient, InstanceConfig, InstanceRegistry, roster_text


def _cfg(name: str, read_only: bool = False) -> InstanceConfig:
    return InstanceConfig(
        name=name,
        description=f"{name} description",
        host=f"https://{name}.example",
        api_token="tok",
        read_only=read_only,
    )


def test_single_instance_resolves_when_omitted() -> None:
    registry = InstanceRegistry([_cfg("only-fw")])

    client = registry.resolve(None)

    assert isinstance(client, FortiOSClient)
    assert client.name == "only-fw"


@pytest.mark.parametrize("omitted", [None, "", "   "])
async def test_omitting_instance_with_several_configured_errors(
    omitted: str | None,
) -> None:
    registry = InstanceRegistry([_cfg("a"), _cfg("b"), _cfg("c")])

    client = registry.resolve(omitted)

    assert isinstance(client, ErrorClient)
    with pytest.raises(FortiOSError) as excinfo:
        await client.cmdb_get("firewall/policy")
    message = str(excinfo.value)
    assert "'instance' is required" in message
    assert "3 FortiGates configured" in message
    assert "a, b, c" in message


def test_known_name_resolves_to_the_right_client() -> None:
    registry = InstanceRegistry([_cfg("a"), _cfg("b")])

    assert registry.resolve("b").name == "b"  # type: ignore[union-attr]


def test_surrounding_whitespace_is_stripped() -> None:
    registry = InstanceRegistry([_cfg("a"), _cfg("b")])

    assert registry.resolve("  b  ").name == "b"  # type: ignore[union-attr]


async def test_unknown_name_errors_and_lists_configured_names() -> None:
    registry = InstanceRegistry([_cfg("a"), _cfg("b")])

    client = registry.resolve("nope")

    assert isinstance(client, ErrorClient)
    with pytest.raises(FortiOSError) as excinfo:
        await client.cmdb_get("firewall/policy")
    assert "Unknown instance 'nope'" in str(excinfo.value)
    assert "Configured: a, b" in str(excinfo.value)


def test_read_only_flag_reaches_the_client() -> None:
    registry = InstanceRegistry([_cfg("ro", read_only=True), _cfg("rw")])

    assert registry.resolve("ro").read_only is True  # type: ignore[union-attr]
    assert registry.resolve("rw").read_only is False  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "method",
    [
        "cmdb_get",
        "cmdb_delete",
        "monitor_get",
        "log_get",
        "service_get",
    ],
)
async def test_error_client_raises_from_every_no_body_method(method: str) -> None:
    client = ErrorClient("boom", 7)

    with pytest.raises(FortiOSError) as excinfo:
        await getattr(client, method)("some/path")

    assert str(excinfo.value) == "boom"
    assert excinfo.value.status_code == 7


@pytest.mark.parametrize(
    "method", ["cmdb_post", "cmdb_put", "monitor_post", "log_post", "service_post"]
)
async def test_error_client_raises_from_every_body_method(method: str) -> None:
    client = ErrorClient("boom", 7)

    with pytest.raises(FortiOSError):
        await getattr(client, method)("some/path", {"a": 1})


def test_registry_exposes_configs_and_names_in_order() -> None:
    registry = InstanceRegistry([_cfg("z"), _cfg("a")])

    assert registry.names() == ["z", "a"]
    assert [c.name for c in registry.configs] == ["z", "a"]
    assert list(registry.clients) == ["z", "a"]


def test_roster_text_lists_names_descriptions_and_read_only() -> None:
    text = roster_text([_cfg("hq-fw", read_only=True), _cfg("dc-edge")])

    assert "- hq-fw — hq-fw description [READ-ONLY]" in text
    assert "- dc-edge — dc-edge description" in text
    assert "[READ-ONLY]" not in text.split("dc-edge")[1]
    assert '`instance` is required' in text
    assert 'instance="*"' in text


def test_roster_text_for_one_instance_says_instance_may_be_omitted() -> None:
    text = roster_text([_cfg("only-fw")])

    assert "may be omitted" in text


def test_roster_text_with_no_instances_explains_how_to_configure() -> None:
    text = roster_text([])

    assert "No FortiGate instances are configured" in text
    assert "FORTIOS_INSTANCES_FILE" in text


def test_roster_text_never_leaks_a_token() -> None:
    assert "tok" not in roster_text([_cfg("a")])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_registry_resolve.py -v`
Expected: FAIL — `ImportError: cannot import name 'ErrorClient' from 'instances'`

- [ ] **Step 3: Append the protocol and `ErrorClient` to `instances.py`**

First extend the imports at the top of `instances.py`:

```python
from typing import Any, Protocol
```

and add:

```python
from fortios_client import FortiOSClient, FortiOSError
```

Then append to the end of the file:

```python
class FortiOSAPI(Protocol):
    """Structural type shared by the real client and the registry's stand-ins.

    Declares the ten FortiOS API methods so tools can be annotated against a
    single type regardless of which object ``InstanceRegistry.resolve`` hands
    back.
    """

    async def cmdb_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...

    async def cmdb_post(
        self,
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...

    async def cmdb_put(
        self,
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...

    async def cmdb_delete(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...

    async def monitor_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...

    async def monitor_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...

    async def log_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...

    async def log_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...

    async def service_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...

    async def service_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]: ...


class ErrorClient:
    """Stand-in returned when a target instance cannot be resolved.

    Every method raises :class:`FortiOSError`, so the ``except FortiOSError``
    block each tool already has converts the resolution failure into the
    standard ``{"error": ..., "status_code": ...}`` payload. This is why
    :meth:`InstanceRegistry.resolve` can promise never to raise, even though
    the 240 tool call sites look it up outside their ``try`` blocks.
    """

    def __init__(self, message: str, status_code: int = 0) -> None:
        self.message = message
        self.status_code = status_code

    def _fail(self) -> dict[str, Any]:
        raise FortiOSError(self.message, self.status_code)

    async def cmdb_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()

    async def cmdb_post(
        self,
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()

    async def cmdb_put(
        self,
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()

    async def cmdb_delete(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()

    async def monitor_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()

    async def monitor_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()

    async def log_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()

    async def log_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()

    async def service_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()

    async def service_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._fail()


def roster_text(instances: list[InstanceConfig]) -> str:
    """Render the fleet roster for the server's MCP instructions block."""
    if not instances:
        return (
            "No FortiGate instances are configured. Set FORTIOS_INSTANCES_FILE to a "
            "JSON file, or FORTIOS_HOST and FORTIOS_API_TOKEN for a single device, "
            "then restart the server."
        )

    lines = [
        "Configured FortiGates — pass the name as the `instance` parameter on any tool:"
    ]
    for cfg in instances:
        suffix = " [READ-ONLY]" if cfg.read_only else ""
        lines.append(f"- {cfg.name} — {cfg.description}{suffix}")

    if len(instances) == 1:
        lines.append("Only one FortiGate is configured, so `instance` may be omitted.")
    else:
        lines.append(
            "`instance` is required on every tool call. "
            'Use instance="*" to read from all FortiGates at once.'
        )
    return "\n".join(lines)


class InstanceRegistry:
    """Holds one live client per configured FortiGate and resolves targets."""

    def __init__(self, instances: list[InstanceConfig]) -> None:
        self._configs: dict[str, InstanceConfig] = {c.name: c for c in instances}
        self._clients: dict[str, FortiOSClient] = {
            c.name: FortiOSClient(
                host=c.host,
                api_token=c.api_token,
                vdom=c.vdom,
                verify_ssl=c.verify_ssl,
                timeout=c.timeout,
                name=c.name,
                read_only=c.read_only,
            )
            for c in instances
        }

    @property
    def configs(self) -> list[InstanceConfig]:
        """The configured instances, in file order."""
        return list(self._configs.values())

    @property
    def clients(self) -> dict[str, FortiOSClient]:
        """The live clients, keyed by instance name, in file order."""
        return self._clients

    def names(self) -> list[str]:
        """Configured instance names, in file order."""
        return list(self._configs)

    def resolve(self, instance: str | None) -> FortiOSAPI:
        """Return the API object for ``instance``. Never raises.

        On any resolution failure an :class:`ErrorClient` is returned whose
        methods raise, so the caller's existing ``except FortiOSError`` handles
        it. See :class:`ErrorClient` for why.
        """
        target = (instance or "").strip()

        if not target:
            if len(self._clients) == 1:
                return next(iter(self._clients.values()))
            return ErrorClient(
                f"'instance' is required: {len(self._clients)} FortiGates "
                f"configured. Choose one of: {', '.join(self.names())}"
            )

        if target == FAN_OUT:
            return ErrorClient(
                "instance='*' fan-out is not available in this build."
            )

        client = self._clients.get(target)
        if client is None:
            return ErrorClient(
                f"Unknown instance {target!r}. Configured: {', '.join(self.names())}"
            )
        return client
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_registry_resolve.py -v`
Expected: PASS

- [ ] **Step 5: Run the full gate and commit**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest -v
git add instances.py tests/test_registry_resolve.py
git diff --cached --name-only
git commit -m "feat(instances): add FortiOSAPI protocol, ErrorClient and registry

resolve() never raises: unresolvable targets yield an ErrorClient whose
methods raise FortiOSError, which each tool's existing handler converts into
a standard error payload. Fan-out lands in the next commit."
```

---

### Task 4: `FanOutClient` for `instance="*"`

**Files:**
- Modify: `instances.py` (add `FanOutClient`, wire into `resolve`)
- Create: `tests/test_registry_fanout.py`

**Interfaces:**
- Consumes: `FortiOSAPI`, `InstanceRegistry`, `FAN_OUT` (Task 3).
- Produces: `FanOutClient(clients: Mapping[str, FortiOSAPI])`; `resolve("*")` now returns it.

`Mapping` (not `dict`) is required: `Mapping` is covariant in its value type, so `dict[str, FortiOSClient]` is assignable to `Mapping[str, FortiOSAPI]`. With `dict[str, FortiOSAPI]` pyright would reject the call, because `dict` is invariant.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_registry_fanout.py`:

```python
"""Tests for instance='*' read fan-out."""

from __future__ import annotations

import contextlib

import pytest
from pytest_httpx import HTTPXMock

from fortios_client import FortiOSError
from instances import FanOutClient, InstanceConfig, InstanceRegistry


def _registry() -> InstanceRegistry:
    return InstanceRegistry(
        [
            InstanceConfig(
                name="a", description="A", host="https://a.example", api_token="t"
            ),
            InstanceConfig(
                name="b", description="B", host="https://b.example", api_token="t"
            ),
        ]
    )


@contextlib.asynccontextmanager
async def _open(registry: InstanceRegistry):
    async with contextlib.AsyncExitStack() as stack:
        for client in registry.clients.values():
            await stack.enter_async_context(client)
        yield


def test_star_resolves_to_a_fan_out_client() -> None:
    assert isinstance(_registry().resolve("*"), FanOutClient)


def test_star_with_a_single_instance_still_fans_out() -> None:
    registry = InstanceRegistry(
        [
            InstanceConfig(
                name="only", description="O", host="https://o.example", api_token="t"
            )
        ]
    )

    assert isinstance(registry.resolve("*"), FanOutClient)


async def test_fan_out_read_returns_a_map_keyed_by_instance(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://a.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 1}], "http_status": 200},
    )
    httpx_mock.add_response(
        url="https://b.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 2}], "http_status": 200},
    )
    registry = _registry()

    async with _open(registry):
        result = await registry.resolve("*").cmdb_get("firewall/policy")

    assert list(result) == ["a", "b"]
    assert result["a"]["results"][0]["policyid"] == 1
    assert result["b"]["results"][0]["policyid"] == 2


async def test_fan_out_reports_per_instance_failures_alongside_successes(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://a.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 1}], "http_status": 200},
    )
    httpx_mock.add_response(
        url="https://b.example/api/v2/cmdb/firewall/policy?vdom=root",
        status_code=500,
        json={"http_status": 500, "status": "error", "cli_error": "boom"},
    )
    registry = _registry()

    async with _open(registry):
        result = await registry.resolve("*").cmdb_get("firewall/policy")

    assert result["a"]["results"][0]["policyid"] == 1
    assert "error" in result["b"]
    assert result["b"]["status_code"] == 500


async def test_fan_out_passes_vdom_through(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://a.example/api/v2/cmdb/firewall/policy?vdom=tenant1",
        json={"results": [], "http_status": 200},
    )
    httpx_mock.add_response(
        url="https://b.example/api/v2/cmdb/firewall/policy?vdom=tenant1",
        json={"results": [], "http_status": 200},
    )
    registry = _registry()

    async with _open(registry):
        await registry.resolve("*").cmdb_get("firewall/policy", vdom="tenant1")


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("cmdb_post", ("firewall/policy", {"name": "x"})),
        ("cmdb_put", ("firewall/policy/1", {"name": "x"})),
        ("cmdb_delete", ("firewall/policy/1",)),
        ("monitor_post", ("system/config/restore",)),
        ("log_post", ("forward/raw",)),
        ("service_post", ("security-rating/trigger",)),
    ],
)
async def test_fan_out_refuses_writes_without_issuing_a_request(
    httpx_mock: HTTPXMock, method: str, args: tuple[object, ...]
) -> None:
    registry = _registry()

    async with _open(registry):
        with pytest.raises(FortiOSError) as excinfo:
            await getattr(registry.resolve("*"), method)(*args)

    assert "read-only" in str(excinfo.value)
    assert httpx_mock.get_requests() == []


async def test_fan_out_includes_read_only_instances(httpx_mock: HTTPXMock) -> None:
    registry = InstanceRegistry(
        [
            InstanceConfig(
                name="ro",
                description="RO",
                host="https://ro.example",
                api_token="t",
                read_only=True,
            )
        ]
    )
    httpx_mock.add_response(
        url="https://ro.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [], "http_status": 200},
    )

    async with _open(registry):
        result = await registry.resolve("*").cmdb_get("firewall/policy")

    assert "ro" in result
    assert "error" not in result["ro"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_registry_fanout.py -v`
Expected: FAIL — `ImportError: cannot import name 'FanOutClient' from 'instances'`

- [ ] **Step 3: Add `FanOutClient`**

Extend the `instances.py` imports:

```python
import asyncio
from collections.abc import Mapping
```

Insert this class into `instances.py` immediately after `ErrorClient`:

```python
class FanOutClient:
    """Runs read operations against every configured FortiGate concurrently.

    Returned by :meth:`InstanceRegistry.resolve` for ``instance="*"``. Reads
    return a mapping of instance name to that instance's response, in
    configuration order; an instance that fails contributes the same
    ``{"error": ..., "status_code": ...}`` shape a single failed call would
    produce, so one unreachable device never fails the whole query. Writes are
    refused outright.
    """

    def __init__(self, clients: Mapping[str, FortiOSAPI]) -> None:
        self._clients = clients

    async def _gather(self, method: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        names = list(self._clients)
        results = await asyncio.gather(
            *(getattr(self._clients[n], method)(*args, **kwargs) for n in names),
            return_exceptions=True,
        )
        merged: dict[str, Any] = {}
        for name, result in zip(names, results):
            if isinstance(result, BaseException):
                merged[name] = {
                    "error": str(result),
                    "status_code": getattr(result, "status_code", 0),
                }
            else:
                merged[name] = result
        return merged

    def _refuse(self) -> dict[str, Any]:
        raise FortiOSError(
            "instance='*' fan-out is read-only. "
            "Target a single instance for write operations.",
            0,
        )

    async def cmdb_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return await self._gather("cmdb_get", path, params, vdom=vdom)

    async def cmdb_post(
        self,
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._refuse()

    async def cmdb_put(
        self,
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._refuse()

    async def cmdb_delete(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._refuse()

    async def monitor_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return await self._gather("monitor_get", path, params, vdom=vdom)

    async def monitor_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._refuse()

    async def log_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return await self._gather("log_get", path, params, vdom=vdom)

    async def log_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._refuse()

    async def service_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return await self._gather("service_get", path, params, vdom=vdom)

    async def service_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        return self._refuse()
```

Every method signature above must match `FortiOSAPI` exactly, including the leading
`path: str` on all ten and the required (defaultless) `body` on `cmdb_post` / `cmdb_put`.
Pyright checks this at the `return FanOutClient(...)` line in `resolve()`; a mismatch fails
the type gate rather than surfacing at runtime.

- [ ] **Step 4: Wire `*` into `resolve()`**

In `InstanceRegistry.resolve`, replace the placeholder branch from Task 3:

```python
        if target == FAN_OUT:
            return ErrorClient(
                "instance='*' fan-out is not available in this build."
            )
```

with:

```python
        if target == FAN_OUT:
            return FanOutClient(self._clients)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_registry_fanout.py tests/test_registry_resolve.py -v`
Expected: PASS

- [ ] **Step 6: Run the full gate and commit**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest -v
git add instances.py tests/test_registry_fanout.py
git diff --cached --name-only
git commit -m "feat(instances): add instance='*' read fan-out

Reads run concurrently across the fleet and return a map keyed by instance
name; a failing device contributes an error entry rather than failing the
whole query. Writes are refused."
```

---

### Task 5: Wire the registry into `server.py`

**Files:**
- Modify: `server.py` (imports, `_get_config` removal, `lifespan`, `instructions`)
- Create: `tests/test_server_wiring.py`

**Interfaces:**
- Consumes: `load_instances`, `roster_text`, `InstanceRegistry` (Tasks 1, 3).
- Produces: lifespan context `{"registry": InstanceRegistry, "client": FortiOSClient}`. The `client` key is **transitional** — it keeps the 240 not-yet-migrated tools working, and Task 8 removes it.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_server_wiring.py`:

```python
"""Tests for server lifespan wiring and the instructions roster."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import server
from instances import InstanceRegistry


def _write_fleet(tmp_path: Path) -> str:
    path = tmp_path / "fortigates.json"
    path.write_text(
        json.dumps(
            [
                {
                    "name": "hq-fw",
                    "description": "HQ perimeter",
                    "host": "https://hq.example",
                    "api_token": "t",
                    "read_only": True,
                },
                {
                    "name": "dc-edge",
                    "description": "DC edge",
                    "host": "https://dc.example",
                    "api_token": "t",
                },
            ]
        ),
        encoding="utf-8",
    )
    return str(path)


async def test_lifespan_yields_a_registry_with_every_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))

    async with server.lifespan(server.mcp) as ctx:
        registry = ctx["registry"]
        assert isinstance(registry, InstanceRegistry)
        assert registry.names() == ["hq-fw", "dc-edge"]
        assert registry.clients["hq-fw"].read_only is True
        # Transitional key kept until the tools are migrated (Task 8).
        assert ctx["client"] is registry.clients["hq-fw"]


async def test_lifespan_raises_on_invalid_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "fortigates.json"
    path.write_text(json.dumps([{"name": "a"}]), encoding="utf-8")
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", str(path))

    with pytest.raises(EnvironmentError) as excinfo:
        async with server.lifespan(server.mcp):
            pass

    assert "invalid" in str(excinfo.value)


async def test_lifespan_raises_when_nothing_is_configured() -> None:
    with pytest.raises(EnvironmentError) as excinfo:
        async with server.lifespan(server.mcp):
            pass

    assert "No FortiGate" in str(excinfo.value)


def test_importing_server_without_env_still_works() -> None:
    # Guards the contract that tests/test_server.py relies on.
    assert server.mcp.name == "FortiOS MCP Server"


def test_instructions_mention_the_instance_parameter() -> None:
    instructions = server.mcp.instructions or ""

    assert "instance" in instructions
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server_wiring.py -v`
Expected: FAIL — `KeyError: 'registry'` on the first test.

- [ ] **Step 3: Replace the config and lifespan sections of `server.py`**

Replace the import block, delete `_required_env` and `_get_config`, and rewrite `lifespan`. The imports become:

```python
from __future__ import annotations

import logging
import os
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from typing import AsyncGenerator

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from instances import InstanceRegistry, load_instances, roster_text
```

`FortiOSClient` is no longer imported by `server.py`. Delete the entire "Configuration" section (`_required_env` and `_get_config`) and replace the lifespan with:

```python
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
            "FortiGate instance configuration is invalid:\n  - "
            + "\n  - ".join(errors)
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
        yield {
            "registry": registry,
            # Transitional: keeps not-yet-migrated tools working. Removed in
            # the commit that migrates the last tool module.
            "client": next(iter(registry.clients.values())),
        }
    logger.info("FortiGate clients closed.")
```

- [ ] **Step 4: Add the roster to the instructions**

In the `FastMCP(...)` call, change the opening line and insert the roster. The `instructions` argument becomes:

```python
    instructions=(
        "You are connected to one or more Fortinet FortiGates running "
        "FortiOS 7.6.6. "
        "This server exposes the complete FortiOS REST API as MCP tools. "
        "\n\n"
        + roster_text(_IMPORT_INSTANCES)
        + "\n\n"
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_server_wiring.py -v`
Expected: PASS

- [ ] **Step 6: Confirm the server still starts against a single-device env**

Run:
```bash
FORTIOS_HOST=https://fw.example FORTIOS_API_TOKEN=tok \
  uv run python -c "
import asyncio, server
async def main():
    async with server.lifespan(server.mcp) as ctx:
        print('instances:', ctx['registry'].names())
asyncio.run(main())
"
```
Expected: `instances: ['default']`

- [ ] **Step 7: Run the full gate and commit**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest -v
git add server.py tests/test_server_wiring.py
git diff --cached --name-only
git commit -m "feat(server): build one client per FortiGate in the lifespan

The lifespan yields an InstanceRegistry and logs the fleet; the roster is
rendered into the MCP instructions at import. A transitional 'client' key
keeps the unmigrated tools working until the tool migration lands."
```

---

### Task 6: `fortigate_list` tool

**Files:**
- Create: `tools/fleet.py`
- Modify: `server.py` (import and register `fleet`)
- Create: `tests/test_fleet.py`

**Interfaces:**
- Consumes: lifespan key `registry` (Task 5); `InstanceRegistry.configs` / `.clients` (Task 3).
- Produces: MCP tool `fortigate_list(check_health: bool = False)`. Takes no `instance` param — it is a fleet-wide meta tool, and Task 8's guard test exempts this module.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_fleet.py`:

```python
"""Tests for the fortigate_list meta tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pytest_httpx import HTTPXMock


def _write_fleet(tmp_path: Path) -> str:
    path = tmp_path / "fortigates.json"
    path.write_text(
        json.dumps(
            [
                {
                    "name": "hq-fw",
                    "description": "HQ perimeter",
                    "host": "https://hq.example",
                    "api_token": "super-secret-token",
                    "read_only": True,
                },
                {
                    "name": "dc-edge",
                    "description": "DC edge",
                    "host": "https://dc.example",
                    "api_token": "another-secret",
                    "vdom": "tenant1",
                },
            ]
        ),
        encoding="utf-8",
    )
    return str(path)


async def _call(tool: str, args: dict[str, object]) -> str:
    from server import mcp

    async with create_connected_server_and_client_session(mcp) as client:
        result = await client.call_tool(tool, args)
    assert not result.isError, result.content
    return result.content[0].text  # type: ignore[union-attr]


async def test_lists_instances_with_descriptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))

    payload = json.loads(await _call("fortigate_list", {}))

    assert [i["name"] for i in payload["instances"]] == ["hq-fw", "dc-edge"]
    assert payload["instances"][0]["description"] == "HQ perimeter"
    assert payload["instances"][0]["read_only"] is True
    assert payload["instances"][1]["vdom"] == "tenant1"
    assert payload["count"] == 2


async def test_never_leaks_api_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))

    raw = await _call("fortigate_list", {})

    assert "super-secret-token" not in raw
    assert "another-secret" not in raw


async def test_health_check_reports_reachable_and_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))
    httpx_mock.add_response(
        url="https://hq.example/api/v2/monitor/system/status?vdom=root",
        json={
            "results": {"version": "v7.6.6", "serial": "FG-1"},
            "http_status": 200,
        },
    )
    httpx_mock.add_response(
        url="https://dc.example/api/v2/monitor/system/status?vdom=tenant1",
        status_code=401,
        json={"http_status": 401, "status": "error", "cli_error": "bad token"},
    )

    payload = json.loads(await _call("fortigate_list", {"check_health": True}))
    by_name = {i["name"]: i for i in payload["instances"]}

    assert by_name["hq-fw"]["reachable"] is True
    assert by_name["hq-fw"]["version"] == "v7.6.6"
    assert by_name["hq-fw"]["serial"] == "FG-1"
    assert by_name["dc-edge"]["reachable"] is False
    assert "error" in by_name["dc-edge"]


async def test_health_check_is_not_run_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock
) -> None:
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", _write_fleet(tmp_path))

    payload = json.loads(await _call("fortigate_list", {}))

    assert "reachable" not in payload["instances"][0]
    assert httpx_mock.get_requests() == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_fleet.py -v`
Expected: FAIL — unknown tool `fortigate_list`

- [ ] **Step 3: Create `tools/fleet.py`**

```python
"""Fleet meta tools — inspect the configured FortiGates themselves.

Unlike every other tool module these tools describe the server's own instance
inventory rather than proxying a FortiOS endpoint, so they take no ``instance``
parameter.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from instances import InstanceRegistry


def register(mcp: FastMCP) -> None:
    """Register the fleet meta tools onto the FastMCP instance."""

    @mcp.tool()
    async def fortigate_list(
        ctx: Context,
        check_health: Annotated[
            bool,
            Field(
                default=False,
                description=(
                    "When true, query each FortiGate's system status to report "
                    "reachability, firmware version and serial number. Adds one "
                    "HTTP request per instance."
                ),
            ),
        ] = False,
    ) -> dict[str, Any]:
        """List the FortiGates this server manages.

        Returns each instance's name, description, host, default VDOM and
        read-only status. Pass the returned name as the `instance` parameter on
        any other tool. API tokens are never returned.
        """
        registry: InstanceRegistry = ctx.request_context.lifespan_context["registry"]
        instances: list[dict[str, Any]] = [
            {
                "name": cfg.name,
                "description": cfg.description,
                "host": cfg.host,
                "vdom": cfg.vdom,
                "read_only": cfg.read_only,
            }
            for cfg in registry.configs
        ]

        if check_health:
            names = [entry["name"] for entry in instances]
            results = await asyncio.gather(
                *(
                    registry.clients[name].monitor_get("system/status")
                    for name in names
                ),
                return_exceptions=True,
            )
            for entry, result in zip(instances, results):
                if isinstance(result, BaseException):
                    entry["reachable"] = False
                    entry["error"] = str(result)
                    continue
                entry["reachable"] = True
                details = result.get("results") or {}
                if isinstance(details, dict):
                    entry["version"] = details.get("version")
                    entry["serial"] = details.get("serial")

        return {"count": len(instances), "instances": instances}
```

This module deliberately does **not** import `FortiOSError`: it never calls `resolve()`, and
`asyncio.gather(return_exceptions=True)` already captures per-instance failures into the
`error` field, so there is nothing to catch. Importing it would trip ruff's F401.

- [ ] **Step 4: Register the module in `server.py`**

Add `fleet` to the tool-module import list:

```python
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
```

and add the registration call after `wireless.register(mcp)`:

```python
fleet.register(mcp)
```

Update the count log line:

```python
logger.info("All 11 tool modules registered (205+ tools).")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_fleet.py -v`
Expected: PASS

- [ ] **Step 6: Run the full gate and commit**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest -v
git add tools/fleet.py server.py tests/test_fleet.py
git diff --cached --name-only
git commit -m "feat(fleet): add fortigate_list tool

Reports each configured FortiGate's name, description, host, vdom and
read-only status, never its token. check_health=True adds a concurrent
system/status probe per instance."
```

---

### Task 7: Migration script, proven on `tools/generic.py`

**Files:**
- Create: `add_instance_param.py` (repo root, one-off; gitignored)
- Modify: `.gitignore` (add the script alongside the existing one-off entries)
- Modify: `tools/generic.py` (by script)
- Create: `tests/test_tool_instance_routing.py`

**Interfaces:**
- Consumes: lifespan key `registry`, `FortiOSAPI`, fan-out and read-only behaviour (Tasks 2-5).
- Produces: every tool in `tools/generic.py` accepting `instance: str | None = None` and resolving via the registry. The remaining nine modules are migrated in Task 8.

This task exists as its own gate so a reviewer can reject the script's approach before it touches 6,700 lines.

- [ ] **Step 1: Write the migration script**

Create `add_instance_param.py`:

```python
#!/usr/bin/env python3
"""One-off: add an `instance` parameter to every @mcp.tool() in tools/*.py.

Usage:
    uv run python add_instance_param.py tools/generic.py [tools/firewall.py ...]

For each tool function the script:
  1. inserts an `instance` parameter immediately before the `vdom` parameter,
  2. rewrites the lifespan client lookup to resolve through the registry,
  3. fixes the module's fortios_client import.

Anchoring on `vdom` rather than appending at the end keeps `wifi_vap_create`
(which has two parameters after `vdom`) working with no special case.

Idempotent: a tool that already declares `instance` is skipped. Run
`uv run ruff format .` afterwards — the rewritten lookup line is deliberately
left over-long for the formatter to wrap.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

INSTANCE_PARAM = """        instance: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Target FortiGate name; see fortigate_list. "
                    "Omit if only one is configured. '*' = all (reads only)."
                ),
            ),
        ] = None,
"""

OLD_LOOKUP = (
    '        client: FortiOSClient = ctx.request_context.lifespan_context["client"]\n'
)
NEW_LOOKUP = (
    '        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"]'
    ".resolve(instance)\n"
)

OLD_IMPORT = "from fortios_client import FortiOSClient, FortiOSError\n"
NEW_IMPORT = "from fortios_client import FortiOSError\nfrom instances import FortiOSAPI\n"


def is_tool(node: ast.AST) -> bool:
    if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
        return False
    return any("mcp.tool" in ast.unparse(d) for d in node.decorator_list)


def transform(path: Path) -> tuple[int, int]:
    """Rewrite one module. Returns (params_inserted, lookups_rewritten)."""
    src = path.read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)

    insert_at: list[int] = []
    for node in ast.walk(ast.parse(src)):
        if not is_tool(node):
            continue
        assert isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
        names = [a.arg for a in node.args.args]
        if "instance" in names:
            continue
        if "vdom" not in names:
            raise SystemExit(
                f"{path}:{node.lineno} {node.name}: no 'vdom' parameter to anchor on"
            )
        vdom_arg = node.args.args[names.index("vdom")]
        insert_at.append(vdom_arg.lineno - 1)

    for index in sorted(insert_at, reverse=True):
        lines.insert(index, INSTANCE_PARAM)

    out = "".join(lines)
    lookups = out.count(OLD_LOOKUP)
    out = out.replace(OLD_LOOKUP, NEW_LOOKUP)
    if OLD_IMPORT in out:
        out = out.replace(OLD_IMPORT, NEW_IMPORT, 1)

    path.write_text(out, encoding="utf-8")
    return len(insert_at), lookups


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    total_params = total_lookups = 0
    for name in argv:
        params, lookups = transform(Path(name))
        print(f"{name}: +{params} instance params, {lookups} lookups rewritten")
        total_params += params
        total_lookups += lookups
    print(f"TOTAL: +{total_params} params, {total_lookups} lookups")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```

- [ ] **Step 2: Gitignore the one-off script**

In `.gitignore`, under the existing `# One-off migration / utility scripts` heading, add:

```
add_instance_param.py
```

- [ ] **Step 3: Write the failing integration tests**

Create `tests/test_tool_instance_routing.py`:

```python
"""End-to-end tests that tool calls reach the instance they name."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pytest_httpx import HTTPXMock


@pytest.fixture
def fleet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "fortigates.json"
    path.write_text(
        json.dumps(
            [
                {
                    "name": "hq-fw",
                    "description": "HQ perimeter",
                    "host": "https://hq.example",
                    "api_token": "t",
                    "read_only": True,
                },
                {
                    "name": "dc-edge",
                    "description": "DC edge",
                    "host": "https://dc.example",
                    "api_token": "t",
                },
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", str(path))


async def _call(tool: str, args: dict[str, object]) -> dict[str, object]:
    from server import mcp

    async with create_connected_server_and_client_session(mcp) as client:
        result = await client.call_tool(tool, args)
    assert not result.isError, result.content
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


async def test_named_instance_is_the_only_one_contacted(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://dc.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 2}], "http_status": 200},
    )

    payload = await _call(
        "cmdb_list", {"resource_path": "firewall/policy", "instance": "dc-edge"}
    )

    assert payload["results"][0]["policyid"] == 2
    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    assert requests[0].url.host == "dc.example"


async def test_omitting_instance_with_two_configured_returns_an_error(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call("cmdb_list", {"resource_path": "firewall/policy"})

    assert "'instance' is required" in payload["error"]
    assert "hq-fw, dc-edge" in payload["error"]
    assert httpx_mock.get_requests() == []


async def test_unknown_instance_returns_an_error(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call(
        "cmdb_list", {"resource_path": "firewall/policy", "instance": "nope"}
    )

    assert "Unknown instance 'nope'" in payload["error"]
    assert httpx_mock.get_requests() == []


async def test_star_fans_out_and_keys_results_by_instance(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://hq.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 1}], "http_status": 200},
    )
    httpx_mock.add_response(
        url="https://dc.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 2}], "http_status": 200},
    )

    payload = await _call(
        "cmdb_list", {"resource_path": "firewall/policy", "instance": "*"}
    )

    assert payload["hq-fw"]["results"][0]["policyid"] == 1
    assert payload["dc-edge"]["results"][0]["policyid"] == 2


async def test_write_to_a_read_only_instance_is_refused(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call(
        "cmdb_delete",
        {"resource_path": "firewall/policy/1", "instance": "hq-fw"},
    )

    assert "read-only" in payload["error"]
    assert payload["status_code"] == 403
    assert httpx_mock.get_requests() == []


async def test_write_with_star_is_refused(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call(
        "cmdb_delete", {"resource_path": "firewall/policy/1", "instance": "*"}
    )

    assert "read-only" in payload["error"]
    assert httpx_mock.get_requests() == []


async def test_single_instance_config_allows_omitting_instance(
    monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock
) -> None:
    monkeypatch.setenv("FORTIOS_HOST", "https://only.example")
    monkeypatch.setenv("FORTIOS_API_TOKEN", "t")
    httpx_mock.add_response(
        url="https://only.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [], "http_status": 200},
    )

    payload = await _call("cmdb_list", {"resource_path": "firewall/policy"})

    assert payload["results"] == []
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `uv run pytest tests/test_tool_instance_routing.py -v`
Expected: FAIL — the `instance` argument is rejected as an unexpected input by the tool schema.

- [ ] **Step 5: Run the script on `tools/generic.py`**

Run: `uv run python add_instance_param.py tools/generic.py`
Expected output: `tools/generic.py: +9 instance params, 9 lookups rewritten`

- [ ] **Step 6: Format and inspect the result**

Run:
```bash
uv run ruff format tools/generic.py
git diff --stat tools/generic.py
```
Expected: the long `NEW_LOOKUP` line is wrapped by the formatter. Read the first migrated tool to confirm the parameter sits immediately before `vdom` and the lookup reads `...lifespan_context["registry"].resolve(instance)`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_tool_instance_routing.py -v`
Expected: PASS — all seven cases exercise `cmdb_list` / `cmdb_delete`, both in `generic.py`.

- [ ] **Step 8: Confirm the script is idempotent**

Run:
```bash
uv run python add_instance_param.py tools/generic.py
```
Expected: `tools/generic.py: +0 instance params, 0 lookups rewritten`

- [ ] **Step 9: Run the full gate and commit**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest -v
git add .gitignore tools/generic.py tests/test_tool_instance_routing.py
git diff --cached --name-only   # add_instance_param.py must NOT appear
git commit -m "feat(generic): route generic tools through the instance registry

Adds the instance parameter to the nine generic pass-through tools and
resolves the client through the registry. Covers named targeting, ambiguous
omission, unknown names, fan-out and read-only refusal end to end."
```

---

### Task 8: Migrate the remaining nine modules and drop the transitional key

**Files:**
- Modify: `tools/firewall.py`, `tools/security.py`, `tools/system.py`, `tools/vpn.py`, `tools/router.py`, `tools/monitor.py`, `tools/wireless.py`, `tools/user.py`, `tools/log.py` (by script)
- Modify: `server.py` (remove the transitional `client` key)
- Modify: `tests/test_server_wiring.py` (drop the transitional-key assertion)
- Create: `tests/test_tools_have_instance_param.py`

**Interfaces:**
- Consumes: `add_instance_param.py` (Task 7).
- Produces: all 240 tools accepting `instance`; lifespan context is `{"registry": ...}` only.

- [ ] **Step 1: Write the failing guard test**

Create `tests/test_tools_have_instance_param.py`:

```python
"""Structural guards over the tool modules.

These protect the multi-instance invariant for tools added in future: every
tool must accept an `instance` parameter and resolve its client through the
registry.
"""

from __future__ import annotations

import ast
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

# Fleet meta tools describe the server's own inventory rather than proxying a
# FortiOS endpoint, so they take no `instance` parameter.
MODULES_WITHOUT_INSTANCE_PARAM = {"fleet.py"}


def _tool_functions(path: Path) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    found: list[ast.AsyncFunctionDef | ast.FunctionDef] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        if any("mcp.tool" in ast.unparse(d) for d in node.decorator_list):
            found.append(node)
    return found


def _tool_modules() -> list[Path]:
    return sorted(p for p in TOOLS_DIR.glob("*.py") if p.name != "__init__.py")


def test_the_exemption_list_has_not_grown() -> None:
    assert MODULES_WITHOUT_INSTANCE_PARAM == {"fleet.py"}


def test_every_tool_accepts_an_instance_parameter() -> None:
    missing: list[str] = []
    for path in _tool_modules():
        if path.name in MODULES_WITHOUT_INSTANCE_PARAM:
            continue
        for fn in _tool_functions(path):
            if "instance" not in [a.arg for a in fn.args.args]:
                missing.append(f"{path.name}:{fn.lineno} {fn.name}")

    assert missing == [], f"tools missing an 'instance' parameter: {missing}"


def test_no_tool_still_reads_the_legacy_client_key() -> None:
    offenders = [
        path.name
        for path in _tool_modules()
        if 'lifespan_context["client"]' in path.read_text(encoding="utf-8")
    ]

    assert offenders == [], f"modules still using the legacy client key: {offenders}"


def test_expected_number_of_tools_is_registered() -> None:
    total = sum(len(_tool_functions(p)) for p in _tool_modules())

    # 240 FortiOS tools + fortigate_list
    assert total == 241
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tools_have_instance_param.py -v`
Expected: FAIL — `test_every_tool_accepts_an_instance_parameter` lists 231 tools across the nine unmigrated modules; `test_no_tool_still_reads_the_legacy_client_key` lists those nine modules.

- [ ] **Step 3: Migrate the remaining nine modules**

Run:
```bash
uv run python add_instance_param.py \
  tools/firewall.py tools/security.py tools/system.py tools/vpn.py \
  tools/router.py tools/monitor.py tools/wireless.py tools/user.py tools/log.py
```
Expected final line: `TOTAL: +231 params, 231 lookups`

Per-module expected counts: firewall 37, security 35, system 33, vpn 26, router 24, monitor 21, wireless 20, user 19, log 16.

- [ ] **Step 4: Format**

Run: `uv run ruff format .`

- [ ] **Step 5: Run the guard tests to verify they pass**

Run: `uv run pytest tests/test_tools_have_instance_param.py -v`
Expected: PASS — all four cases.

- [ ] **Step 6: Verify `wifi_vap_create` specifically**

The one tool where `vdom` is not the last parameter. Run:

```bash
uv run python -c "
import ast
tree = ast.parse(open('tools/wireless.py').read())
for n in ast.walk(tree):
    if isinstance(n, ast.AsyncFunctionDef) and n.name == 'wifi_vap_create':
        print([a.arg for a in n.args.args])
"
```
Expected: the list contains `instance` immediately before `vdom`, with `broadcast_ssid` and `fast_bss_transition` still after it.

- [ ] **Step 7: Remove the transitional lifespan key**

In `server.py`, change the yield to:

```python
        yield {"registry": registry}
```

deleting the `"client"` entry and its comment.

- [ ] **Step 8: Drop the transitional assertion from the wiring test**

In `tests/test_server_wiring.py`, delete these two lines from
`test_lifespan_yields_a_registry_with_every_instance`:

```python
        # Transitional key kept until the tools are migrated (Task 8).
        assert ctx["client"] is registry.clients["hq-fw"]
```

- [ ] **Step 9: Verify a typed tool routes correctly too**

Append to `tests/test_tool_instance_routing.py`:

```python
async def test_typed_firewall_tool_also_honours_instance(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://dc.example/api/v2/cmdb/firewall/policy?vdom=root",
        json={"results": [{"policyid": 9}], "http_status": 200},
    )

    payload = await _call("firewall_policy_list", {"instance": "dc-edge"})

    assert payload["results"][0]["policyid"] == 9
    assert httpx_mock.get_requests()[0].url.host == "dc.example"


async def test_typed_firewall_tool_reports_ambiguous_omission(
    fleet: None, httpx_mock: HTTPXMock
) -> None:
    payload = await _call("firewall_policy_list", {})

    assert "'instance' is required" in payload["error"]
    assert httpx_mock.get_requests() == []
```

`firewall_policy_list` is verified to exist in `tools/firewall.py` and to call
`client.cmdb_get("firewall/policy", params, vdom=vdom)`. Called with no filters it sends
only the `vdom` query param, which is why the mocked URL above ends in `?vdom=root`.

- [ ] **Step 10: Run the full gate**

Run: `uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest -v`
Expected: all clean.

- [ ] **Step 11: Confirm the full tool set still loads over MCP**

Run:
```bash
FORTIOS_HOST=https://fw.example FORTIOS_API_TOKEN=tok uv run python -c "
import asyncio
from mcp.shared.memory import create_connected_server_and_client_session
from server import mcp
async def main():
    async with create_connected_server_and_client_session(mcp) as c:
        tools = await c.list_tools()
        names = {t.name for t in tools.tools}
        print('tools:', len(tools.tools))
        print('fortigate_list present:', 'fortigate_list' in names)
        schema = next(t for t in tools.tools if t.name == 'cmdb_list').inputSchema
        print('instance in cmdb_list schema:', 'instance' in schema['properties'])
asyncio.run(main())
"
```
Expected: `tools: 241`, `fortigate_list present: True`, `instance in cmdb_list schema: True`

- [ ] **Step 12: Commit**

```bash
git add tools/ server.py tests/
git diff --cached --name-only   # add_instance_param.py must NOT appear
git commit -m "feat(tools): route all 240 tools through the instance registry

Adds the instance parameter to the remaining nine tool modules and drops the
transitional lifespan 'client' key. A structural guard test fails if a future
tool omits the parameter or reads the legacy key."
```

---

### Task 9: Documentation

**Files:**
- Create: `fortigates.example.json`
- Modify: `.gitignore`
- Modify: `.env.example`
- Modify: `README.md` (new section after `## HTTP Mode`, plus the Table of Contents and Project Structure)
- Modify: `CLAUDE.md` (working copy only — **never staged**)

- [ ] **Step 1: Add the example fleet file**

Create `fortigates.example.json`:

```json
[
  {
    "name": "hq-fw",
    "description": "HQ perimeter firewall, Vienna. Production internet edge and IPsec hub.",
    "host": "https://10.0.0.1",
    "api_token": "your-api-token-here",
    "vdom": "root",
    "read_only": true
  },
  {
    "name": "dc-edge",
    "description": "Datacenter edge, one VDOM per tenant. Change window Sundays 02:00.",
    "host": "https://10.9.0.1",
    "api_token_env": "DC_EDGE_TOKEN",
    "vdom": "tenant1",
    "verify_ssl": true,
    "timeout": 45
  }
]
```

- [ ] **Step 2: Ignore the real fleet file**

In `.gitignore`, under `# Secrets`, add:

```
fortigates.json
!fortigates.example.json
```

- [ ] **Step 3: Extend `.env.example`**

Append:

```bash
# ── Multiple FortiGates ───────────────────────────────────────────────
# Point this at a JSON array of instances to manage several FortiGates from
# one server process. See fortigates.example.json.
# When set, FORTIOS_HOST below is ignored, and the file must exist and be
# valid — the server will not silently fall back to a single device.
# FORTIOS_INSTANCES_FILE=./fortigates.json

# The FORTIOS_VDOM / FORTIOS_VERIFY_SSL / FORTIOS_TIMEOUT values above act as
# fleet-wide defaults for instances that omit those fields.
```

- [ ] **Step 4: Add the README section**

Insert after the `## HTTP Mode` section and before `## Usage Examples`. The block below is
fenced with **four** backticks so the nested three-backtick fences are part of the content —
copy everything between the four-backtick markers into the README verbatim:

````markdown
## Managing Multiple FortiGates

One server process can manage a fleet. The LLM picks the target per tool call,
so the 240-tool set is loaded into its context once rather than once per device.

Point `FORTIOS_INSTANCES_FILE` at a JSON array (see
[`fortigates.example.json`](fortigates.example.json)):

```json
[
  {
    "name": "hq-fw",
    "description": "HQ perimeter firewall, Vienna. Production internet edge.",
    "host": "https://10.0.0.1",
    "api_token": "...",
    "read_only": true
  },
  {
    "name": "dc-edge",
    "description": "Datacenter edge, one VDOM per tenant.",
    "host": "https://10.9.0.1",
    "api_token_env": "DC_EDGE_TOKEN",
    "vdom": "tenant1"
  }
]
```

| Field | Required | Default |
|---|---|---|
| `name` | yes | — `[A-Za-z0-9._-]`, 1–64 chars; `*` is reserved |
| `description` | yes | — shown to the LLM so it can pick the right device |
| `host` | yes | — |
| `api_token` or `api_token_env` | exactly one | — `api_token_env` names an env var holding the token |
| `vdom` | no | `FORTIOS_VDOM`, else `root` |
| `verify_ssl` | no | `FORTIOS_VERIFY_SSL`, else `false` |
| `timeout` | no | `FORTIOS_TIMEOUT`, else `30` |
| `read_only` | no | `false` |

### Targeting a device

Every tool takes an optional `instance` parameter:

```
# Target one device
cmdb_list(resource_path="firewall/policy", instance="dc-edge")

# Read from every device at once — returns results keyed by instance name
cmdb_list(resource_path="firewall/policy", instance="*")

# Discover what's configured
fortigate_list()
fortigate_list(check_health=True)   # adds reachability, firmware, serial
```

`instance` may be omitted only when exactly one device is configured. With two
or more, omitting it returns an error listing the valid names rather than
guessing — a config change must never land on the wrong firewall.

### Read-only devices

`"read_only": true` makes the server refuse every write (create, update,
delete, and monitor/log/service actions) against that device before any request
is sent. Reads, including `instance="*"` fan-out, still work. Use it to expose
production firewalls safely.

`instance="*"` is reads-only in all cases; write tools reject it.

### Backward compatibility

Leaving `FORTIOS_INSTANCES_FILE` unset keeps the existing single-device setup
working unchanged: `FORTIOS_HOST` and `FORTIOS_API_TOKEN` become one instance
named `default`, and `instance` can be omitted everywhere.
````

- [ ] **Step 5: Update the README Table of Contents and Project Structure**

In `## Table of Contents`, insert the new entry between the `HTTP Mode` and `Usage Examples` lines so it matches the section order:

```markdown
- [HTTP Mode](#http-mode)
- [Managing Multiple FortiGates](#managing-multiple-fortigates)
  - [Targeting a device](#targeting-a-device)
  - [Read-only devices](#read-only-devices)
  - [Backward compatibility](#backward-compatibility)
- [Usage Examples](#usage-examples)
```

In `## Project Structure`, add two entries to the file listing, matching the surrounding format:

- `instances.py` — fleet configuration loading and the instance registry
- `tools/fleet.py` — `fortigate_list` fleet meta tool

- [ ] **Step 6: Update `CLAUDE.md` (working copy only)**

`CLAUDE.md` is in `.git/info/exclude` and must never be staged. Make these edits so future sessions follow the new conventions:

- In **Architecture**, item 2: note the lifespan creates one `FortiOSClient` per configured FortiGate and yields `{"client": ...}` → change to `{"registry": InstanceRegistry}`.
- Add `instances.py` as a layer: fleet config loading (`load_instances`), `InstanceRegistry`, the `FortiOSAPI` protocol, `FanOutClient`, `ErrorClient`.
- In **Tool conventions**, replace the client-retrieval bullet with:
  `Retrieve the client inside the tool: client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(instance)`
- Add: every tool takes an optional `instance: str | None` parameter alongside `vdom`, using the standard description; `tests/test_tools_have_instance_param.py` enforces this.
- In **Commands**, note `FORTIOS_INSTANCES_FILE` as the multi-device configuration entry point.

- [ ] **Step 7: Verify the docs match reality**

Run:
```bash
FORTIOS_INSTANCES_FILE=fortigates.example.json DC_EDGE_TOKEN=x uv run python -c "
from instances import load_instances, roster_text
instances, errors = load_instances()
print('errors:', errors)
print(roster_text(instances))
"
```
Expected: `errors: []` and a two-line roster with `[READ-ONLY]` on `hq-fw`.

- [ ] **Step 8: Run the full gate and commit**

```bash
uv run ruff format . && uv run ruff check . && uv run pyright && uv run pytest -v
git add README.md .env.example .gitignore fortigates.example.json
git diff --cached --name-only   # CLAUDE.md must NOT appear
git commit -m "docs: document multi-FortiGate configuration and targeting"
```

---

## Final verification

- [ ] **All checks green:** `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest -v`
- [ ] **Tool count is 241:** the MCP listing in Task 8 Step 11.
- [ ] **Single-device path works:** `FORTIOS_HOST` + `FORTIOS_API_TOKEN` only, `instance` omitted, a tool call succeeds.
- [ ] **Multi-device path works:** `FORTIOS_INSTANCES_FILE` set, `instance="dc-edge"` reaches only that host.
- [ ] **No excluded files committed:** `git log --stat feat/multi-fortigate-instances ^master | grep -E 'CLAUDE\.md|\.claude/|\.mcp\.json|add_instance_param\.py'` returns nothing.
- [ ] **Interactive smoke test:** `FORTIOS_INSTANCES_FILE=... uv run mcp dev server.py`, then call `fortigate_list` and one `cmdb_list` against a named instance.
