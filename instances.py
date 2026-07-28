"""FortiGate fleet configuration and instance registry.

Loads the set of managed FortiGates either from a JSON file named by
``FORTIOS_INSTANCES_FILE`` or, as a fallback, from the single-device
environment variables ``FORTIOS_HOST`` / ``FORTIOS_API_TOKEN``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from fortios_client import FortiOSClient, FortiOSError

logger = logging.getLogger(__name__)

FAN_OUT = "*"
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass(frozen=True)
class InstanceConfig:
    """Configuration for one managed FortiGate."""

    name: str
    description: str
    host: str
    api_token: str = field(repr=False)
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


def _required_string(
    raw: dict[str, Any], key: str, where: str, errors: list[str]
) -> str | None:
    """Return the stripped string value of ``key``, or ``None`` on failure.

    Records a ``'{key}' is required`` error when the key is absent or blank,
    and a distinct ``'{key}' is not a string`` error when it is present with a
    non-string value (e.g. JSON ``null``) — the latter must fail closed rather
    than silently coercing via ``str()``.
    """
    if key not in raw:
        errors.append(f"{where}: '{key}' is required")
        return None
    value = raw[key]
    if not isinstance(value, str):
        errors.append(f"{where}: '{key}' is not a string: {value!r}")
        return None
    value = value.strip()
    if not value:
        errors.append(f"{where}: '{key}' is required")
        return None
    return value


def _credential_string(
    raw: dict[str, Any], key: str, where: str, errors: list[str]
) -> str | None:
    """Return the stripped string at ``key``, or ``None`` with an error recorded.

    Like :func:`_required_string` but for the credential fields, and with two
    differences that matter there: the caller has already established the key
    is present (so absence is not a case here), and the recorded error never
    echoes the value — for ``api_token`` that value is a secret.
    """
    value = raw[key]
    if not isinstance(value, str):
        errors.append(f"{where}: '{key}' must be a string, got {type(value).__name__}")
        return None
    value = value.strip()
    if not value:
        errors.append(f"{where}: '{key}' must not be empty")
        return None
    return value


def _optional_bool(
    raw: dict[str, Any], key: str, default: bool, where: str, errors: list[str]
) -> bool | None:
    """Return the bool value of ``key``, ``default`` if absent, else ``None``.

    ``None`` signals a present-but-wrong-type value (e.g. JSON ``null`` or the
    string ``"false"``) and always comes with a recorded error, so callers can
    treat ``None`` as "fail this instance" without confusing it with a real
    ``False`` default.
    """
    if key not in raw:
        return default
    value = raw[key]
    if not isinstance(value, bool):
        errors.append(f"{where}: '{key}' is not a boolean: {value!r}")
        return None
    return value


def _parse_instance(
    raw: Any, index: int, defaults: dict[str, Any], errors: list[str]
) -> InstanceConfig | None:
    """Validate one entry from the instances file. Records errors, never raises."""
    where = f"instance #{index}"
    if not isinstance(raw, dict):
        errors.append(f"{where}: expected a JSON object, got {type(raw).__name__}")
        return None

    name = _required_string(raw, "name", where, errors)
    if name is None:
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

    description = _required_string(raw, "description", where, errors)
    if description is None:
        return None

    host = _required_string(raw, "host", where, errors)
    if host is None:
        return None

    # Which credential field was *supplied* is decided by key membership, not
    # truthiness: `{"api_token": ""}` is a supplied-but-empty token (a precise
    # error) rather than a missing one, and a mis-typed `{"api_token": 1234}`
    # must fail closed instead of being coerced into a credential by `str()`.
    if ("api_token" in raw) == ("api_token_env" in raw):
        errors.append(f"{where}: set exactly one of 'api_token' or 'api_token_env'")
        return None
    if "api_token_env" in raw:
        token_env = _credential_string(raw, "api_token_env", where, errors)
        if token_env is None:
            return None
        api_token = os.environ.get(token_env, "").strip()
        if not api_token:
            errors.append(
                f"{where}: environment variable {token_env!r} named by "
                f"'api_token_env' is unset or empty"
            )
            return None
    else:
        inline_token = _credential_string(raw, "api_token", where, errors)
        if inline_token is None:
            return None
        api_token = inline_token

    timeout = float(defaults["timeout"])
    if "timeout" in raw:
        try:
            timeout = float(raw["timeout"])
        except (TypeError, ValueError):
            errors.append(f"{where}: 'timeout' is not a number: {raw['timeout']!r}")
            return None

    # verify_ssl is checked first among the optional fields: a present-but-
    # invalid value here would otherwise silently disable TLS certificate
    # verification, which is the highest-severity outcome this function
    # guards against.
    verify_ssl = _optional_bool(
        raw, "verify_ssl", bool(defaults["verify_ssl"]), where, errors
    )
    if verify_ssl is None:
        return None

    vdom = str(defaults["vdom"])
    if "vdom" in raw:
        vdom_raw = raw["vdom"]
        if not isinstance(vdom_raw, str):
            errors.append(f"{where}: 'vdom' is not a string: {vdom_raw!r}")
            return None
        vdom = vdom_raw.strip() or str(defaults["vdom"])

    read_only = _optional_bool(raw, "read_only", False, where, errors)
    if read_only is None:
        return None

    return InstanceConfig(
        name=name,
        description=description,
        host=host,
        api_token=api_token,
        vdom=vdom,
        verify_ssl=verify_ssl,
        timeout=timeout,
        read_only=read_only,
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


def _load_from_env(defaults: dict[str, Any], errors: list[str]) -> list[InstanceConfig]:
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
    the 90 tools that take an ``instance`` parameter look it up outside their
    ``try`` blocks.
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
        # 403, matching FortiOSClient._write_guard: both are "refused by
        # policy", and a caller reading `status_code` should not have to tell
        # the two refusals apart from a network or unknown failure (0).
        raise FortiOSError(
            "instance='*' fan-out is read-only. "
            "Target a single instance for write operations.",
            403,
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
            return FanOutClient(self._clients)

        client = self._clients.get(target)
        if client is None:
            return ErrorClient(
                f"Unknown instance {target!r}. Configured: {', '.join(self.names())}"
            )
        return client
