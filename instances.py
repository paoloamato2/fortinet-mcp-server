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
