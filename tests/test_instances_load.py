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
        (
            [{"description": "d", "host": "https://a", "api_token": "t"}],
            "'name' is required",
        ),
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
            [
                {
                    "name": "bad name",
                    "description": "d",
                    "host": "https://a",
                    "api_token": "t",
                }
            ],
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
                {
                    "name": "a",
                    "description": "first",
                    "host": "https://1",
                    "api_token": "t",
                },
                {
                    "name": "a",
                    "description": "second",
                    "host": "https://2",
                    "api_token": "t",
                },
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


def test_null_verify_ssl_is_rejected_rather_than_silently_disabling_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A present `"verify_ssl": null` must fail closed, not coerce to False.

    `bool(None)` is `False`, so silently coercing this field would disable TLS
    certificate verification against a firewall management channel even when
    the fleet default (`FORTIOS_VERIFY_SSL=true`) says otherwise.
    """
    monkeypatch.setenv("FORTIOS_VERIFY_SSL", "true")
    path = _write(
        tmp_path,
        [
            {
                "name": "a",
                "description": "d",
                "host": "https://a",
                "api_token": "t",
                "verify_ssl": None,
            }
        ],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)

    instances, errors = load_instances()

    assert instances == []
    assert any("'verify_ssl' is not a boolean" in e for e in errors), errors


def test_null_vdom_is_rejected_rather_than_becoming_the_string_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORTIOS_VDOM", "mgmt")
    path = _write(
        tmp_path,
        [
            {
                "name": "a",
                "description": "d",
                "host": "https://a",
                "api_token": "t",
                "vdom": None,
            }
        ],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)

    instances, errors = load_instances()

    assert instances == []
    assert any("'vdom' is not a string" in e for e in errors), errors


def test_null_name_is_rejected_rather_than_becoming_the_string_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(
        tmp_path,
        [{"name": None, "description": "B", "host": "https://b", "api_token": "t"}],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)

    instances, errors = load_instances()

    assert instances == []
    assert any("'name' is not a string" in e for e in errors), errors


def test_null_host_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write(
        tmp_path,
        [{"name": "a", "description": "d", "host": None, "api_token": "t"}],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)

    instances, errors = load_instances()

    assert instances == []
    assert any("'host' is not a string" in e for e in errors), errors


def test_null_description_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(
        tmp_path,
        [{"name": "a", "description": None, "host": "https://a", "api_token": "t"}],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)

    instances, errors = load_instances()

    assert instances == []
    assert any("'description' is not a string" in e for e in errors), errors


def test_string_read_only_is_rejected_rather_than_coerced_to_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`"read_only": "false"` (a truthy non-empty string) must be an error,

    not silently coerced to `True` via `bool("false")`.
    """
    path = _write(
        tmp_path,
        [
            {
                "name": "c",
                "description": "C",
                "host": "https://c",
                "api_token": "t",
                "read_only": "false",
            }
        ],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)

    instances, errors = load_instances()

    assert instances == []
    assert any("'read_only' is not a boolean" in e for e in errors), errors


def test_full_repro_payload_from_the_fix_wave_produces_only_recorded_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact three-entry payload from the review finding: every entry is
    invalid, and none of the four silent misconfigurations happen — no
    instance is returned and each bad field is named in `errors`.

    Each instance stops validation at its first bad field (consistent with
    every other field check in `_parse_instance`), so instance "a" — which has
    both `vdom: null` and `verify_ssl: null` — contributes one error for
    whichever is checked first, not two. Three instances therefore produce
    three recorded errors, not four.
    """
    monkeypatch.setenv("FORTIOS_VERIFY_SSL", "true")
    monkeypatch.setenv("FORTIOS_VDOM", "mgmt")
    path = _write(
        tmp_path,
        [
            {
                "name": "a",
                "description": "A",
                "host": "https://a",
                "api_token": "t",
                "verify_ssl": None,
                "vdom": None,
            },
            {"name": None, "description": "B", "host": "https://b", "api_token": "t"},
            {
                "name": "c",
                "description": "C",
                "host": "https://c",
                "api_token": "t",
                "read_only": "false",
            },
        ],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)

    instances, errors = load_instances()

    assert instances == []
    assert len(errors) == 3
    assert any(
        "'vdom' is not a string" in e or "'verify_ssl' is not a boolean" in e
        for e in errors
    ), errors
    assert any("'name' is not a string" in e for e in errors), errors
    assert any("'read_only' is not a boolean" in e for e in errors), errors


def test_absent_optional_keys_still_inherit_fleet_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guards the absent-key path: omitting vdom/verify_ssl/read_only entirely
    must still inherit the fleet defaults exactly as before this fix wave."""
    monkeypatch.setenv("FORTIOS_VDOM", "mgmt")
    monkeypatch.setenv("FORTIOS_VERIFY_SSL", "true")
    path = _write(
        tmp_path,
        [{"name": "a", "description": "d", "host": "https://a", "api_token": "t"}],
    )
    monkeypatch.setenv("FORTIOS_INSTANCES_FILE", path)

    instances, errors = load_instances()

    assert errors == []
    assert len(instances) == 1
    assert instances[0].vdom == "mgmt"
    assert instances[0].verify_ssl is True
    assert instances[0].read_only is False


def test_repr_never_includes_the_api_token() -> None:
    """Finding 2: the dataclass repr must not leak `api_token`."""
    cfg = InstanceConfig(
        name="a",
        description="d",
        host="https://a",
        api_token="super-secret-token",
    )

    assert "super-secret-token" not in repr(cfg)
