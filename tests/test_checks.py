"""Tests for the deterministic checks.

Beyond "does each check fire", these test the reviewer's own controls:
grounded findings (PR-11), secret redaction (PR-14), strict input handling
(PR-07), and that untrusted tool annotations can't lower risk.
"""

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from agent_reviewer.checks import (
    LEAKAGE_PATH,
    MISSING_APPROVAL,
    SECRET_IN_CONFIG,
    ConfigError,
    Severity,
    load_config,
    run_checks,
)

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
RISKY = SAMPLES / "expense_helper_risky.json"
BASELINE = SAMPLES / "expense_helper_baseline.json"
FAKE_SECRET = "FAKE-KEY-DO-NOT-USE"


@pytest.fixture
def risky() -> dict[str, Any]:
    return load_config(RISKY)


@pytest.fixture
def baseline() -> dict[str, Any]:
    return load_config(BASELINE)


def _check_ids(config: dict[str, Any]) -> set[str]:
    return {f.check_id for f in run_checks(config)}


def _resolve(config: dict[str, Any], field: str) -> Any:
    """Follow a finding's field path, e.g. 'tools[3].permissions[1]'. '' is the whole config."""
    value: Any = config
    for name, index in re.findall(r"([^.\[\]]+)|\[(\d+)\]", field):
        value = value[int(index)] if index else value[name]
    return value


def _tool(config: dict[str, Any], name: str) -> dict[str, Any]:
    return next(t for t in config["tools"] if t["name"] == name)


# --- Detection on the samples ----------------------------------------------


def test_risky_sample_findings_match_seeded_flaws(risky: dict[str, Any]) -> None:
    assert _check_ids(risky) == set(risky["seeded_flaws"])


def test_baseline_sample_has_no_findings(baseline: dict[str, Any]) -> None:
    assert run_checks(baseline) == []


def test_findings_are_sorted_most_severe_first(risky: dict[str, Any]) -> None:
    severities = [f.severity for f in run_checks(risky)]
    assert severities == sorted(severities, reverse=True)


# --- Reviewer controls ------------------------------------------------------


def test_every_finding_points_at_a_real_field(risky: dict[str, Any]) -> None:
    # PR-11 grounded findings: each finding cites a field that exists.
    for finding in run_checks(risky):
        _resolve(risky, finding.field)  # raises if the path doesn't exist


def test_secret_values_never_appear_in_findings(risky: dict[str, Any]) -> None:
    # PR-14 secret redaction.
    findings = run_checks(risky)
    assert any(f.check_id == SECRET_IN_CONFIG for f in findings)
    for finding in findings:
        for text in (finding.title, finding.field, finding.evidence, finding.recommendation):
            assert FAKE_SECRET not in text


def test_annotations_cannot_make_a_tool_read_only(risky: dict[str, Any]) -> None:
    # update_claim claims readOnlyHint=true but has write and delete permissions.
    assert _tool(risky, "update_claim")["annotations"]["readOnlyHint"] is True
    flagged = [f for f in run_checks(risky) if f.check_id == MISSING_APPROVAL]
    assert any("update_claim" in f.evidence for f in flagged)


def test_open_world_annotation_can_raise_risk(baseline: dict[str, Any]) -> None:
    # A tool with no outbound permission that says it reaches the open world is
    # treated as outbound.
    config = copy.deepcopy(baseline)
    config["tools"].append(
        {
            "name": "fetch_policy_page",
            "server": "finance-records",
            "permissions": ["read:expense_claims"],
            "annotations": {"openWorldHint": True},
        }
    )
    assert LEAKAGE_PATH in _check_ids(config)


def test_missing_requires_approval_fails_closed(baseline: dict[str, Any]) -> None:
    config = copy.deepcopy(baseline)
    del _tool(config, "add_claim_note")["requires_approval"]
    assert MISSING_APPROVAL in _check_ids(config)


# --- Individual checks ------------------------------------------------------


def test_leakage_path_is_critical_when_untrusted_content_is_read(risky: dict[str, Any]) -> None:
    leak = next(f for f in run_checks(risky) if f.check_id == LEAKAGE_PATH)
    assert leak.severity is Severity.CRITICAL
    assert "AML.T0086" in leak.maps_to


def test_leakage_path_is_high_without_untrusted_content(risky: dict[str, Any]) -> None:
    config = copy.deepcopy(risky)
    for source in config["data_sources"]:
        source["origin"] = "internal"
    leak = next(f for f in run_checks(config) if f.check_id == LEAKAGE_PATH)
    assert leak.severity is Severity.HIGH


def test_approval_on_outbound_tool_breaks_leakage_path(risky: dict[str, Any]) -> None:
    config = copy.deepcopy(risky)
    _tool(config, "send_email")["requires_approval"] = True
    assert LEAKAGE_PATH not in _check_ids(config)


@pytest.mark.parametrize(
    "value",
    [
        "${env:FINANCE_API_TOKEN}",
        "${FINANCE_API_TOKEN}",
        "Bearer ${env:FINANCE_API_TOKEN}",
    ],
)
def test_runtime_references_are_not_secrets(baseline: dict[str, Any], value: str) -> None:
    config = copy.deepcopy(baseline)
    config["mcp_servers"][0]["env"]["FINANCE_API_TOKEN"] = value
    assert SECRET_IN_CONFIG not in _check_ids(config)


@pytest.mark.parametrize(
    "prompt",
    [
        "Use the api key FAKE-KEY-DO-NOT-USE for the finance API.",
        "password: Example2026",
        "Send requests with Authorization: Bearer FAKEtoken1234567890",
    ],
)
def test_credentials_in_prompt_are_found(baseline: dict[str, Any], prompt: str) -> None:
    config = copy.deepcopy(baseline)
    config["agent"]["system_prompt"] = prompt
    assert SECRET_IN_CONFIG in _check_ids(config)


@pytest.mark.parametrize(
    "prompt",
    [
        "Keep each answer under a token budget of 500.",
        "Never ask an employee for their password.",
        "Explain the expense policy; do not discuss secret projects.",
    ],
)
def test_ordinary_prompt_text_is_not_a_secret(baseline: dict[str, Any], prompt: str) -> None:
    config = copy.deepcopy(baseline)
    config["agent"]["system_prompt"] = prompt
    assert SECRET_IN_CONFIG not in _check_ids(config)


# --- Input handling (PR-07) -------------------------------------------------


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.json"
    path.write_text(text, encoding="utf-8")
    return path


def test_rejects_config_not_marked_synthetic(tmp_path: Path, baseline: dict[str, Any]) -> None:
    config = copy.deepcopy(baseline)
    config["synthetic"] = False
    with pytest.raises(ConfigError, match="synthetic"):
        load_config(_write(tmp_path, json.dumps(config)))


def test_rejects_duplicate_keys(tmp_path: Path) -> None:
    # A duplicate key could show the reviewer one value and the real runtime another.
    with pytest.raises(ConfigError, match="duplicate key"):
        load_config(_write(tmp_path, '{"synthetic": true, "synthetic": false}'))


def test_rejects_malformed_permission(tmp_path: Path, baseline: dict[str, Any]) -> None:
    config = copy.deepcopy(baseline)
    config["tools"][0]["permissions"] = ["read expense claims"]
    with pytest.raises(ConfigError, match="action:resource"):
        load_config(_write(tmp_path, json.dumps(config)))


def test_rejects_tool_on_undeclared_server(tmp_path: Path, baseline: dict[str, Any]) -> None:
    config = copy.deepcopy(baseline)
    config["tools"][0]["server"] = "shadow-server"
    with pytest.raises(ConfigError, match="server"):
        load_config(_write(tmp_path, json.dumps(config)))


def test_rejects_unsafe_tool_name(tmp_path: Path, baseline: dict[str, Any]) -> None:
    # Names are echoed into findings, so markup or control characters are refused.
    config = copy.deepcopy(baseline)
    config["tools"][0]["name"] = "<img src=x onerror=alert(1)>"
    with pytest.raises(ConfigError, match="name"):
        load_config(_write(tmp_path, json.dumps(config)))


def test_rejects_oversized_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_reviewer.checks.MAX_CONFIG_BYTES", 100)
    with pytest.raises(ConfigError, match="larger than"):
        load_config(_write(tmp_path, json.dumps({"padding": "x" * 200})))


def test_rejects_invalid_json(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(_write(tmp_path, '{"synthetic": true,'))
