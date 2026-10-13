"""Deterministic checks over a submitted (synthetic) agent configuration.

This is the reviewer's first layer: rules that don't depend on a model. The
reasoning-based layer (v0.1) sits on top and is cross-checked against these
results (README control PR-11).

Design rules
- The configuration is untrusted data (PR-08). It is parsed and inspected,
  never executed, followed or fetched.
- Malformed input is rejected, not guessed at (PR-07).
- Every finding names the config field it comes from (PR-11). When the problem
  is a missing field, the finding points at the nearest field that exists
  ("" means the whole configuration).
- Secret values never appear in a finding (PR-14).
- Missing or unknown values fail closed: a tool with no ``requires_approval``
  is treated as unapproved, and an unknown permission action as a side effect.
- MCP tool annotations are hints. The MCP specification says clients must treat
  them as untrusted unless they come from trusted servers, so here they can
  raise risk but never lower it.

IDs in ``maps_to``: ASI = OWASP Top 10 for Agentic Applications (2026) ·
LLM = OWASP Top 10 for LLM Applications (2025) · AML = MITRE ATLAS.
"""

import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any

MAX_CONFIG_BYTES = 1_000_000

# Fields that describe a sample for tests and evals, not the agent under
# review. Checks skip them, and the reasoning layer must never see them
# (otherwise the answer key leaks into the evaluation).
SAMPLE_METADATA_KEYS = frozenset(
    {"synthetic", "sample_id", "sample_notes", "seeded_flaws", "seeded_flaws_reasoning"}
)

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
PERMISSION_RE = re.compile(r"^(?:[a-z_]{1,32}|\*):(?:[a-z0-9_.-]{1,64}|\*)$")
VERSION_RE = re.compile(r"^[A-Za-z0-9_.^~*+-]{0,64}$")

READ_ACTIONS = frozenset({"read", "list", "get", "search"})
DESTRUCTIVE_ACTIONS = frozenset({"delete"})
OUTBOUND_ACTIONS = frozenset({"send", "post", "upload", "publish", "http"})
EXECUTE_ACTIONS = frozenset({"execute", "run"})
WILDCARD_ACTIONS = frozenset({"*", "admin"})

CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted"})
SENSITIVE_CLASSIFICATIONS = frozenset({"confidential", "restricted"})
ORIGINS = frozenset({"internal", "external"})
TRANSPORTS = frozenset({"stdio", "streamable-http", "sse", "http"})
REMOTE_TRANSPORTS = TRANSPORTS - {"stdio"}
UNPINNED_VERSIONS = frozenset({"", "latest", "*"})

# Check IDs. Samples list the ones they seed in "seeded_flaws".
EXCESSIVE_PERMISSIONS = "excessive_permissions"
MISSING_APPROVAL = "missing_approval"
LEAKAGE_PATH = "leakage_path"
SECRET_IN_CONFIG = "secret_in_config"
UNVETTED_MCP_SERVER = "unvetted_mcp_server"
MCP_SERVER_NO_AUTH = "mcp_server_no_auth"
MISSING_AUDIT_LOGGING = "missing_audit_logging"

# A field whose name says it holds a credential...
SECRET_KEY_RE = re.compile(
    r"api[_-]?key|secret|token|passw(?:or)?d|authorization|credential|private[_-]?key",
    re.IGNORECASE,
)
# ...is fine when it holds a reference resolved at runtime, e.g. ${env:NAME}
# or "Bearer ${env:NAME}".
SECRET_REFERENCE_RE = re.compile(r"^(?:Bearer\s+)?\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\}$")
# Credential-shaped values anywhere, including free text such as a system
# prompt. A heuristic: it will miss some secrets and flag some non-secrets.
# CI secret scanning (v0.1) is the backstop.
SECRET_VALUE_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key ID format
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"),  # GitHub token format
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),  # Slack token format
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i:\bbearer)\s+[A-Za-z0-9._~+/-]{8,}"),
    # A credential word followed by a value that has a capital or a digit,
    # e.g. "service token FAKE-KEY-DO-NOT-USE", but not "token budget".
    re.compile(
        r"(?i:\b(?:api[ _-]?key|token|password|passwd|secret)\b)\s*(?:is|:|=)?\s*[\"']?"
        r"(?=[A-Za-z0-9_./+=-]*[A-Z0-9])[A-Za-z0-9][A-Za-z0-9_./+=-]{7,}"
    ),
)


class ConfigError(ValueError):
    """The submitted configuration is malformed and was rejected."""


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    field: str
    evidence: str
    recommendation: str
    maps_to: tuple[str, ...]
    source: str = "deterministic"


# --- Loading and validation -------------------------------------------------


def load_config(path: str | Path) -> dict[str, Any]:
    """Read and validate a configuration file. Raises ConfigError if it's unsafe to review."""
    path = Path(path)
    with path.open("rb") as f:
        raw = f.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{path.name}: larger than {MAX_CONFIG_BYTES} bytes")
    try:
        config = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path.name}: not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path.name}: not valid JSON ({exc.msg}, line {exc.lineno})") from exc
    validate_config(config)
    return config


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # json would otherwise keep the last value silently, so a reviewer and the
    # agent's real runtime could read different values for the same key.
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> None:
    raise ConfigError(f"non-standard JSON value {name}")


def validate_config(config: Any) -> None:
    """Enforce the minimal structure the checks rely on. A full schema comes in v0.1 (PR-07)."""
    _require(isinstance(config, dict), "configuration must be a JSON object")
    _require(config.get("synthetic") is True, '"synthetic": true is required (synthetic data only)')

    agent = config.get("agent")
    _require(isinstance(agent, dict), '"agent" must be an object')
    _require_name(agent.get("name"), "agent.name")
    _require(isinstance(agent.get("system_prompt", ""), str), "agent.system_prompt must be a string")

    sources = config.get("data_sources", [])
    _require(isinstance(sources, list), '"data_sources" must be a list')
    for i, source in enumerate(sources):
        _require(isinstance(source, dict), f"data_sources[{i}] must be an object")
        _require_name(source.get("name"), f"data_sources[{i}].name")
        _require(
            source.get("classification") in CLASSIFICATIONS,
            f"data_sources[{i}].classification must be one of {sorted(CLASSIFICATIONS)}",
        )
        _require(
            source.get("origin") in ORIGINS,
            f"data_sources[{i}].origin must be one of {sorted(ORIGINS)}",
        )

    servers = config.get("mcp_servers", [])
    _require(isinstance(servers, list), '"mcp_servers" must be a list')
    server_names = set()
    for i, server in enumerate(servers):
        _require(isinstance(server, dict), f"mcp_servers[{i}] must be an object")
        _require_name(server.get("name"), f"mcp_servers[{i}].name")
        _require(server["name"] not in server_names, f"duplicate server name {server['name']!r}")
        server_names.add(server["name"])
        _require(
            server.get("transport") in TRANSPORTS,
            f"mcp_servers[{i}].transport must be one of {sorted(TRANSPORTS)}",
        )
        version = server.get("version", "")
        _require(
            isinstance(version, str) and VERSION_RE.match(version) is not None,
            f"mcp_servers[{i}].version is malformed",
        )
        if "source" in server:
            _require_name(server["source"], f"mcp_servers[{i}].source")
        if "auth" in server:
            _require(isinstance(server["auth"], dict), f"mcp_servers[{i}].auth must be an object")

    tools = config.get("tools")
    _require(isinstance(tools, list) and tools, '"tools" must be a non-empty list')
    tool_names = set()
    for i, tool in enumerate(tools):
        _require(isinstance(tool, dict), f"tools[{i}] must be an object")
        _require_name(tool.get("name"), f"tools[{i}].name")
        _require(tool["name"] not in tool_names, f"duplicate tool name {tool['name']!r}")
        tool_names.add(tool["name"])
        _require(
            tool.get("server") in server_names,
            f"tools[{i}].server must name a server in mcp_servers",
        )
        permissions = tool.get("permissions")
        _require(isinstance(permissions, list), f"tools[{i}].permissions must be a list")
        for j, permission in enumerate(permissions):
            _require(
                isinstance(permission, str) and PERMISSION_RE.match(permission) is not None,
                f'tools[{i}].permissions[{j}] must look like "action:resource"',
            )
        if "requires_approval" in tool:
            _require(
                isinstance(tool["requires_approval"], bool),
                f"tools[{i}].requires_approval must be true or false",
            )
        annotations = tool.get("annotations", {})
        _require(
            isinstance(annotations, dict)
            and all(isinstance(v, bool) for k, v in annotations.items() if k.endswith("Hint")),
            f"tools[{i}].annotations hints must be true or false",
        )

    logging = config.get("logging", {})
    _require(isinstance(logging, dict), '"logging" must be an object')


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def _require_name(value: Any, field: str) -> None:
    # Names are echoed into findings and reports, so they must be short and plain.
    _require(
        isinstance(value, str) and NAME_RE.match(value) is not None,
        f"{field} must be 1-64 letters, digits, '.', '_' or '-'",
    )


# --- Helpers ----------------------------------------------------------------


def _permissions(tool: dict[str, Any]) -> Iterator[tuple[int, str, str]]:
    for j, permission in enumerate(tool["permissions"]):
        action, _, resource = permission.partition(":")
        yield j, action, resource


def _is_read_only(tool: dict[str, Any]) -> bool:
    # Decided by permissions alone. A readOnlyHint=true annotation can't make a
    # tool read-only; an explicit readOnlyHint=false can make it not read-only.
    if _annotations(tool).get("readOnlyHint") is False:
        return False
    return all(action in READ_ACTIONS for _, action, _ in _permissions(tool))


def _is_outbound(tool: dict[str, Any]) -> bool:
    if _annotations(tool).get("openWorldHint") is True:
        return True
    return any(action in OUTBOUND_ACTIONS | WILDCARD_ACTIONS for _, action, _ in _permissions(tool))


def _is_high_impact(tool: dict[str, Any]) -> bool:
    high_impact = DESTRUCTIVE_ACTIONS | OUTBOUND_ACTIONS | EXECUTE_ACTIONS | WILDCARD_ACTIONS
    if _annotations(tool).get("destructiveHint") is True:
        return True
    return any(
        action in high_impact or (resource == "*" and action not in READ_ACTIONS)
        for _, action, resource in _permissions(tool)
    )


def _annotations(tool: dict[str, Any]) -> dict[str, Any]:
    return tool.get("annotations", {})


def _requires_approval(tool: dict[str, Any]) -> bool:
    return tool.get("requires_approval") is True


def _walk_strings(value: Any, path: str = "") -> Iterator[tuple[str, str, str]]:
    """Yield (path, key, text) for every string in the config, skipping sample metadata."""
    if isinstance(value, dict):
        for key, child in value.items():
            if not path and key in SAMPLE_METADATA_KEYS:
                continue
            child_path = f"{path}.{key}" if path else key
            if isinstance(child, str):
                yield child_path, key, child
            else:
                yield from _walk_strings(child, child_path)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            child_path = f"{path}[{i}]"
            if isinstance(child, str):
                yield child_path, "", child
            else:
                yield from _walk_strings(child, child_path)


# --- Checks -----------------------------------------------------------------


def check_excessive_permissions(config: dict[str, Any]) -> Iterator[Finding]:
    """Wildcard, admin or delete access (least privilege)."""
    for i, tool in enumerate(config["tools"]):
        for j, action, resource in _permissions(tool):
            field = f"tools[{i}].permissions[{j}]"
            if action in WILDCARD_ACTIONS or resource == "*":
                yield Finding(
                    check_id=EXCESSIVE_PERMISSIONS,
                    title="Wildcard or admin permission",
                    severity=Severity.HIGH,
                    field=field,
                    evidence=f"Tool '{tool['name']}' is granted '{action}:{resource}'.",
                    recommendation=(
                        "Replace it with the specific actions and resources the agent's "
                        "purpose needs (least privilege)."
                    ),
                    maps_to=("ASI02", "ASI03", "LLM06"),
                )
            elif action in DESTRUCTIVE_ACTIONS:
                yield Finding(
                    check_id=EXCESSIVE_PERMISSIONS,
                    title="Delete permission",
                    severity=Severity.MEDIUM,
                    field=field,
                    evidence=f"Tool '{tool['name']}' can delete '{resource}'.",
                    recommendation=(
                        "Remove delete access unless the purpose requires it. If it does, "
                        "require human approval and make deletions recoverable."
                    ),
                    maps_to=("ASI02", "ASI03", "LLM06"),
                )


def check_missing_approval(config: dict[str, Any]) -> Iterator[Finding]:
    """Tools with side effects that run without a human approval step."""
    for i, tool in enumerate(config["tools"]):
        if _is_read_only(tool) or _requires_approval(tool):
            continue
        permissions = ", ".join(f"'{p}'" for p in tool["permissions"]) or "no declared permissions"
        evidence = f"Tool '{tool['name']}' has {permissions} and no approval step."
        if _annotations(tool).get("readOnlyHint") is True:
            evidence += " Its annotations claim it is read-only; its permissions say otherwise."
        yield Finding(
            check_id=MISSING_APPROVAL,
            title="Side-effecting tool runs without human approval",
            severity=Severity.HIGH if _is_high_impact(tool) else Severity.MEDIUM,
            field=f"tools[{i}].requires_approval" if "requires_approval" in tool else f"tools[{i}]",
            evidence=evidence,
            recommendation=(
                "Require human approval before this tool runs, and show the approver the "
                "exact arguments (the MCP spec says clients should show tool inputs before "
                "calling, to avoid data exfiltration)."
            ),
            maps_to=("ASI02", "LLM06"),
        )


def check_leakage_path(config: dict[str, Any]) -> Iterator[Finding]:
    """Sensitive read access plus an unapproved outbound tool: a data exfiltration path."""
    sources = config.get("data_sources", [])
    classification = {s["name"]: s["classification"] for s in sources}
    external = {s["name"] for s in sources if s["origin"] == "external"}
    any_sensitive = bool(SENSITIVE_CLASSIFICATIONS & set(classification.values()))

    sensitive_reads: set[str] = set()
    untrusted_reads: set[str] = set()
    for tool in config["tools"]:
        for _, action, resource in _permissions(tool):
            if action not in READ_ACTIONS | WILDCARD_ACTIONS:
                continue
            if resource == "*":
                if any_sensitive:
                    sensitive_reads.add(f"{tool['name']} (any resource)")
                if external:
                    untrusted_reads.add(f"{tool['name']} (any resource)")
            else:
                # An undeclared data source can't be judged, so it fails closed.
                level = classification.get(resource, "unclassified")
                if level in SENSITIVE_CLASSIFICATIONS or level == "unclassified":
                    sensitive_reads.add(f"{tool['name']} ({resource}: {level})")
                if resource in external:
                    untrusted_reads.add(f"{tool['name']} ({resource})")
    if not sensitive_reads:
        return

    for i, tool in enumerate(config["tools"]):
        if not _is_outbound(tool) or _requires_approval(tool):
            continue
        evidence = (
            f"Sensitive data is readable via {', '.join(sorted(sensitive_reads))}, and tool "
            f"'{tool['name']}' can send data out without human approval."
        )
        if untrusted_reads:
            evidence += (
                f" The agent also reads untrusted external content via "
                f"{', '.join(sorted(untrusted_reads))}, so an indirect prompt injection in "
                "that content could trigger the exfiltration with no malicious user involved."
            )
            severity = Severity.CRITICAL
            maps_to = ("ASI01", "ASI02", "LLM01", "LLM02", "AML.T0051.001", "AML.T0086")
        else:
            severity = Severity.HIGH
            maps_to = ("ASI02", "LLM02", "AML.T0086")
        yield Finding(
            check_id=LEAKAGE_PATH,
            title="Data leakage path: sensitive read plus unapproved outbound tool",
            severity=severity,
            field=f"tools[{i}]",
            evidence=evidence,
            recommendation=(
                "Break the path: require approval on the outbound tool (showing recipient "
                "and content), restrict its destinations to an allowlist, or remove sensitive "
                "read access the purpose doesn't need. Where the agent reads untrusted content, "
                "block outbound tools for the rest of that session."
            ),
            maps_to=maps_to,
        )


def check_secrets(config: dict[str, Any]) -> Iterator[Finding]:
    """Literal credentials anywhere in the configuration, including the system prompt."""
    for path, key, text in _walk_strings(config):
        named_secret = (
            bool(key)
            and SECRET_KEY_RE.search(key) is not None
            and text.strip() != ""
            and SECRET_REFERENCE_RE.match(text.strip()) is None
        )
        if not named_secret and not any(p.search(text) for p in SECRET_VALUE_PATTERNS):
            continue
        in_prompt = path == "agent.system_prompt"
        yield Finding(
            check_id=SECRET_IN_CONFIG,
            title="Credential in system prompt" if in_prompt else "Credential in configuration",
            severity=Severity.HIGH,
            field=path,
            # Never include the value itself (PR-14).
            evidence="A credential-like value was found in this field (value redacted).",
            recommendation=(
                "Remove it and rotate it as if exposed. Load credentials at runtime from the "
                "environment or a secrets manager (for example ${env:NAME}), and never put "
                "them in a prompt."
            ),
            maps_to=("LLM02", "LLM07", "AML.T0055") if in_prompt else ("LLM02", "AML.T0055"),
        )


def check_unvetted_mcp_servers(config: dict[str, Any]) -> Iterator[Finding]:
    """MCP servers that aren't approved, or whose version isn't pinned (supply chain)."""
    for i, server in enumerate(config.get("mcp_servers", [])):
        name = server["name"]
        if server.get("approved") is not True:
            source = server.get("source", "unknown")
            yield Finding(
                check_id=UNVETTED_MCP_SERVER,
                title="MCP server is not approved",
                severity=Severity.HIGH,
                field=f"mcp_servers[{i}].approved" if "approved" in server else f"mcp_servers[{i}]",
                evidence=f"Server '{name}' (source: {source}) has not been approved.",
                recommendation=(
                    "Review the server's code, publisher and tool definitions before use, "
                    "and add it to an approved list."
                ),
                maps_to=("ASI04", "LLM03"),
            )
        version = server.get("version", "")
        if version in UNPINNED_VERSIONS or version[:1] in {"^", "~"}:
            yield Finding(
                check_id=UNVETTED_MCP_SERVER,
                title="MCP server version is not pinned",
                severity=Severity.MEDIUM,
                field=f"mcp_servers[{i}].version" if "version" in server else f"mcp_servers[{i}]",
                evidence=f"Server '{name}' tracks '{version or 'no version'}'.",
                recommendation=(
                    "Pin an exact version (ideally with a content hash) so the reviewed code "
                    "and tool definitions can't change after approval (a 'rug pull')."
                ),
                maps_to=("ASI04", "LLM03"),
            )


def check_mcp_auth(config: dict[str, Any]) -> Iterator[Finding]:
    """Remote MCP servers reached without authentication or over plain HTTP."""
    for i, server in enumerate(config.get("mcp_servers", [])):
        if server["transport"] not in REMOTE_TRANSPORTS:
            continue
        name = server["name"]
        auth_type = server.get("auth", {}).get("type", "none")
        if auth_type in {"none", ""}:
            yield Finding(
                check_id=MCP_SERVER_NO_AUTH,
                title="Remote MCP server is unauthenticated",
                severity=Severity.HIGH,
                field=f"mcp_servers[{i}].auth" if "auth" in server else f"mcp_servers[{i}]",
                evidence=f"Remote server '{name}' is reached with no authentication.",
                recommendation=(
                    "Authenticate every request (MCP authorization is based on OAuth 2.1). "
                    "The server must check each token was issued for it and never pass "
                    "tokens through to other APIs."
                ),
                maps_to=("ASI03",),
            )
        url = server.get("url", "")
        if not (isinstance(url, str) and url.startswith("https://")):
            yield Finding(
                check_id=MCP_SERVER_NO_AUTH,
                title="Remote MCP server is not reached over HTTPS",
                severity=Severity.HIGH,
                field=f"mcp_servers[{i}].url" if "url" in server else f"mcp_servers[{i}]",
                evidence=f"Remote server '{name}' has no HTTPS URL.",
                recommendation="Use HTTPS so tokens and tool traffic aren't exposed in transit.",
                maps_to=("ASI03",),
            )


def check_audit_logging(config: dict[str, Any]) -> Iterator[Finding]:
    """Tool calls and approval decisions must be logged."""
    logging = config.get("logging", {})
    missing = [key for key in ("tool_calls", "approval_decisions") if logging.get(key) is not True]
    if not missing:
        return
    yield Finding(
        check_id=MISSING_AUDIT_LOGGING,
        title="Audit logging is incomplete",
        severity=Severity.MEDIUM,
        field="logging" if "logging" in config else "",
        evidence=f"Not logged: {', '.join(missing)}.",
        recommendation=(
            "Log every tool call (tool, arguments, result status) and every approval "
            "decision, so actions can be investigated (the MCP spec says clients should "
            "log tool usage for audit purposes)."
        ),
        maps_to=("ASI10",),
    )


CHECKS: tuple[Callable[[dict[str, Any]], Iterator[Finding]], ...] = (
    check_excessive_permissions,
    check_missing_approval,
    check_leakage_path,
    check_secrets,
    check_unvetted_mcp_servers,
    check_mcp_auth,
    check_audit_logging,
)


def run_checks(config: dict[str, Any]) -> list[Finding]:
    """Validate the config, run every check, and return findings, most severe first."""
    validate_config(config)
    findings = [finding for check in CHECKS for finding in check(config)]
    return sorted(findings, key=lambda f: (-f.severity, f.check_id, f.field))
