# Threat model

> **Placeholder.** Planned for v0.1. Nothing below is a finding yet.

Method: CSA MAESTRO layers, with each threat mapped to the OWASP Top 10 for Agentic Applications (2026, ASI01–ASI10), the OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS techniques where they fit. Controls are referenced by their IDs in the README control set (for example `PR-08`).

Scope: the **reviewer agent itself** — an agent whose main input (the configurations it reviews) is untrusted by design.

## Sections to complete

1. System description and trust boundaries (submitted config, reviewer agent, its MCP tool server, model provider, human approver, report output)
2. Assets and actions (submitted configs and any secrets in them, review verdicts, credentials, audit logs; what the reviewer can and cannot do)
3. Threats by MAESTRO layer, each mapped to ASI / LLM / ATLAS (for example: tool poisoning in a submitted config steering the verdict; secrets leaking into reports; an approver rubber-stamping a manipulated summary)
4. Controls per threat (README control IDs)
5. Test evidence per control (assurance IDs)
6. Residual risk, linked to the risk register (GV-03)
