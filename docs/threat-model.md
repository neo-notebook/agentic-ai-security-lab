# Threat model

> **Placeholder.** Planned for v0.1. Nothing below is a finding yet.

Method: CSA MAESTRO layers mapped to OWASP Agentic AI Threats & Mitigations, with MITRE ATLAS references where useful.

Scope: the **reviewer agent itself** — an agent whose main input (the configurations it reviews) is untrusted by design.

## Sections to complete

1. System description and trust boundaries (submitted config, reviewer agent, its MCP tool server, model provider, human sign-off, report output)
2. Assets (submitted configs and any secrets in them, review verdicts, credentials, audit logs)
3. Threats by MAESTRO layer, each mapped to an OWASP Agentic threat (for example: tool poisoning in a submitted config steering the verdict; secrets leaking into reports)
4. Controls per threat (linked to the README control table)
5. Test evidence per control
6. Residual risk and open items
