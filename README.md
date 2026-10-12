# agentic-ai-security-lab

**An AI security review agent — an agent that reviews other agents — built and secured.** It reads an AI agent's configuration (MCP server and tool definitions, tool permissions, system prompt, data flows), checks it against agentic AI threat guidance, and drafts a security review with findings and a risk rating. A human signs off on every verdict.

The reviewer is itself an agent that reads untrusted input, so every control around it — a scoped MCP permission manifest, read-only tools, a human sign-off gate, guardrails, audit logging, and tool-poisoning and leakage tests — is built and tested here, then mapped to a threat model and to the NIST AI RMF.

This lab implements the controls from my BSides Edmonton 2025 talk, *"Agentic AI – Security Lessons for Early Adopters"*, and turns them into first-hand evidence.

> **Status:** v0, in progress. This is a learning and research lab, **not production software**. Its findings are drafts for a human reviewer, not a substitute for one.

## Why this lab

Organizations are connecting agents to real tools and data faster than security teams can review them. This lab asks a practical question: *can an agent help a security team review agentic systems consistently — and how do you stop the reviewer itself from being manipulated?*

It combines two things:

- **AI for security:** an agent that does a first-pass security review of other agents.
- **Securing AI:** the controls that keep the reviewer within its authority, and the tests that show whether they hold.

## What the reviewer checks (v0 scope)

| Check | Example finding |
|---|---|
| Excessive permissions / agency | A tool has write or delete access the agent's purpose doesn't need |
| Risky tool combinations | Read access to sensitive data **plus** an outbound tool (email, HTTP) = a data-leakage path |
| Missing human approval | Tools with side effects run without an approval step |
| Tool poisoning | A tool description contains hidden instructions aimed at the model |
| Secrets in configuration | Credentials embedded in a manifest or prompt |
| Unvetted MCP servers | Servers from unknown sources or unpinned versions (supply chain) |
| Missing audit logging | No record of tool calls or decisions |

Design choice, from the talk: **deterministic checks first** (rules over the manifest that don't depend on a model), then **reasoning-based review** layered on top for things rules can't judge, such as whether a system prompt's stated purpose matches the tools granted.

## Data rule

**Synthetic data only.** The configurations the reviewer reads are invented examples of fictional agents. No employer, customer or real system configurations, ever. See [`data/samples/README.md`](data/samples/README.md).

## Controls on the reviewer itself

Controls are grouped using the framing from the talk: **deterministic** controls (enforced by code, independent of the model) and **reasoning-based** controls (rely on a model's judgement, so they need testing and a deterministic backstop).

| # | Control | Type | Status | Evidence |
|---|---|---|---|---|
| 1 | Read-only tools: the reviewer reads configs; it never executes, installs or connects to the systems it reviews | Deterministic | Planned | — |
| 2 | Reviewer's own tools exposed via an MCP server with a scoped permission manifest | Deterministic | Planned | — |
| 3 | Untrusted-input isolation: reviewed configs are treated as data, never as instructions | Deterministic + reasoning-based | Planned | — |
| 4 | Human sign-off before any review verdict is issued | Deterministic | Planned | — |
| 5 | Grounded findings: every finding must cite the config field it comes from; uncited findings are rejected | Deterministic + reasoning-based | Planned | — |
| 6 | Secret redaction: credentials found in configs never appear in the report | Deterministic | Planned | — |
| 7 | Audit logging of every model call, tool call and sign-off decision | Deterministic | Planned | — |
| 8 | Tool-poisoning / indirect-injection test suite (hidden instructions in tool descriptions, prompts and manifests) | Evaluation | Planned | — |
| 9 | Reviewer accuracy evals on seeded configs with known flaws (detection rate, false positives) | Evaluation | Planned | — |
| 10 | Data-leakage tests on review output | Evaluation | Planned | — |
| 11 | Dependency and code scanning in CI, with findings triage | Deterministic | Planned | — |
| 12 | Cloud deploy with a least-privilege IAM role for the reviewer (non-human identity), via Terraform | Deterministic | Planned | — |

<!-- TODO (Neo): reconcile this table with the deterministic vs reasoning-based control lists in the talk slides (18 and 20). Add, rename or regroup controls so the README matches the talk exactly. -->

## Governance

- **Threat model:** CSA MAESTRO mapped to OWASP Agentic AI Threats & Mitigations, with MITRE ATLAS references where useful → [`docs/threat-model.md`](docs/threat-model.md)
- **NIST AI RMF mapping:** how the controls above support Govern / Map / Measure / Manage → [`docs/nist-ai-rmf-mapping.md`](docs/nist-ai-rmf-mapping.md)

## Roadmap

| Milestone | Scope |
|---|---|
| v0 | Repo skeleton · deterministic checks on one sample manifest · drafted review report |
| v0.1 (public) | Reasoning-based review · MCP tool server + manifest · sign-off gate · tool-poisoning tests · accuracy evals · threat model · NIST AI RMF mapping · CI scanning · architecture diagram |
| v0.2 | AWS deploy via Terraform with least-privilege IAM role · audit logging · leakage tests · test-results write-up |

## Repository layout

```
.
├── data/samples/          # synthetic agent configs only (see its README)
├── docs/                  # threat model, governance mapping, write-ups
├── src/agent_reviewer/    # the review agent and its tools
└── tests/                 # unit, tool-poisoning, accuracy and leakage tests
```

## Security

See [`SECURITY.md`](SECURITY.md).

## License

To be added.
