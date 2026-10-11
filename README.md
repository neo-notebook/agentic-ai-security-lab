# agentic-ai-security-lab

**A DLP alert triage agent, built and secured.** The agent reads synthetic data-loss-prevention and shadow-AI alerts, enriches them, and drafts a triage ticket. Every control around it — tool permissions, an MCP permission manifest, a human approval gate, guardrails, audit logging, injection and leakage tests — is built and tested here, then mapped to a threat model and to the NIST AI RMF.

This lab implements the controls from my BSides Edmonton 2025 talk, *"Agentic AI – Security Lessons for Early Adopters"*, and turns them into first-hand evidence.

> **Status:** v0, in progress. This is a learning and research lab, **not production software**. Don't deploy it against real data.

## Why this lab

Most guidance on agentic AI security is written at the framework level. This lab asks a practical question: *what does it take to let an AI agent touch security operations data in a regulated environment, and how do you prove the controls work?*

It combines two things:

- **AI for security:** an agent that does useful triage work.
- **Securing AI:** the controls that keep that agent within its authority, and the tests that show whether they hold.

## Data rule

**Synthetic data only.** No employer, customer or real personal data, ever. See [`data/synthetic/README.md`](data/synthetic/README.md) for how synthetic alerts are generated and labelled.

## Control checklist

Controls are grouped using the framing from the talk: **deterministic** controls (enforced by code, independent of the model) and **reasoning-based** controls (rely on a model's judgement, so they need testing and a deterministic backstop).

| # | Control | Type | Status | Evidence |
|---|---|---|---|---|
| 1 | Least-privilege tool permissions (read-only by default) | Deterministic | Planned | — |
| 2 | Agent tools exposed via an MCP server with a scoped permission manifest | Deterministic | Planned | — |
| 3 | Human approval gate before any action with side effects | Deterministic | Planned | — |
| 4 | Input guardrails (untrusted alert content treated as data, not instructions) | Deterministic + reasoning-based | Planned | — |
| 5 | Output guardrails (no sensitive values in drafted tickets) | Deterministic + reasoning-based | Planned | — |
| 6 | Audit logging of every model call, tool call and approval decision | Deterministic | Planned | — |
| 7 | Prompt-injection test suite, incl. indirect injection hidden in alert content (filenames, email bodies) | Evaluation | Planned | — |
| 8 | Data-leakage tests | Evaluation | Planned | — |
| 9 | Dependency and code scanning in CI, with findings triage | Deterministic | Planned | — |
| 10 | Cloud deploy with a least-privilege IAM role for the agent (non-human identity), via Terraform | Deterministic | Planned | — |

<!-- TODO (Neo): reconcile this table with the deterministic vs reasoning-based control lists in the talk slides (18 and 20). Add, rename or regroup controls so the README matches the talk exactly. -->

## Governance

- **Threat model:** CSA MAESTRO mapped to OWASP Agentic AI Threats & Mitigations, with MITRE ATLAS references where useful → [`docs/threat-model.md`](docs/threat-model.md)
- **NIST AI RMF mapping:** how the controls above support Govern / Map / Measure / Manage → [`docs/nist-ai-rmf-mapping.md`](docs/nist-ai-rmf-mapping.md)

## Roadmap

| Milestone | Scope |
|---|---|
| v0 | Repo skeleton · agent with one read-only tool on synthetic alerts |
| v0.1 (public) | MCP tool server + manifest · guardrails · approval gate · injection tests · threat model · NIST AI RMF mapping · CI scanning · architecture diagram |
| v0.2 | AWS deploy via Terraform with least-privilege IAM role · audit logging · data-leakage tests · test-results write-up |

## Repository layout

```
.
├── data/synthetic/        # synthetic alerts only (see its README)
├── docs/                  # threat model, governance mapping, write-ups
├── src/triage_agent/      # the agent and its tools
└── tests/                 # unit, injection and leakage tests
```

## Security

See [`SECURITY.md`](SECURITY.md).

## License

To be added.
