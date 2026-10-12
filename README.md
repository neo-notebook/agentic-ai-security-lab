# agentic-ai-security-lab

**An AI security review agent — an agent that reviews other agents — built and secured.** It reads an AI agent's configuration (MCP server and tool definitions, tool permissions, system prompt, data flows), checks it against agentic AI threat guidance, and drafts a security review with findings and a risk rating. A human signs off on every verdict.

The reviewer is itself an agent that reads untrusted input, so it gets the same treatment it gives others: traditional and reasoning-based controls, built and tested here, mapped to a threat model and to the NIST AI RMF.

This lab implements the controls and roadmap from my BSides Edmonton 2025 talk, *"Agentic AI – Security Lessons for Early Adopters"*, and turns them into first-hand evidence.

> **Status:** v0, in progress. This is a learning and research lab, **not production software**. Its findings are drafts for a human reviewer, not a substitute for one.

## Why this lab

Organizations are connecting agents to real tools and data faster than security teams can review them. This lab asks a practical question: *can an agent help a security team review agentic systems consistently — and how do you stop the reviewer itself from being manipulated?*

It combines two things:

- **AI for security:** an agent that does a first-pass security review of other agents.
- **Securing AI:** the controls that keep the reviewer within its authority, and the tests that show whether they hold.

Principles from the talk that shape every choice here: **no one size fits all** · balance productivity with security, aligned to business goals · **security by design** · **human oversight** · start small, mature over time · always have a **kill switch and rollback**.

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

**Risk rating** uses the talk's method: task **autonomy** combined with **impact × likelihood**, which also sets the human-in-the-loop tier the reviewed agent should have.

**Design choice from the talk:** deterministic checks first (rules over the config that don't depend on a model), then reasoning-based review layered on top for what rules can't judge, such as whether a system prompt's stated purpose matches the tools granted.

## Data rule

**Synthetic data only.** The configurations the reviewer reads are invented examples of fictional agents. No employer, customer or real system configurations, ever. See [`data/samples/README.md`](data/samples/README.md).

## Controls on the reviewer itself

The two control families come from the talk. The talk's lists aren't exhaustive, so a third table adds controls this lab needs beyond them.

**Status key:** v0.1 / v0.2 = planned milestone · Later = valuable, not in this quarter's scope · **N/A by design** = the risk is removed by an architecture choice, which is documented as a control in its own right.

### Traditional controls

| Control (from the talk) | How it applies to the reviewer | Status |
|---|---|---|
| Sandboxing & least privilege | Read-only tools; the reviewer never executes, installs or connects to the systems it reviews | v0.1 |
| Network & API security | Only outbound connection is the model provider's API; the tool server has no network access | v0.1 (tools) · v0.2 (cloud egress rules) |
| Identity & access control | Reviewer runs as its own non-human identity with a least-privilege IAM role; only named humans can sign off | v0.2 |
| Data isolation | Each review runs alone: no shared state between reviews; submitted configs aren't retained after the run | v0.1 |
| Runtime hardening | Container runs as non-root with pinned dependencies and a minimal image | v0.2 |
| Logging, observability & forensics | Audit log of every model call, tool call, finding and sign-off, enough to reconstruct a review | v0.2 |
| Supply chain security | Pinned dependencies; CI dependency scanning; report-only scan with Visa's open-source VVAH | v0.1 |
| Patch & config hygiene | Automated dependency update PRs; secure defaults (sign-off required, tools read-only) | v0.1 |
| Classic AppSec practices | Strict schema validation of submitted configs; static analysis (Bandit) in CI; secrets only from environment | v0.1 |

### Reasoning-based controls

| Control (from the talk) | How it applies to the reviewer | Status |
|---|---|---|
| Adversarial prompt defenses | Submitted configs treated as data, never instructions; tool-poisoning and indirect-injection test suite | v0.1 |
| Reasoning / planning validation | Grounded findings: every finding must cite the config field it comes from, and model findings are cross-checked against the deterministic results | v0.1 |
| Memory security | Reviewer is stateless per review, so there is no persistent memory to poison | N/A by design (documented) |
| Behavioral monitoring & anomaly detection | Flag runs where the model's verdict diverges sharply from deterministic checks, or output looks abnormal | v0.2 |
| Dynamic guardrails / HITL controls | Tiered sign-off: higher risk ratings need a fuller human review before a verdict is issued | v0.1 |
| Multi-agent trust frameworks | Single reviewer agent today | Later |
| Explainability & transparency | Each finding includes evidence and rationale; the report states what the reviewer could not assess | v0.1 |
| Red teaming & stress testing | Tool-poisoning tests, accuracy evals on seeded configs (detection rate, false positives), leakage tests | v0.1 · v0.2 |
| Continuous learning security | No model training or fine-tuning; instead, every prompt or rule change must pass the eval suite before release | v0.2 |
| Secure RAG & embedding protections | No retrieval in v0.x; applies if the reviewer later retrieves from a guidance corpus | Later |

### Beyond the talk

| Control | Why | Status |
|---|---|---|
| Secret redaction in output | Credentials found in a config must never appear in the review report | v0.1 |
| Model-provider data boundary | Documents exactly what leaves the boundary to the model provider (synthetic configs only) and the provider's data-retention settings | v0.1 |
| Cost and abuse limits | Caps on model calls, tokens and run time per review, against runaway loops and denial-of-wallet | v0.1 |
| Kill switch & rollback | One switch disables model calls; prompts and rules are versioned so a bad change can be rolled back | v0.2 |

## How the lab follows the talk's roadmap

| Talk step | In this lab |
|---|---|
| 1. Awareness, planning & visibility | The reviewer itself is a visibility tool: a consistent inventory of what each agent can do. The lab documents its own components the same way. |
| 2. Threat modeling | Model the reviewer's agent loop, its assets and actions, mapped with MAESTRO → [`docs/threat-model.md`](docs/threat-model.md) |
| 3. Risk assessment | Autonomy × impact × likelihood scoring and HITL tiers, used both in the reviewer's output and for the reviewer itself |
| 4. Mitigation | The traditional and reasoning-based control tables above |
| 5. Monitoring & response | Audit logging, red-team evals, kill switch and rollback |
| 6. Mature & scale | Multi-agent trust and continuous improvement: later milestones |

## Governance

- **Threat model:** CSA MAESTRO mapped to OWASP Agentic AI Threats & Mitigations, with MITRE ATLAS references where useful → [`docs/threat-model.md`](docs/threat-model.md)
- **NIST AI RMF mapping:** how the controls above support Govern / Map / Measure / Manage → [`docs/nist-ai-rmf-mapping.md`](docs/nist-ai-rmf-mapping.md)

## Roadmap

| Milestone | Scope |
|---|---|
| v0 | Repo skeleton · deterministic checks on one sample config · drafted review report |
| v0.1 (public) | Reasoning-based review · MCP tool server + manifest · tiered sign-off · grounded findings · tool-poisoning tests · accuracy evals · CI + VVAH scanning · threat model · NIST AI RMF mapping · architecture diagram |
| v0.2 | AWS deploy via Terraform with least-privilege IAM role · hardened container · audit logging · anomaly flags · kill switch and rollback · eval gate on changes · leakage tests · test-results write-up |

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
