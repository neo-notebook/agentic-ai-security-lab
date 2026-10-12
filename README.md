# agentic-ai-security-lab

**An AI security review agent — an agent that reviews other agents — built and secured.** It reads an AI agent's configuration (MCP server and tool definitions, tool permissions, system prompt, data flows), checks it against agentic AI threat guidance, and drafts a security review with findings and a risk rating. A human signs off on every verdict.

The reviewer is itself an agent that reads untrusted input, so it gets the same treatment it gives others: a full control set across the security lifecycle, mapped to industry frameworks, and tested.

This lab implements the controls and roadmap from my BSides Edmonton 2025 talk, *"Agentic AI – Security Lessons for Early Adopters"*, extends them against current industry frameworks, and turns them into first-hand evidence.

> **Status:** v0, in progress. This is a learning and research lab, **not production software**. Its findings are drafts for a human reviewer, not a substitute for one.

## Contents

1. [Why this lab](#why-this-lab)
2. [What the reviewer checks](#what-the-reviewer-checks)
3. [How the controls are organized](#how-the-controls-are-organized)
4. [Control set](#control-set) — Govern · Identify · Protect · Detect · Respond · Recover · Assurance
5. [Out of scope today](#out-of-scope-today)
6. [Crosswalks](#crosswalks) — talk roadmap and talk controls → this lab
7. [Roadmap](#roadmap)
8. [Frameworks referenced](#frameworks-referenced)

## Why this lab

Organizations are connecting agents to real tools and data faster than security teams can review them. This lab asks a practical question: *can an agent help a security team review agentic systems consistently — and how do you stop the reviewer itself from being manipulated?*

- **AI for security:** an agent that does a first-pass security review of other agents.
- **Securing AI:** the controls that keep the reviewer within its authority, and the tests that show whether they hold.

Principles from the talk that shape every choice here: **no one size fits all** · balance productivity with security, aligned to business goals · **security by design** · **human oversight** · start small, mature over time · always have a **kill switch and rollback**.

**Data rule:** synthetic data only. The configurations the reviewer reads are invented examples of fictional agents — no employer, customer or real system configurations, ever. See [`data/samples/README.md`](data/samples/README.md).

## What the reviewer checks

This is what the reviewer looks for in *other* agents' configurations (v0 scope).

| Check | Example finding | Maps to |
|---|---|---|
| Excessive permissions / agency | A tool has write or delete access the agent's purpose doesn't need | ASI02, ASI03 · LLM06 |
| Risky tool combinations | Read access to sensitive data **plus** an outbound tool (email, HTTP) = a data-leakage path | ASI02 · LLM02 |
| Missing human approval | Tools with side effects run without an approval step | ASI09 · LLM06 |
| Tool poisoning | A tool description contains hidden instructions aimed at the model | ASI01, ASI04 · LLM01 |
| Unpinned tool definitions | Approved tool definitions aren't pinned, so they can change after review ("rug pull") | ASI04 |
| MCP authentication and token handling | A remote MCP server accepts unauthenticated calls, or forwards its access token to another API | ASI03 |
| Secrets in configuration | Credentials embedded in a manifest or system prompt | LLM02, LLM07 |
| Unvetted MCP servers | Servers from unknown sources or unpinned versions | ASI04 · LLM03 |
| Missing audit logging | No record of tool calls or decisions | ASI10 |

**Risk rating** uses the talk's method — task **autonomy** combined with **impact × likelihood** — which also sets the human-in-the-loop tier the reviewed agent should have.

**Design choice from the talk:** deterministic checks first (rules over the config that don't depend on a model), then reasoning-based review layered on top for what rules can't judge, such as whether a system prompt's stated purpose matches the tools granted.

## How the controls are organized

The controls follow the six functions of the **NIST Cybersecurity Framework 2.0** — Govern, Identify, Protect, Detect, Respond, Recover — the security lifecycle most security teams and reviewers already use. An **Assurance** section covers the testing that proves the controls work.

Each control shows:

- **ID** — a stable reference used in the threat model and test results (for example `PR-08`).
- **Talk** — where the control comes from: **T** = traditional control from the talk · **R** = reasoning-based control from the talk · **+** = added beyond the talk after review against current frameworks.
- **Mitigates** — the risks it addresses: **ASI** = OWASP Top 10 for Agentic Applications (2026) · **LLM** = OWASP Top 10 for LLM Applications (2025) · **AML.T** = MITRE ATLAS technique · **600-1** = NIST AI 600-1 risk.
- **AI RMF** — the NIST AI RMF function it supports: **GV** Govern · **MP** Map · **MS** Measure · **MG** Manage.
- **Milestone** — **In place**, **v0.1** (public, ~Nov 2026) or **v0.2**.

## Control set

### Govern (GV) — who owns the reviewer, what it's for, and how it changes

| ID | Control | How it applies to the reviewer | Talk | Mitigates | AI RMF | Milestone |
|---|---|---|---|---|---|---|
| GV-01 | System card | Named owner, intended use and users, known limitations, and uses that are out of scope | + | 600-1 Human-AI configuration | GV, MP | v0.1 |
| GV-02 | Data and usage policy | Synthetic data only; what may be submitted for review; no real secrets in samples | + | LLM02 | GV | In place |
| GV-03 | Risk register and risk acceptance | Each residual risk recorded with an owner, a rating and a documented accept / mitigate decision | + | All (residual) | GV, MG | v0.1 |
| GV-04 | Change management with an eval gate | Prompt, rule and model-version changes are reviewed, versioned, and must pass the assurance suite before release | R | ASI10 · LLM09 | GV, MG | v0.2 |

### Identify (ID) — what the reviewer is made of and what can go wrong

| ID | Control | How it applies to the reviewer | Talk | Mitigates | AI RMF | Milestone |
|---|---|---|---|---|---|---|
| ID-01 | AI bill of materials (AIBOM) | Inventory of model and pinned version, provider, prompts, MCP servers and dependencies | + | ASI04 · LLM03 | MP | v0.1 |
| ID-02 | Threat model of the agent loop | Assets and actions of the reviewer, modelled with CSA MAESTRO layers and mapped to the ASI risks | Step 2 | ASI01–ASI10 | MP | v0.1 |
| ID-03 | Risk assessment and HITL tiers | Autonomy × impact × likelihood scoring; the score sets how much human review a verdict needs | Step 3 | ASI09 · LLM06 | MP, MS | v0.1 |
| ID-04 | Model-provider data boundary | Documents exactly what leaves to the model provider (synthetic configs only), the provider's retention settings, and a short provider risk review | + | LLM02 · ASI04 · 600-1 Data privacy | GV, MP | v0.1 |

### Protect (PR) — preventive controls

| ID | Control | How it applies to the reviewer | Talk | Mitigates | AI RMF | Milestone |
|---|---|---|---|---|---|---|
| | **Identity and access** | | | | | |
| PR-01 | Non-human identity, least privilege | Reviewer runs as its own identity with a least-privilege IAM role | T | ASI03 | MG | v0.2 |
| PR-02 | Short-lived, scoped credentials | Credentials are task-scoped and expire; access reviewed periodically | + | ASI03 | MG | v0.2 |
| PR-03 | Authenticated sign-off | Only named, authenticated humans can approve a verdict | T | ASI03, ASI09 | MG | v0.2 |
| | **Tools and MCP** | | | | | |
| PR-04 | Least agency (sandboxing) | Read-only tools; the reviewer never executes, installs or connects to the systems it reviews | T | ASI02, ASI05 · LLM06 · AML.T0085.001 | MG | v0.1 |
| PR-05 | MCP server authentication | When served remotely: authenticate every call, check each token was issued for this server, never forward tokens to another API | + | ASI03 | MG | v0.2 |
| PR-06 | Tool-definition pinning | Approved tool definitions are hashed; any change blocks the tool until re-reviewed ("rug pull" defence) | + | ASI04 · ATLAS: Publish Poisoned AI Agent Tool | MG | v0.1 |
| PR-07 | Strict input validation | Submitted configs and tool parameters must match a strict schema; anything malformed is rejected | T | ASI02 · LLM05 | MG | v0.1 |
| | **Input and context** | | | | | |
| PR-08 | Untrusted-input isolation | Submitted configs are clearly separated as data and never treated as instructions | R | ASI01 · LLM01 · AML.T0051 | MG | v0.1 |
| PR-09 | Context hygiene | No persistent memory between reviews; content within a review is still treated as untrusted | R | ASI06 · AML.T0080 | MG | v0.1 |
| PR-10 | System prompt hygiene | No secrets or sensitive logic in prompts; prompts are written assuming they will be seen | + | LLM07 | MG | v0.1 |
| | **Output** | | | | | |
| PR-11 | Grounded findings | Every finding cites the config field it comes from; model findings are cross-checked against deterministic results | R | LLM09 · ASI01 · 600-1 Confabulation | MG, MS | v0.1 |
| PR-12 | Explainability | Each finding includes evidence and rationale; the report states what the reviewer could not assess | R | 600-1 Human-AI configuration | MG | v0.1 |
| PR-13 | Safe output handling | The report is sanitized before it's rendered or sent anywhere (links, images and HTML stripped or escaped) | + | LLM05 | MG | v0.1 |
| PR-14 | Secret redaction | Credentials found in a config never appear in the report or the logs | + | LLM02 | MG | v0.1 |
| | **Human oversight** | | | | | |
| PR-15 | Evidence-based tiered sign-off | Higher risk ratings need fuller review, and the approver sees the raw config fields behind each finding — not only the agent's summary | R | ASI09 · 600-1 Human-AI configuration | MG | v0.1 |
| | **Data** | | | | | |
| PR-16 | Data isolation | Each review runs alone; submitted configs aren't retained; logs keep field references and hashes, not full configs | T | LLM02 | MG | v0.1 |
| | **Platform** | | | | | |
| PR-17 | Network and API restriction | Only outbound connection is the model provider's API; the tool server has no network access; cloud egress rules enforce it | T | ASI02 · LLM02 | MG | v0.1 / v0.2 |
| PR-18 | Runtime hardening | Container runs as non-root, from a minimal image, with pinned dependencies | T | ASI05 | MG | v0.2 |
| PR-19 | Supply chain security | Pinned dependencies; CI dependency scanning; report-only scan with Visa's open-source VVAH; findings triaged | T | ASI04 · LLM03 | MG | v0.1 |
| PR-20 | Patch and config hygiene | Automated dependency updates; secure defaults (sign-off required, tools read-only) | T | LLM03 | MG | v0.1 |
| PR-21 | Classic AppSec | Static analysis (Bandit) in CI; secrets only from the environment or a secrets manager | T | LLM02 | MG | v0.1 |
| PR-22 | Cost and abuse limits | Caps on model calls, tokens and run time per review | + | LLM10 | MG | v0.1 |

### Detect (DE) — noticing when something is wrong

| ID | Control | How it applies to the reviewer | Talk | Mitigates | AI RMF | Milestone |
|---|---|---|---|---|---|---|
| DE-01 | Audit logging | Every model call, tool call, finding, what was shown to the approver, and each sign-off decision | T | ASI09, ASI10 | MS, MG | v0.2 |
| DE-02 | Tamper-evident logs | Logs are written to write-once storage so they can't be silently changed | + | ASI10 | MG | v0.2 |
| DE-03 | Behavioral monitoring and anomaly flags | Flags verdicts that diverge sharply from deterministic checks, unusual call patterns, and approvals made without any change (a rubber-stamp signal) | R | ASI09, ASI10 · AML.T0085.001 | MS | v0.2 |

### Respond (RS) — containing an incident

| ID | Control | How it applies to the reviewer | Talk | Mitigates | AI RMF | Milestone |
|---|---|---|---|---|---|---|
| RS-01 | AI incident response playbook | Triggers (for example a poisoned verdict, a leaked secret, runaway cost), triage, containment, communication and postmortem | + | ASI10 | MG | v0.2 |
| RS-02 | Kill switch | One switch disables model calls; the reviewer fails closed and issues no verdict | Summary | ASI10 · LLM10 | MG | v0.2 |
| RS-03 | Tabletop exercise | The playbook is exercised once against a realistic scenario, with written results | + | ASI10 | MG | v0.2 |

### Recover (RC) — getting back to a known-good state

| ID | Control | How it applies to the reviewer | Talk | Mitigates | AI RMF | Milestone |
|---|---|---|---|---|---|---|
| RC-01 | Rollback | Prompts, rules and model version are versioned, so the reviewer can return to the last known-good release | Summary | ASI10 · LLM09 | MG | v0.2 |
| RC-02 | Lessons learned | Postmortem findings feed back into the threat model and the assurance suite | Step 6 | All | GV, MG | v0.2 |

### Assurance (AS) — proving the controls work

| ID | Test | What it shows | Talk | Mitigates | AI RMF | Milestone |
|---|---|---|---|---|---|---|
| AS-01 | Tool-poisoning and indirect-injection suite | Hidden instructions in tool descriptions, prompts and manifests don't change the reviewer's verdict | R | ASI01, ASI04 · LLM01 · AML.T0051 | MS | v0.1 |
| AS-02 | Accuracy evals on seeded configs | Detection rate and false-positive rate on configs with known flaws, against pass thresholds | R | LLM09 · 600-1 Confabulation | MS | v0.1 |
| AS-03 | Leakage tests | No secrets or sensitive data appear in reports or logs | R | LLM02 | MS | v0.2 |
| AS-04 | Control verification | Each Protect control has at least one test showing it works (for example, a changed tool definition is blocked) | + | All | MS | v0.1 / v0.2 |

## Out of scope today

Named so the gaps are deliberate, not missed:

| Area | Why it's deferred | Maps to |
|---|---|---|
| Multi-agent trust frameworks | Single reviewer agent today | ASI07, ASI08 |
| Secure RAG and embedding protections | No retrieval in v0.x; applies if the reviewer later retrieves from a guidance corpus | LLM08 · ASI06 |
| Continuous learning security (training-time) | No model training or fine-tuning; change control (GV-04) covers prompt and rule changes instead | LLM04 |
| Full CSA AI Controls Matrix or ISO/IEC 42001 mapping | A later governance milestone | — |

## Crosswalks

### Talk roadmap → lifecycle

| Talk step | NIST CSF 2.0 | NIST AI RMF | In this lab |
|---|---|---|---|
| 1. Awareness, planning & visibility | Govern, Identify | Govern, Map | GV-01–GV-03, ID-01, ID-04 |
| 2. Threat modeling | Identify | Map | ID-02 |
| 3. Risk assessment | Identify | Map, Measure | ID-03 |
| 4. Mitigation | Protect | Manage | PR-01–PR-22 |
| 5. Monitoring & response | Detect, Respond, Recover | Measure, Manage | DE, RS and RC controls · AS-01–AS-04 |
| 6. Mature & scale | Govern | Govern, Manage | GV-04, RC-02 · out-of-scope items |

### Talk controls → this lab

| Traditional control (talk) | Lab ID | Reasoning-based control (talk) | Lab ID |
|---|---|---|---|
| Sandboxing & least privilege | PR-04 | Adversarial prompt defenses | PR-08, AS-01 |
| Network & API security | PR-17 | Reasoning / planning validation | PR-11 |
| Identity & access control | PR-01, PR-03 | Memory security | PR-09 |
| Data isolation | PR-16 | Behavioral monitoring & anomaly detection | DE-03 |
| Runtime hardening | PR-18 | Dynamic guardrails / HITL controls | PR-15, ID-03 |
| Logging, observability & forensics | DE-01 | Multi-agent trust frameworks | Out of scope today |
| Supply chain security | PR-19 | Explainability & transparency | PR-12 |
| Patch & config hygiene | PR-20 | Red teaming & stress testing | AS-01–AS-03 |
| Classic AppSec practices | PR-07, PR-21 | Continuous learning security | GV-04 |
| | | Secure RAG & embedding protections | Out of scope today |

## Roadmap

| Milestone | Scope |
|---|---|
| v0 | Repo skeleton · deterministic checks on one sample config · drafted review report |
| v0.1 (public) | Reasoning-based review · MCP tool server with pinned definitions · evidence-based tiered sign-off · input, context, prompt and output controls · system card, AIBOM, risk register, provider data boundary · threat model · CI and VVAH scanning · tool-poisoning tests and accuracy evals · NIST AI RMF mapping · architecture diagram |
| v0.2 | AWS deploy via Terraform with a least-privilege, short-lived identity · authenticated MCP and sign-off · hardened container · audit logging to tamper-evident storage · anomaly flags · incident response playbook and tabletop · kill switch and rollback · change management with an eval gate · leakage tests · test-results write-up |

## Frameworks referenced

- **NIST Cybersecurity Framework (CSF) 2.0** — lifecycle structure for the control set
- **NIST AI Risk Management Framework 1.0** and **NIST AI 600-1** (Generative AI Profile)
- **OWASP Top 10 for Agentic Applications (2026)** — ASI01–ASI10
- **OWASP Top 10 for LLM Applications (2025)** — LLM01–LLM10
- **OWASP MCP Security Cheat Sheet**
- **MITRE ATLAS** — adversary techniques against AI systems, including agent-specific techniques
- **CSA MAESTRO** — layered threat modeling for agentic AI (used in the threat model)

Mappings are at the level of risks and functions, not formal compliance claims. Framework IDs were checked against public sources in October 2026; check the current versions before relying on them.

## Repository layout

```
.
├── data/samples/          # synthetic agent configs only (see its README)
├── docs/                  # system card, threat model, governance mapping, playbook, write-ups
├── src/agent_reviewer/    # the review agent and its tools
└── tests/                 # unit, tool-poisoning, accuracy and leakage tests
```

## Security

See [`SECURITY.md`](SECURITY.md).

## License

To be added.
