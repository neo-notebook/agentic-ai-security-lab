# Security policy

## Scope

This is a research and learning lab, not production software. It is intentionally used to test attacks against an AI agent (for example, prompt injection), so some test files contain adversarial text by design.

## Rules for this repository

- **Synthetic data only.** No employer, customer or real personal data in code, tests, issues or commits.
- **No secrets in the repo.** API keys and credentials come from environment variables or a secrets manager. `.env` files are git-ignored; commit only `.env.example` with placeholder names, never values.
- **Least privilege by default.** New tools start read-only. Any tool with side effects must sit behind the human approval gate.
- **Dependencies are scanned in CI** (planned for v0.1).

## Reporting a vulnerability

If you find a security issue in this lab, please report it privately through GitHub's **"Report a vulnerability"** option on this repository's Security tab rather than opening a public issue.
