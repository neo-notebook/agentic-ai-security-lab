# Sample agent configurations

Everything in this folder is invented: configurations for fictional agents (for example an "expense-helper" or an "hr-faq-bot") that the reviewer reads. None of it describes a real employer's, customer's or vendor's system.

## Rules for every sample

- **Mark it.** Each sample carries `"synthetic": true`.
- **Fictional agents and owners.** Made-up names; email addresses and URLs only on reserved test domains (`example.com`, `example.org`, `example.net`).
- **Obviously fake secrets.** Where a sample needs an embedded credential to test detection, use a value like `FAKE-KEY-DO-NOT-USE` — never a real or realistic-looking key.
- **Generic tools.** Describe tools generically (for example `send_email`, `read_hr_records`) rather than copying a real product's tool definitions.
- **Label the purpose.** Seeded flaws set `"seeded_flaws": [...]` so accuracy evals know the expected findings. Adversarial samples set `"test_case": "tool_poisoning"` so they are never mistaken for normal input.
