# Synthetic data

Everything in this folder is invented. Nothing here comes from an employer, a customer or a real person.

## Rules for every synthetic alert

- **Mark it.** Each record carries `"synthetic": true`.
- **Invented people and places.** Made-up names; email addresses only on reserved test domains (`example.com`, `example.org`, `example.net`).
- **No real identifiers.** No real card numbers, account numbers, government IDs or phone numbers. Where a detection needs a pattern, use an obviously fake value and label it as fake.
- **Generic tools.** Describe sources generically (for example `"source": "dlp-endpoint"`) rather than naming a real product deployment or internal system.
- **Adversarial content is labelled.** Alerts used for injection tests set `"test_case": "injection"` so they are never mistaken for normal data.
