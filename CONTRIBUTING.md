# Contributing

Contributions should improve defensive analysis, explainability or the safety of the example workflows.

## Quick start: add a new security rule

All security checks live in `src/rules.mjs`. To add a new rule:

1. Add a detection function that returns `true` when the issue is present
2. Add a finding entry in the `auditN8nWorkflow` function with your unique ID, severity, title, evidence, recommendation, and reference
3. Add a test case in `test/audit.test.mjs` with a minimal workflow that triggers the rule

Each rule is a pure function. Keep it modular, deterministic, and explainable.

## Good contributions

- a redacted workflow pattern that produces a false positive
- a small rule with a clear unsafe path and recommendation
- a safer version of an existing example
- a test that demonstrates expected behavior
- a redacted staging contract that covers a common runtime regression
- a clearer book explanation, missing evidence boundary or small reproducible diagram correction
- a GitHub PR Gate usability or portability improvement that keeps the action credential-free and non-executing

Book corrections can start with the `Book correction` issue form. Name the page or chapter, explain the reader problem, and provide concise replacement text. Use a primary public source when the correction depends on a technical fact.

## Before opening a pull request

1. Remove credentials, personal data and private URLs.
2. Keep new rules deterministic and explainable.
3. Add or update a test.
4. Run `npm test`, `npm run audit`, `npm run gate:demo` and `npm run pr-gate:demo`.
5. If the change touches the importable n8n fixture, run `npm run verify:n8n`.
6. Explain the limitation of the rule.

Parser and loader changes must include synthetic boundary tests. Do not commit a real customer export, credential, token, private URL or production payload as a fixture.

Do not submit offensive automation, credential theft, persistence or unauthorized access instructions.
