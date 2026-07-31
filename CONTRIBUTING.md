# Contributing

Contributions should improve defensive analysis, explainability or the safety of the example workflows.

## Good contributions

- a redacted workflow pattern that produces a false positive
- a small rule with a clear unsafe path and recommendation
- a safer version of an existing example
- a test that demonstrates expected behavior
- a redacted staging contract that covers a common runtime regression

## Before opening a pull request

1. Remove credentials, personal data and private URLs.
2. Keep new rules deterministic and explainable.
3. Add or update a test.
4. Run `npm test`, `npm run audit` and `npm run gate:demo`.
5. If the change touches the importable n8n fixture, run `npm run verify:n8n`.
6. Explain the limitation of the rule.

Do not submit offensive automation, credential theft, persistence or unauthorized access instructions.
