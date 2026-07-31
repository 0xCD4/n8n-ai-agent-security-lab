# n8n AI Security Regression Gate

[![test](https://github.com/0xCD4/n8n-ai-agent-security-lab/actions/workflows/test.yml/badge.svg)](https://github.com/0xCD4/n8n-ai-agent-security-lab/actions/workflows/test.yml)
[![license](https://img.shields.io/badge/license-MIT-1f2933.svg)](LICENSE)

A [CSINT Research](https://en.csintresearch.org/) side project that catches security regressions in n8n AI workflows before production.

It provides three small, explainable outputs:

- **Static audit:** follows paths through an exported workflow and reports risky security patterns.
- **Regression gate:** sends synthetic requests to an isolated staging webhook and checks the behavior that must not change.
- **Exposure graph:** turns structured risky paths into JSON, Mermaid and a print-ready SVG report figure.

Workflow exports stay local. The scanner does not upload them or call an AI API.

![Unsafe and hardened workflow comparison](assets/unsafe-vs-hardened.png)

## Exposure graph

Generate a static graph beside the audit report:

```bash
node bin/audit.mjs \
  workflows/unsafe-support-agent.json \
  reports/unsafe-support-agent-audit.md \
  --graph reports/unsafe-support-agent-exposure
```

The command writes `.json`, `.mmd` and `.svg` files. The JSON keeps scanner finding IDs so the same paths can be correlated with SARIF results. The graph contains only structured risky paths, not every workflow node.

The SVG is a self-contained report figure: one merged data flow from the entry point to the final privileged action, finding IDs on each risky edge, and a findings ledger that maps every ID and severity back to the exact path the scanner proved. It uses system fonts only and stays readable on screens, in PDF exports and in printed reports.

![Unsafe support agent exposure graph](reports/unsafe-support-agent-exposure.svg)

## Start in one minute

Requirements: Node.js 20 or newer.

```bash
npm test
npm run audit
npm run gate:demo
```

No npm package installation is required.

## Verify the real n8n fixture

The repository includes an importable staging workflow and a matching runtime contract. With Docker Desktop running:

```bash
npm run verify:n8n
```

This command:

1. creates a temporary n8n 2.21.5 instance
2. imports and publishes the staging workflow
3. runs all eight contract tests
4. confirms that no simulated external action ran
5. removes the temporary container and volume

It does not use an existing n8n instance, volume or credential.

## Current result

| Workflow | Static result | Main finding |
| --- | ---: | --- |
| Unsafe support agent | 10/100, F | 9 findings, including 4 high severity |
| Hardened support agent | 93/100, A | 1 medium item kept for manual URL review |
| Runtime staging fixture | 8/8 passed | 0 simulated external actions |

The score is a review aid, not proof that a workflow is secure.

## What the gate checks

| Check | Expected staging behavior |
| --- | --- |
| Missing authentication | Reject |
| Invalid staging signature | Reject |
| Missing or unexpected fields | Reject |
| Prompt injection marker | Keep behind approval |
| Invalid approval token | Reject |
| Valid request | Queue without external action |
| Repeated request ID | Return the same operation |
| Unsupported method | Reject |

The included runtime fixture contains no email, HTTP request, database or AI nodes. A valid approval only increments an isolated test counter.

## Scan your own export

```bash
node bin/audit.mjs path/to/workflow.json reports/my-audit.md
```

Remove credentials, customer data, private URLs and production payloads before storing or sharing an export.

## Run a staging contract

```bash
export N8N_STAGING_SIGNATURE="replace-with-a-test-only-value"

node bin/gate.mjs \
  --workflow path/to/workflow.json \
  --contract path/to/security-contract.json \
  --target http://127.0.0.1:5678 \
  --out reports/runtime-gate.md
```

PowerShell:

```powershell
$env:N8N_STAGING_SIGNATURE = "replace-with-a-test-only-value"
```

Loopback targets are allowed by default. Remote targets require `--allow-remote`, an exact hostname allowlist and a narrow path allowlist. Redirects are not followed. Reports omit request headers and bodies.

Read the [security contract guide](docs/security-contract.md) before adapting the fixture.

## Output formats

The regression gate can write:

- Markdown for human review
- JSON for automation
- JUnit for test pipelines
- SARIF for code scanning

See [GitHub Actions integration](docs/github-actions.md).

## Repository map

| Path | Purpose |
| --- | --- |
| `bin/` | Static audit and regression gate commands |
| `contracts/` | Runtime behavior contracts |
| `src/` | Scanner, target policy and report generation |
| `test/` | Deterministic unit and contract tests |
| `workflows/unsafe-support-agent.json` | Intentionally unsafe teaching fixture |
| `workflows/hardened-support-agent.json` | Hardened comparison fixture |
| `workflows/security-regression-staging-target.json` | Importable, action-free n8n staging target |
| `reports/` | Example audit and gate output |

## Safety boundary

This project is defensive and educational.

- Never activate the unsafe workflow.
- Never attach production credentials to a test fixture.
- Run dynamic checks only against an isolated system you own or are authorized to test.
- Do not treat a passing report as a penetration test, compliance result or security guarantee.

Read [SECURITY.md](SECURITY.md) before reporting a sensitive issue.

## Contributing

Redacted false positives, small deterministic rules and safe runtime checks are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

## CSINT Research

Built and maintained by Ahmet Göker as a CSINT Research side project.

- [CSINT Research](https://en.csintresearch.org/)
- [AI agent workflow review](https://en.csintresearch.org/ai-agent-audit)
- [Manual review scope](SERVICE.md)

## License

MIT. See [LICENSE](LICENSE).
