# n8n AI Agent Security Lab

[![test](https://github.com/0xCD4/n8n-ai-agent-security-lab/actions/workflows/test.yml/badge.svg)](https://github.com/0xCD4/n8n-ai-agent-security-lab/actions/workflows/test.yml)

This defensive lab compares two small n8n AI support workflows:

- `unsafe-support-agent.json` exposes common security and reliability mistakes.
- `hardened-support-agent.json` adds authentication, input checks, an approval gate, bounded outbound calls, output validation, logging and an error route.

The repository also contains a local static scanner. It does not upload the workflow or call an AI API.

![Unsafe and hardened workflow comparison](assets/unsafe-vs-hardened.png)

## Results

| Workflow | Score | Findings |
| --- | ---: | --- |
| Unsafe support agent | 10/100, F | 9 findings, including 4 high severity |
| Hardened support agent | 93/100, A | 1 medium finding kept for manual URL review |

The remaining finding is intentional. A URL can be derived from workflow data after validation, so the scanner keeps it visible for manual review. A high score is not proof of runtime security.

## Run the lab

Requirements: Node.js 20 or newer. No package installation is needed.

```bash
npm test
npm run audit
```

Run the scanner against your own exported workflow:

```bash
node bin/audit.mjs path/to/workflow.json reports/my-audit.md
```

Remove production data and credentials before storing or sharing an export.

## What changes between the examples

1. The webhook requires native authentication.
2. Untrusted input is length-checked and normalized before model use.
3. Outbound destinations are restricted to HTTPS and an explicit host allowlist.
4. Model output is parsed and checked against a small schema.
5. A person approves the recipient, message and destination before external actions.
6. HTTP requests use a timeout, bounded retry and disabled redirects.
7. External actions create an audit record.
8. A workflow-level error route is configured.

The input guard includes a visible rate and budget boundary, but a real deployment still needs a shared gateway or datastore-backed rate limiter.

## Video

[Watch the 27-second unsafe workflow scan](assets/unsafe-support-agent-demo-en.mp4)

## Contribute

Open an issue if you have:

- a false positive with a redacted sample
- a common unsafe workflow pattern that deserves a rule
- an improvement to the hardened example
- a request for another n8n security lab

Do not post client workflows, personal data, credentials or private URLs.

## Need a manual review?

The free scanner handles repeatable static checks. A manual review follows the important paths, checks assumptions the export cannot prove, and returns a prioritized remediation plan.

[Read the EUR 99 pilot review scope](SERVICE.md) or visit [CSINT AI Agent Audit](https://en.csintresearch.org/ai-agent-audit).

## Safety boundary

This project is defensive and educational. The unsafe workflow must remain inactive and must never receive credentials. The scanner is not a penetration test, compliance certification or security guarantee.

## License

MIT. See [LICENSE](LICENSE).
