# n8n AI Agent Security Lab - Community Announcement

## What is it?

A lightweight, dependency-free security scanner for n8n AI workflows. It catches common risks before they reach production:

- Hardcoded API keys and secrets
- Unauthenticated webhooks
- AI agents with no validation or approval boundaries
- Missing audit logs and error handling
- Credential reuse across trust boundaries

## 60-second quick start

```bash
git clone https://github.com/0xCD4/n8n-ai-agent-security-lab.git
cd n8n-ai-agent-security-lab
node bin/audit.mjs workflows/demo-handoff.json
```

No npm install required. The demo workflow intentionally contains security issues to demonstrate the scanner.

## What makes it different?

1. **Local-only**: Workflow exports never leave your machine. No AI API calls, no uploads.
2. **No dependencies**: Pure Node.js 20+. Works in CI without package installation.
3. **Explainable**: Every finding shows the exact path, severity, recommendation, and OWASP reference.
4. **GitHub Action**: Add automated PR reviews with zero credentials or external services.

## Use cases

- **Pre-production review**: Scan workflow exports before deploying AI agents
- **Pull request gate**: Automatically review workflow changes in CI
- **Multi-workflow mapping**: Find cross-workflow paths from untrusted input to privileged actions
- **Learning**: Use the intentionally unsafe teaching fixtures to understand AI workflow security patterns

## Example findings

The scanner checks for:

- **AA-001**: Embedded credentials (CRITICAL)
- **AA-002**: Unauthenticated webhook triggers (MEDIUM)
- **AA-003**: Untrusted input reaching AI models without validation (MEDIUM)
- **AA-006**: No rate or cost boundaries before model usage (HIGH)
- **AA-009**: External actions with no audit trail (MEDIUM)

Plus 15+ other checks based on OWASP Top 10 for LLM Applications and NIST AI RMF.

## Roadmap

Current focus:
- Issue #2: Detect webhook nodes missing n8n header authentication
- Issue #3: Flag AI Agent HTTP tools with over-broad URL allowlists
- Issue #4: Create a 20-second terminal demo GIF

All issues labeled `good first issue` welcome contributions.

## Contributing

The project follows a clear contribution model:

- Add a rule = Add one function to `src/rules.mjs`
- Each rule is deterministic, modular, and testable
- See `CONTRIBUTING.md` for the exact pattern

## Links

- Repository: https://github.com/0xCD4/n8n-ai-agent-security-lab
- License: MIT
- Maintained by: CSINT Research (https://en.csintresearch.org/)

## Safety note

This is a defensive tool. The included unsafe workflows are teaching fixtures only — never activate them with real credentials or production data.

---

*This announcement is ready for the n8n community forum. Do not post without explicit approval.*
