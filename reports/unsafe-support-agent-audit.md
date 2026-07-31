# AI Agent Security and Reliability Audit

Workflow: Demo - Unsafe Support Agent
Source: workflows/unsafe-support-agent.json
Score: 10/100 (F)

## Executive summary

The static review found 9 item(s): 0 critical, 4 high, 4 medium and 1 low.

## Workflow inventory

- Nodes: 4 active, 4 total
- External inputs: Public Support Webhook
- Model nodes: Customer Support Agent
- Write-capable nodes: Send Account Email, Fetch Customer URL

## Exposure graph

![Risky workflow paths](unsafe-support-agent-exposure.svg)

Only structured risky paths found by the static scanner are shown. Manual review remains required.

## Findings

### AA-003 | HIGH | Untrusted input can reach a model without a visible validation boundary

Evidence: Path: Public Support Webhook -> Customer Support Agent.

Recommended action: Add a deterministic validation step before the model. Enforce size, type and allowlist rules, separate instructions from data, and test direct and indirect prompt injection cases.

Reference: OWASP LLM01: Prompt Injection

### AA-004 | HIGH | A model can reach an external write action without an approval step

Evidence: Path: Customer Support Agent -> Send Account Email.

Recommended action: Require explicit human approval for messages, writes, deletions, purchases, account changes and other high-impact actions. Use least-privilege credentials for the final action.

Reference: OWASP LLM06: Excessive Agency

### AA-006 | HIGH | No rate or cost boundary was detected before model usage

Evidence: External inputs: Public Support Webhook.

Recommended action: Add per-user and per-origin limits, a maximum input size, a model-call budget, timeouts, and a bounded retry policy.

Reference: OWASP LLM10: Unbounded Consumption

### AA-007 | HIGH | Review HTTP request URLs derived from workflow data

Evidence: Unvalidated path: Public Support Webhook -> Customer Support Agent -> Send Account Email -> Fetch Customer URL.

Recommended action: Parse URLs with a real URL parser, allowlist schemes and destinations, block private and metadata IP ranges, and disable redirects unless required.

Reference: OWASP LLM06: Excessive Agency and SSRF boundary

### AA-002 | MEDIUM | Public webhook authentication is not enforced by the trigger

Evidence: Webhook nodes without native authentication: Public Support Webhook.

Recommended action: Use header, JWT, or basic authentication at the webhook boundary. If custom validation is retained, reject before processing and rate-limit failures.

Reference: OWASP LLM07: System Prompt Leakage and access control

### AA-005 | MEDIUM | No structured model-output validation was detected

Evidence: Model-related nodes: Customer Support Agent.

Recommended action: Validate model output against a strict schema before it is parsed, stored or passed to another tool. Reject unknown fields and unsafe values.

Reference: OWASP LLM05: Improper Output Handling

### AA-008 | MEDIUM | Outbound requests do not show an explicit timeout or retry policy

Evidence: HTTP nodes: Fetch Customer URL.

Recommended action: Set short timeouts and bounded retries with backoff. Make write actions idempotent so a retry cannot publish or charge twice.

Reference: NIST AI RMF: Measure and Manage

### AA-009 | MEDIUM | External actions have no visible audit record

Evidence: Write-capable nodes: Send Account Email, Fetch Customer URL.

Recommended action: Record actor, request ID, approved action, destination, result, time and error without storing secrets or unnecessary personal data.

Reference: NIST AI RMF: Govern and Manage

### AA-010 | LOW | No workflow-level failure route was detected

Evidence: The export has no errorWorkflow setting or explicit error node.

Recommended action: Add a failure route that records the error, alerts the operator and prevents partial actions from being treated as success.

Reference: NIST AI RMF: Manage

## Review limits

- Static analysis cannot prove runtime authorization, credential scopes, upstream controls or model behavior.
- A clean report is not a penetration-test result or a guarantee of security.
- Review production logs, permissions, model prompts and failure handling before release.

## Reference baseline

- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- OWASP Excessive Agency guidance: https://owasp.org/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM06_ExcessiveAgency.html
- NIST AI RMF Generative AI Profile: https://doi.org/10.6028/NIST.AI.600-1
