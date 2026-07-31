# AI Agent Security and Reliability Audit

Workflow: Demo - Hardened Support Agent
Source: workflows\hardened-support-agent.json
Score: 93/100 (A)

## Executive summary

The static review found 1 item(s): 0 critical, 0 high, 1 medium and 0 low.

## Workflow inventory

- Nodes: 8 active, 8 total
- External inputs: Authenticated Support Webhook
- Model nodes: Customer Support Agent
- Write-capable nodes: Send Approved Account Email, Fetch Allowlisted Customer URL, Audit Log

## Findings

### AA-007 | MEDIUM | Review HTTP request URLs derived from workflow data

Evidence: Dynamic URL nodes behind a visible validation boundary: Fetch Allowlisted Customer URL.

Recommended action: Parse URLs with a real URL parser, allowlist schemes and destinations, block private and metadata IP ranges, and disable redirects unless required.

Reference: OWASP LLM06: Excessive Agency and SSRF boundary

## Review limits

- Static analysis cannot prove runtime authorization, credential scopes, upstream controls or model behavior.
- A clean report is not a penetration-test result or a guarantee of security.
- Review production logs, permissions, model prompts and failure handling before release.

## Reference baseline

- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- OWASP Excessive Agency guidance: https://owasp.org/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM06_ExcessiveAgency.html
- NIST AI RMF Generative AI Profile: https://doi.org/10.6028/NIST.AI.600-1
