# Security Policy

## Reporting a problem

Do not open a public issue for a vulnerability that could expose a real system, credential or client workflow.

Use GitHub private vulnerability reporting for repository security problems. For service-related concerns, use the contact method on csintresearch.org.

Include only the minimum evidence needed to reproduce the problem. Remove credentials, personal data and private infrastructure details.

## Scope

This repository contains defensive examples, a heuristic static scanner and a staging-only regression gate. Do not connect the unsafe example to a live webhook, credential or production system.

The runtime gate is restricted by default:

- only loopback targets work without explicit remote approval
- remote hosts must exactly match the contract allowlist
- remote paths must match an explicit contract allowlist
- redirects are not followed
- reports omit request bodies and authentication values

Use only systems you own or are explicitly authorized to test. Use redacted fixtures and isolated test credentials. Do not point the gate at production.

The importable staging target contains only Webhook, Code and Respond to Webhook nodes. It has no email, database, AI or outbound HTTP action. `npm run verify:n8n` creates a temporary Docker volume and removes it after the check.
