# Share Kit

## X

I built the same n8n AI support workflow twice.

The unsafe version scored 10/100. The hardened version scored 93/100 and still keeps one dynamic URL path visible for manual review.

Both workflows and the local scanner are open:
https://github.com/0xCD4/n8n-ai-agent-security-lab

## Reddit follow-up

I rebuilt the intentionally unsafe n8n support agent with the controls the first scan was missing.

The original scored 10/100 with nine findings. The hardened version scores 93/100. I did not force it to 100. It still derives an outbound URL from workflow data, so the scanner keeps that path visible for manual review even though the workflow validates the scheme and host first.

The repository contains both workflows, both reports, the scanner and a manual review checklist:
https://github.com/0xCD4/n8n-ai-agent-security-lab

I would be interested in redacted examples of false positives or common agent workflow patterns that deserve another rule.

## Reddit - candidate-linked staging receipt

**Title:** I added a local receipt that links n8n staging checks to a candidate workflow export

I kept running into a small release-control gap with n8n. A staging check can pass, but the execution log alone does not tell me which local export was reviewed with it.

The local runner now fingerprints the candidate export and security contract, sends synthetic requests only to loopback or an explicitly allowlisted staging host, records the checks, and includes a named zero-action canary. Change Review uses the runtime evidence only when the receipt fingerprint matches the candidate selected in the browser.

The included action-free fixture passed 8 scenarios and 56 assertions with 0 simulated external actions. It contains no email, database, AI or outbound HTTP action nodes.

Important boundary: the generic runner does not independently read the workflow deployed on a remote n8n instance. The operator must confirm that staging is running the supplied candidate. The receipt records that association; it is not a third-party attestation, penetration test or safety certificate.

Code, workflow and contract:
https://github.com/0xCD4/n8n-ai-agent-security-lab/tree/main

How do you currently link staging evidence to the workflow version being released?

## Telegram

Unsafe and hardened n8n AI workflows are now available in one defensive lab.

The unsafe support agent scores 10/100. The hardened version adds authenticated input, validation, human approval, bounded outbound calls, logging and an error route. It scores 93/100 and keeps one dynamic URL path open for manual review.

Repository:
https://github.com/0xCD4/n8n-ai-agent-security-lab

Self-service change review:
https://en.csintresearch.org/ai-security#change-review

## Reply when someone asks for a review

The change review is self-service. Choose the current export and the candidate in your browser, then download the record yourself. Both files and the report stay on your device. If you need runtime evidence, the local runner creates a receipt carrying the candidate fingerprint. You still need to confirm that staging is running that export:
https://en.csintresearch.org/ai-security#change-review
