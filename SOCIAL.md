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

## Telegram

Unsafe and hardened n8n AI workflows are now available in one defensive lab.

The unsafe support agent scores 10/100. The hardened version adds authenticated input, validation, human approval, bounded outbound calls, logging and an error route. It scores 93/100 and keeps one dynamic URL path open for manual review.

Repository:
https://github.com/0xCD4/n8n-ai-agent-security-lab

Manual review:
https://en.csintresearch.org/ai-agent-audit

## Reply when someone asks for a review

Yes. The free scanner is useful for repeatable static checks. For a real workflow I also trace the five highest-risk paths manually, check permissions and approval boundaries, and retest the fixes. The pilot scope is EUR 99 for one workflow with up to 40 active nodes:
https://en.csintresearch.org/ai-agent-audit
