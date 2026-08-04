# Self-service n8n Workflow Change Review

Compare the workflow running today with the version you plan to release. The workspace produces a client-ready change record: what changed, which security boundaries improved or weakened, what was tested, and what still needs a person to verify.

Access is activated through a CSINT account and Stripe checkout. After payment, the tools open inside the AI Security workspace.

## Included

- baseline and candidate workflow comparison
- local security comparison with SHA-256 fingerprints for both files
- changed-node, connection, domain, credential and policy findings
- a client-ready JSON, Markdown or print/PDF report
- repeatable reviews after each workflow change
- an optional local staging receipt carrying the candidate fingerprint

## What I review

- new, removed or reconfigured nodes and connections
- webhook authentication and untrusted input boundaries
- input-to-model and model-to-action paths
- structured output, prompt boundaries and human approval points
- new outbound destinations, credential types and tool permissions
- runtime evidence, when its recorded fingerprint matches the candidate selected for review
- open limits such as production permissions, dynamic targets and error handling

## Local staging evidence

The local runner can execute a narrow security contract against an n8n staging instance you control. It creates a receipt containing fingerprints, check outcomes, the staging scope and a named zero-action proof. Use an isolated fixture without production credentials or real external actions.

The generic runner does not read the deployed workflow back from n8n. The operator must confirm that staging is running the candidate export supplied to the CLI. The receipt records that association but is not an independent deployment attestation.

```bash
node bin/gate.mjs \
  --workflow candidate.json \
  --contract security-contract.json \
  --target http://127.0.0.1:5678 \
  --format receipt \
  --out runtime-receipt.json
```

## Data boundary

Workflow files, contracts and generated reports remain on your device. CSINT does not receive or store them. The hosted backend handles account access and billing state only. Never put passwords, API keys, OAuth tokens, cookies, customer records or production credentials in a test fixture.

## Boundary

This is a defensive change and configuration review. A passing staging contract proves only the recorded checks and the candidate fingerprint supplied by the operator. The local receipt is not a signed third-party attestation, penetration test, compliance certification or security guarantee. Production systems must not be attacked or changed.

[Open the service page](https://en.csintresearch.org/ai-security#change-review)
