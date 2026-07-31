# Security contract guide

The security regression contract records the behavior an n8n staging workflow must preserve. It is a small JSON file that can be reviewed beside the workflow export.

## What the gate checks

The gate always runs the static graph audit first. It then executes the ordered tests in `tests`.

Each test contains:

- a GET or POST request
- accepted response status codes
- optional duration and header checks
- required, forbidden and exact JSON Pointer checks
- an optional observation request for a separate canary or state endpoint

The included contract uses an observation endpoint to prove that no simulated external action occurs before approval. In a real staging environment, use a same-origin staging webhook that reads a canary sink containing no production data.

## Target restrictions

Loopback targets work without extra flags. A remote target requires all three controls:

1. pass `--allow-remote`
2. add the exact DNS hostname to `target.allowedHosts`
3. allow each staging path prefix in `target.allowedPathPrefixes`

The local Node demo contract permits only `/webhook-test/`. The importable n8n fixture uses the narrower `/webhook/security-regression-support-agent` prefix. A production hostname must never be allowlisted.

Raw remote IP addresses, URL credentials, cross-origin request paths and redirects are rejected.

The gate does not register, publish or modify a remote n8n workflow. The staging workflow must already be published before a remote contract runs.

## Importable n8n fixture

`workflows/security-regression-staging-target.json` is a credential-free, action-free target for the included `contracts/n8n-staging.contract.json`.

With Docker Desktop running, verify the complete import and runtime path:

```bash
npm run verify:n8n
```

The command creates a temporary n8n 2.21.5 instance, imports and publishes the fixture, runs all eight tests, then removes the temporary container and volume. It never opens an existing n8n data directory.

The fixture reads two test-only environment variables:

- `N8N_STAGING_SIGNATURE`
- `N8N_STAGING_APPROVAL_TOKEN`

Do not reuse either value in another environment. The approval route only changes a local counter and never calls an external service.

## Keep secrets outside the contract

Header and JSON values support environment variable substitution:

```json
{
  "headers": {
    "x-staging-signature": "${N8N_STAGING_SIGNATURE}"
  }
}
```

Set the value in the shell or CI secret store. Do not commit it:

```bash
export N8N_STAGING_SIGNATURE="replace-with-a-test-only-value"
```

PowerShell:

```powershell
$env:N8N_STAGING_SIGNATURE = "replace-with-a-test-only-value"
```

The gate result stores the request method and path only. It does not store request headers or bodies.

## Gate decision

`gate.failOnStaticSeverity` controls which static findings block the run:

```json
{
  "gate": {
    "failOnStaticSeverity": "high",
    "requireRuntime": true
  }
}
```

With `high`, critical and high findings block the gate. Medium and low findings remain visible for review. Any failed runtime test blocks the gate.

The process exits with:

- `0` when the gate passes
- `1` when a security expectation fails
- `2` for invalid configuration or an execution error

## Report formats

```bash
node bin/gate.mjs \
  --workflow workflow.json \
  --contract security-contract.json \
  --target http://127.0.0.1:47111 \
  --format markdown \
  --out reports/gate.md
```

Supported formats:

- `markdown` for reviewers
- `json` for automation
- `junit` for CI test results
- `sarif` for code scanning systems

## Safe test design

- Use synthetic email addresses, messages and identifiers.
- Use a dedicated staging instance and test credentials.
- Replace email, ticket, storage and payment actions with canary sinks.
- Test approval failure before testing a successful action.
- Keep the request count small and deterministic.
- Never use the gate to discover or probe systems you do not own.
