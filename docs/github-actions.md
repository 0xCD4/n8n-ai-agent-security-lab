# GitHub Actions integration

## Local, credential-free pull-request review

`action.yml` packages the static multi-workflow mapper as a reusable composite action. It reads exported n8n workflow JSON as untrusted data and produces:

- a compact GitHub step summary;
- JSON and Markdown review records;
- SARIF for code scanning;
- Mermaid, SVG, and JSON exposure graphs; and
- explicit `pass` or `review` outputs.

The decision is a review aid. It is not a release approval. The action never imports or executes a workflow, starts n8n, calls an AI model, reads production settings, or sends the workflow to CSINT.

```yaml
name: ReleaseGuard pull-request review

on:
  pull_request:
    paths:
      - "workflows/**/*.json"

permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1

      - id: releaseguard
        uses: 0xCD4/n8n-ai-agent-security-lab@v1
        with:
          path: workflows
          output-prefix: reports/releaseguard-pr
          name: Pull request workflow set
          fail-on: high

      - name: Upload the evidence pack
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: releaseguard-pr-evidence
          path: reports/releaseguard-pr*
```

GitHub tags are convenient but mutable. Pin ReleaseGuard itself to a reviewed full commit SHA in a hardened workflow. Keep `permissions` read-only unless a separate, narrowly scoped SARIF upload job needs `security-events: write`.

Run the same path locally before committing:

```bash
node bin/pr-gate.mjs workflows \
  --out reports/releaseguard-pr \
  --name "Local workflow set" \
  --fail-on never
```

`fail-on: high` exits with code 3 after writing every evidence file when a high-severity path is present. `fail-on: never` records the same result without failing the job. Unknown, malformed, oversized, symbolic-link, or structurally excessive input still fails closed.

## Optional staging contract

The gate can publish JUnit or SARIF output in CI. The repository test workflow uses the local action-free demo, so pull requests do not need an n8n credential or remote endpoint.

A real remote run needs a dedicated n8n staging instance whose workflow is already published.

Store the staging signature as a GitHub Actions secret and the base URL as a repository variable.

First copy `contracts/n8n-staging.contract.json` to a CI-specific file. Replace `target.allowedHosts` with the exact staging hostname. Keep `target.allowedPathPrefixes` limited to the one staging workflow prefix you intend to test.

```yaml
name: n8n security regression

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  regression:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run staging security contract
        env:
          N8N_STAGING_SIGNATURE: ${{ secrets.N8N_STAGING_SIGNATURE }}
        run: |
          node bin/gate.mjs \
            --workflow workflows/hardened-support-agent.json \
            --contract contracts/ci-security-contract.json \
            --target "${{ vars.N8N_STAGING_BASE_URL }}" \
            --allow-remote \
            --format sarif \
            --out reports/runtime-gate.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/runtime-gate.sarif
```

Do not use production credentials or a production webhook URL. Keep the staging hostname exact in `target.allowedHosts`.
