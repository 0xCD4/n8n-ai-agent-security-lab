# GitHub Actions integration

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
