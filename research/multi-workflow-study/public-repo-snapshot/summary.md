# Public multi-workflow snapshot

Collected on 2026-08-03 from [`dvasquez08/n8n-workflows`](https://github.com/dvasquez08/n8n-workflows) at commit `dff5ff6075c50a8fc1500218887b147ec05300f2`.

The scanner parsed all JSON workflow exports in the pinned public repository. It did not import, activate or execute a workflow. Raw third-party exports are not stored here.

## Measured result

| Static signal | Count |
| --- | ---: |
| Workflow exports | 24 |
| Nodes | 297 |
| Sub-workflow calls | 8 |
| Resolved calls | 5 |
| Unresolved or ambiguous calls | 3 |
| Unique credential aliases | 43 |
| Credential reuse review signals | 10 |
| Cross-workflow high-severity review paths | 2 |

The two high-severity items are static review paths, not claims that the source workflows are exploitable. Both follow an exported route from a public trigger or model through a resolved sub-workflow call to a credentialed action without a visible explicit approval boundary.

Credential names and IDs are not published. Stable report-local aliases such as `credential-15` allow reviewers to correlate reuse without disclosing the exported references.

Reproduce the scan without importing the workflows:

```bash
git clone https://github.com/dvasquez08/n8n-workflows.git
git -C n8n-workflows checkout dff5ff6075c50a8fc1500218887b147ec05300f2
node bin/map.mjs ../n8n-workflows --name "Public n8n workflow repository snapshot" --out reports/public-multi-workflow-snapshot
```

See the [source manifest](source-manifest.json) and the generated [JSON report](../../../reports/public-multi-workflow-snapshot.json).
