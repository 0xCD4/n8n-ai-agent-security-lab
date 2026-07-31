# Manual validation summary for the feasibility sample

Reviewed: 2026-07-31

All 15 path-level findings from the initial 20-template feasibility run were reviewed against the public workflow exports.

| Classification | Findings |
| --- | ---: |
| Plausible path requiring deployment context | 7 |
| Context-dependent | 1 |
| Likely false positive at high priority | 7 |
| Confirmed vulnerabilities | 0 |

`Plausible` means the exported graph supports the risk path. It does not prove exploitability, credential scope, missing infrastructure controls or unsafe runtime behavior.

## Rule refinements from the review

- Recognize Baserow's omitted-operation `getAll` default as read-only.
- Recognize sub-workflow tools whose exported description is explicitly read-only.
- Treat a WhatsApp media URL resolved by the provider node as a visible URL trust boundary, while retaining the dynamic request as a medium review signal.

One fixed-recipient result email remains context-dependent because the export shows a real send action but cannot establish the sensitivity of the report or the recipient's role.

Template-level classifications remain in a git-ignored private review record. This public summary contains no template names, IDs or individual allegations.
