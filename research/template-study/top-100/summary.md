# Public n8n AI Agent template static scan

Collected: 2026-07-31T16:35:55.745Z
Sample: 100 most-viewed free AI Agent templates available through the official n8n template API at collection time.

## Method

- Source: official n8n template search and workflow-template APIs.
- Filter: AI category, AI Agent node, free public templates only.
- Order: public view count descending, then template ID ascending for deterministic ties.
- Analysis: local static scan of each downloaded export; no workflow was imported or executed.
- Publication boundary: this aggregate report contains no template-level score or finding list.

## Study result

| Metric | Result |
| --- | ---: |
| Templates scanned | 100 |
| Median active nodes | 22.5 |
| Median heuristic score | 62/100 |
| Templates with any signal | 100 (100%) |
| Templates queued for path-level manual review | 52 (52%) |
| Path-level finding instances to validate | 86 |

## Aggregate signals

| Rule | Highest severity | Severity breakdown | Templates | Share |
| --- | --- | --- | ---: | ---: |
| AA-006: No rate or cost boundary was detected before model usage | high | high: 77 | 77 | 77% |
| AA-003: Untrusted input can reach a model without a visible validation boundary | high | high: 30, medium: 42 | 72 | 72% |
| AA-004: A model can reach an external write action without an approval step | high | high: 49 | 49 | 49% |
| AA-007: Review HTTP request URLs derived from workflow data | high | high: 7, medium: 19 | 26 | 26% |
| AA-008: Outbound requests do not show an explicit timeout or retry policy | medium | medium: 57 | 57 | 57% |
| AA-005: No structured model-output validation was detected | medium | medium: 40 | 40 | 40% |
| AA-009: External actions have no visible audit record | medium | medium: 37 | 37 | 37% |
| AA-002: Public webhook authentication is not enforced by the trigger | medium | medium: 15 | 15 | 15% |
| AA-011: A credential reference is shared across untrusted and approved lanes | medium | medium: 1 | 1 | 1% |
| AA-010: No workflow-level failure route was detected | low | low: 99 | 99 | 99% |

## Interpretation limits

- These are heuristic static-analysis signals, not confirmed vulnerabilities.
- No community workflow was imported, activated or executed.
- Public exports cannot prove runtime authorization, credential scopes, upstream controls or model behavior.
- Critical findings and high-severity path findings require manual validation before publication.
- AA-006 remains an aggregate scanner signal, but it is not a template-level publication target because exports cannot reveal instance-level rate or cost controls.
- AA-011 compares credential references within one export; it cannot prove real credential scopes or correlate credentials hidden across separate workflows.
- The sample represents the most-viewed free AI Agent templates returned by the official API at collection time, not the entire template library.
