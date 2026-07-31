# Public n8n AI Agent template static scan

Collected: 2026-07-31T16:35:52.652Z
Sample: 20 most-viewed free AI Agent templates available through the official n8n template API at collection time.

## Method

- Source: official n8n template search and workflow-template APIs.
- Filter: AI category, AI Agent node, free public templates only.
- Order: public view count descending, then template ID ascending for deterministic ties.
- Analysis: local static scan of each downloaded export; no workflow was imported or executed.
- Publication boundary: this aggregate report contains no template-level score or finding list.

## Study result

| Metric | Result |
| --- | ---: |
| Templates scanned | 20 |
| Median active nodes | 22.5 |
| Median heuristic score | 62/100 |
| Templates with any signal | 20 (100%) |
| Templates queued for path-level manual review | 6 (30%) |
| Path-level finding instances to validate | 8 |

## Aggregate signals

| Rule | Highest severity | Severity breakdown | Templates | Share |
| --- | --- | --- | ---: | ---: |
| AA-006: No rate or cost boundary was detected before model usage | high | high: 17 | 17 | 85% |
| AA-003: Untrusted input can reach a model without a visible validation boundary | high | high: 2, medium: 13 | 15 | 75% |
| AA-004: A model can reach an external write action without an approval step | high | high: 6 | 6 | 30% |
| AA-008: Outbound requests do not show an explicit timeout or retry policy | medium | medium: 11 | 11 | 55% |
| AA-005: No structured model-output validation was detected | medium | medium: 6 | 6 | 30% |
| AA-007: Review HTTP request URLs derived from workflow data | medium | medium: 6 | 6 | 30% |
| AA-009: External actions have no visible audit record | medium | medium: 6 | 6 | 30% |
| AA-002: Public webhook authentication is not enforced by the trigger | medium | medium: 1 | 1 | 5% |
| AA-011: A credential reference is shared across untrusted and approved lanes | medium | medium: 1 | 1 | 5% |
| AA-010: No workflow-level failure route was detected | low | low: 20 | 20 | 100% |

## Interpretation limits

- These are heuristic static-analysis signals, not confirmed vulnerabilities.
- No community workflow was imported, activated or executed.
- Public exports cannot prove runtime authorization, credential scopes, upstream controls or model behavior.
- Critical findings and high-severity path findings require manual validation before publication.
- AA-006 remains an aggregate scanner signal, but it is not a template-level publication target because exports cannot reveal instance-level rate or cost controls.
- AA-011 compares credential references within one export; it cannot prove real credential scopes or correlate credentials hidden across separate workflows.
- The sample represents the most-viewed free AI Agent templates returned by the official API at collection time, not the entire template library.
