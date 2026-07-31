# Public n8n AI Agent template study

This research workflow measures static security signals in a bounded sample of public n8n AI Agent templates.

The feasibility command collects the 20 most-viewed free templates returned by the official n8n template API for the AI category and AI Agent app filter:

```bash
npm run study:templates:feasibility
```

After the feasibility findings have been reviewed, reproduce the 100-template sample with:

```bash
npm run study:templates:top100
```

The command writes:

- `manifest.json`: source IDs, public URLs, collection-time view counts, workflow hashes and node counts. It contains no template-level scores or findings.
- `summary.json`: anonymous aggregate statistics.
- `summary.md`: a publication-safe aggregate summary with explicit limitations.
- `review-queue.private.json`: template-level findings for manual validation. Git ignores this file.

## Safety and publication boundary

- Only `https://api.n8n.io` is contacted.
- Only public free templates are selected.
- Community workflows are never imported, activated or executed.
- Raw workflow exports are processed in memory and are not saved.
- Scanner evidence is redacted before it enters the private review queue.
- Do not publish critical findings or high-severity AA-003, AA-004 or AA-007 path findings until a human has reproduced the path and ruled out visible controls the static export cannot observe.
- Keep AA-006 as an aggregate signal. Do not attribute it to a template because exports cannot reveal instance-level rate or cost controls.
- Public reporting should use aggregate statistics and anonymized examples. Do not rank or shame template authors.

## From feasibility to the 100-template study

The initial feasibility run produced 15 study-priority paths. All 15 were classified before expansion: seven plausible paths requiring deployment context, one context-dependent path and seven likely high-priority false positives. The review produced three deterministic rule refinements and reduced the same sample to eight priority paths. See the [anonymous validation summary](feasibility-20/manual-validation-summary.md).

The 100-template sample is generated with:

```bash
npm run study:templates:top100
```

## Current 100-template snapshot

Collected on 2026-07-31 from the official API:

| Metric | Result |
| --- | ---: |
| Templates scanned | 100 |
| Failed downloads | 0 |
| Median active nodes | 22.5 |
| Median heuristic score | 62/100 |
| Templates queued for path-level review | 52 |
| Path-level finding instances | 86 |
| Shared credential lane signals | 1 |

These figures are static-analysis signals, not confirmed vulnerabilities. The [aggregate report](top-100/summary.md) separates high and medium instances for rules that can produce both severities. Template-level findings remain private until validated.

The official API is a live source. Every published study must keep the generated manifest, collection timestamp and SHA-256 hashes so the sample remains auditable when listings change.
