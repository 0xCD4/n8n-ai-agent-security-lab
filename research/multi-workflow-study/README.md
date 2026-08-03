# Multi-workflow trust-boundary study

This directory contains bounded, reproducible static-analysis notes for public n8n workflow sets.

Publication rules:

- Pin every public source to an immutable commit.
- Parse JSON only; never import, activate or execute third-party workflows.
- Do not store copied raw exports in this repository.
- Publish aggregate signals and review paths, not exploitability claims.
- Omit raw workflow IDs and credential names or IDs from generated reports.

The first snapshot is documented in [`public-repo-snapshot`](public-repo-snapshot/summary.md).
