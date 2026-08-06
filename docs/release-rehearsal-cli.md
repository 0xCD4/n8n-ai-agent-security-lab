# Release Rehearsal local CLI

Phase 7 packages the verified Phase 6 action-level core as one local command. It compares one baseline workflow with one candidate workflow using one to three sanitized fixture cases and writes a deterministic evidence bundle.

The command does not make the release decision and does not provide node-level execution tracing.

## Usage

```text
node bin/rehearse.mjs \
  --baseline baseline.json \
  --candidate candidate.json \
  --fixtures fixtures.json \
  --output rehearsal-result
```

Optional arguments:

- `--timestamp 2026-08-06T12:00:00.000Z` records a caller-supplied canonical UTC timestamp. No current timestamp is invented when this option is omitted.
- `--synthetic-example` adds the exact label `Generated from synthetic fixtures. Not customer or production evidence.`
- `--help` prints command help and must be used alone.

Arguments are strict. Missing, duplicate, unknown, malformed, or excessive arguments are rejected. Baseline, candidate, and fixture inputs are read through the existing bounded JSON loaders. Symbolic links, non-regular files, malformed JSON, and inputs outside the configured limits are rejected.

The output path must be absent or an existing empty regular directory. An existing non-empty directory or other filesystem entry is preserved. Files are built and verified in a private sibling directory, then the complete directory is published by rename. An existing empty directory is moved aside only during the final rename and is restored if publication fails.

## Output

```text
rehearsal-result/
  evidence-manifest.json
  report.md
  summary.json
```

- `summary.json` contains the strict schema version, result, input fingerprints, pinned n8n identity, supported-scope counts, planned/observed/unresolved evidence counts, deterministic action diffs, containment, cleanup, redaction facts, and unsupported claims.
- `report.md` is the client-readable view of the same result and evidence boundary.
- `evidence-manifest.json` binds the original inputs, each transformed workflow, normalized capture evidence, execution case identifiers, the pinned image digest, `summary.json`, and `report.md` by SHA-256.

The manifest cannot contain its own full-file hash. Its `manifestCanonicalSha256` field instead hashes the canonical manifest object with that one field omitted. This verifies the third generated file while avoiding a circular self-hash.

No output file contains raw workflow content, fixture bodies, request or response bodies, query values, header values, credentials, raw Docker streams, or raw capture streams.

## Supported workflow subset

- At most 20 active nodes and 100 parsed nodes per workflow.
- One built-in Webhook node at type version `2.1` with a literal `POST` path and last-node response mode.
- Built-in Set nodes at type version `3.4` with literal sanitized parameters.
- Built-in HTTP Request nodes at type version `4.2` with literal `POST`, `PUT`, or `PATCH`, canonical sanitized JSON, no credential reference, no original header/query configuration, no redirect, and no retry or alternate error mode.
- One reachable acyclic `main[0]` graph.
- The existing Phase 6 disabled-node and static-blocker policies.

Dynamic methods or destinations, other HTTP methods, credentials, Code, Execute Command, AI, community/custom nodes, subworkflows, unsupported triggers or control semantics, cycles, disconnected nodes, and unknown versions stop before Docker execution.

## Result and exit codes

| Exit | Result | Meaning |
| ---: | --- | --- |
| `0` | `REHEARSAL_COMPLETE` | Every supported case completed and expected local capture evidence was observed, with no observed-action difference. |
| `2` | `REVIEW_REQUIRED` | Every supported case completed and meaningful observed-action differences exist. |
| `3` | `BLOCKED_UNSUPPORTED` | One or both workflows are outside the supported subset; Docker execution does not start. |
| `4` | `INCOMPLETE_EVIDENCE` | Expected capture evidence is missing or unresolved. |
| `5` | `CONTAINMENT_FAILURE` | A DNS, forwarding, unexpected-action, inventory, or cleanup check failed. |
| `64` | command/input error | Arguments, input files, or the output target were rejected. |
| `70` | runtime error | The command failed before it could publish a complete bundle. |
| `130` | interrupted | An interrupt was received; runtime and private output cleanup were attempted and no bundle was published. |

## Evidence boundary

Observed means only that the contained local capture service accepted a transformed synthetic request. Planned intent comes from the original-workflow-bound transformation manifest. Unresolved means expected runtime capture evidence was unavailable.

The result does not establish node order, item linking, approval execution, retries, loops, structural-node execution, downstream completion, original-destination delivery, production readiness, a penetration-test outcome, complete workflow equivalence, deployment identity, or a human release decision.

## Synthetic example

The input set is in `examples/release-rehearsal/inputs/`. Generate its checked example bundle with:

```text
node bin/rehearse.mjs \
  --baseline examples/release-rehearsal/inputs/baseline.json \
  --candidate examples/release-rehearsal/inputs/candidate.json \
  --fixtures examples/release-rehearsal/inputs/fixtures.json \
  --output examples/release-rehearsal/evidence-bundle \
  --timestamp 2026-08-06T12:00:00.000Z \
  --synthetic-example
```

The example changes one HTTP action from `POST` to `PATCH`, so its expected result is `REVIEW_REQUIRED`.
