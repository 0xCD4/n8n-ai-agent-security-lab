# Release Rehearsal Evidence

Generated from synthetic fixtures. Not customer or production evidence.

## Executive summary

Result: REVIEW_REQUIRED

Every supported case completed, and meaningful observed-action differences were found. A person must decide whether the candidate should proceed.

The human makes the release decision.

## What was checked

- 1 sanitized fixture case against separate transformed baseline and candidate runs.
- Literal POST, PUT, and PATCH actions using n8n-nodes-base.httpRequest type version 4.2.
- 2 accepted local capture occurrence(s), with forwarding observed: false.
- Containment: COMPLETE. Cleanup: COMPLETE.

## Observed action changes

- method_changed: fixture fixture\-example, node submit\-order, POST to PATCH.

## Coverage limits

Observed means only that the contained local capture service accepted the transformed synthetic request. Planned data comes from the source-bound transformation. Unresolved means runtime capture evidence was unavailable.

- Not established: Node-level execution order or item linking.
- Not established: Approval-node execution.
- Not established: Retry or loop behavior.
- Not established: Structural-node or downstream completion.
- Not established: Delivery to an original destination.
- Not established: Production readiness.
- Not established: A penetration-test outcome.
- Not established: Complete workflow equivalence.
- Not established: Deployment identity.
- Not established: A human release decision.

## Items requiring human review

- Review every observed-action change listed above.
- Decide whether additional fixtures or manual review are required.

## Input and evidence fingerprints

- Baseline workflow: 20e9cdac509c7c46353b39b015b1eb6279af61a214d6fe45b34568a4e3b84679
- Candidate workflow: a45479d7ea0822ee3f7fcbce506cd3f49977d22080bbd622e2528767d62942b6
- Fixture set: eaca526d69aa02ab5e5bc034de9b720d689b64b4509b7e51a7349c53a121fad6
- n8n image: docker.n8n.io/n8nio/n8n@sha256:34df96d9a7e14c21c70dea69dc2d9c62f920ffe56238f03861ce5ea4ba56481e
- Caller-supplied generation timestamp: 2026-08-06T12:00:00.000Z
