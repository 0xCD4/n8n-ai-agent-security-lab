import assert from "node:assert/strict";

import {
  buildDynamicLabReceipt,
  renderDynamicLabMarkdown,
} from "../src/dynamic-lab-report.mjs";
import { buildEvidenceSubject, fingerprintJson } from "../src/evidence-fingerprint.mjs";

const result = {
  decision: "pass",
  passed: true,
  static: { score: 93, grade: "A", blockers: [] },
  runtime: {
    passed: 2,
    failed: 0,
    total: 2,
    tests: [
      {
        id: "contain-prompt-injection",
        name: "Keep an instruction override behind approval",
        passed: true,
        status: 202,
        durationMs: 18,
        checks: [{ name: "status", passed: true }],
        observation: {
          status: 200,
          durationMs: 6,
          checks: [{ name: "actions remain zero", passed: true }],
        },
      },
      {
        id: "block-approval-bypass",
        name: "Block an invalid approval token",
        passed: true,
        status: 403,
        durationMs: 12,
        checks: [{ name: "approval required", passed: true }],
      },
    ],
  },
  limitations: ["Synthetic fixture only."],
};

const receipt = buildDynamicLabReceipt(result, {
  image: "docker.n8n.io/n8nio/n8n:2.21.5",
  verifiedAt: "2026-08-04T12:00:00.000Z",
  finalState: { actions_executed: 0, accepted_requests: 1 },
  subjects: {
    staticWorkflow: buildEvidenceSubject("Static workflow", "workflows/static.json", { nodes: [1] }),
    executedWorkflow: buildEvidenceSubject("Executed workflow", "workflows/staging.json", { nodes: [2] }),
    securityContract: buildEvidenceSubject("Contract", "contracts/staging.json", { tests: [1] }),
  },
  cleanup: { containerRemoved: true, volumeRemoved: true },
});

assert.equal(receipt.kind, "csint-n8n-dynamic-lab-receipt");
assert.equal(receipt.outcome.externalActionsExecuted, 0);
assert.equal(receipt.runtime.passed, 2);
assert.deepEqual(receipt.runtime.checks, { passed: 3, total: 3 });
assert.equal(receipt.runtime.scenarios[0].observationStatus, 200);
assert.equal(receipt.environment.cleanup.containerRemoved, true);
assert.equal(receipt.schemaVersion, 2);
assert.equal(receipt.subjects.executedWorkflow.canonicalSha256, fingerprintJson({ nodes: [2] }));

const serialized = JSON.stringify(receipt);
assert.ok(!serialized.includes("approval-token"));
assert.ok(!serialized.includes("127.0.0.1"));
assert.ok(!serialized.includes("request body"));

const markdown = renderDynamicLabMarkdown(receipt);
assert.match(markdown, /Runtime scenarios: 2\/2 passed/);
assert.match(markdown, /External actions executed: 0/);
assert.match(markdown, /Executed workflow: [a-f0-9]{64}/);
assert.match(markdown, /Keep an instruction override behind approval/);

console.log("dynamic lab receipt: all checks passed");
