import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startDemoStagingServer } from "../examples/staging-target.mjs";
import {
  renderGateJUnit,
  renderGateMarkdown,
  renderGateSarif,
} from "../src/reporters.mjs";
import {
  runSecurityRegressionGate,
  validateSecurityContract,
} from "../src/runtime-gate.mjs";
import { buildRuntimeGateReceipt } from "../src/runtime-receipt.mjs";
import { assertTargetAllowed } from "../src/target-policy.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = JSON.parse(
  await readFile(path.join(root, "workflows", "hardened-support-agent.json"), "utf8"),
);
const contract = JSON.parse(
  await readFile(
    path.join(root, "contracts", "hardened-support-agent.contract.json"),
    "utf8",
  ),
);

validateSecurityContract(contract);

const staging = await startDemoStagingServer();
try {
  const result = await runSecurityRegressionGate({
    workflow,
    contract,
    sourcePath: "workflows/hardened-support-agent.json",
    targetOverride: staging.baseUrl,
  });

  assert.equal(result.passed, true);
  assert.equal(result.decision, "pass");
  assert.equal(result.static.grade, "A");
  assert.deepEqual(result.static.blockers, []);
  assert.equal(result.runtime.total, 8);
  assert.equal(result.runtime.passed, 8);
  assert.equal(result.runtime.failed, 0);
  assert.equal(staging.state.actionsExecuted, 0);

  const markdown = renderGateMarkdown(result);
  assert.match(markdown, /Decision: PASS/);
  assert.match(markdown, /8\/8 passed/);
  assert.doesNotMatch(markdown, /demo-staging-signature/);
  assert.doesNotMatch(markdown, /reader@example\.org/);

  const junit = renderGateJUnit(result);
  assert.match(junit, /tests="9" failures="0"/);
  assert.doesNotMatch(junit, /demo-staging-signature/);

  const blockedJunit = renderGateJUnit({
    ...result,
    passed: false,
    decision: "fail",
    static: {
      ...result.static,
      blockers: ["AA-004"],
    },
  });
  assert.match(blockedJunit, /tests="9" failures="1"/);
  assert.match(blockedJunit, /Blocking static findings/);

  const sarif = renderGateSarif(result);
  assert.match(sarif, /"version": "2\.1\.0"/);
  assert.doesNotMatch(sarif, /demo-staging-signature/);

  const receipt = buildRuntimeGateReceipt({
    result,
    workflow,
    contract,
    workflowSource: "candidate.json",
    contractSource: "security-contract.json",
    verifiedAt: "2026-08-04T10:00:00.000Z",
  });
  assert.equal(receipt.kind, "csint-n8n-runtime-gate-receipt");
  assert.equal(receipt.outcome.passed, true);
  assert.equal(receipt.outcome.externalActionsExecuted, 0);
  assert.equal(receipt.evidence.externalActionProof.verified, true);
  assert.match(receipt.environment.deploymentBinding, /not independently attested/);
  assert.ok(
    receipt.limitations.some((item) => item.includes("does not read the deployed workflow back")),
  );
  assert.match(receipt.subjects.executedWorkflow.canonicalSha256, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(receipt), /demo-staging-signature|reader@example\.org/);
} finally {
  await staging.close();
}

const driftedStaging = await startDemoStagingServer({ schemaDrift: true });
try {
  const driftedResult = await runSecurityRegressionGate({
    workflow,
    contract,
    sourcePath: "workflows/hardened-support-agent.json",
    targetOverride: driftedStaging.baseUrl,
  });

  assert.equal(driftedResult.passed, false);
  assert.equal(
    driftedResult.runtime.tests.some(
      (test) =>
        !test.passed &&
        test.checks.some(
          (item) =>
            item.name === "Response has no unexpected top-level fields" && !item.passed,
        ),
    ),
    true,
    "Expected the response shape regression to fail the gate",
  );
} finally {
  await driftedStaging.close();
}

await assert.rejects(
  () =>
    runSecurityRegressionGate({
      workflow,
      contract: {
        ...contract,
        target: {
          ...contract.target,
          baseUrl: "https://staging.example.org",
          allowedHosts: ["staging.example.org"],
        },
      },
    }),
  /Remote targets are blocked by default/,
);

assert.throws(
  () =>
    assertTargetAllowed("https://staging.example.org/webhook/production", {
      allowRemote: true,
      allowedHosts: ["staging.example.org"],
    }),
  /request path is not allowlisted/,
);

assert.throws(
  () =>
    validateSecurityContract({
      ...contract,
      receipt: {
        externalActionEvidence: {
          testId: "missing-test",
          source: "observation",
          pointer: "/actions_executed",
        },
      },
    }),
  /does not match a contract test/,
);

assert.throws(
  () =>
    validateSecurityContract({
      ...contract,
      tests: [...contract.tests, contract.tests[0]],
    }),
  /Duplicate runtime test id/,
);

assert.throws(
  () =>
    validateSecurityContract({
      ...contract,
      target: {
        ...contract.target,
        allowedPathPrefixes: ["/"],
      },
    }),
  /specific paths/,
);

console.log("AI security regression gate: all checks passed");
