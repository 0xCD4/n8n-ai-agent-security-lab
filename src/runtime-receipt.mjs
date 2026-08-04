import { buildEvidenceSubject } from "./evidence-fingerprint.mjs";

export const RUNTIME_GATE_RECEIPT_KIND = "csint-n8n-runtime-gate-receipt";

function countChecks(test) {
  const primary = Array.isArray(test?.checks) ? test.checks : [];
  const observation = Array.isArray(test?.observation?.checks) ? test.observation.checks : [];
  const checks = [...primary, ...observation];
  return {
    passed: checks.filter((check) => check.passed).length,
    total: checks.length,
  };
}

function publicScenario(test) {
  return {
    id: test.id,
    name: test.name,
    passed: Boolean(test.passed),
    status: test.status ?? null,
    durationMs: test.durationMs ?? null,
    observationStatus: test.observation?.status ?? null,
    observationDurationMs: test.observation?.durationMs ?? null,
    checks: countChecks(test),
  };
}

function externalActionProof(result, contract) {
  const configured = contract?.receipt?.externalActionEvidence;
  if (!configured) {
    return {
      verified: false,
      testId: null,
      source: null,
      pointer: null,
      expected: 0,
      note: "The security contract did not identify a zero-action canary check.",
    };
  }

  const contractTest = contract.tests.find((test) => test.id === configured.testId);
  const resultTest = result.runtime.tests.find((test) => test.id === configured.testId);
  const expectation =
    configured.source === "observation" ? contractTest?.observe?.expect : contractTest?.expect;
  const checks =
    configured.source === "observation" ? resultTest?.observation?.checks : resultTest?.checks;
  const expectedZero = expectation?.json?.equals?.[configured.pointer] === 0;
  const matchingCheck = checks?.find(
    (check) => check.name === `JSON path ${configured.pointer} matches contract`,
  );
  const verified = expectedZero && matchingCheck?.passed === true;

  return {
    verified,
    testId: configured.testId,
    source: configured.source,
    pointer: configured.pointer,
    expected: 0,
    note: verified
      ? "The named contract check observed a zero external-action canary value."
      : "The named zero-action canary check did not pass.",
  };
}

export function buildRuntimeGateReceipt({
  result,
  workflow,
  contract,
  workflowSource = "candidate-workflow.json",
  contractSource = "security-contract.json",
  verifiedAt = new Date().toISOString(),
} = {}) {
  if (!result?.runtime || !Array.isArray(result.runtime.tests)) {
    throw new TypeError("A completed regression-gate result is required.");
  }
  if (!workflow || typeof workflow !== "object") {
    throw new TypeError("The candidate workflow supplied to the gate is required.");
  }
  if (!contract || typeof contract !== "object") {
    throw new TypeError("The tested security contract is required.");
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(verifiedAt)) {
    throw new TypeError("verifiedAt must be an ISO timestamp.");
  }

  const proof = externalActionProof(result, contract);
  const scenarios = result.runtime.tests.map(publicScenario);
  const checks = scenarios.reduce(
    (total, scenario) => ({
      passed: total.passed + scenario.checks.passed,
      total: total.total + scenario.checks.total,
    }),
    { passed: 0, total: 0 },
  );
  const passed = result.passed === true && proof.verified;
  const loopback = /^https?:\/\/(?:127\.0\.0\.1|localhost)(?::|\/|$)/i.test(result.target || "");

  return {
    schemaVersion: 1,
    kind: RUNTIME_GATE_RECEIPT_KIND,
    verifiedAt,
    subjects: {
      executedWorkflow: buildEvidenceSubject(
        "Candidate workflow supplied to the gate",
        workflowSource,
        workflow,
      ),
      securityContract: buildEvidenceSubject("Runtime security contract", contractSource, contract),
    },
    environment: {
      runtime: "customer-controlled n8n staging",
      targetScope: loopback ? "loopback" : "exact allowlisted staging host",
      credentials: "test-only values supplied by the customer",
      deploymentBinding: "operator-controlled; not independently attested by the gate",
    },
    outcome: {
      decision: passed ? "pass" : "fail",
      passed,
      externalActionsExecuted: proof.verified ? 0 : null,
    },
    static: {
      score: result.static.score,
      grade: result.static.grade,
      blockers: result.static.blockers.length,
    },
    runtime: {
      passed: result.runtime.passed,
      failed: result.runtime.failed,
      total: result.runtime.total,
      checks,
      scenarios,
    },
    evidence: {
      externalActionProof: proof,
    },
    boundaries: [
      "The workflow and contract were read by a local CLI and were not uploaded to CSINT.",
      "Only synthetic requests defined in the security contract were sent to the selected staging target.",
      "Remote targets require an explicit flag, an exact hostname allowlist and narrow path prefixes.",
      "The operator is responsible for confirming that the selected staging target is running the fingerprinted candidate export.",
    ],
    limitations: [
      ...result.limitations,
      "This receipt records the supplied contract and candidate fingerprint. It is not a penetration test or production safety certificate.",
      "A passing run does not prove model safety, production credential scope or authorization in external systems.",
      "The generic gate does not read the deployed workflow back from n8n, so the receipt links the run to the operator-supplied candidate rather than independently attesting the staging deployment.",
    ],
  };
}

export function renderRuntimeGateReceiptMarkdown(receipt) {
  return [
    "# CSINT n8n Runtime Gate receipt",
    "",
    "Generated locally from a candidate-linked staging contract.",
    "",
    `Verified: ${receipt.verifiedAt}`,
    `Candidate export: ${receipt.subjects.executedWorkflow.canonicalSha256}`,
    `Contract: ${receipt.subjects.securityContract.canonicalSha256}`,
    `Decision: ${receipt.outcome.decision.toUpperCase()}`,
    `Runtime scenarios: ${receipt.runtime.passed}/${receipt.runtime.total} passed`,
    `Assertions: ${receipt.runtime.checks.passed}/${receipt.runtime.checks.total} passed`,
    `External actions: ${receipt.outcome.externalActionsExecuted ?? "not proven"}`,
    "",
    "## Evidence boundary",
    "",
    ...receipt.boundaries.map((item) => `- ${item}`),
    "",
    "## Limits",
    "",
    ...receipt.limitations.map((item) => `- ${item}`),
    "",
  ].join("\n");
}
