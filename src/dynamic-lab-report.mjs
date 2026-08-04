const RECEIPT_KIND = "csint-n8n-dynamic-lab-receipt";

function countChecks(test) {
  const primary = Array.isArray(test.checks) ? test.checks : [];
  const observation = Array.isArray(test.observation?.checks) ? test.observation.checks : [];
  const checks = [...primary, ...observation];
  return {
    passed: checks.filter((check) => check.passed).length,
    total: checks.length,
  };
}

function publicScenario(test) {
  const checks = countChecks(test);
  return {
    id: test.id,
    name: test.name,
    passed: Boolean(test.passed),
    status: test.status,
    durationMs: test.durationMs,
    observationStatus: test.observation?.status ?? null,
    observationDurationMs: test.observation?.durationMs ?? null,
    checks,
  };
}

export function buildDynamicLabReceipt(
  result,
  {
    image,
    verifiedAt = new Date().toISOString(),
    finalState,
    subjects,
    cleanup = { containerRemoved: false, volumeRemoved: false },
  },
) {
  if (!result || !result.runtime || !Array.isArray(result.runtime.tests)) {
    throw new TypeError("A completed regression-gate result is required.");
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(verifiedAt)) {
    throw new TypeError("verifiedAt must be an ISO timestamp.");
  }
  if (!image || typeof image !== "string") {
    throw new TypeError("The verified n8n image is required.");
  }
  if (!finalState || !Number.isInteger(finalState.actions_executed)) {
    throw new TypeError("The final isolated action count is required.");
  }
  for (const key of ["staticWorkflow", "executedWorkflow", "securityContract"]) {
    const subject = subjects?.[key];
    if (!subject || !/^[a-f0-9]{64}$/.test(subject.canonicalSha256 || "")) {
      throw new TypeError(`A canonical fingerprint is required for subjects.${key}.`);
    }
  }

  const scenarios = result.runtime.tests.map(publicScenario);
  const checks = scenarios.reduce(
    (total, scenario) => ({
      passed: total.passed + scenario.checks.passed,
      total: total.total + scenario.checks.total,
    }),
    { passed: 0, total: 0 },
  );

  return {
    schemaVersion: 2,
    kind: RECEIPT_KIND,
    verifiedAt,
    subjects,
    environment: {
      runtime: "n8n",
      image,
      isolation: "ephemeral Docker container",
      network: "loopback-only test target",
      credentials: "test-only environment values",
      cleanup,
    },
    outcome: {
      decision: result.decision,
      passed: Boolean(result.passed),
      externalActionsExecuted: finalState.actions_executed,
      acceptedRequests: Number(finalState.accepted_requests ?? 0),
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
    boundaries: [
      "No production credentials are mounted.",
      "No email, chat, database or HTTP action node is allowed to contact a live service.",
      "The target is bound to loopback and removed after the run.",
      "Approval, replay, authentication and prompt-injection containment are checked with synthetic requests.",
    ],
    limitations: [
      ...result.limitations,
      "No language model is invoked. The prompt-injection scenario measures the deterministic controls around an agent workflow, not the model's resistance to manipulation.",
      "This receipt covers the bundled action-free fixture. It is not permission to execute an arbitrary uploaded workflow.",
    ],
  };
}

export function renderDynamicLabMarkdown(receipt) {
  const lines = [
    "# CSINT Dynamic Workflow Lab receipt",
    "",
    "Measured in an isolated staging run. This is not a production safety certificate.",
    "",
    `Verified: ${receipt.verifiedAt}`,
    `Runtime: ${receipt.environment.image}`,
    `Executed workflow: ${receipt.subjects.executedWorkflow.canonicalSha256}`,
    `Security contract: ${receipt.subjects.securityContract.canonicalSha256}`,
    `Decision: ${receipt.outcome.decision.toUpperCase()}`,
    `Static audit: ${receipt.static.score}/100 (${receipt.static.grade})`,
    `Runtime scenarios: ${receipt.runtime.passed}/${receipt.runtime.total} passed`,
    `Assertions: ${receipt.runtime.checks.passed}/${receipt.runtime.checks.total} passed`,
    `External actions executed: ${receipt.outcome.externalActionsExecuted}`,
    "",
    "## Scenario receipt",
    "",
    "| Scenario | HTTP | Observation | Checks | Result |",
    "| --- | ---: | ---: | ---: | --- |",
    ...receipt.runtime.scenarios.map(
      (scenario) =>
        `| ${scenario.name} | ${scenario.status ?? "-"} | ${scenario.observationStatus ?? "-"} | ${scenario.checks.passed}/${scenario.checks.total} | ${scenario.passed ? "PASS" : "FAIL"} |`,
    ),
    "",
    "## Boundaries",
    "",
    ...receipt.boundaries.map((boundary) => `- ${boundary}`),
    "",
    "## Limits",
    "",
    ...receipt.limitations.map((limitation) => `- ${limitation}`),
    "",
  ];
  return lines.join("\n");
}
