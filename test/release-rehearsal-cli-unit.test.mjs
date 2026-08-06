import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { canonicalJson, fingerprintJson } from "../src/evidence-fingerprint.mjs";
import { executeReleaseRehearsalCommand } from "../src/release-rehearsal-cli.mjs";
import { diffReleaseRehearsalActions } from "../src/release-rehearsal-diff.mjs";
import {
  scanReleaseRehearsalEvidenceText,
  validateReleaseRehearsalSummary,
  verifyReleaseRehearsalEvidenceBundle,
} from "../src/release-rehearsal-evidence.mjs";
import { validateReleaseRehearsalFixtureSet } from "../src/release-rehearsal-fixture.mjs";
import { preflightReleaseRehearsalActionWorkflow } from "../src/release-rehearsal-preflight.mjs";

const tests = [];

function test(name, callback) {
  tests.push({ name, callback });
}

function webhook(pathValue = "phase7-unit") {
  return {
    id: "entry-webhook",
    name: "Synthetic Entry",
    type: "n8n-nodes-base.webhook",
    typeVersion: 2.1,
    webhookId: "11111111-1111-4111-8111-111111111111",
    position: [0, 0],
    parameters: {
      httpMethod: "POST",
      path: pathValue,
      responseMode: "lastNode",
      options: {},
    },
  };
}

function action(method = "POST", url = "https://api.example.invalid/v1/items?tenant=query-value-991a") {
  return {
    id: "action-a",
    name: "Synthetic Action A",
    type: "n8n-nodes-base.httpRequest",
    typeVersion: 4.2,
    position: [240, 0],
    parameters: {
      method,
      url,
      authentication: "none",
      sendBody: true,
      contentType: "json",
      specifyBody: "json",
      jsonBody: canonicalJson({
        kind: "synthetic-action",
        payload: "workflow-payload-value-662b",
      }),
      options: {
        redirect: { followRedirects: false },
        response: {
          response: { fullResponse: false, responseFormat: "json" },
        },
        timeout: 5_000,
      },
    },
  };
}

function workflow({ method = "POST", url, dynamic = false } = {}) {
  const http = action(
    method,
    dynamic ? "={{$json.destination}}" : url,
  );
  return {
    id: "csint-phase7-unit-v1",
    name: "Synthetic Phase 7 unit workflow",
    active: false,
    nodes: [webhook(), http],
    connections: {
      "Synthetic Entry": {
        main: [[{ node: http.name, type: "main", index: 0 }]],
      },
    },
    settings: { executionOrder: "v1" },
    versionId: "22222222-2222-4222-8222-222222222222",
  };
}

function fixtures() {
  return {
    schemaVersion: 1,
    fixtures: [
      {
        schemaVersion: 1,
        id: "fixture-unit",
        correlationId: "fixture-unit-seed",
        webhook: {
          method: "POST",
          path: "/phase7-unit",
          headers: { "x-fixture-mode": "fixture-header-value-881a" },
          json: { value: "fixture-payload-value-551c" },
        },
        nodes: [
          {
            nodeId: "action-a",
            minimumOccurrences: 1,
            maximumOccurrences: 1,
            responses: [
              {
                status: 200,
                headers: {
                  "content-type": "application/json; charset=utf-8",
                },
                json: { result: "stub-payload-value-772a" },
              },
            ],
          },
        ],
      },
    ],
  };
}

function observedAction(preflight, fixture) {
  const planned = preflight.actions[0];
  return {
    schemaVersion: 1,
    evidenceStatus: "observed",
    variant: preflight.variant,
    fixtureId: fixture.id,
    workflowCanonicalSha256: preflight.workflow.canonicalSha256,
    source: { nodeId: planned.nodeId, nodeName: planned.nodeName },
    sequence: planned.sequence,
    attempt: 1,
    intent: {
      kind: "http",
      method: planned.method,
      destination: planned.destination,
    },
    resolutionCode: null,
  };
}

function caseResult(preflight, fixture, { complete = true } = {}) {
  const variant = preflight.variant;
  const transformed = fingerprintJson({
    kind: "synthetic-transformed-workflow",
    variant,
    fixture: fixture.canonicalSha256,
    original: preflight.workflow.canonicalSha256,
  });
  return {
    schemaVersion: 1,
    status: complete ? "COMPLETE" : "INCOMPLETE",
    variant,
    fixtureId: fixture.id,
    fixtureCanonicalSha256: fixture.canonicalSha256,
    caseId: `case-${variant}-${fixture.canonicalSha256.slice(0, 12)}`,
    subjects: {
      originalWorkflowCanonicalSha256: preflight.workflow.canonicalSha256,
      transformedWorkflowCanonicalSha256: transformed,
      transformationManifestCanonicalSha256: fingerprintJson({ transformed }),
    },
    observedActions: complete ? [observedAction(preflight, fixture)] : [],
    process: {
      importExitCode: 0,
      publishExitCode: 0,
      injectorExitCode: complete ? 0 : null,
      n8nProcessExitCode: 0,
      startupCompletionMarkerObserved: true,
      healthReadinessObserved: true,
    },
    evidence: {
      captureStatus: complete ? "COMPLETE" : "INCOMPLETE",
      captureEventCount: complete ? 1 : 0,
      captureForwarded: false,
      captureViolationCodes: [],
      responseStatuses: complete ? [200] : [],
      dnsStatus: "COMPLETE",
      dnsQueryCount: 0,
      rawValuesRetained: false,
    },
    containment: {
      captureNetworkMode: "none",
      setupNetworkMode: "none",
      publishNetworkMode: "none",
      serverNetworkMode: "container:<capture-container-id>",
      noPublishedPorts: true,
      noProxyEnvironment: true,
      unexpectedActionDetected: false,
    },
    cleanup: { status: "COMPLETE", remainingResourceCount: 0 },
    errorCodes: complete ? [] : ["CAPTURE_INCOMPLETE"],
  };
}

function mockCore(input, { missingCandidate = false } = {}) {
  const validated = validateReleaseRehearsalFixtureSet(input.fixtureSet);
  const fixture = validated.fixtures[0];
  const preflight = {
    baseline: preflightReleaseRehearsalActionWorkflow(input.baselineWorkflow, {
      variant: "baseline",
    }),
    candidate: preflightReleaseRehearsalActionWorkflow(input.candidateWorkflow, {
      variant: "candidate",
    }),
  };
  const baselineCase = caseResult(preflight.baseline, fixture);
  const candidateCase = caseResult(preflight.candidate, fixture, {
    complete: !missingCandidate,
  });
  const baselineActions = baselineCase.observedActions;
  const candidateActions = candidateCase.observedActions;
  const diff = diffReleaseRehearsalActions({
    baselineActions: missingCandidate ? [] : baselineActions,
    candidateActions: missingCandidate ? [] : candidateActions,
    baselineCoverage: missingCandidate
      ? { status: "COMPLETE", reasonCodes: [] }
      : { status: "COMPLETE", reasonCodes: [] },
    candidateCoverage: missingCandidate
      ? { status: "UNRESOLVED", reasonCodes: ["CAPTURE_INCOMPLETE"] }
      : { status: "COMPLETE", reasonCodes: [] },
  });
  return {
    schemaVersion: 1,
    outcome: missingCandidate
      ? "PARTIAL_ACTION_REHEARSAL"
      : "PASS_ACTION_REHEARSAL_CORE",
    status: missingCandidate ? "INCOMPLETE" : "PASS",
    cases: [baselineCase, candidateCase],
    diff,
    cleanup: { status: "COMPLETE", remainingResourceCount: 0 },
    imageCleanup: { status: "COMPLETE", remainingResourceCount: 0 },
    inventory: { unchanged: true, beforeCounts: {}, afterCounts: {} },
  };
}

function containmentFailureCore() {
  return {
    schemaVersion: 1,
    outcome: "FAIL_CONTAINMENT",
    status: "FAILED",
    cases: [],
    cleanup: { status: "COMPLETE", remainingResourceCount: 0 },
    imageCleanup: { status: "COMPLETE", remainingResourceCount: 0 },
    inventory: { unchanged: true, beforeCounts: {}, afterCounts: {} },
    errorCodes: ["CONTAINMENT_PROBE_FAILED"],
  };
}

async function writeInputs(root, { baseline = workflow(), candidate = workflow() } = {}) {
  const paths = {
    baseline: path.join(root, "baseline.json"),
    candidate: path.join(root, "candidate.json"),
    fixtures: path.join(root, "fixtures.json"),
  };
  await Promise.all([
    writeFile(paths.baseline, JSON.stringify(baseline), "utf8"),
    writeFile(paths.candidate, JSON.stringify(candidate), "utf8"),
    writeFile(paths.fixtures, JSON.stringify(fixtures()), "utf8"),
  ]);
  return paths;
}

function args(paths, output, additions = []) {
  return [
    "--baseline",
    paths.baseline,
    "--candidate",
    paths.candidate,
    "--fixtures",
    paths.fixtures,
    "--output",
    output,
    ...additions,
  ];
}

async function bundleText(directory) {
  const names = (await readdir(directory)).sort();
  return Promise.all(names.map((name) => readFile(path.join(directory, name), "utf8")));
}

test("strict arguments reject missing, duplicate, unknown, and excessive input", async () => {
  const cases = [
    [],
    ["--baseline", "a", "--baseline", "b"],
    ["--unknown", "value"],
    Array.from({ length: 13 }, () => "x"),
  ];
  for (const argv of cases) {
    const result = await executeReleaseRehearsalCommand(argv);
    assert.equal(result.status, "REJECTED");
    assert.equal(result.exitCode, 64);
  }
});

test("a complete mock rehearsal writes REHEARSAL_COMPLETE evidence", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-complete-"));
  try {
    const inputPaths = await writeInputs(root);
    const output = path.join(root, "result");
    await mkdir(output);
    const result = await executeReleaseRehearsalCommand(args(inputPaths, output), {
      runPair: async (input) => mockCore(input),
    });
    assert.equal(result.overallResult, "REHEARSAL_COMPLETE");
    assert.equal(result.exitCode, 0);
    assert.equal(result.verification.status, "VERIFIED");
    const summary = JSON.parse(await readFile(path.join(output, "summary.json"), "utf8"));
    assert.equal(summary.actionDiff.summary.totalChanges, 0);
    assert.equal(summary.evidenceCounts.observed.total, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a verified method change maps to REVIEW_REQUIRED", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-review-"));
  try {
    const inputPaths = await writeInputs(root, {
      candidate: workflow({ method: "PATCH" }),
    });
    const output = path.join(root, "result");
    const result = await executeReleaseRehearsalCommand(args(inputPaths, output), {
      runPair: async (input) => mockCore(input),
    });
    assert.equal(result.overallResult, "REVIEW_REQUIRED");
    assert.equal(result.exitCode, 2);
    const summary = JSON.parse(await readFile(path.join(output, "summary.json"), "utf8"));
    assert.equal(summary.actionDiff.summary.method_changed, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an unsupported workflow is blocked before Docker work", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-unsupported-"));
  try {
    const inputPaths = await writeInputs(root, {
      candidate: workflow({ dynamic: true }),
    });
    const output = path.join(root, "result");
    const result = await executeReleaseRehearsalCommand(args(inputPaths, output));
    assert.equal(result.overallResult, "BLOCKED_UNSUPPORTED");
    assert.equal(result.exitCode, 3);
    const summary = JSON.parse(await readFile(path.join(output, "summary.json"), "utf8"));
    assert.ok(summary.supportedScope.candidate.reasonCodes.includes("DESTINATION_DYNAMIC"));
    assert.equal(summary.containment.status, "NOT_RUN");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("missing evidence maps to INCOMPLETE_EVIDENCE without behavioral claims", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-incomplete-"));
  try {
    const inputPaths = await writeInputs(root);
    const output = path.join(root, "result");
    const result = await executeReleaseRehearsalCommand(args(inputPaths, output), {
      runPair: async (input) => mockCore(input, { missingCandidate: true }),
    });
    assert.equal(result.overallResult, "INCOMPLETE_EVIDENCE");
    assert.equal(result.exitCode, 4);
    const summary = JSON.parse(await readFile(path.join(output, "summary.json"), "utf8"));
    assert.equal(summary.actionDiff.summary.unresolved_coverage, 1);
    assert.equal(summary.actionDiff.summary.method_changed, 0);
    assert.equal(summary.evidenceCounts.unresolved.candidate, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("containment failure produces a failure report, never a successful result", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-containment-"));
  try {
    const inputPaths = await writeInputs(root);
    const output = path.join(root, "result");
    const result = await executeReleaseRehearsalCommand(args(inputPaths, output), {
      runPair: async () => containmentFailureCore(),
    });
    assert.equal(result.overallResult, "CONTAINMENT_FAILURE");
    assert.equal(result.exitCode, 5);
    const report = await readFile(path.join(output, "report.md"), "utf8");
    assert.match(report, /Result: CONTAINMENT_FAILURE/u);
    assert.doesNotMatch(report, /Result: (?:REHEARSAL_COMPLETE|REVIEW_REQUIRED)/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an existing non-empty output directory is preserved", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-output-"));
  try {
    const inputPaths = await writeInputs(root);
    const output = path.join(root, "result");
    await writeFile(output, "not-a-directory", "utf8");
    let runnerCalled = false;
    const result = await executeReleaseRehearsalCommand(args(inputPaths, output), {
      runPair: async () => {
        runnerCalled = true;
        return containmentFailureCore();
      },
    });
    assert.equal(result.exitCode, 64);
    assert.equal(runnerCalled, false);
    assert.equal(await readFile(output, "utf8"), "not-a-directory");

    await rm(output);
    await mkdir(output);
    const marker = path.join(output, "keep.txt");
    await writeFile(marker, "preserve-me", "utf8");
    const nonEmpty = await executeReleaseRehearsalCommand(args(inputPaths, output));
    assert.equal(nonEmpty.exitCode, 64);
    assert.equal(await readFile(marker, "utf8"), "preserve-me");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("symlink and malformed workflow input are rejected", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-input-"));
  try {
    const inputPaths = await writeInputs(root);
    const malformed = path.join(root, "malformed.json");
    await writeFile(malformed, "{", "utf8");
    const malformedResult = await executeReleaseRehearsalCommand(
      args({ ...inputPaths, candidate: malformed }, path.join(root, "malformed-output")),
    );
    assert.equal(malformedResult.exitCode, 64);
    assert.equal(malformedResult.errorCode, "INPUT_INVALID");

    const link = path.join(root, "baseline-link.json");
    try {
      await symlink(inputPaths.baseline, link, "file");
      const linked = await executeReleaseRehearsalCommand(
        args({ ...inputPaths, baseline: link }, path.join(root, "link-output")),
      );
      assert.equal(linked.exitCode, 64);
      assert.equal(linked.errorCode, "UNSAFE_FILE_TYPE");
    } catch (error) {
      if (!["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) throw error;
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("fixed inputs and an explicit timestamp produce byte-identical bundles", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-determinism-"));
  try {
    const inputPaths = await writeInputs(root);
    const timestamp = ["--timestamp", "2026-08-06T12:00:00.000Z"];
    const first = path.join(root, "first");
    const second = path.join(root, "second");
    const runPair = async (input) => mockCore(input);
    const left = await executeReleaseRehearsalCommand(args(inputPaths, first, timestamp), {
      runPair,
    });
    const right = await executeReleaseRehearsalCommand(args(inputPaths, second, timestamp), {
      runPair,
    });
    assert.equal(left.exitCode, 0);
    assert.equal(right.exitCode, 0);
    const leftFiles = await bundleText(first);
    const rightFiles = await bundleText(second);
    assert.deepEqual(leftFiles, rightFiles);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("manifest verification covers every generated file and strict summary fields", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-manifest-"));
  try {
    const inputPaths = await writeInputs(root);
    const output = path.join(root, "result");
    await executeReleaseRehearsalCommand(args(inputPaths, output), {
      runPair: async (input) => mockCore(input),
    });
    const verified = await verifyReleaseRehearsalEvidenceBundle(output);
    assert.equal(verified.status, "VERIFIED");
    assert.equal(verified.fileCount, 3);
    const summary = JSON.parse(await readFile(path.join(output, "summary.json"), "utf8"));
    assert.throws(
      () => validateReleaseRehearsalSummary({ ...summary, unknown: true }),
      /unknown fields/u,
    );

    const summaryPath = path.join(output, "summary.json");
    const reportPath = path.join(output, "report.md");
    const manifestPath = path.join(output, "evidence-manifest.json");
    const originalSummary = await readFile(summaryPath);
    const originalReport = await readFile(reportPath);
    const originalManifest = await readFile(manifestPath);

    await writeFile(summaryPath, Buffer.concat([originalSummary, Buffer.from(" ")]));
    await assert.rejects(
      verifyReleaseRehearsalEvidenceBundle(output),
      /canonical JSON/u,
    );
    await writeFile(summaryPath, originalSummary);

    await writeFile(reportPath, Buffer.concat([originalReport, Buffer.from("tampered\n")]));
    await assert.rejects(
      verifyReleaseRehearsalEvidenceBundle(output),
      /hash mismatch/u,
    );
    await writeFile(reportPath, originalReport);

    const changedManifest = JSON.parse(originalManifest.toString("utf8"));
    changedManifest.generation = {
      generatedAt: "2026-08-06T12:00:00.000Z",
      timestampSource: "caller",
    };
    await writeFile(manifestPath, canonicalJson(changedManifest) + "\n", "utf8");
    await assert.rejects(
      verifyReleaseRehearsalEvidenceBundle(output),
      /canonical fingerprint/u,
    );
    await writeFile(manifestPath, originalManifest);
    assert.equal(
      (await verifyReleaseRehearsalEvidenceBundle(output)).status,
      "VERIFIED",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("secret and raw payload-value scans are high-confidence and fail closed", async () => {
  const direct = scanReleaseRehearsalEvidenceText([
    "Bearer abcdefghijklmnop",
    "fixture-payload-value-551c",
  ], {
    forbiddenValues: ["fixture-payload-value-551c"],
  });
  assert.equal(direct.passed, false);
  assert.equal(direct.secretPatternMatches, 1);
  assert.equal(direct.forbiddenValueMatches, 1);

  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-redaction-"));
  try {
    const inputPaths = await writeInputs(root);
    const output = path.join(root, "result");
    const result = await executeReleaseRehearsalCommand(args(inputPaths, output), {
      runPair: async (input) => mockCore(input),
    });
    assert.equal(result.redactionScan.passed, true);
    const text = (await bundleText(output)).join("\n");
    for (const rawValue of [
      "query-value-991a",
      "workflow-payload-value-662b",
      "fixture-header-value-881a",
      "fixture-payload-value-551c",
      "stub-payload-value-772a",
    ]) {
      assert.doesNotMatch(text, new RegExp(rawValue, "u"));
    }
    assert.doesNotMatch(
      text,
      /\bsecure\b|security guarantee|penetration test passed|production safe/iu,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("interrupt and publication errors remove private staging output", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase7-cleanup-"));
  try {
    const inputPaths = await writeInputs(root);
    const controller = new AbortController();
    const interrupted = executeReleaseRehearsalCommand(
      args(inputPaths, path.join(root, "interrupted")),
      {
        signal: controller.signal,
        runPair: async (_input, options) =>
          new Promise((_resolve, reject) => {
            options.signal.addEventListener(
              "abort",
              () => reject(Object.assign(new Error("interrupted"), { code: "ACTION_INTERRUPTED" })),
              { once: true },
            );
          }),
      },
    );
    controller.abort();
    const interruptedResult = await interrupted;
    assert.equal(interruptedResult.exitCode, 130);

    const output = path.join(root, "changed-output");
    await mkdir(output);
    const changed = await executeReleaseRehearsalCommand(args(inputPaths, output), {
      runPair: async (input) => {
        await writeFile(path.join(output, "external-change.txt"), "preserve", "utf8");
        return mockCore(input);
      },
    });
    assert.equal(changed.exitCode, 64);
    assert.equal(await readFile(path.join(output, "external-change.txt"), "utf8"), "preserve");
    const leftovers = (await readdir(root)).filter((name) =>
      name.includes(".rehearsal-tmp-"),
    );
    assert.deepEqual(leftovers, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

let failed = 0;
for (const entry of tests) {
  try {
    await entry.callback();
  } catch (error) {
    failed += 1;
    console.error(`not ok - ${entry.name}`);
    console.error(error);
  }
}

if (failed > 0) {
  process.exitCode = 1;
} else {
  console.log(`release rehearsal CLI unit core: ${tests.length} tests passed`);
}
