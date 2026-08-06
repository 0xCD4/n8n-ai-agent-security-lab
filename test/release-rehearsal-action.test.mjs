import assert from "node:assert/strict";

import { runReleaseRehearsalActionIntegrationSuite } from "../src/release-rehearsal-action-docker.mjs";
import { RELEASE_REHEARSAL_N8N_IMAGE } from "../src/release-rehearsal-n8n.mjs";

const suite = await runReleaseRehearsalActionIntegrationSuite();

if (suite.outcome !== "PASS_ACTION_REHEARSAL_CORE") {
  process.stderr.write(
    JSON.stringify({
      outcome: suite.outcome,
      scenarios: suite.scenarios,
      errorCodes: suite.errorCodes,
      caseErrors: Object.fromEntries(
        suite.operational.results.map((scenario) => [
          scenario.name,
          scenario.result.cases.map((item) => ({
            variant: item.variant,
            status: item.status,
            errorCodes: item.errorCodes,
            captureStatus: item.evidence.captureStatus,
            captureEventCount: item.evidence.captureEventCount,
          })),
        ]),
      ),
    }) + "\n",
  );
}

assert.equal(suite.outcome, "PASS_ACTION_REHEARSAL_CORE");
assert.equal(suite.scenarioCount, 10);
assert.equal(suite.scenarios.length, 10);
assert.ok(suite.scenarios.every((scenario) => scenario.matchesExpected));
assert.ok(suite.scenarios.every((scenario) => scenario.cleanupStatus === "COMPLETE"));
assert.deepEqual(suite.image, RELEASE_REHEARSAL_N8N_IMAGE);
assert.equal(suite.containmentProbe.status, "PASS");
assert.equal(suite.containmentProbe.cleanupStatus, "COMPLETE");
assert.equal(suite.imageCleanup.status, "COMPLETE");
assert.equal(suite.imageCleanup.remainingResourceCount, 0);
assert.equal(suite.inventory.unchanged, true);
assert.deepEqual(suite.inventory.afterCounts, suite.inventory.beforeCounts);
assert.deepEqual(suite.inventory.managedAfterCounts, {
  containers: 0,
  images: 0,
  volumes: 0,
  networks: 0,
});
assert.equal(suite.inventory.managedAfterTotal, 0);
assert.deepEqual(suite.errorCodes, []);

const byName = new Map(
  suite.operational.results.map((scenario) => [scenario.name, scenario]),
);
assert.equal(byName.get("identical").result.diff.summary.totalChanges, 0);
assert.equal(byName.get("new-action").result.diff.summary.new_action, 1);
assert.equal(byName.get("removed-action").result.diff.summary.removed_action, 1);
assert.equal(
  byName.get("destination-change").result.diff.summary.destination_changed,
  1,
);
assert.equal(byName.get("method-change").result.diff.summary.method_changed, 1);
assert.equal(
  byName.get("count-change").result.diff.summary.action_count_changed,
  1,
);
assert.equal(
  byName.get("unsupported-dynamic").result.outcome,
  "BLOCKED_TRANSFORMATION_FIDELITY",
);
assert.equal(byName.get("unsupported-dynamic").result.cases.length, 0);
assert.equal(
  byName.get("correlation-mismatch").result.diff.summary.unresolved_coverage,
  1,
);
assert.equal(
  byName.get("missing-capture").result.diff.summary.unresolved_coverage,
  1,
);
assert.ok(
  byName
    .get("stub-variation")
    .result.cases.every((item) => item.evidence.responseStatuses.includes(202)),
);

const executedCases = suite.operational.results.flatMap(
  (scenario) => scenario.result.cases,
);
assert.equal(executedCases.length, 18);
for (const item of executedCases) {
  assert.equal(item.cleanup.status, "COMPLETE");
  assert.equal(item.cleanup.remainingResourceCount, 0);
  assert.equal(item.containment.captureNetworkMode, "none");
  assert.equal(item.containment.setupNetworkMode, "none");
  assert.equal(item.containment.publishNetworkMode, "none");
  assert.equal(
    item.containment.serverNetworkMode,
    "container:<capture-container-id>",
  );
  assert.equal(item.containment.noPublishedPorts, true);
  assert.equal(item.containment.noProxyEnvironment, true);
  assert.equal(item.evidence.captureForwarded, false);
  assert.equal(item.evidence.dnsQueryCount, 0);
  assert.equal(item.evidence.rawValuesRetained, false);
  assert.equal(item.process.n8nProcessExitCodeIsNodeTrace, false);
  assert.equal(item.process.n8nProcessExitCodeIsWorkflowStatus, false);
  assert.equal(item.process.startupCompletionMarkerObserved, true);
  assert.equal(item.process.healthReadinessObserved, true);
  assert.equal(item.process.startupOutputRetained, false);
  assert.equal(item.operational.rawValuesRetained, false);
  const scans = [
    ...Object.values(item.operational.logScans.setup.stream),
    ...Object.values(item.operational.logScans.setup.logs),
    ...Object.values(item.operational.logScans.publish.stream),
    ...Object.values(item.operational.logScans.publish.logs),
    ...Object.values(item.operational.logScans.capture),
    ...Object.values(item.operational.logScans.server),
  ];
  assert.ok(
    scans.every(
      (scan) =>
        scan.encryptionKeyAbsent === true &&
        scan.credentialPatternAbsent === true &&
        scan.retained === false,
    ),
  );
}

for (const scenario of suite.operational.results.filter(
  (item) => item.result.outcome === "PASS_ACTION_REHEARSAL_CORE",
)) {
  assert.deepEqual(scenario.result.resourceIsolation, {
    separateRunIds: true,
    separateCorrelationIds: true,
    separateVolumes: true,
    separateRunDirectories: true,
    separateCaptureLedgers: true,
  });
  assert.ok(
    scenario.result.cases.every(
      (item) =>
        item.process.importExitCode === 0 &&
        item.process.publishExitCode === 0 &&
        item.process.injectorExitCode === 0 &&
        item.status === "COMPLETE",
    ),
  );
}

const logicalText = JSON.stringify({
  outcome: suite.outcome,
  scenarios: suite.scenarios,
});
assert.doesNotMatch(
  logicalText,
  /Bearer\s|-----BEGIN [^-]{0,64}PRIVATE KEY-----|authorization|cookie|password|api[_-]?key|jsonBody|rawStdout|rawStderr|N8N_ENCRYPTION_KEY/iu,
);

process.stdout.write(
  "release rehearsal action integration: PASS_ACTION_REHEARSAL_CORE (10 scenarios, 18 contained cases, 0 skipped)\n",
);
process.stdout.write(`image identity: ${suite.image.repositoryDigest}\n`);
process.stdout.write(
  "observed capture comparison, fault closure, containment, redaction, and cleanup: COMPLETE\n",
);
