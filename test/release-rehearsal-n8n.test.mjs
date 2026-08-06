import assert from "node:assert/strict";

import { runReleaseRehearsalN8nIntegrationSuite } from "../src/release-rehearsal-n8n-docker.mjs";
import {
  RELEASE_REHEARSAL_N8N_IMAGE,
  serializeReleaseRehearsalN8nLogicalResult,
} from "../src/release-rehearsal-n8n.mjs";

const suite = await runReleaseRehearsalN8nIntegrationSuite();

assert.equal(
  suite.status,
  "EXECUTION_TRACE_UNAVAILABLE",
  "the pinned CLI result is prefixed output, not strict JSON",
);
assert.deepEqual(suite.errorCodes, []);
assert.ok(suite.primary);
assert.equal(suite.primary.status, "EXECUTION_TRACE_UNAVAILABLE");
assert.deepEqual(suite.primary.image, RELEASE_REHEARSAL_N8N_IMAGE);
assert.equal(suite.primary.cli.importSucceeded, true);
assert.equal(suite.primary.cli.executionSucceeded, true);
assert.equal(suite.primary.cli.rawOutputStrictJson, false);
assert.ok(suite.primary.errorCodes.includes("RAW_OUTPUT_JSON_INVALID"));
assert.equal(suite.primary.execution, null);
assert.equal(suite.primary.capture.status, "CORRELATED");
assert.equal(suite.primary.capture.eventCount, 1);
assert.equal(suite.primary.capture.nodeId, "csint-capture-http");
assert.equal(suite.primary.capture.method, "POST");
assert.equal(suite.primary.capture.forwarded, false);
assert.equal(suite.primary.capture.captureStatus, "COMPLETE");
assert.equal(suite.primary.capture.dnsStatus, "COMPLETE");
assert.equal(suite.primary.capture.dnsQueryCount, 0);

assert.equal(suite.primary.containment.captureNetworkMode, "none");
assert.equal(suite.primary.containment.setupNetworkMode, "none");
assert.equal(
  suite.primary.containment.runnerNetworkMode,
  "container:<capture-container-id>",
);
assert.equal(suite.primary.containment.noPublishedPorts, true);
assert.equal(suite.primary.containment.noProxyEnvironment, true);
assert.equal(suite.primary.containment.externalHooksConfigured, false);
for (const security of [
  suite.primary.containment.captureSecurity,
  suite.primary.containment.setupSecurity,
  suite.primary.containment.runnerSecurity,
]) {
  assert.equal(security.privileged, false);
  assert.equal(security.readOnlyRootFilesystem, true);
  assert.deepEqual(security.capabilityDrop, ["ALL"]);
  assert.deepEqual(security.capabilityAdd, []);
  assert.equal(security.noNewPrivileges, true);
  assert.equal(security.seccompUnconfined, false);
  assert.equal(security.user, "1000:1000");
  assert.equal(security.dockerSocketMounted, false);
  assert.equal(security.publishedPorts, false);
}
assert.equal(
  suite.primary.containment.setupSecurity.syntheticEncryptionKeyConfigured,
  true,
);
assert.equal(
  suite.primary.containment.runnerSecurity.syntheticEncryptionKeyConfigured,
  true,
);
assert.equal(
  suite.primary.containment.setupSecurity.environmentNames.includes(
    "N8N_ENCRYPTION_KEY",
  ),
  false,
);
assert.equal(
  suite.primary.containment.runnerSecurity.environmentNames.includes(
    "N8N_ENCRYPTION_KEY",
  ),
  false,
);
assert.equal(
  suite.primary.containment.volumeSecurity.ownershipLabelsVerified,
  true,
);

const framing = suite.primary.operational.rawFraming;
assert.ok(framing.bytes > 0);
assert.ok(framing.firstBraceByteOffset > 0, "non-JSON prefix must be observed");
assert.equal(framing.extractionAttempted, false);
assert.equal(framing.retained, false);
assert.equal(suite.primary.operational.rawValuesRetained, false);
for (const scan of [
  suite.primary.operational.streamScans.importAttached.stdout,
  suite.primary.operational.streamScans.importAttached.stderr,
  suite.primary.operational.streamScans.executeAttached.stdout,
  suite.primary.operational.streamScans.executeAttached.stderr,
  suite.primary.operational.streamScans.dockerLogs.setup.stdout,
  suite.primary.operational.streamScans.dockerLogs.setup.stderr,
  suite.primary.operational.streamScans.dockerLogs.runner.stdout,
  suite.primary.operational.streamScans.dockerLogs.runner.stderr,
  suite.primary.operational.streamScans.dockerLogs.capture.stdout,
  suite.primary.operational.streamScans.dockerLogs.capture.stderr,
]) {
  assert.equal(scan.encryptionKeyAbsent, true);
  assert.equal(scan.credentialPatternAbsent, true);
  assert.equal(scan.retained, false);
}

assert.equal(suite.primary.cleanup.status, "COMPLETE");
assert.equal(suite.primary.cleanup.setupContainerRemoved, true);
assert.equal(suite.primary.cleanup.runnerContainerRemoved, true);
assert.equal(suite.primary.cleanup.captureContainerRemoved, true);
assert.equal(suite.primary.cleanup.n8nVolumeRemoved, true);
assert.equal(suite.primary.cleanup.privateRunDirectoryRemoved, true);
assert.equal(suite.primary.cleanup.captureImageRemoved, true);
assert.equal(suite.primary.cleanup.remainingResourceCount, 0);

assert.deepEqual(
  suite.failureCases.map((result) => ({
    scenario: result.expectedFailureScenario,
    status: result.status,
    cleanup: result.cleanup.status,
    expectedCode: result.errorCodes.includes(result.expectedFailureCode),
  })),
  [
    {
      scenario: "import-failure",
      status: "FAILED",
      cleanup: "COMPLETE",
      expectedCode: true,
    },
    {
      scenario: "execution-timeout",
      status: "FAILED",
      cleanup: "COMPLETE",
      expectedCode: true,
    },
    {
      scenario: "capture-mismatch",
      status: "FAILED",
      cleanup: "COMPLETE",
      expectedCode: true,
    },
  ],
);
assert.equal(suite.inventory.unchanged, true);
assert.deepEqual(suite.inventory.afterCounts, suite.inventory.beforeCounts);
assert.equal(suite.imageCleanup.status, "COMPLETE");
assert.equal(suite.imageCleanup.remainingResourceCount, 0);

const serialized = serializeReleaseRehearsalN8nLogicalResult(suite.primary);
assert.doesNotMatch(
  serialized,
  /\.invalid\b|Bearer\s|authorization|cookie|password|rawStdout|rawStderr|N8N_ENCRYPTION_KEY/iu,
);
assert.doesNotMatch(
  JSON.stringify(suite),
  /probe@rehearsal\.invalid|Bearer\s|-----BEGIN [^-]{0,64}PRIVATE KEY-----/iu,
);

process.stdout.write(
  "release rehearsal n8n CLI integration: EXECUTION_TRACE_UNAVAILABLE (4 cases, 0 skipped)\n",
);
process.stdout.write(
  `image identity: ${suite.primary.image.repositoryDigest}\n`,
);
process.stdout.write(
  "import, execution, capture correlation, containment, and cleanup: COMPLETE\n",
);
process.stdout.write(
  "strict raw JSON: unavailable because the documented CLI emitted a non-JSON prefix\n",
);
