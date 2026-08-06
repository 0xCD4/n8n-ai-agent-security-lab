import assert from "node:assert/strict";

import { runReleaseRehearsalN8nExportIntegration } from "../src/release-rehearsal-n8n-export-docker.mjs";
import {
  RELEASE_REHEARSAL_N8N_EXPORT_LIMITS,
} from "../src/release-rehearsal-n8n-export.mjs";
import {
  RELEASE_REHEARSAL_N8N_IMAGE,
  serializeReleaseRehearsalN8nLogicalResult,
} from "../src/release-rehearsal-n8n.mjs";

const suite = await runReleaseRehearsalN8nExportIntegration();

assert.equal(suite.status, "TRACE_EXPORT_UNAVAILABLE");
assert.deepEqual(suite.errorCodes, []);
assert.ok(suite.result);
const result = suite.result;
assert.equal(result.status, "TRACE_EXPORT_UNAVAILABLE");
assert.deepEqual(result.image, RELEASE_REHEARSAL_N8N_IMAGE);
assert.equal(result.cli.importSucceeded, true);
assert.equal(result.cli.executionSucceeded, true);
assert.equal(result.cli.exportSucceeded, true);
assert.equal(result.cli.stdoutParsingUsed, false);
assert.equal(
  result.cli.exportCommand,
  "n8n export:entities --outputDir=<empty-dir> --includeExecutionHistoryDataTables=true",
);

assert.equal(result.capture.status, "CORRELATED");
assert.equal(result.capture.eventCount, 1);
assert.equal(result.capture.nodeId, "csint-capture-http");
assert.equal(result.capture.method, "POST");
assert.equal(result.capture.forwarded, false);
assert.equal(result.capture.captureStatus, "COMPLETE");
assert.equal(result.capture.dnsStatus, "COMPLETE");
assert.equal(result.capture.dnsQueryCount, 0);

assert.equal(result.export.status, "TRACE_EXPORT_UNAVAILABLE");
assert.equal(result.export.archive.format, "ZIP_JSONL");
assert.ok(result.export.archive.archiveBytes > 0);
assert.ok(result.export.archive.archiveBytes <= RELEASE_REHEARSAL_N8N_EXPORT_LIMITS.maxArchiveBytes);
assert.match(result.export.archive.archiveSha256, /^[a-f0-9]{64}$/u);
assert.ok(result.export.archive.fileCount <= RELEASE_REHEARSAL_N8N_EXPORT_LIMITS.maxEntries);
assert.ok(
  result.export.archive.totalUncompressedBytes <=
    RELEASE_REHEARSAL_N8N_EXPORT_LIMITS.maxTotalEntryBytes,
);
assert.deepEqual(
  result.export.archive.targetFiles.map((file) => file.kind),
  ["workflow", "execution", "executionData"],
);
assert.ok(
  result.export.archive.targetFiles.every(
    (file) => file.bytes <= RELEASE_REHEARSAL_N8N_EXPORT_LIMITS.maxEntryBytes,
  ),
);
assert.equal(
  result.export.archive.targetPayloadEncoding,
  "OPAQUE_SALTED_BASE64_ENVELOPE",
);
assert.equal(result.export.archive.encryptedTargetFileCount, 3);
assert.equal(result.export.archive.rawRetained, false);
assert.equal(result.export.correlation, null);
assert.equal(result.export.trace, null);
assert.deepEqual(result.export.requiredEvidence, {
  terminalStatus: false,
  executedNodeIdentities: false,
  nodeOrder: false,
  runAndOutputIndexes: false,
  itemLinkInformation: false,
  downstreamFinalNodeExecution: false,
});
assert.deepEqual(result.export.limitationCodes, [
  "DOCUMENTED_EXPORT_TARGETS_ENCRYPTED",
  "EXACT_WORKFLOW_EXECUTION_CORRELATION_UNAVAILABLE",
  "NO_DOCUMENTED_STANDALONE_DECRYPT_OUTPUT_SURFACE",
]);

assert.equal(result.containment.captureNetworkMode, "none");
assert.equal(result.containment.setupNetworkMode, "none");
assert.equal(result.containment.runnerNetworkMode, "container:<capture-container-id>");
assert.equal(result.containment.exporterNetworkMode, "none");
assert.equal(result.containment.noPublishedPorts, true);
assert.equal(result.containment.noProxyEnvironment, true);
assert.equal(result.containment.externalHooksConfigured, false);
for (const security of [
  result.containment.captureSecurity,
  result.containment.setupSecurity,
  result.containment.runnerSecurity,
  result.containment.exporterSecurity,
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

for (const scan of [
  result.operational.streamScans.importAttached.stdout,
  result.operational.streamScans.importAttached.stderr,
  result.operational.streamScans.executeAttached.stdout,
  result.operational.streamScans.executeAttached.stderr,
  result.operational.streamScans.exportAttached.stdout,
  result.operational.streamScans.exportAttached.stderr,
  ...Object.values(result.operational.streamScans.dockerLogs).flatMap((logs) => [
    logs.stdout,
    logs.stderr,
  ]),
]) {
  assert.equal(scan.encryptionKeyAbsent, true);
  assert.equal(scan.credentialPatternAbsent, true);
  assert.equal(scan.retained, false);
}

assert.equal(result.cleanup.status, "COMPLETE");
assert.equal(result.cleanup.setupContainerRemoved, true);
assert.equal(result.cleanup.runnerContainerRemoved, true);
assert.equal(result.cleanup.exporterContainerRemoved, true);
assert.equal(result.cleanup.captureContainerRemoved, true);
assert.equal(result.cleanup.n8nVolumeRemoved, true);
assert.equal(result.cleanup.privateRunDirectoryRemoved, true);
assert.equal(result.cleanup.rawArchiveDeleted, true);
assert.equal(result.cleanup.exportDirectoryWasEmptyAfterDeletion, true);
assert.equal(result.cleanup.captureImageRemoved, true);
assert.equal(result.cleanup.remainingResourceCount, 0);
assert.equal(suite.inventory.unchanged, true);
assert.deepEqual(suite.inventory.afterCounts, suite.inventory.beforeCounts);
assert.deepEqual(suite.inventory.managedAfterCounts, {
  containers: 0,
  images: 0,
  volumes: 0,
  networks: 0,
});
assert.equal(suite.inventory.managedResourceCount, 0);
assert.equal(suite.imageCleanup.status, "COMPLETE");
assert.equal(suite.imageCleanup.remainingResourceCount, 0);

const serialized = serializeReleaseRehearsalN8nLogicalResult(result);
assert.doesNotMatch(
  serialized,
  /\.invalid\b|Bearer\s|authorization|cookie|password|api[_-]?key|rawStdout|rawStderr|N8N_ENCRYPTION_KEY/iu,
);
assert.doesNotMatch(
  JSON.stringify(suite),
  /probe@rehearsal\.invalid|Bearer\s|-----BEGIN [^-]{0,64}PRIVATE KEY-----/iu,
);

process.stdout.write(
  "release rehearsal n8n documented entity export: TRACE_EXPORT_UNAVAILABLE (1 execution, 0 skipped)\n",
);
process.stdout.write(`image identity: ${result.image.repositoryDigest}\n`);
process.stdout.write(
  "import, execution, one capture, export, bounded inventory, raw deletion, and cleanup: COMPLETE\n",
);
process.stdout.write(
  "trace boundary: target entity members are encrypted and have no documented standalone decrypt output surface\n",
);
