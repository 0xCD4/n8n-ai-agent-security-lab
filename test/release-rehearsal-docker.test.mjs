import assert from "node:assert/strict";

import {
  runReleaseRehearsalDockerIntegrationSuite,
  serializeReleaseRehearsalLogicalResult,
} from "../src/release-rehearsal-docker.mjs";

const suite = await runReleaseRehearsalDockerIntegrationSuite();

assert.equal(suite.status, "PASS", "Docker containment suite must pass without skips.");
assert.equal(suite.primary.status, "PASS");
assert.equal(suite.primary.network.captureMode, "none");
assert.equal(
  suite.primary.network.probeMode,
  "container:<capture-container-id>",
);
assert.equal(suite.primary.network.captureModeVerified, true);
assert.equal(suite.primary.network.probeModeVerified, true);
assert.equal(suite.primary.network.onlyApprovedAttachments, true);
assert.deepEqual(suite.primary.interfaces.names, ["lo"]);
assert.equal(suite.primary.interfaces.onlyLoopback, true);
assert.equal(suite.primary.routes.ipv4Default, false);
assert.equal(suite.primary.routes.ipv6Default, false);
assert.equal(suite.primary.http.succeeded, true);
assert.equal(suite.primary.capture.status, "COMPLETE");
assert.equal(suite.primary.capture.eventCount, 1);
assert.equal(suite.primary.capture.forwarded, false);
assert.equal(suite.primary.dns.resolverIsLocalOnly, true);
assert.equal(suite.primary.dns.ordinaryQuery.nxdomain, true);
assert.equal(suite.primary.hostAccess.blocked, true);
assert.equal(suite.primary.dnsSink.status, "COMPLETE");
assert.ok(suite.primary.dnsSink.queryCount >= 1);
assert.equal(suite.primary.dnsSink.forwarded, false);
assert.ok(
  suite.primary.dnsSink.queries.every((query) =>
    /^[a-f0-9]{64}$/u.test(query.queryNameSha256),
  ),
);
assert.deepEqual(
  suite.primary.blockedDestinations.map(({ label, blocked }) => ({ label, blocked })),
  [
    { label: "public-test-ip", blocked: true },
    { label: "cloud-metadata", blocked: true },
    { label: "private-lan", blocked: true },
    { label: "docker-gateway", blocked: true },
  ],
);
assert.equal(suite.primary.publishedPorts.capture, true);
assert.equal(suite.primary.publishedPorts.probe, true);
assert.equal(suite.primary.security.capture.privileged, false);
assert.equal(suite.primary.security.probe.privileged, false);
assert.deepEqual(suite.primary.security.capture.capabilityAdd, []);
assert.deepEqual(suite.primary.security.probe.capabilityAdd, []);
assert.equal(suite.primary.security.capture.seccompUnconfined, false);
assert.equal(suite.primary.security.probe.seccompUnconfined, false);
assert.equal(suite.primary.security.capture.dockerSocketMounted, false);
assert.equal(suite.primary.security.probe.dockerSocketMounted, false);
assert.equal(suite.primary.cleanup.status, "COMPLETE");
assert.equal(suite.primary.cleanup.imageRemoved, true);
assert.match(
  suite.primary.image.repositoryDigest,
  /^node@sha256:[a-f0-9]{64}$/u,
);
assert.match(suite.primary.image.localImageId, /^sha256:[a-f0-9]{64}$/u);

assert.deepEqual(
  suite.failureCases.map((result) => ({
    scenario: result.expectedFailureScenario,
    cleanup: result.cleanup.status,
    expectedCode:
      result.expectedFailureScenario === "capture-crash"
        ? result.errorCodes.includes("CAPTURE_CRASHED")
        : result.expectedFailureScenario === "probe-failure"
          ? result.errorCodes.includes("PROBE_FAILED")
          : result.errorCodes.includes("PROBE_TIMEOUT"),
  })),
  [
    { scenario: "capture-crash", cleanup: "COMPLETE", expectedCode: true },
    { scenario: "probe-failure", cleanup: "COMPLETE", expectedCode: true },
    { scenario: "timeout", cleanup: "COMPLETE", expectedCode: true },
  ],
);
assert.equal(suite.inventory.unchanged, true);
assert.deepEqual(suite.inventory.afterCounts, suite.inventory.beforeCounts);

const serialized = serializeReleaseRehearsalLogicalResult(suite.primary);
assert.doesNotMatch(
  serialized,
  /\.invalid\b|host\.docker\.internal|authorization|cookie|password|Bearer\s|[A-Za-z]:[\\/]/iu,
);
for (const result of [suite.primary, ...suite.failureCases]) {
  assert.doesNotMatch(
    result.operational.containerLogs,
    /\.invalid\b|host\.docker\.internal|x-csint-rehearsal|authorization|cookie|password|Bearer\s/iu,
  );
}

process.stdout.write("release rehearsal Docker containment: PASS (4 cases, 0 skipped)\n");
process.stdout.write(`image identity: ${suite.primary.image.repositoryDigest}\n`);
process.stdout.write("cleanup and unrelated-resource inventory: COMPLETE\n");
