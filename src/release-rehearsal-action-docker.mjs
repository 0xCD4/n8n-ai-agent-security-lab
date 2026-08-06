import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { canonicalJson, fingerprintJson } from "./evidence-fingerprint.mjs";
import {
  createReleaseRehearsalActionCaptureConfig,
  createReleaseRehearsalUnresolvedActions,
  diffReleaseRehearsalObservedPair,
  normalizeReleaseRehearsalObservedActions,
  prepareReleaseRehearsalActionPair,
  serializeReleaseRehearsalActionCore,
} from "./release-rehearsal-action.mjs";
import {
  assertReleaseRehearsalPrivatePath,
  buildReleaseRehearsalCaptureCreateArgs,
  buildReleaseRehearsalCaptureImage,
  cleanupReleaseRehearsalContainer,
  createReleaseRehearsalDockerIdentifier,
  createReleaseRehearsalPrivateRunDirectory,
  getReleaseRehearsalDockerRuntime,
  inspectReleaseRehearsalContainer,
  inspectReleaseRehearsalDockerObject,
  listReleaseRehearsalDockerInventory,
  listReleaseRehearsalManagedDockerInventory,
  releaseRehearsalDockerInventoriesEqual,
  removeReleaseRehearsalCaptureImage,
  removeReleaseRehearsalPrivateRunDirectory,
  resolveReleaseRehearsalNodeImage,
  runReleaseRehearsalDockerCommand,
  runReleaseRehearsalDockerProbe,
  waitForReleaseRehearsalCaptureReady,
} from "./release-rehearsal-docker.mjs";
import {
  buildReleaseRehearsalN8nCreateArgs,
  inspectReleaseRehearsalN8nContainer,
  inspectReleaseRehearsalN8nVolume,
  RELEASE_REHEARSAL_N8N_ENVIRONMENT,
  cleanupReleaseRehearsalN8nVolume,
  createReleaseRehearsalN8nVolume,
  resolveReleaseRehearsalPinnedN8nImage,
  scanReleaseRehearsalN8nContainerLogs,
  scanReleaseRehearsalN8nProcessStream,
  validateReleaseRehearsalN8nContainerId,
} from "./release-rehearsal-n8n-docker.mjs";
import {
  RELEASE_REHEARSAL_N8N_CAPTURE_URL,
} from "./release-rehearsal-n8n.mjs";
import {
  serializeReleaseRehearsalTransformationManifest,
  transformReleaseRehearsalWorkflow,
} from "./release-rehearsal-transform.mjs";
import { readBoundedJsonFile } from "./safe-json.mjs";

export const RELEASE_REHEARSAL_ACTION_DOCKER_SCHEMA_VERSION = 1;

const CONTAINER_CONFIG_PATH = "/run/rehearsal/config/config.json";
const CONTAINER_FIXTURE_PATH = "/run/rehearsal/fixture/fixture-set.json";
const CONTAINER_OUTPUT_PATH = "/run/rehearsal/output";
const CONTAINER_RESOLVER_PATH = "/etc/resolv.conf";
const CONTAINER_WORKFLOW_PATH = "/run/rehearsal/workflow/workflow.json";
const CONTAINER_N8N_HOME = "/home/node/.n8n";
const ACTION_INJECTOR_PATH = "/app/lab/release-rehearsal-capture/injector.mjs";
const N8N_STARTUP_COMPLETION_MARKER = "\nEditor is now accessible via:\n";
const RESOLVER_CONTENT =
  "nameserver 127.0.0.1\noptions timeout:1 attempts:1 ndots:1\n";
const CASE_TIMEOUT_MS = 120_000;
const LOG_LIMIT_BYTES = 2 * 1024 * 1024;
const EVIDENCE_LIMITS = Object.freeze({
  maxBytes: 256 * 1024,
  maxDepth: 32,
  maxValues: 20_000,
});
const UNEXPECTED_ACTION_VIOLATION_CODES = new Set([
  "METHOD_MISMATCH",
  "METHOD_UNSUPPORTED",
  "NODE_UNKNOWN",
  "OCCURRENCE_LIMIT_EXCEEDED",
  "REQUEST_AFTER_FINALIZATION",
  "RESPONSE_SEQUENCE_EXHAUSTED",
  "ROUTE_UNEXPECTED",
]);
const EVIDENCE_IDENTITY_SEED_PATTERN = /^[a-f0-9]{64}$/u;

class ActionDockerError extends Error {
  constructor(code, category = "runtime") {
    super(code);
    this.code = code;
    this.category = category;
  }
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableUnique(values) {
  return [...new Set(values)].sort(stableCompare);
}

function inventoryCounts(inventory) {
  return Object.fromEntries(
    Object.entries(inventory).map(([key, values]) => [key, values.length]),
  );
}

function managedTotal(inventory) {
  return Object.values(inventory).reduce((sum, values) => sum + values.length, 0);
}

function labels(ownerId, runId, role) {
  return { ownerId, runId, role };
}

function deterministicEvidenceIdentity(seed, variant, fixtureCanonicalSha256) {
  if (!EVIDENCE_IDENTITY_SEED_PATTERN.test(seed)) {
    throw new TypeError("evidenceIdentitySeed must be a lowercase SHA-256 value.");
  }
  const material = { seed, variant, fixtureCanonicalSha256 };
  return {
    runId: `evidence-${fingerprintJson({ ...material, kind: "run" }).slice(0, 32)}`,
    correlationId: `correlation-${fingerprintJson({
      ...material,
      kind: "correlation",
    }).slice(0, 32)}`,
  };
}

function normalizeActionRunOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("Action runner options must be an object.");
  }
  const allowed = new Set(["evidenceIdentitySeed", "faults", "signal"]);
  if (Object.keys(options).some((key) => !allowed.has(key))) {
    throw new TypeError("Action runner options contain unknown fields.");
  }
  if (
    options.evidenceIdentitySeed !== undefined &&
    !EVIDENCE_IDENTITY_SEED_PATTERN.test(options.evidenceIdentitySeed)
  ) {
    throw new TypeError("evidenceIdentitySeed must be a lowercase SHA-256 value.");
  }
  if (
    options.signal !== undefined &&
    options.signal !== null &&
    (!options.signal ||
      typeof options.signal !== "object" ||
      typeof options.signal.aborted !== "boolean" ||
      typeof options.signal.addEventListener !== "function")
  ) {
    throw new TypeError("signal must be an AbortSignal.");
  }
  return {
    evidenceIdentitySeed: options.evidenceIdentitySeed ?? null,
    faults: options.faults ?? {},
    signal: options.signal ?? null,
  };
}

function strictInjectorDiagnosticCode(error) {
  const text = String(error?.diagnostic ?? "").trim();
  if (!text || Buffer.byteLength(text, "utf8") > 1_024) return null;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    canonicalJson(parsed) !== text ||
    Object.keys(parsed).length !== 1 ||
    !/^N8N_READY_TIMEOUT_(?:HTTP_[1-5][0-9]{2}|TRANSPORT)$/u.test(
      parsed.code ?? "",
    )
  ) {
    return null;
  }
  return parsed.code;
}

async function inspectExitCode(containerId) {
  if (!containerId) return null;
  const inspect = await inspectReleaseRehearsalDockerObject(
    "container",
    containerId,
    { allowMissing: true },
  );
  return Number.isInteger(inspect?.State?.ExitCode) ? inspect.State.ExitCode : null;
}

async function stopContainer(containerId, code) {
  if (!containerId) return;
  const inspect = await inspectReleaseRehearsalDockerObject(
    "container",
    containerId,
    { allowMissing: true },
  );
  if (inspect?.State?.Running) {
    await runReleaseRehearsalDockerCommand(
      ["container", "stop", "--time", "5", containerId],
      { code, timeoutMs: 10_000 },
    );
  }
}

async function waitForN8nStartupCompletion({
  containerId,
  encryptionKey,
  runDocker,
  inspectDocker,
  signal,
}) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const logs = await runDocker(["container", "logs", containerId], {
      code: "ACTION_SERVER_STARTUP_LOG_FAILED",
      maxBuffer: LOG_LIMIT_BYTES,
      timeoutMs: 5_000,
    });
    const stdoutScan = scanReleaseRehearsalN8nProcessStream(
      logs.stdout,
      encryptionKey,
      "ACTION_SERVER_STARTUP_STDOUT",
    );
    const stderrScan = scanReleaseRehearsalN8nProcessStream(
      logs.stderr,
      encryptionKey,
      "ACTION_SERVER_STARTUP_STDERR",
    );
    if (
      `${logs.stdout}\n${logs.stderr}`.includes(N8N_STARTUP_COMPLETION_MARKER)
    ) {
      return {
        completionMarkerObserved: true,
        stdoutBytes: stdoutScan.bytes,
        stderrBytes: stderrScan.bytes,
        retained: false,
      };
    }
    const inspect = await inspectDocker("container", containerId, {
      allowMissing: true,
    });
    if (!inspect?.State?.Running) {
      throw new ActionDockerError("ACTION_SERVER_EXITED_BEFORE_READY");
    }
    try {
      await delay(250, undefined, { signal });
    } catch {
      throw new ActionDockerError("ACTION_CASE_TIMEOUT");
    }
  }
  throw new ActionDockerError("ACTION_SERVER_STARTUP_MARKER_TIMEOUT");
}

function rawFixtureSet(fixture) {
  const raw = structuredClone(fixture);
  delete raw.canonicalSha256;
  return { schemaVersion: 1, fixtures: [raw] };
}

async function prepareActionCaseFiles({
  workflow,
  preflight,
  fixture,
  variant,
  runId,
  caseId,
  correlationId,
  sentCorrelationId,
  resourceRunId = runId,
}) {
  const runDirectory = await createReleaseRehearsalPrivateRunDirectory(resourceRunId);
  try {
    const configDirectory = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "config"),
    );
    const fixtureDirectory = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "fixture"),
    );
    const outputDirectory = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "output"),
    );
    const workflowDirectory = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "workflow"),
    );
    await Promise.all(
      [configDirectory, fixtureDirectory, outputDirectory, workflowDirectory].map(
        (directory) => mkdir(directory, { mode: 0o700 }),
      ),
    );

    const transformed = transformReleaseRehearsalWorkflow(workflow, {
      variant,
      runId,
      caseId,
      fixtureId: fixture.id,
      correlationId: sentCorrelationId,
      captureUrl: RELEASE_REHEARSAL_N8N_CAPTURE_URL,
    });
    if (
      transformed.manifest.workflow.originalCanonicalSha256 !==
      preflight.workflow.canonicalSha256
    ) {
      throw new ActionDockerError("TRANSFORM_ORIGINAL_BINDING_MISMATCH");
    }
    serializeReleaseRehearsalTransformationManifest(transformed.manifest);
    const captureConfig = createReleaseRehearsalActionCaptureConfig({
      runId,
      caseId,
      correlationId,
      variant,
      fixture,
      preflight,
    });

    const configPath = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(configDirectory, "config.json"),
    );
    const fixturePath = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(fixtureDirectory, "fixture-set.json"),
    );
    const workflowPath = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(workflowDirectory, "workflow.json"),
    );
    const resolverPath = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "resolv.conf"),
    );
    await Promise.all([
      writeFile(configPath, canonicalJson(captureConfig) + "\n", {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      }),
      writeFile(fixturePath, canonicalJson(rawFixtureSet(fixture)) + "\n", {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      }),
      writeFile(
        workflowPath,
        canonicalJson(transformed.transformedWorkflow) + "\n",
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      ),
      writeFile(resolverPath, RESOLVER_CONTENT, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      }),
    ]);
    return {
      runDirectory,
      configPath,
      fixturePath,
      outputDirectory,
      workflowPath,
      resolverPath,
      captureConfig,
      transformed,
    };
  } catch (error) {
    await removeReleaseRehearsalPrivateRunDirectory(runDirectory);
    throw error;
  }
}

async function readInjectorResult(outputDirectory) {
  return readBoundedJsonFile(path.join(outputDirectory, "injector-result.json"), {
    ...EVIDENCE_LIMITS,
    label: "action injector result",
  });
}

async function readCaptureEvidence(outputDirectory) {
  const names = [
    "capture-events.json",
    "capture-summary.json",
    "dns-events.json",
    "dns-summary.json",
  ];
  const values = await Promise.all(
    names.map((name) =>
      readBoundedJsonFile(path.join(outputDirectory, name), {
        ...EVIDENCE_LIMITS,
        label: name,
      }),
    ),
  );
  return Object.fromEntries(names.map((name, index) => [name, values[index]]));
}

function containerMounts({ volumeName, resolverPath, workflowPath }) {
  const mounts = [
    {
      type: "volume",
      name: volumeName,
      destination: CONTAINER_N8N_HOME,
      readWrite: true,
    },
    {
      type: "bind",
      source: resolverPath,
      destination: CONTAINER_RESOLVER_PATH,
      readWrite: false,
    },
  ];
  if (workflowPath) {
    mounts.push({
      type: "bind",
      source: workflowPath,
      destination: CONTAINER_WORKFLOW_PATH,
      readWrite: false,
    });
  }
  return mounts;
}

async function runAttachedContainer({
  createArgs,
  ownership,
  inspectExpected,
  createCode,
  runCode,
  encryptionKey,
  runDocker,
  createDocker = runDocker,
  inspectDocker,
}) {
  let containerId = null;
  let result = null;
  let failure = null;
  try {
    const created = await createDocker(createArgs, {
      code: createCode,
      timeoutMs: 15_000,
    });
    containerId = validateReleaseRehearsalN8nContainerId(
      created.stdout.trim(),
    );
    const inspect = await inspectDocker("container", containerId);
    const security = inspectReleaseRehearsalN8nContainer(
      inspect,
      inspectExpected,
    );
    const attached = await runDocker(
      ["container", "start", "--attach", containerId],
      {
        code: runCode,
        timeoutCode: `${runCode}_TIMEOUT`,
        maxBuffer: LOG_LIMIT_BYTES,
        timeoutMs: 30_000,
      },
    );
    const exitCode = await inspectExitCode(containerId);
    const streamScan = {
      stdout: scanReleaseRehearsalN8nProcessStream(
        attached.stdout,
        encryptionKey,
        `${runCode}_STDOUT`,
      ),
      stderr: scanReleaseRehearsalN8nProcessStream(
        attached.stderr,
        encryptionKey,
        `${runCode}_STDERR`,
      ),
    };
    const logScan = await scanReleaseRehearsalN8nContainerLogs(
      containerId,
      encryptionKey,
      runCode,
    );
    result = { containerId, security, exitCode, streamScan, logScan };
  } catch (error) {
    failure = error;
  }
  let cleanup;
  try {
    cleanup = await cleanupReleaseRehearsalContainer(containerId, ownership);
  } catch (error) {
    throw new ActionDockerError(
      error?.code ?? `${runCode}_CLEANUP_FAILED`,
      "containment",
    );
  }
  if (!cleanup.removed) {
    throw new ActionDockerError(`${runCode}_CLEANUP_FAILED`, "containment");
  }
  if (failure) throw failure;
  return result;
}

async function runActionVariantCase({
  docker,
  n8nImage,
  captureImage,
  ownerId,
  workflow,
  preflight,
  fixture,
  variant,
  fault = null,
  evidenceIdentitySeed = null,
  signal = null,
}) {
  if (signal?.aborted) throw new ActionDockerError("ACTION_INTERRUPTED");
  const resourceRunId = createReleaseRehearsalDockerIdentifier("n8n-action");
  const evidenceIdentity = evidenceIdentitySeed
    ? deterministicEvidenceIdentity(
        evidenceIdentitySeed,
        variant,
        fixture.canonicalSha256,
      )
    : null;
  const runId = evidenceIdentity?.runId ?? resourceRunId;
  const suffix = resourceRunId.slice(-16);
  const caseId = `case-${variant}-${fixture.canonicalSha256.slice(0, 12)}`;
  const correlationId =
    evidenceIdentity?.correlationId ??
    `correlation-${randomBytes(8).toString("hex")}`;
  const sentCorrelationId =
    fault === "correlation-mismatch"
      ? `sent-${randomBytes(8).toString("hex")}`
      : correlationId;
  const captureName = `capture-${resourceRunId}`;
  const setupName = `setup-${resourceRunId}`;
  const publishName = `publish-${resourceRunId}`;
  const serverName = `server-${resourceRunId}`;
  const volumeName = `csint-n8n-${suffix}`;
  const encryptionKeyBytes = randomBytes(32);
  let encryptionKey = encryptionKeyBytes.toString("hex");
  const controller = new AbortController();
  const abortFromCaller = () => controller.abort();
  signal?.addEventListener("abort", abortFromCaller, { once: true });
  const timer = setTimeout(() => controller.abort(), CASE_TIMEOUT_MS);
  timer.unref();
  const runDocker = (args, options = {}) =>
    runReleaseRehearsalDockerCommand(args, {
      ...options,
      signal: controller.signal,
      timeoutCode: options.timeoutCode ?? "ACTION_CASE_TIMEOUT",
    });
  const createDocker = (args, options = {}) =>
    runReleaseRehearsalDockerCommand(args, {
      ...options,
      timeoutCode: options.timeoutCode ?? "ACTION_CASE_TIMEOUT",
    });
  const inspectDocker = (kind, id, options = {}) =>
    inspectReleaseRehearsalDockerObject(kind, id, {
      ...options,
      signal: controller.signal,
      timeoutCode: options.timeoutCode ?? "ACTION_CASE_TIMEOUT",
    });

  const captureOwnership = labels(ownerId, resourceRunId, "capture");
  const setupOwnership = labels(ownerId, resourceRunId, "n8n-setup");
  const publishOwnership = labels(ownerId, resourceRunId, "n8n-publish");
  const serverOwnership = labels(ownerId, resourceRunId, "n8n-server");
  let files = null;
  let captureId = null;
  let setupId = null;
  let publishId = null;
  let serverId = null;
  let captureStarted = false;
  let volumeCreated = false;
  let directoryRemoved = false;
  let captureSecurity = null;
  let setupSecurity = null;
  let publishSecurity = null;
  let serverSecurity = null;
  let volumeSecurity = null;
  let importExitCode = null;
  let publishExitCode = null;
  let n8nProcessExitCode = null;
  let serverStartup = null;
  let healthReadinessObserved = false;
  let injectorExitCode = null;
  let injectorResult = null;
  let observed = null;
  let evidence = null;
  let setupScans = null;
  let publishScans = null;
  let logScans = null;
  let cleanup = null;
  const errorCodes = [];

  try {
    files = await prepareActionCaseFiles({
      workflow,
      preflight,
      fixture,
      variant,
      runId,
      caseId,
      correlationId,
      sentCorrelationId,
      resourceRunId,
    });
    await createReleaseRehearsalN8nVolume({
      volumeName,
      ownerId,
      runId: resourceRunId,
    });
    volumeCreated = true;
    volumeSecurity = inspectReleaseRehearsalN8nVolume(
      await inspectDocker("volume", volumeName),
      { volumeName, ownerId, runId: resourceRunId },
    );

    const captureCreate = await createDocker(
      buildReleaseRehearsalCaptureCreateArgs({
        name: captureName,
        ownerId,
        runId: resourceRunId,
        imageId: captureImage.imageId,
        runDirectory: files.runDirectory,
        configPath: files.configPath,
        fixturePath: files.fixturePath,
        outputPath: files.outputDirectory,
      }),
      { code: "ACTION_CAPTURE_CREATE_FAILED", timeoutMs: 15_000 },
    );
    captureId = validateReleaseRehearsalN8nContainerId(
      captureCreate.stdout.trim(),
    );
    captureSecurity = inspectReleaseRehearsalContainer(
      await inspectDocker("container", captureId),
      {
        ...captureOwnership,
        imageId: captureImage.imageId,
        networkMode: "none",
        logicalNetworkMode: "none",
        mounts: [
          {
            source: files.configPath,
            destination: CONTAINER_CONFIG_PATH,
            readWrite: false,
          },
          {
            source: files.outputDirectory,
            destination: CONTAINER_OUTPUT_PATH,
            readWrite: true,
          },
          {
            source: files.fixturePath,
            destination: CONTAINER_FIXTURE_PATH,
            readWrite: false,
          },
        ],
      },
    );
    await runDocker(["container", "start", captureId], {
      code: "ACTION_CAPTURE_START_FAILED",
      timeoutMs: 10_000,
    });
    captureStarted = true;
    await waitForReleaseRehearsalCaptureReady(captureId, controller.signal);

    const setup = await runAttachedContainer({
      createArgs: buildReleaseRehearsalN8nCreateArgs({
        role: "n8n-setup",
        name: setupName,
        ownerId,
        runId: resourceRunId,
        imageId: n8nImage.localImageId,
        volumeName,
        runDirectory: files.runDirectory,
        resolverPath: files.resolverPath,
        workflowPath: files.workflowPath,
        encryptionKey,
      }),
      ownership: setupOwnership,
      inspectExpected: {
        ...setupOwnership,
        networkMode: "none",
        logicalNetworkMode: "none",
        importFailure: false,
        mounts: containerMounts({
          volumeName,
          resolverPath: files.resolverPath,
          workflowPath: files.workflowPath,
        }),
      },
      createCode: "ACTION_SETUP_CREATE_FAILED",
      runCode: "ACTION_IMPORT_FAILED",
      encryptionKey,
      runDocker,
      createDocker,
      inspectDocker,
    });
    setupId = setup.containerId;
    importExitCode = setup.exitCode;
    setupSecurity = setup.security;
    setupScans = { stream: setup.streamScan, logs: setup.logScan };

    const published = await runAttachedContainer({
      createArgs: buildReleaseRehearsalN8nCreateArgs({
        role: "n8n-publish",
        name: publishName,
        ownerId,
        runId: resourceRunId,
        imageId: n8nImage.localImageId,
        volumeName,
        runDirectory: files.runDirectory,
        resolverPath: files.resolverPath,
        workflowId: workflow.id,
        encryptionKey,
      }),
      ownership: publishOwnership,
      inspectExpected: {
        ...publishOwnership,
        workflowId: workflow.id,
        networkMode: "none",
        logicalNetworkMode: "none",
        mounts: containerMounts({
          volumeName,
          resolverPath: files.resolverPath,
        }),
      },
      createCode: "ACTION_PUBLISH_CREATE_FAILED",
      runCode: "ACTION_PUBLISH_FAILED",
      encryptionKey,
      runDocker,
      createDocker,
      inspectDocker,
    });
    publishId = published.containerId;
    publishExitCode = published.exitCode;
    publishSecurity = published.security;
    publishScans = {
      stream: published.streamScan,
      logs: published.logScan,
    };

    const serverCreate = await createDocker(
      buildReleaseRehearsalN8nCreateArgs({
        role: "n8n-server",
        name: serverName,
        ownerId,
        runId: resourceRunId,
        imageId: n8nImage.localImageId,
        captureContainerId: captureId,
        volumeName,
        runDirectory: files.runDirectory,
        resolverPath: files.resolverPath,
        encryptionKey,
      }),
      { code: "ACTION_SERVER_CREATE_FAILED", timeoutMs: 15_000 },
    );
    serverId = validateReleaseRehearsalN8nContainerId(
      serverCreate.stdout.trim(),
    );
    serverSecurity = inspectReleaseRehearsalN8nContainer(
      await inspectDocker("container", serverId),
      {
        ...serverOwnership,
        networkMode: `container:${captureId}`,
        logicalNetworkMode: "container:<capture-container-id>",
        mounts: containerMounts({
          volumeName,
          resolverPath: files.resolverPath,
        }),
      },
    );
    await runDocker(["container", "start", serverId], {
      code: "ACTION_SERVER_START_FAILED",
      timeoutMs: 10_000,
    });
    serverStartup = await waitForN8nStartupCompletion({
      containerId: serverId,
      encryptionKey,
      runDocker,
      inspectDocker,
      signal: controller.signal,
    });
    const readyResult = await runDocker(
      [
        "container",
        "exec",
        "--user",
        "1000:1000",
        captureId,
        "node",
        ACTION_INJECTOR_PATH,
        "--mode",
        "ready",
      ],
      {
        code: "ACTION_SERVER_READY_FAILED",
        timeoutCode: "ACTION_SERVER_READY_TIMEOUT",
        timeoutMs: 65_000,
        maxBuffer: 64 * 1024,
      },
    );
    scanReleaseRehearsalN8nProcessStream(
      readyResult.stdout,
      encryptionKey,
      "ACTION_READY_STDOUT",
    );
    scanReleaseRehearsalN8nProcessStream(
      readyResult.stderr,
      encryptionKey,
      "ACTION_READY_STDERR",
    );
    healthReadinessObserved = true;

    if (fault !== "missing-capture") {
      const injector = await runDocker(
        [
          "container",
          "exec",
          "--user",
          "1000:1000",
          captureId,
          "node",
          ACTION_INJECTOR_PATH,
          "--mode",
          "trigger",
        ],
        {
          code: "ACTION_INJECTOR_FAILED",
          timeoutCode: "ACTION_INJECTOR_TIMEOUT",
          timeoutMs: 20_000,
          maxBuffer: 64 * 1024,
        },
      );
      injectorExitCode = 0;
      scanReleaseRehearsalN8nProcessStream(
        injector.stdout,
        encryptionKey,
        "ACTION_INJECTOR_STDOUT",
      );
      scanReleaseRehearsalN8nProcessStream(
        injector.stderr,
        encryptionKey,
        "ACTION_INJECTOR_STDERR",
      );
      injectorResult = await readInjectorResult(files.outputDirectory);
      if (
        injectorResult.status !== "COMPLETED" ||
        injectorResult.fixtureId !== fixture.id ||
        injectorResult.fixtureCanonicalSha256 !== fixture.canonicalSha256 ||
        injectorResult.rawValuesRetained !== false
      ) {
        throw new ActionDockerError("ACTION_INJECTOR_RESULT_INVALID");
      }
    }
  } catch (error) {
    errorCodes.push(
      strictInjectorDiagnosticCode(error) ??
        error?.code ??
        error?.message ??
        "ACTION_CASE_FAILED",
    );
  } finally {
    clearTimeout(timer);
    try {
      await stopContainer(serverId, "ACTION_SERVER_STOP_FAILED");
      n8nProcessExitCode = await inspectExitCode(serverId);
    } catch (error) {
      errorCodes.push(error?.code ?? "ACTION_SERVER_STOP_FAILED");
    }
    try {
      await stopContainer(captureId, "ACTION_CAPTURE_STOP_FAILED");
    } catch (error) {
      errorCodes.push(error?.code ?? "ACTION_CAPTURE_STOP_FAILED");
    }
    if (captureStarted && files) {
      try {
        evidence = await readCaptureEvidence(files.outputDirectory);
        if (
          !Array.isArray(evidence["dns-events.json"]) ||
          evidence["dns-events.json"].length !== 0
        ) {
          errorCodes.push("DNS_CONTAINMENT_VIOLATION");
        }
        observed = normalizeReleaseRehearsalObservedActions({
          events: evidence["capture-events.json"],
          summary: evidence["capture-summary.json"],
          dnsSummary: evidence["dns-summary.json"],
          config: files.captureConfig,
          preflight,
        });
      } catch (error) {
        errorCodes.push(error?.code ?? error?.message ?? "CAPTURE_EVIDENCE_INVALID");
      }
    }
    try {
      logScans = {
        setup: setupScans,
        publish: publishScans,
        capture: await scanReleaseRehearsalN8nContainerLogs(
          captureId,
          encryptionKey,
          "ACTION_CAPTURE",
        ),
        server: await scanReleaseRehearsalN8nContainerLogs(
          serverId,
          encryptionKey,
          "ACTION_SERVER",
        ),
      };
    } catch (error) {
      errorCodes.push(error?.code ?? "ACTION_LOG_SCAN_FAILED");
    }
    const [setupCleanup, publishCleanup, serverCleanup, captureCleanup] =
      await Promise.all([
        cleanupReleaseRehearsalContainer(setupId, setupOwnership),
        cleanupReleaseRehearsalContainer(publishId, publishOwnership),
        cleanupReleaseRehearsalContainer(serverId, serverOwnership),
        cleanupReleaseRehearsalContainer(captureId, captureOwnership),
      ]);
    const volumeCleanup = await cleanupReleaseRehearsalN8nVolume(
      volumeCreated ? volumeName : null,
      { ownerId, runId: resourceRunId },
    );
    if (files) {
      try {
        await removeReleaseRehearsalPrivateRunDirectory(files.runDirectory);
        directoryRemoved = true;
      } catch {
        errorCodes.push("ACTION_TEMP_DIRECTORY_CLEANUP_FAILED");
      }
    } else {
      directoryRemoved = true;
    }
    const remainingResources = [
      setupCleanup.remainingId,
      publishCleanup.remainingId,
      serverCleanup.remainingId,
      captureCleanup.remainingId,
      volumeCleanup.remainingName,
    ].filter(Boolean);
    cleanup = {
      status:
        setupCleanup.removed &&
        publishCleanup.removed &&
        serverCleanup.removed &&
        captureCleanup.removed &&
        volumeCleanup.removed &&
        directoryRemoved
          ? "COMPLETE"
          : "FAILED",
      setupContainerRemoved: setupCleanup.removed,
      publishContainerRemoved: publishCleanup.removed,
      serverContainerRemoved: serverCleanup.removed,
      captureContainerRemoved: captureCleanup.removed,
      n8nVolumeRemoved: volumeCleanup.removed,
      privateRunDirectoryRemoved: directoryRemoved,
      remainingResourceCount: remainingResources.length,
    };
    if (cleanup.status !== "COMPLETE") {
      errorCodes.push("ACTION_CLEANUP_INCOMPLETE");
    }
    encryptionKeyBytes.fill(0);
    encryptionKey = null;
    signal?.removeEventListener("abort", abortFromCaller);
  }

  const errors = stableUnique(errorCodes);
  const expectedFaultObserved =
    (fault === "correlation-mismatch" &&
      errors.includes("CAPTURE_SUMMARY_INVALID")) ||
    (fault === "missing-capture" && errors.includes("CAPTURE_SUMMARY_INVALID"));
  const status =
    observed && cleanup.status === "COMPLETE" && errors.length === 0
      ? "COMPLETE"
      : fault === "missing-capture"
        ? "INCOMPLETE"
        : "FAILED";
  const captureSummary = evidence?.["capture-summary.json"] ?? null;
  const dnsSummary = evidence?.["dns-summary.json"] ?? null;
  const captureViolationCodes = Array.isArray(captureSummary?.violationCodes)
    ? stableUnique(captureSummary.violationCodes)
    : [];
  const unexpectedActionDetected = captureViolationCodes.some((code) =>
    UNEXPECTED_ACTION_VIOLATION_CODES.has(code),
  );
  const logical = {
    schemaVersion: RELEASE_REHEARSAL_ACTION_DOCKER_SCHEMA_VERSION,
    status,
    variant,
    fixtureId: fixture.id,
    fixtureCanonicalSha256: fixture.canonicalSha256,
    runId,
    caseId,
    correlationId,
    subjects: files
      ? {
          originalWorkflowCanonicalSha256:
            files.transformed.manifest.workflow.originalCanonicalSha256,
          transformedWorkflowCanonicalSha256:
            files.transformed.manifest.workflow.transformedCanonicalSha256,
          transformationManifestCanonicalSha256:
            files.transformed.manifest.manifestCanonicalSha256,
        }
      : null,
    transformation: files?.transformed.manifest ?? null,
    process: {
      importExitCode,
      publishExitCode,
      injectorExitCode,
      n8nProcessExitCode,
      startupCompletionMarkerObserved:
        serverStartup?.completionMarkerObserved ?? false,
      healthReadinessObserved,
      startupOutputRetained: serverStartup?.retained ?? false,
      n8nProcessExitCodeIsNodeTrace: false,
      n8nProcessExitCodeIsWorkflowStatus: false,
    },
    observedActions: observed?.actions ?? [],
    evidence: {
      triggerStatus: injectorResult?.status ?? null,
      triggerResponseStatusCode:
        injectorResult?.responseStatusCode ?? null,
      triggerResponseBytes: injectorResult?.responseBytes ?? null,
      triggerResponseSha256: injectorResult?.responseSha256 ?? null,
      captureStatus: captureSummary?.status ?? null,
      captureEventCount: captureSummary?.eventCount ?? null,
      captureForwarded: captureSummary?.forwarded ?? null,
      captureViolationCodes,
      responseStatuses: Array.isArray(evidence?.["capture-events.json"])
        ? evidence["capture-events.json"].map((event) => event.responseStatus)
        : [],
      dnsStatus: dnsSummary?.status ?? null,
      dnsQueryCount: dnsSummary?.queryCount ?? null,
      rawValuesRetained: false,
    },
    containment: {
      docker,
      captureNetworkMode: captureSecurity?.networkMode ?? null,
      setupNetworkMode: setupSecurity?.networkMode ?? null,
      publishNetworkMode: publishSecurity?.networkMode ?? null,
      serverNetworkMode: serverSecurity?.networkMode ?? null,
      noPublishedPorts:
        captureSecurity?.publishedPorts === false &&
        setupSecurity?.publishedPorts === false &&
        publishSecurity?.publishedPorts === false &&
        serverSecurity?.publishedPorts === false,
      noProxyEnvironment:
        setupSecurity?.proxyEnvironmentPresent === false &&
        publishSecurity?.proxyEnvironmentPresent === false &&
        serverSecurity?.proxyEnvironmentPresent === false,
      volumeSecurity,
      unexpectedActionDetected,
    },
    cleanup,
    expectedFault: fault,
    expectedFaultObserved,
    errorCodes: errors,
    limitations: [
      "Observed means only that the local capture service accepted the synthetic request.",
      "The n8n process exit code is not a node trace or terminal workflow status.",
      "No structural or downstream node execution is inferred.",
    ],
  };
  const operational = {
    resourceRunId,
    runDirectory: files?.runDirectory ?? null,
    captureContainerId: captureId,
    setupContainerId: setupId,
    publishContainerId: publishId,
    serverContainerId: serverId,
    volumeName,
    logScans,
    rawValuesRetained: false,
  };
  return { ...logical, operational };
}

function unresolvedCode(caseResult) {
  if (caseResult.errorCodes.includes("CAPTURE_SUMMARY_INVALID")) {
    return caseResult.expectedFault === "correlation-mismatch"
      ? "CAPTURE_CORRELATION_MISMATCH"
      : "CAPTURE_INCOMPLETE";
  }
  return caseResult.errorCodes[0] ?? "CAPTURE_INCOMPLETE";
}

async function runPreparedPair({
  preparation,
  docker,
  n8nImage,
  captureImage,
  ownerId,
  faults = {},
  evidenceIdentitySeed = null,
  signal = null,
}) {
  const cases = [];
  for (const fixture of preparation.fixtureSet.fixtures) {
    for (const variant of ["baseline", "candidate"]) {
      if (signal?.aborted) throw new ActionDockerError("ACTION_INTERRUPTED");
      cases.push(
        await runActionVariantCase({
          docker,
          n8nImage,
          captureImage,
          ownerId,
          workflow: preparation.workflows[variant],
          preflight: preparation.preflight[variant],
          fixture,
          variant,
          fault: faults[variant] ?? null,
          evidenceIdentitySeed,
          signal,
        }),
      );
      if (signal?.aborted) throw new ActionDockerError("ACTION_INTERRUPTED");
    }
  }
  const baselineCases = cases.filter((item) => item.variant === "baseline");
  const candidateCases = cases.filter((item) => item.variant === "candidate");
  const baselineComplete = baselineCases.every((item) => item.status === "COMPLETE");
  const candidateComplete = candidateCases.every(
    (item) => item.status === "COMPLETE",
  );
  const baselineActions = baselineCases.flatMap((item) =>
    item.status === "COMPLETE"
      ? item.observedActions
      : createReleaseRehearsalUnresolvedActions(
          preparation.preflight.baseline,
          item.fixtureId,
          unresolvedCode(item),
        ),
  );
  const candidateActions = candidateCases.flatMap((item) =>
    item.status === "COMPLETE"
      ? item.observedActions
      : createReleaseRehearsalUnresolvedActions(
          preparation.preflight.candidate,
          item.fixtureId,
          unresolvedCode(item),
        ),
  );
  const baselineCodes = stableUnique(
    baselineCases
      .filter((item) => item.status !== "COMPLETE")
      .map(unresolvedCode),
  );
  const candidateCodes = stableUnique(
    candidateCases
      .filter((item) => item.status !== "COMPLETE")
      .map(unresolvedCode),
  );
  const diff = diffReleaseRehearsalObservedPair({
    baselineActions,
    candidateActions,
    baselineCoverage: baselineComplete
      ? { status: "COMPLETE", reasonCodes: [] }
      : { status: "UNRESOLVED", reasonCodes: baselineCodes },
    candidateCoverage: candidateComplete
      ? { status: "COMPLETE", reasonCodes: [] }
      : { status: "UNRESOLVED", reasonCodes: candidateCodes },
  });
  const cleanupComplete = cases.every((item) => item.cleanup.status === "COMPLETE");
  const containmentFailure = cases.some(
    (item) =>
      item.cleanup.status !== "COMPLETE" ||
      item.containment.unexpectedActionDetected === true ||
      item.errorCodes.some((code) => /(?:DNS|EGRESS|NETWORK|CLEANUP)/u.test(code)),
  );
  const allUnique = (values) =>
    values.every((value) => typeof value === "string" && value.length > 0) &&
    new Set(values).size === values.length;
  const resourceIsolation = {
    separateRunIds: allUnique(cases.map((item) => item.runId)),
    separateCorrelationIds: allUnique(cases.map((item) => item.correlationId)),
    separateVolumes: allUnique(
      cases.map((item) => item.operational.volumeName),
    ),
    separateRunDirectories: allUnique(
      cases.map((item) => item.operational.runDirectory),
    ),
    separateCaptureLedgers: allUnique(
      cases.map((item) => item.operational.captureContainerId),
    ),
  };
  const resourcesIsolated = Object.values(resourceIsolation).every(Boolean);
  const outcome = containmentFailure
    ? "FAIL_CONTAINMENT"
    : baselineComplete &&
        candidateComplete &&
        diff.status === "COMPLETE" &&
        cleanupComplete &&
        resourcesIsolated
      ? "PASS_ACTION_REHEARSAL_CORE"
      : "PARTIAL_ACTION_REHEARSAL";
  const result = {
    schemaVersion: RELEASE_REHEARSAL_ACTION_DOCKER_SCHEMA_VERSION,
    outcome,
    status: outcome === "PASS_ACTION_REHEARSAL_CORE" ? "PASS" : "INCOMPLETE",
    subjects: {
      baselineOriginalCanonicalSha256:
        preparation.preflight.baseline.workflow.canonicalSha256,
      candidateOriginalCanonicalSha256:
        preparation.preflight.candidate.workflow.canonicalSha256,
      fixtureSetCanonicalSha256: preparation.fixtureSetCanonicalSha256,
    },
    cases,
    diff,
    resourceIsolation,
    cleanup: {
      status: cleanupComplete ? "COMPLETE" : "FAILED",
      remainingResourceCount: cases.reduce(
        (sum, item) => sum + item.cleanup.remainingResourceCount,
        0,
      ),
    },
    limitations: [
      "Observed actions are accepted local capture events only.",
      "Planned intent comes from the immutable source-bound transformation manifest.",
      "Unresolved means runtime capture evidence was unavailable.",
      "No node order, item linking, approval execution, retry, loop, downstream completion, production safety, penetration test, or workflow-equivalence claim is made.",
    ],
  };
  serializeReleaseRehearsalActionCore({
    ...result,
    cases: result.cases.map(({ operational: _operational, ...item }) => item),
  });
  return result;
}

function unsupportedPairResult(preparation) {
  return {
    schemaVersion: RELEASE_REHEARSAL_ACTION_DOCKER_SCHEMA_VERSION,
    outcome: "BLOCKED_TRANSFORMATION_FIDELITY",
    status: "BLOCKED",
    cases: [],
    diff: preparation.diff,
    cleanup: { status: "COMPLETE", remainingResourceCount: 0 },
    errorCodes: preparation.reasonCodes,
  };
}

async function prepareHarness() {
  const docker = await getReleaseRehearsalDockerRuntime();
  const n8nImage = await resolveReleaseRehearsalPinnedN8nImage();
  const nodeImage = await resolveReleaseRehearsalNodeImage();
  const ownerId = createReleaseRehearsalDockerIdentifier("action-owner");
  const captureImage = await buildReleaseRehearsalCaptureImage(nodeImage, ownerId);
  return { docker, n8nImage, nodeImage, ownerId, captureImage };
}

export async function runReleaseRehearsalActionPairInDocker(input, options = {}) {
  const normalizedOptions = normalizeActionRunOptions(options);
  if (normalizedOptions.signal?.aborted) {
    throw new ActionDockerError("ACTION_INTERRUPTED");
  }
  const preparation = prepareReleaseRehearsalActionPair(input);
  if (!preparation.executionAuthorized) return unsupportedPairResult(preparation);
  const containmentProbe = await runReleaseRehearsalDockerProbe();
  if (normalizedOptions.signal?.aborted) {
    throw new ActionDockerError("ACTION_INTERRUPTED");
  }
  if (containmentProbe.status !== "PASS") {
    return {
      schemaVersion: RELEASE_REHEARSAL_ACTION_DOCKER_SCHEMA_VERSION,
      outcome: "FAIL_CONTAINMENT",
      status: "FAILED",
      cases: [],
      cleanup: containmentProbe.cleanup ?? {
        status: "FAILED",
        remainingResourceCount: null,
      },
      errorCodes: ["CONTAINMENT_PROBE_FAILED"],
    };
  }
  const before = await listReleaseRehearsalDockerInventory();
  let harness = null;
  let result;
  let imageCleanup = { status: "COMPLETE", remainingIds: [] };
  try {
    harness = await prepareHarness();
    result = await runPreparedPair({
      preparation,
      ...harness,
      faults: normalizedOptions.faults,
      evidenceIdentitySeed: normalizedOptions.evidenceIdentitySeed,
      signal: normalizedOptions.signal,
    });
  } finally {
    imageCleanup = await removeReleaseRehearsalCaptureImage(
      harness?.captureImage,
      harness?.ownerId,
    );
  }
  const after = await listReleaseRehearsalDockerInventory();
  const inventoryUnchanged = releaseRehearsalDockerInventoriesEqual(before, after);
  if (!inventoryUnchanged || imageCleanup.status !== "COMPLETE") {
    result.outcome = "FAIL_CONTAINMENT";
    result.status = "FAILED";
  }
  return {
    ...result,
    imageCleanup: {
      status: imageCleanup.status,
      remainingResourceCount: imageCleanup.remainingIds.length,
    },
    inventory: {
      unchanged: inventoryUnchanged,
      beforeCounts: inventoryCounts(before),
      afterCounts: inventoryCounts(after),
    },
  };
}

function actionOptions() {
  return {
    redirect: { followRedirects: false },
    response: {
      response: { fullResponse: false, responseFormat: "json" },
    },
    timeout: 5_000,
  };
}

function syntheticWebhook(pathValue) {
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

function syntheticSet(id, name, x, y = 0) {
  return {
    id,
    name,
    type: "n8n-nodes-base.set",
    typeVersion: 3.4,
    position: [x, y],
    parameters: {
      assignments: {
        assignments: [
          {
            id: `${id}-assignment`,
            name: "syntheticState",
            type: "string",
            value: id,
          },
        ],
      },
      options: {},
    },
  };
}

function syntheticAction(id, name, { method = "POST", url, x, y = 0 } = {}) {
  return {
    id,
    name,
    type: "n8n-nodes-base.httpRequest",
    typeVersion: 4.2,
    position: [x, y],
    parameters: {
      method,
      url: url ?? `https://${id}.example.invalid/v1/action`,
      authentication: "none",
      sendBody: true,
      contentType: "json",
      specifyBody: "json",
      jsonBody: canonicalJson({ kind: "synthetic-action", node: id }),
      options: actionOptions(),
    },
  };
}

function edge(node) {
  return { node, type: "main", index: 0 };
}

function workflow(pathValue, nodes, connections) {
  return {
    id: "csint-action-rehearsal-v1",
    name: `Synthetic ${pathValue}`,
    active: false,
    nodes: [syntheticWebhook(pathValue), ...nodes],
    connections: {
      "Synthetic Entry": { main: [[edge(nodes[0].name)]] },
      ...connections,
    },
    settings: { executionOrder: "v1" },
    versionId: "22222222-2222-4222-8222-222222222222",
  };
}

function linearWorkflow(pathValue, actions, { downstream = false } = {}) {
  const nodes = actions.map((action, index) =>
    syntheticAction(action.id, action.name, {
      ...action,
      x: 240 + index * 240,
    }),
  );
  if (downstream) {
    nodes.push(syntheticSet("downstream-set", "Synthetic Downstream", 720));
  }
  const connections = {};
  for (let index = 0; index < nodes.length - 1; index += 1) {
    connections[nodes[index].name] = { main: [[edge(nodes[index + 1].name)]] };
  }
  return workflow(pathValue, nodes, connections);
}

function countWorkflow(pathValue, doubled) {
  const left = syntheticSet("left-set", "Synthetic Left", 240, -100);
  const action = syntheticAction("action-a", "Synthetic Action A", { x: 480 });
  if (!doubled) {
    return workflow(pathValue, [left, action], {
      [left.name]: { main: [[edge(action.name)]] },
    });
  }
  const right = syntheticSet("right-set", "Synthetic Right", 240, 100);
  return {
    ...workflow(pathValue, [left, right, action], {
      [left.name]: { main: [[edge(action.name)]] },
      [right.name]: { main: [[edge(action.name)]] },
    }),
    connections: {
      "Synthetic Entry": { main: [[edge(left.name), edge(right.name)]] },
      [left.name]: { main: [[edge(action.name)]] },
      [right.name]: { main: [[edge(action.name)]] },
    },
  };
}

function fixtureSet(name, nodeIds, options = {}) {
  return {
    schemaVersion: 1,
    fixtures: [
      {
        schemaVersion: 1,
        id: `fixture-${name}`,
        correlationId: `fixture-${name}-seed`,
        webhook: {
          method: "POST",
          path: `/phase6-${name}`,
          headers: {},
          json: { fixture: name, kind: "synthetic-webhook" },
        },
        nodes: nodeIds.map((nodeId) => {
          const count = options.maximumOccurrences?.[nodeId] ?? 1;
          const status = options.status ?? 200;
          return {
            nodeId,
            minimumOccurrences: options.optional?.includes(nodeId) ? 0 : 1,
            maximumOccurrences: count,
            responses: Array.from({ length: count }, (_value, index) => ({
              status,
              headers: { "content-type": "application/json; charset=utf-8" },
              json: {
                result: options.stubResult ?? "accepted",
                sequence: index + 1,
              },
            })),
          };
        }),
      },
    ],
  };
}

function integrationScenarios() {
  const actionA = { id: "action-a", name: "Synthetic Action A" };
  const actionB = { id: "action-b", name: "Synthetic Action B" };
  const identical = linearWorkflow("phase6-identical", [actionA]);
  return [
    {
      name: "identical",
      baselineWorkflow: identical,
      candidateWorkflow: structuredClone(identical),
      fixtureSet: fixtureSet("identical", ["action-a"]),
      expected: { totalChanges: 0 },
    },
    {
      name: "new-action",
      baselineWorkflow: linearWorkflow("phase6-new-action", [actionA]),
      candidateWorkflow: linearWorkflow("phase6-new-action", [actionA, actionB]),
      fixtureSet: fixtureSet("new-action", ["action-a", "action-b"], {
        optional: ["action-b"],
      }),
      expected: { new_action: 1 },
    },
    {
      name: "removed-action",
      baselineWorkflow: linearWorkflow("phase6-removed-action", [actionA, actionB]),
      candidateWorkflow: linearWorkflow("phase6-removed-action", [actionA]),
      fixtureSet: fixtureSet("removed-action", ["action-a", "action-b"], {
        optional: ["action-b"],
      }),
      expected: { removed_action: 1 },
    },
    {
      name: "destination-change",
      baselineWorkflow: linearWorkflow("phase6-destination-change", [actionA]),
      candidateWorkflow: linearWorkflow("phase6-destination-change", [
        {
          ...actionA,
          url: "https://changed.example.invalid/v2/action",
        },
      ]),
      fixtureSet: fixtureSet("destination-change", ["action-a"]),
      expected: { destination_changed: 1 },
    },
    {
      name: "method-change",
      baselineWorkflow: linearWorkflow("phase6-method-change", [actionA]),
      candidateWorkflow: linearWorkflow("phase6-method-change", [
        { ...actionA, method: "PATCH" },
      ]),
      fixtureSet: fixtureSet("method-change", ["action-a"]),
      expected: { method_changed: 1 },
    },
    {
      name: "count-change",
      baselineWorkflow: countWorkflow("phase6-count-change", false),
      candidateWorkflow: countWorkflow("phase6-count-change", true),
      fixtureSet: fixtureSet("count-change", ["action-a"], {
        maximumOccurrences: { "action-a": 2 },
      }),
      expected: { action_count_changed: 1 },
    },
    {
      name: "unsupported-dynamic",
      baselineWorkflow: linearWorkflow("phase6-unsupported-dynamic", [actionA]),
      candidateWorkflow: linearWorkflow("phase6-unsupported-dynamic", [
        { ...actionA, url: "={{$json.destination}}" },
      ]),
      fixtureSet: fixtureSet("unsupported-dynamic", ["action-a"]),
      expectedOutcome: "BLOCKED_TRANSFORMATION_FIDELITY",
    },
    {
      name: "correlation-mismatch",
      baselineWorkflow: linearWorkflow("phase6-correlation-mismatch", [actionA]),
      candidateWorkflow: linearWorkflow("phase6-correlation-mismatch", [actionA]),
      fixtureSet: fixtureSet("correlation-mismatch", ["action-a"]),
      faults: { candidate: "correlation-mismatch" },
      expectedOutcome: "PARTIAL_ACTION_REHEARSAL",
    },
    {
      name: "missing-capture",
      baselineWorkflow: linearWorkflow("phase6-missing-capture", [actionA]),
      candidateWorkflow: linearWorkflow("phase6-missing-capture", [actionA]),
      fixtureSet: fixtureSet("missing-capture", ["action-a"]),
      faults: { candidate: "missing-capture" },
      expectedOutcome: "PARTIAL_ACTION_REHEARSAL",
    },
    {
      name: "stub-variation",
      baselineWorkflow: linearWorkflow("phase6-stub-variation", [actionA], {
        downstream: true,
      }),
      candidateWorkflow: linearWorkflow("phase6-stub-variation", [actionA], {
        downstream: true,
      }),
      fixtureSet: fixtureSet("stub-variation", ["action-a"], {
        status: 202,
        stubResult: "alternate",
      }),
      expected: { totalChanges: 0, responseStatus: 202 },
    },
  ];
}

function scenarioMatches(result, scenario) {
  if (scenario.expectedOutcome) {
    if (result.outcome !== scenario.expectedOutcome) return false;
    if (result.cleanup.status !== "COMPLETE") return false;
    if (scenario.name === "unsupported-dynamic") {
      return result.cases.length === 0 && result.diff.summary.unsupported_coverage === 1;
    }
    if (scenario.name === "missing-capture") {
      return result.diff.summary.unresolved_coverage === 1;
    }
    return result.cases.some((item) => item.expectedFaultObserved);
  }
  if (result.outcome !== "PASS_ACTION_REHEARSAL_CORE") return false;
  for (const [key, value] of Object.entries(scenario.expected ?? {})) {
    if (key === "responseStatus") {
      if (
        !result.cases.every((item) =>
          item.evidence.responseStatuses.includes(value),
        )
      ) {
        return false;
      }
    } else if (result.diff.summary[key] !== value) {
      return false;
    }
  }
  return true;
}

export async function runReleaseRehearsalActionIntegrationSuite() {
  const before = await listReleaseRehearsalDockerInventory();
  const containmentProbe = await runReleaseRehearsalDockerProbe();
  if (containmentProbe.status !== "PASS") {
    return {
      schemaVersion: RELEASE_REHEARSAL_ACTION_DOCKER_SCHEMA_VERSION,
      outcome: "FAIL_CONTAINMENT",
      scenarios: [],
      errorCodes: ["CONTAINMENT_PROBE_FAILED"],
    };
  }
  let harness = null;
  let imageCleanup = { status: "COMPLETE", remainingIds: [] };
  const results = [];
  try {
    harness = await prepareHarness();
    for (const scenario of integrationScenarios()) {
      const preparation = prepareReleaseRehearsalActionPair(scenario);
      const result = preparation.executionAuthorized
        ? await runPreparedPair({
            preparation,
            ...harness,
            faults: scenario.faults ?? {},
          })
        : unsupportedPairResult(preparation);
      results.push({
        name: scenario.name,
        matchesExpected: scenarioMatches(result, scenario),
        result,
      });
    }
  } finally {
    imageCleanup = await removeReleaseRehearsalCaptureImage(
      harness?.captureImage,
      harness?.ownerId,
    );
  }
  const after = await listReleaseRehearsalDockerInventory();
  const managedAfter = await listReleaseRehearsalManagedDockerInventory();
  const inventoryUnchanged = releaseRehearsalDockerInventoriesEqual(before, after);
  const allExpected = results.length === 10 && results.every((item) => item.matchesExpected);
  const cleanupComplete =
    imageCleanup.status === "COMPLETE" &&
    managedTotal(managedAfter) === 0 &&
    results.every((item) => item.result.cleanup.status === "COMPLETE");
  const outcome =
    allExpected && inventoryUnchanged && cleanupComplete
      ? "PASS_ACTION_REHEARSAL_CORE"
      : !inventoryUnchanged || !cleanupComplete
        ? "FAIL_CONTAINMENT"
        : "PARTIAL_ACTION_REHEARSAL";
  const logical = {
    schemaVersion: RELEASE_REHEARSAL_ACTION_DOCKER_SCHEMA_VERSION,
    outcome,
    scenarioCount: results.length,
    scenarios: results.map((item) => ({
      name: item.name,
      matchesExpected: item.matchesExpected,
      outcome: item.result.outcome,
      diffSummary: item.result.diff?.summary ?? null,
      caseCount: item.result.cases.length,
      cleanupStatus: item.result.cleanup.status,
    })),
    image: harness?.n8nImage ?? null,
    containmentProbe: {
      status: containmentProbe.status,
      cleanupStatus: containmentProbe.cleanup?.status ?? null,
    },
    imageCleanup: {
      status: imageCleanup.status,
      remainingResourceCount: imageCleanup.remainingIds.length,
    },
    inventory: {
      unchanged: inventoryUnchanged,
      beforeCounts: inventoryCounts(before),
      afterCounts: inventoryCounts(after),
      managedAfterCounts: inventoryCounts(managedAfter),
      managedAfterTotal: managedTotal(managedAfter),
    },
    errorCodes: stableUnique([
      ...(!allExpected ? ["INTEGRATION_EXPECTATION_MISMATCH"] : []),
      ...(!inventoryUnchanged ? ["DOCKER_INVENTORY_CHANGED"] : []),
      ...(!cleanupComplete ? ["CLEANUP_INCOMPLETE"] : []),
    ]),
  };
  serializeReleaseRehearsalActionCore(logical);
  return { ...logical, operational: { results } };
}
