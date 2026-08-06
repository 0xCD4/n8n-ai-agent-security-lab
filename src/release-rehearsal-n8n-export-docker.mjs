import { randomBytes } from "node:crypto";
import { mkdir, readdir } from "node:fs/promises";
import path from "node:path";

import {
  assertReleaseRehearsalPrivatePath,
  buildReleaseRehearsalCaptureCreateArgs,
  buildReleaseRehearsalCaptureImage,
  cleanupReleaseRehearsalContainer,
  createReleaseRehearsalDockerIdentifier,
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
  waitForReleaseRehearsalCaptureReady,
} from "./release-rehearsal-docker.mjs";
import {
  buildReleaseRehearsalN8nCreateArgs,
  cleanupReleaseRehearsalN8nVolume,
  createReleaseRehearsalN8nVolume,
  inspectReleaseRehearsalN8nContainer,
  inspectReleaseRehearsalN8nVolume,
  prepareReleaseRehearsalN8nCaseFiles,
  readReleaseRehearsalN8nCaptureEvidence,
  resolveReleaseRehearsalPinnedN8nImage,
  scanReleaseRehearsalN8nContainerLogs,
  scanReleaseRehearsalN8nProcessStream,
  validateReleaseRehearsalN8nContainerId,
} from "./release-rehearsal-n8n-docker.mjs";
import {
  deleteReleaseRehearsalN8nRawExport,
  readReleaseRehearsalN8nEntityExport,
  RELEASE_REHEARSAL_N8N_EXPORT_COMMAND,
  RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION,
  ReleaseRehearsalN8nExportError,
} from "./release-rehearsal-n8n-export.mjs";
import {
  correlateReleaseRehearsalN8nCapture,
  loadReleaseRehearsalN8nWorkflowTemplate,
  RELEASE_REHEARSAL_N8N_IMAGE,
  RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
  serializeReleaseRehearsalN8nLogicalResult,
} from "./release-rehearsal-n8n.mjs";

const CONTAINER_CONFIG_PATH = "/run/rehearsal/config/config.json";
const CONTAINER_OUTPUT_PATH = "/run/rehearsal/output";
const CONTAINER_RESOLVER_PATH = "/etc/resolv.conf";
const CONTAINER_WORKFLOW_PATH = "/run/rehearsal/workflow/workflow.json";
const CONTAINER_EXPORT_PATH = "/run/rehearsal/export";
const CONTAINER_N8N_HOME = "/home/node/.n8n";
const LOG_LIMIT_BYTES = 2 * 1024 * 1024;

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(stableCompare);
}

function inventoryCounts(inventory) {
  return Object.fromEntries(
    Object.entries(inventory).map(([key, values]) => [key, values.length]),
  );
}

function inventoryTotal(inventory) {
  return Object.values(inventory).reduce((total, values) => total + values.length, 0);
}

async function stopCapture(containerId) {
  if (!containerId) return;
  const inspect = await inspectReleaseRehearsalDockerObject("container", containerId, {
    allowMissing: true,
  });
  if (inspect?.State?.Running) {
    await runReleaseRehearsalDockerCommand(
      ["container", "stop", "--time", "5", containerId],
      { code: "N8N_EXPORT_CAPTURE_STOP_FAILED", timeoutMs: 10_000 },
    );
  }
}

async function runExportCase({ docker, n8nImage, captureImage, ownerId, template }) {
  const runId = createReleaseRehearsalDockerIdentifier("n8n-export");
  const suffix = runId.slice(-16);
  const captureName = `capture-${runId}`;
  const setupName = `setup-${runId}`;
  const runnerName = `runner-${runId}`;
  const exporterName = `exporter-${runId}`;
  const volumeName = `csint-n8n-${suffix}`;
  const encryptionKeyBytes = randomBytes(32);
  let encryptionKey = encryptionKeyBytes.toString("hex");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 90_000);
  timer.unref();
  const runDocker = (args, options = {}) =>
    runReleaseRehearsalDockerCommand(args, {
      ...options,
      signal: controller.signal,
      timeoutCode: options.timeoutCode ?? "N8N_EXPORT_CASE_TIMEOUT",
    });
  const inspectObject = (kind, id, options = {}) =>
    inspectReleaseRehearsalDockerObject(kind, id, {
      ...options,
      signal: controller.signal,
      timeoutCode: options.timeoutCode ?? "N8N_EXPORT_CASE_TIMEOUT",
    });

  const ownership = Object.freeze({
    capture: { ownerId, runId, role: "capture" },
    setup: { ownerId, runId, role: "n8n-setup" },
    runner: { ownerId, runId, role: "n8n-runner" },
    exporter: { ownerId, runId, role: "n8n-export" },
  });
  let files = null;
  let exportDirectory = null;
  let captureId = null;
  let setupId = null;
  let runnerId = null;
  let exporterId = null;
  let captureSecurity = null;
  let setupSecurity = null;
  let runnerSecurity = null;
  let exporterSecurity = null;
  let volumeSecurity = null;
  let volumeCreated = false;
  let captureStarted = false;
  let captureCorrelation = null;
  let exportEvidence = null;
  let rawDeletion = null;
  let streamScans = null;
  let setupAttachedScan = null;
  let runnerAttachedScan = null;
  let exporterAttachedScan = null;
  let cleanup = null;
  let mainOutcome = null;
  const errorCodes = [];
  let importSucceeded = false;
  let executionSucceeded = false;
  let exportSucceeded = false;

  try {
    files = await prepareReleaseRehearsalN8nCaseFiles(template, runId, "success");
    exportDirectory = assertReleaseRehearsalPrivatePath(
      files.runDirectory,
      path.join(files.runDirectory, "export"),
    );
    await mkdir(exportDirectory, { mode: 0o700 });
    if ((await readdir(exportDirectory)).length !== 0) {
      throw new ReleaseRehearsalN8nExportError("EXPORT_DIRECTORY_NOT_EMPTY", "BLOCKED");
    }

    await createReleaseRehearsalN8nVolume({ volumeName, ownerId, runId });
    volumeCreated = true;
    volumeSecurity = inspectReleaseRehearsalN8nVolume(
      await inspectObject("volume", volumeName),
      { volumeName, ownerId, runId },
    );

    const captureCreate = await runDocker(
      buildReleaseRehearsalCaptureCreateArgs({
        name: captureName,
        ownerId,
        runId,
        imageId: captureImage.imageId,
        runDirectory: files.runDirectory,
        configPath: files.configPath,
        outputPath: files.outputDirectory,
      }),
      { code: "N8N_EXPORT_CAPTURE_CREATE_FAILED", timeoutMs: 15_000 },
    );
    captureId = validateReleaseRehearsalN8nContainerId(captureCreate.stdout.trim());
    captureSecurity = inspectReleaseRehearsalContainer(
      await inspectObject("container", captureId),
      {
        ...ownership.capture,
        imageId: captureImage.imageId,
        networkMode: "none",
        logicalNetworkMode: "none",
        mounts: [
          { source: files.configPath, destination: CONTAINER_CONFIG_PATH, readWrite: false },
          { source: files.outputDirectory, destination: CONTAINER_OUTPUT_PATH, readWrite: true },
        ],
      },
    );
    await runDocker(["container", "start", captureId], {
      code: "N8N_EXPORT_CAPTURE_START_FAILED",
      timeoutMs: 10_000,
    });
    captureStarted = true;
    await waitForReleaseRehearsalCaptureReady(captureId, controller.signal);

    const setupCreate = await runDocker(
      buildReleaseRehearsalN8nCreateArgs({
        role: "n8n-setup",
        name: setupName,
        ownerId,
        runId,
        imageId: n8nImage.localImageId,
        volumeName,
        runDirectory: files.runDirectory,
        resolverPath: files.resolverPath,
        workflowPath: files.workflowPath,
        encryptionKey,
        importFailure: false,
      }),
      { code: "N8N_EXPORT_SETUP_CREATE_FAILED", timeoutMs: 15_000 },
    );
    setupId = validateReleaseRehearsalN8nContainerId(setupCreate.stdout.trim());
    setupSecurity = inspectReleaseRehearsalN8nContainer(
      await inspectObject("container", setupId),
      {
        ...ownership.setup,
        networkMode: "none",
        logicalNetworkMode: "none",
        importFailure: false,
        mounts: [
          { type: "volume", name: volumeName, destination: CONTAINER_N8N_HOME, readWrite: true },
          { type: "bind", source: files.resolverPath, destination: CONTAINER_RESOLVER_PATH, readWrite: false },
          { type: "bind", source: files.workflowPath, destination: CONTAINER_WORKFLOW_PATH, readWrite: false },
        ],
      },
    );
    const importResult = await runDocker(["container", "start", "--attach", setupId], {
      code: "N8N_EXPORT_IMPORT_FAILED",
      timeoutCode: "N8N_EXPORT_IMPORT_TIMEOUT",
      maxBuffer: LOG_LIMIT_BYTES,
      timeoutMs: 30_000,
    });
    importSucceeded = true;
    setupAttachedScan = Object.freeze({
      stdout: scanReleaseRehearsalN8nProcessStream(
        importResult.stdout,
        encryptionKey,
        "N8N_EXPORT_IMPORT_STDOUT",
      ),
      stderr: scanReleaseRehearsalN8nProcessStream(
        importResult.stderr,
        encryptionKey,
        "N8N_EXPORT_IMPORT_STDERR",
      ),
    });

    const runnerCreate = await runDocker(
      buildReleaseRehearsalN8nCreateArgs({
        role: "n8n-runner",
        name: runnerName,
        ownerId,
        runId,
        imageId: n8nImage.localImageId,
        captureContainerId: captureId,
        volumeName,
        runDirectory: files.runDirectory,
        resolverPath: files.resolverPath,
        encryptionKey,
      }),
      { code: "N8N_EXPORT_RUNNER_CREATE_FAILED", timeoutMs: 15_000 },
    );
    runnerId = validateReleaseRehearsalN8nContainerId(runnerCreate.stdout.trim());
    runnerSecurity = inspectReleaseRehearsalN8nContainer(
      await inspectObject("container", runnerId),
      {
        ...ownership.runner,
        networkMode: `container:${captureId}`,
        logicalNetworkMode: "container:<capture-container-id>",
        mounts: [
          { type: "volume", name: volumeName, destination: CONTAINER_N8N_HOME, readWrite: true },
          { type: "bind", source: files.resolverPath, destination: CONTAINER_RESOLVER_PATH, readWrite: false },
        ],
      },
    );
    const executeResult = await runDocker(["container", "start", "--attach", runnerId], {
      code: "N8N_EXPORT_EXECUTION_FAILED",
      timeoutCode: "N8N_EXPORT_EXECUTION_TIMEOUT",
      maxBuffer: LOG_LIMIT_BYTES,
      timeoutMs: 30_000,
    });
    executionSucceeded = true;
    runnerAttachedScan = Object.freeze({
      stdout: scanReleaseRehearsalN8nProcessStream(
        executeResult.stdout,
        encryptionKey,
        "N8N_EXPORT_EXECUTE_STDOUT",
      ),
      stderr: scanReleaseRehearsalN8nProcessStream(
        executeResult.stderr,
        encryptionKey,
        "N8N_EXPORT_EXECUTE_STDERR",
      ),
    });

    await stopCapture(captureId);
    const captureEvidence = await readReleaseRehearsalN8nCaptureEvidence(
      files.outputDirectory,
    );
    if (
      !Array.isArray(captureEvidence["dns-events.json"]) ||
      captureEvidence["dns-events.json"].length !== 0
    ) {
      throw new ReleaseRehearsalN8nExportError("DNS_CONTAINMENT_VIOLATION", "BLOCKED");
    }
    captureCorrelation = correlateReleaseRehearsalN8nCapture({
      events: captureEvidence["capture-events.json"],
      summary: captureEvidence["capture-summary.json"],
      dnsSummary: captureEvidence["dns-summary.json"],
      expected: {
        ...files.captureMetadata,
        workflowCanonicalSha256: files.workflowBuild.workflowCanonicalSha256,
      },
    });
    if (captureCorrelation.status !== "CORRELATED" || captureCorrelation.eventCount !== 1) {
      throw new ReleaseRehearsalN8nExportError(
        "N8N_EXPORT_CAPTURE_CORRELATION_FAILED",
        "BLOCKED",
      );
    }

    const exporterCreate = await runDocker(
      buildReleaseRehearsalN8nCreateArgs({
        role: "n8n-export",
        name: exporterName,
        ownerId,
        runId,
        imageId: n8nImage.localImageId,
        volumeName,
        runDirectory: files.runDirectory,
        resolverPath: files.resolverPath,
        exportPath: exportDirectory,
        encryptionKey,
      }),
      { code: "N8N_EXPORTER_CREATE_FAILED", timeoutMs: 15_000 },
    );
    exporterId = validateReleaseRehearsalN8nContainerId(exporterCreate.stdout.trim());
    exporterSecurity = inspectReleaseRehearsalN8nContainer(
      await inspectObject("container", exporterId),
      {
        ...ownership.exporter,
        networkMode: "none",
        logicalNetworkMode: "none",
        mounts: [
          { type: "volume", name: volumeName, destination: CONTAINER_N8N_HOME, readWrite: true },
          { type: "bind", source: files.resolverPath, destination: CONTAINER_RESOLVER_PATH, readWrite: false },
          { type: "bind", source: exportDirectory, destination: CONTAINER_EXPORT_PATH, readWrite: true },
        ],
      },
    );
    if ((await readdir(exportDirectory)).length !== 0) {
      throw new ReleaseRehearsalN8nExportError("EXPORT_DIRECTORY_CHANGED_BEFORE_RUN", "BLOCKED");
    }
    const exportResult = await runDocker(["container", "start", "--attach", exporterId], {
      code: "N8N_EXPORT_COMMAND_FAILED",
      timeoutCode: "N8N_EXPORT_COMMAND_TIMEOUT",
      maxBuffer: LOG_LIMIT_BYTES,
      timeoutMs: 30_000,
    });
    exportSucceeded = true;
    exporterAttachedScan = Object.freeze({
      stdout: scanReleaseRehearsalN8nProcessStream(
        exportResult.stdout,
        encryptionKey,
        "N8N_EXPORT_STDOUT",
      ),
      stderr: scanReleaseRehearsalN8nProcessStream(
        exportResult.stderr,
        encryptionKey,
        "N8N_EXPORT_STDERR",
      ),
    });
    exportEvidence = await readReleaseRehearsalN8nEntityExport(exportDirectory, {
      workflowId: RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
    });
    rawDeletion = await deleteReleaseRehearsalN8nRawExport(exportDirectory);
    mainOutcome = exportEvidence.status;
  } catch (error) {
    const normalized = error instanceof ReleaseRehearsalN8nExportError
      ? error
      : new ReleaseRehearsalN8nExportError(error?.code ?? "N8N_EXPORT_CASE_FAILED", "BLOCKED");
    errorCodes.push(normalized.code);
    mainOutcome = normalized.outcome;
  } finally {
    clearTimeout(timer);
    try {
      await stopCapture(captureId);
    } catch (error) {
      errorCodes.push(error?.code ?? "N8N_EXPORT_CAPTURE_STOP_FAILED");
    }
    try {
      streamScans = Object.freeze({
        importAttached: setupAttachedScan,
        executeAttached: runnerAttachedScan,
        exportAttached: exporterAttachedScan,
        dockerLogs: {
          setup: await scanReleaseRehearsalN8nContainerLogs(setupId, encryptionKey, "N8N_EXPORT_SETUP"),
          runner: await scanReleaseRehearsalN8nContainerLogs(runnerId, encryptionKey, "N8N_EXPORT_RUNNER"),
          exporter: await scanReleaseRehearsalN8nContainerLogs(exporterId, encryptionKey, "N8N_EXPORTER"),
          capture: await scanReleaseRehearsalN8nContainerLogs(captureId, encryptionKey, "N8N_EXPORT_CAPTURE"),
        },
      });
    } catch (error) {
      errorCodes.push(error?.code ?? "N8N_EXPORT_LOG_SCAN_FAILED");
    }
    const [setupCleanup, runnerCleanup, exporterCleanup, captureCleanup] = await Promise.all([
      cleanupReleaseRehearsalContainer(setupId, ownership.setup),
      cleanupReleaseRehearsalContainer(runnerId, ownership.runner),
      cleanupReleaseRehearsalContainer(exporterId, ownership.exporter),
      cleanupReleaseRehearsalContainer(captureId, ownership.capture),
    ]);
    const volumeCleanup = await cleanupReleaseRehearsalN8nVolume(
      volumeCreated ? volumeName : null,
      { ownerId, runId },
    );
    let directoryRemoved = files === null;
    if (files) {
      try {
        await removeReleaseRehearsalPrivateRunDirectory(files.runDirectory);
        directoryRemoved = true;
      } catch {
        errorCodes.push("N8N_EXPORT_TEMP_DIRECTORY_CLEANUP_FAILED");
      }
    }
    const remainingResources = [
      setupCleanup.remainingId,
      runnerCleanup.remainingId,
      exporterCleanup.remainingId,
      captureCleanup.remainingId,
      volumeCleanup.remainingName,
    ].filter(Boolean);
    cleanup = Object.freeze({
      status:
        setupCleanup.removed &&
        runnerCleanup.removed &&
        exporterCleanup.removed &&
        captureCleanup.removed &&
        volumeCleanup.removed &&
        directoryRemoved
          ? "COMPLETE"
          : "FAILED",
      setupContainerRemoved: setupCleanup.removed,
      runnerContainerRemoved: runnerCleanup.removed,
      exporterContainerRemoved: exporterCleanup.removed,
      captureContainerRemoved: captureCleanup.removed,
      n8nVolumeRemoved: volumeCleanup.removed,
      privateRunDirectoryRemoved: directoryRemoved,
      rawArchiveDeleted: rawDeletion?.rawArchiveDeleted === true,
      exportDirectoryWasEmptyAfterDeletion: rawDeletion?.exportDirectoryEmpty === true,
      captureImageRemoved: false,
      remainingResourceCount: remainingResources.length,
      remainingResources,
    });
    if (cleanup.status !== "COMPLETE") errorCodes.push("N8N_EXPORT_CLEANUP_INCOMPLETE");
    if (exportEvidence && rawDeletion === null) errorCodes.push("N8N_EXPORT_RAW_NOT_DELETED");
    encryptionKeyBytes.fill(0);
    encryptionKey = null;
  }

  const status = cleanup.status !== "COMPLETE" || errorCodes.some((code) =>
    [
      "N8N_EXPORT_CLEANUP_INCOMPLETE",
      "N8N_EXPORT_RAW_NOT_DELETED",
      "N8N_EXPORT_LOG_SCAN_FAILED",
    ].includes(code),
  )
    ? "BLOCKED"
    : mainOutcome ?? "BLOCKED";
  return {
    schemaVersion: RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION,
    status,
    image: { ...n8nImage },
    cli: {
      importCommand: "n8n import:workflow --input=<fixed-workflow-file>",
      executeCommand: `n8n execute --id ${RELEASE_REHEARSAL_N8N_WORKFLOW_ID} --rawOutput`,
      exportCommand: RELEASE_REHEARSAL_N8N_EXPORT_COMMAND,
      importSucceeded,
      executionSucceeded,
      exportSucceeded,
      stdoutParsingUsed: false,
    },
    workflow: files
      ? {
          workflowId: files.workflowBuild.workflowId,
          workflowCanonicalSha256: files.workflowBuild.workflowCanonicalSha256,
          expectedNodeIds: files.workflowBuild.expectedNodeIds,
          syntheticOnly: true,
          credentialFree: true,
        }
      : null,
    capture: captureCorrelation,
    export: exportEvidence,
    containment: {
      docker,
      captureNetworkMode: captureSecurity?.networkMode ?? null,
      setupNetworkMode: setupSecurity?.networkMode ?? null,
      runnerNetworkMode: runnerSecurity?.networkMode ?? null,
      exporterNetworkMode: exporterSecurity?.networkMode ?? null,
      captureSecurity,
      setupSecurity,
      runnerSecurity,
      exporterSecurity,
      volumeSecurity,
      noPublishedPorts:
        captureSecurity?.publishedPorts === false &&
        setupSecurity?.publishedPorts === false &&
        runnerSecurity?.publishedPorts === false &&
        exporterSecurity?.publishedPorts === false,
      noProxyEnvironment:
        setupSecurity?.proxyEnvironmentPresent === false &&
        runnerSecurity?.proxyEnvironmentPresent === false &&
        exporterSecurity?.proxyEnvironmentPresent === false,
      externalHooksConfigured: false,
    },
    cleanup: {
      ...cleanup,
      remainingResources: undefined,
    },
    limitationCodes: exportEvidence?.limitationCodes ?? [],
    errorCodes: uniqueSorted(errorCodes),
    operational: {
      comparisonExcluded: true,
      runLabel: runId,
      captureContainerId: captureId,
      setupContainerId: setupId,
      runnerContainerId: runnerId,
      exporterContainerId: exporterId,
      volumeName,
      exactRunnerNetworkMode: captureId ? `container:${captureId}` : null,
      streamScans,
      rawValuesRetained: false,
      remainingResources: cleanup.remainingResources,
    },
  };
}

function finalizeCase(result, imageCleanup, inventory) {
  const errorCodes = [...result.errorCodes];
  if (imageCleanup.status !== "COMPLETE") errorCodes.push("CAPTURE_IMAGE_CLEANUP_INCOMPLETE");
  if (!inventory.unchanged) errorCodes.push("DOCKER_INVENTORY_CHANGED");
  if (inventory.managedResourceCount !== 0) errorCodes.push("MANAGED_RESOURCE_INVENTORY_NOT_EMPTY");
  const remaining = uniqueSorted([
    ...(result.operational?.remainingResources ?? []),
    ...imageCleanup.remainingIds,
  ]);
  const cleanup = {
    ...result.cleanup,
    status:
      result.cleanup.status === "COMPLETE" &&
      imageCleanup.status === "COMPLETE" &&
      inventory.unchanged &&
      inventory.managedResourceCount === 0
        ? "COMPLETE"
        : "FAILED",
    captureImageRemoved: imageCleanup.status === "COMPLETE",
    remainingResourceCount: remaining.length + inventory.managedResourceCount,
  };
  const status = cleanup.status === "COMPLETE" ? result.status : "BLOCKED";
  return {
    ...result,
    status,
    cleanup,
    errorCodes: uniqueSorted(errorCodes),
    operational: { ...result.operational, remainingResources: remaining },
  };
}

export async function runReleaseRehearsalN8nExportIntegration() {
  let docker;
  let n8nImage;
  let nodeImage;
  try {
    docker = await getReleaseRehearsalDockerRuntime();
    n8nImage = await resolveReleaseRehearsalPinnedN8nImage();
    nodeImage = await resolveReleaseRehearsalNodeImage();
  } catch (error) {
    return Object.freeze({
      schemaVersion: RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION,
      status: "BLOCKED",
      result: null,
      errorCodes: [error?.code ?? "N8N_EXPORT_PREREQUISITE_FAILED"],
    });
  }
  if (
    n8nImage.repositoryDigest !== RELEASE_REHEARSAL_N8N_IMAGE.repositoryDigest ||
    n8nImage.localImageId !== RELEASE_REHEARSAL_N8N_IMAGE.localImageId
  ) {
    return Object.freeze({
      schemaVersion: RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION,
      status: "BLOCKED",
      result: null,
      errorCodes: ["N8N_IMAGE_IDENTITY_CHANGED"],
    });
  }
  const [before, managedBefore] = await Promise.all([
    listReleaseRehearsalDockerInventory(),
    listReleaseRehearsalManagedDockerInventory(),
  ]);
  const ownerId = createReleaseRehearsalDockerIdentifier("n8n-export-owner");
  const template = await loadReleaseRehearsalN8nWorkflowTemplate();
  let captureImage = null;
  let imageCleanup = { status: "COMPLETE", remainingIds: [] };
  let result;
  try {
    captureImage = await buildReleaseRehearsalCaptureImage(nodeImage, ownerId);
    result = await runExportCase({
      docker,
      n8nImage,
      captureImage,
      ownerId,
      template,
    });
  } catch (error) {
    result = {
      schemaVersion: RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION,
      status: "BLOCKED",
      cleanup: { status: "FAILED", remainingResourceCount: 0 },
      errorCodes: [error?.code ?? "N8N_EXPORT_EXPERIMENT_FAILED"],
      operational: { remainingResources: [] },
    };
  } finally {
    imageCleanup = await removeReleaseRehearsalCaptureImage(captureImage, ownerId);
  }
  const [after, managedAfter] = await Promise.all([
    listReleaseRehearsalDockerInventory(),
    listReleaseRehearsalManagedDockerInventory(),
  ]);
  const inventory = Object.freeze({
    unchanged: releaseRehearsalDockerInventoriesEqual(before, after),
    beforeCounts: inventoryCounts(before),
    afterCounts: inventoryCounts(after),
    managedBeforeCounts: inventoryCounts(managedBefore),
    managedAfterCounts: inventoryCounts(managedAfter),
    managedResourceCount: inventoryTotal(managedAfter),
  });
  const finalized = finalizeCase(result, imageCleanup, inventory);
  try {
    serializeReleaseRehearsalN8nLogicalResult(finalized);
  } catch (error) {
    finalized.status = "BLOCKED";
    finalized.errorCodes = uniqueSorted([
      ...finalized.errorCodes,
      error?.code ?? "N8N_EXPORT_RESULT_REDACTION_VIOLATION",
    ]);
  }
  return Object.freeze({
    schemaVersion: RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION,
    status: finalized.status,
    result: finalized,
    imageCleanup: {
      status: imageCleanup.status,
      remainingResourceCount: imageCleanup.remainingIds.length,
    },
    inventory,
    errorCodes: [...finalized.errorCodes],
  });
}
