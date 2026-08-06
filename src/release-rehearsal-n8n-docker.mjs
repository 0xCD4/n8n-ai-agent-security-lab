import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";

import { canonicalJson } from "./evidence-fingerprint.mjs";
import {
  assertReleaseRehearsalDockerIdentifier,
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
  releaseRehearsalDockerInventoriesEqual,
  RELEASE_REHEARSAL_DOCKER_LABELS,
  removeReleaseRehearsalCaptureImage,
  removeReleaseRehearsalPrivateRunDirectory,
  resolveReleaseRehearsalNodeImage,
  runReleaseRehearsalDockerCommand,
  waitForReleaseRehearsalCaptureReady,
} from "./release-rehearsal-docker.mjs";
import {
  buildReleaseRehearsalN8nWorkflow,
  correlateReleaseRehearsalN8nCapture,
  createReleaseRehearsalN8nCaptureConfig,
  loadReleaseRehearsalN8nWorkflowTemplate,
  parseReleaseRehearsalN8nRawOutput,
  RELEASE_REHEARSAL_N8N_CAPABILITY_CODES,
  RELEASE_REHEARSAL_N8N_IMAGE,
  RELEASE_REHEARSAL_N8N_LIMITATION_CODES,
  RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
  ReleaseRehearsalN8nError,
  serializeReleaseRehearsalN8nLogicalResult,
} from "./release-rehearsal-n8n.mjs";
import { readBoundedJsonFile } from "./safe-json.mjs";

export const RELEASE_REHEARSAL_N8N_DOCKER_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_N8N_ENVIRONMENT = Object.freeze({
  N8N_DIAGNOSTICS_ENABLED: "false",
  N8N_VERSION_NOTIFICATIONS_ENABLED: "false",
  N8N_TEMPLATES_ENABLED: "false",
  N8N_PERSONALIZATION_ENABLED: "false",
  N8N_COMMUNITY_PACKAGES_ENABLED: "false",
  N8N_COMMUNITY_PACKAGES_PREVENT_LOADING: "true",
  N8N_UNVERIFIED_PACKAGES_ENABLED: "false",
  N8N_RUNNERS_ENABLED: "false",
  N8N_BLOCK_ENV_ACCESS_IN_NODE: "true",
  N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES: "true",
  N8N_DISABLE_UI: "true",
  N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS: "true",
  N8N_LOG_LEVEL: "info",
  N8N_LOG_OUTPUT: "console",
  EXECUTIONS_TIMEOUT: "10",
});

const CONTAINER_CONFIG_PATH = "/run/rehearsal/config/config.json";
const CONTAINER_OUTPUT_PATH = "/run/rehearsal/output";
const CONTAINER_RESOLVER_PATH = "/etc/resolv.conf";
const CONTAINER_WORKFLOW_PATH = "/run/rehearsal/workflow/workflow.json";
const CONTAINER_EXPORT_PATH = "/run/rehearsal/export";
const CONTAINER_N8N_HOME = "/home/node/.n8n";
const RESOLVER_CONTENT =
  "nameserver 127.0.0.1\noptions timeout:1 attempts:1 ndots:1\n";
const IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/u;
const VOLUME_NAME_PATTERN = /^csint-n8n-[a-f0-9]{16}$/u;
const ENCRYPTION_KEY_PATTERN = /^[a-f0-9]{64}$/u;
const WORKFLOW_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u;
const LOG_LIMIT_BYTES = 2 * 1024 * 1024;
const N8N_TMPFS_OPTIONS =
  "rw,noexec,nosuid,nodev,size=33554432,uid=1000,gid=1000,mode=0700";
const EVIDENCE_LIMITS = Object.freeze({
  maxBytes: 256 * 1024,
  maxDepth: 32,
  maxValues: 20_000,
});
const N8N_BASE_ENVIRONMENT_NAMES = Object.freeze([
  "N8N_RELEASE_TYPE",
  "NODE_ENV",
  "NODE_PATH",
  "NODE_VERSION",
  "NPM_CONFIG_UPDATE_NOTIFIER",
  "PATH",
  "SHELL",
]);
const N8N_ENVIRONMENT_NAMES = Object.freeze(
  [...N8N_BASE_ENVIRONMENT_NAMES, "N8N_ENCRYPTION_KEY", ...Object.keys(RELEASE_REHEARSAL_N8N_ENVIRONMENT)]
    .sort(stableCompare),
);
const EXPECTED_IMAGE_EXPOSED_PORTS = Object.freeze(["5678/tcp"]);
const FIXED_LIMITATIONS = Object.freeze([
  ...RELEASE_REHEARSAL_N8N_LIMITATION_CODES.filter(
    (code) =>
      !new Set([
        "EXECUTION_ORDER_UNAVAILABLE",
        "ITEM_LINK_VISIBILITY_UNKNOWN",
      ]).has(code),
  ),
  "TASK_RUNNER_DISABLE_CONTROL_DEPRECATED",
]);

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(stableCompare);
}

function validateContainerId(value) {
  if (typeof value !== "string" || !CONTAINER_ID_PATTERN.test(value)) {
    throw new ReleaseRehearsalN8nError("N8N_CONTAINER_ID_INVALID", "FAILED");
  }
  return value;
}

function validateVolumeName(value) {
  if (typeof value !== "string" || !VOLUME_NAME_PATTERN.test(value)) {
    throw new TypeError("n8n volume name is unsafe.");
  }
  return value;
}

function validateWorkflowId(value) {
  if (typeof value !== "string" || !WORKFLOW_ID_PATTERN.test(value)) {
    throw new TypeError("n8n workflow ID is unsafe.");
  }
  return value;
}

function labelsFor({ ownerId, runId, role }) {
  assertReleaseRehearsalDockerIdentifier(ownerId, "owner ID");
  assertReleaseRehearsalDockerIdentifier(runId, "run ID");
  if (
    !new Set([
      "n8n-setup",
      "n8n-publish",
      "n8n-runner",
      "n8n-server",
      "n8n-export",
      "n8n-volume",
    ]).has(role)
  ) {
    throw new TypeError("Phase 4 Docker role is unsupported.");
  }
  return Object.freeze({
    [RELEASE_REHEARSAL_DOCKER_LABELS.managed]: "true",
    [RELEASE_REHEARSAL_DOCKER_LABELS.owner]: ownerId,
    [RELEASE_REHEARSAL_DOCKER_LABELS.run]: runId,
    [RELEASE_REHEARSAL_DOCKER_LABELS.role]: role,
  });
}

function labelArguments(labels) {
  return Object.entries(labels)
    .sort(([left], [right]) => stableCompare(left, right))
    .flatMap(([name, value]) => ["--label", `${name}=${value}`]);
}

function bindMount(source, target, readOnly) {
  if (String(source).includes(",")) throw new TypeError("Mount sources must not contain commas.");
  const fields = ["type=bind", `source=${source}`, `target=${target}`];
  if (readOnly) fields.push("readonly");
  return fields.join(",");
}

function volumeMount(volumeName) {
  validateVolumeName(volumeName);
  return `type=volume,source=${volumeName},target=${CONTAINER_N8N_HOME}`;
}

function environmentArguments(encryptionKey) {
  if (!ENCRYPTION_KEY_PATTERN.test(encryptionKey ?? "")) {
    throw new TypeError("Synthetic n8n encryption key must be 32 random bytes.");
  }
  const values = {
    N8N_ENCRYPTION_KEY: encryptionKey,
    ...RELEASE_REHEARSAL_N8N_ENVIRONMENT,
  };
  return Object.entries(values)
    .sort(([left], [right]) => stableCompare(left, right))
    .flatMap(([name, value]) => ["--env", `${name}=${value}`]);
}

export function buildReleaseRehearsalN8nCreateArgs(options) {
  const role = options.role;
  if (
    !new Set([
      "n8n-setup",
      "n8n-publish",
      "n8n-runner",
      "n8n-server",
      "n8n-export",
    ]).has(role)
  ) {
    throw new TypeError("n8n container role is unsupported.");
  }
  assertReleaseRehearsalDockerIdentifier(options.name, "container name");
  assertReleaseRehearsalPrivatePath(tmpdir(), options.runDirectory);
  assertReleaseRehearsalPrivatePath(options.runDirectory, options.resolverPath);
  validateVolumeName(options.volumeName);
  if (options.imageId !== RELEASE_REHEARSAL_N8N_IMAGE.localImageId) {
    throw new ReleaseRehearsalN8nError(
      "N8N_IMAGE_IDENTITY_CHANGED",
      "N8N_IMAGE_IDENTITY_CHANGED",
    );
  }
  const args = [
    "container",
    "create",
    "--name",
    options.name,
    ...labelArguments(
      labelsFor({ ownerId: options.ownerId, runId: options.runId, role }),
    ),
    "--pull",
    "never",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges=true",
    "--user",
    "1000:1000",
    "--memory",
    "512m",
    "--memory-swap",
    "512m",
    "--cpus",
    "1.00",
    "--pids-limit",
    "128",
    "--stop-timeout",
    "5",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=33554432,uid=1000,gid=1000,mode=0700",
    "--log-driver",
    "local",
    "--log-opt",
    "max-size=1m",
    "--log-opt",
    "max-file=1",
    "--log-opt",
    "compress=false",
    ...environmentArguments(options.encryptionKey),
    "--mount",
    volumeMount(options.volumeName),
    "--mount",
    bindMount(options.resolverPath, CONTAINER_RESOLVER_PATH, true),
  ];
  if (role === "n8n-setup") {
    assertReleaseRehearsalPrivatePath(options.runDirectory, options.workflowPath);
    args.push(
      "--network",
      "none",
      "--mount",
      bindMount(options.workflowPath, CONTAINER_WORKFLOW_PATH, true),
      options.imageId,
      "import:workflow",
      `--input=${
        options.importFailure
          ? "/run/rehearsal/workflow/missing.json"
          : CONTAINER_WORKFLOW_PATH
      }`,
    );
  } else if (role === "n8n-publish") {
    validateWorkflowId(options.workflowId);
    args.push(
      "--network",
      "none",
      options.imageId,
      "publish:workflow",
      `--id=${options.workflowId}`,
    );
  } else if (role === "n8n-runner") {
    validateContainerId(options.captureContainerId);
    args.push(
      "--network",
      `container:${options.captureContainerId}`,
      options.imageId,
      "execute",
      "--id",
      RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
      "--rawOutput",
    );
  } else if (role === "n8n-server") {
    validateContainerId(options.captureContainerId);
    args.push(
      "--network",
      `container:${options.captureContainerId}`,
      options.imageId,
      "start",
    );
  } else {
    assertReleaseRehearsalPrivatePath(options.runDirectory, options.exportPath);
    args.push(
      "--network",
      "none",
      "--mount",
      bindMount(options.exportPath, CONTAINER_EXPORT_PATH, false),
      options.imageId,
      "export:entities",
      `--outputDir=${CONTAINER_EXPORT_PATH}`,
      "--includeExecutionHistoryDataTables=true",
    );
  }
  return args;
}

function equivalentBindSource(actual, expected) {
  const normalizedActual = String(actual).replaceAll("\\", "/").toLowerCase();
  const normalizedExpected = path.resolve(expected).replaceAll("\\", "/").toLowerCase();
  if (normalizedActual === normalizedExpected) return true;
  const expectedParts = normalizedExpected.split("/");
  const privateDirectoryIndex = expectedParts.findIndex((part) =>
    part.startsWith("csint-n8n-"),
  );
  if (
    privateDirectoryIndex >= 0 &&
    normalizedActual.endsWith(`/${expectedParts.slice(privateDirectoryIndex).join("/")}`)
  ) {
    return true;
  }
  const driveMatch = normalizedExpected.match(/^([a-z]):\/(.*)$/u);
  if (!driveMatch) return false;
  const [, drive, tail] = driveMatch;
  return [
    `/run/desktop/mnt/host/${drive}/${tail}`,
    `/host_mnt/${drive}/${tail}`,
    `/mnt/${drive}/${tail}`,
  ].includes(normalizedActual);
}

function environmentMap(entries) {
  const result = new Map();
  for (const entry of entries ?? []) {
    const separator = String(entry).indexOf("=");
    const name = separator < 0 ? String(entry) : String(entry).slice(0, separator);
    const value = separator < 0 ? "" : String(entry).slice(separator + 1);
    if (result.has(name)) {
      throw new ReleaseRehearsalN8nError("N8N_ENVIRONMENT_DUPLICATE", "FAILED");
    }
    result.set(name, value);
  }
  return result;
}

function verifyOwnershipLabels(actualLabels, expected) {
  const labels = labelsFor(expected);
  for (const [name, value] of Object.entries(labels)) {
    if (actualLabels?.[name] !== value) {
      throw new ReleaseRehearsalN8nError("N8N_OWNERSHIP_LABEL_MISMATCH", "FAILED");
    }
  }
}

function inspectN8nMounts(inspect, expected) {
  const mounts = Array.isArray(inspect.Mounts) ? inspect.Mounts : [];
  if (mounts.length !== expected.length) {
    throw new ReleaseRehearsalN8nError("N8N_MOUNT_SET_UNEXPECTED", "FAILED");
  }
  for (const mount of expected) {
    const actual = mounts.find((candidate) => candidate.Destination === mount.destination);
    if (!actual || actual.Type !== mount.type || actual.RW !== mount.readWrite) {
      throw new ReleaseRehearsalN8nError("N8N_MOUNT_SET_UNEXPECTED", "FAILED");
    }
    if (
      mount.type === "volume" &&
      (actual.Name !== mount.name || actual.Driver !== "local")
    ) {
      throw new ReleaseRehearsalN8nError("N8N_VOLUME_MOUNT_UNEXPECTED", "FAILED");
    }
    if (
      mount.type === "bind" &&
      !equivalentBindSource(actual.Source, mount.source)
    ) {
      const code =
        mount.destination === CONTAINER_RESOLVER_PATH
          ? "N8N_BIND_RESOLVER_SOURCE_UNEXPECTED"
          : mount.destination === CONTAINER_WORKFLOW_PATH
            ? "N8N_BIND_WORKFLOW_SOURCE_UNEXPECTED"
            : mount.destination === CONTAINER_EXPORT_PATH
              ? "N8N_BIND_EXPORT_SOURCE_UNEXPECTED"
            : "N8N_BIND_MOUNT_UNEXPECTED";
      throw new ReleaseRehearsalN8nError(code, "FAILED");
    }
    if (
      `${actual.Source ?? ""}\n${actual.Destination ?? ""}`
        .toLowerCase()
        .includes("docker.sock")
    ) {
      throw new ReleaseRehearsalN8nError("DOCKER_SOCKET_MOUNT_FORBIDDEN", "FAILED");
    }
  }
}

function isEmptyObject(value) {
  return !value || Object.keys(value).length === 0;
}

export function inspectReleaseRehearsalN8nContainer(inspect, expected) {
  if (!inspect || typeof inspect !== "object") {
    throw new ReleaseRehearsalN8nError("N8N_CONTAINER_INSPECT_INVALID", "FAILED");
  }
  validateContainerId(String(inspect.Id ?? ""));
  verifyOwnershipLabels(inspect.Config?.Labels, expected);
  if (inspect.Config?.Image !== RELEASE_REHEARSAL_N8N_IMAGE.localImageId) {
    throw new ReleaseRehearsalN8nError(
      "N8N_IMAGE_IDENTITY_CHANGED",
      "N8N_IMAGE_IDENTITY_CHANGED",
    );
  }
  const host = inspect.HostConfig ?? {};
  const securityOptions = host.SecurityOpt ?? [];
  const env = environmentMap(inspect.Config?.Env);
  const environmentNames = [...env.keys()].sort(stableCompare);
  if (canonicalJson(environmentNames) !== canonicalJson(N8N_ENVIRONMENT_NAMES)) {
    throw new ReleaseRehearsalN8nError("N8N_ENVIRONMENT_ALLOWLIST_VIOLATION", "FAILED");
  }
  if (!ENCRYPTION_KEY_PATTERN.test(env.get("N8N_ENCRYPTION_KEY") ?? "")) {
    throw new ReleaseRehearsalN8nError("N8N_ENCRYPTION_KEY_INVALID", "FAILED");
  }
  for (const [name, value] of Object.entries(RELEASE_REHEARSAL_N8N_ENVIRONMENT)) {
    if (env.get(name) !== value) {
      throw new ReleaseRehearsalN8nError("N8N_ENVIRONMENT_VALUE_INVALID", "FAILED");
    }
  }
  if (
    environmentNames.some((name) => /(?:^|_)(?:HTTP|HTTPS|ALL|NO)_?PROXY$/iu.test(name)) ||
    environmentNames.some((name) => /EXTERNAL_(?:FRONTEND_)?HOOK/iu.test(name))
  ) {
    throw new ReleaseRehearsalN8nError("N8N_EXTERNAL_ENVIRONMENT_FORBIDDEN", "FAILED");
  }
  const exposedPorts = Object.keys(inspect.Config?.ExposedPorts ?? {}).sort(stableCompare);
  const networkPorts = inspect.NetworkSettings?.Ports ?? {};
  const expectedTmpfs = {
    "/tmp": N8N_TMPFS_OPTIONS,
  };
  if (
    host.Privileged !== false ||
    host.ReadonlyRootfs !== true ||
    canonicalJson(host.CapDrop ?? []) !== canonicalJson(["ALL"]) ||
    (host.CapAdd ?? []).length !== 0 ||
    !securityOptions.includes("no-new-privileges=true") ||
    securityOptions.includes("seccomp=unconfined") ||
    inspect.Config?.User !== "1000:1000" ||
    host.Memory !== 536_870_912 ||
    host.MemorySwap !== 536_870_912 ||
    host.NanoCpus !== 1_000_000_000 ||
    host.PidsLimit !== 128 ||
    host.PublishAllPorts !== false ||
    !isEmptyObject(host.PortBindings) ||
    Object.values(networkPorts).some((bindings) => Array.isArray(bindings) && bindings.length > 0) ||
    canonicalJson(exposedPorts) !== canonicalJson(EXPECTED_IMAGE_EXPOSED_PORTS) ||
    (host.ExtraHosts ?? []).length !== 0 ||
    (host.Dns ?? []).length !== 0 ||
    (host.Devices ?? []).length !== 0 ||
    host.AutoRemove !== false ||
    canonicalJson(host.Tmpfs ?? {}) !== canonicalJson(expectedTmpfs)
  ) {
    throw new ReleaseRehearsalN8nError("N8N_CONTAINER_SECURITY_PROFILE_INVALID", "FAILED");
  }
  if (host.NetworkMode !== expected.networkMode) {
    throw new ReleaseRehearsalN8nError("N8N_NETWORK_MODE_MISMATCH", "FAILED");
  }
  const networkNames = Object.keys(inspect.NetworkSettings?.Networks ?? {}).sort(stableCompare);
  if (
    (["n8n-setup", "n8n-publish", "n8n-export"].includes(expected.role) &&
      canonicalJson(networkNames) !== canonicalJson(["none"])) ||
    (["n8n-runner", "n8n-server"].includes(expected.role) &&
      networkNames.length !== 0)
  ) {
    throw new ReleaseRehearsalN8nError("N8N_NETWORK_ATTACHMENT_UNEXPECTED", "FAILED");
  }
  inspectN8nMounts(inspect, expected.mounts);
  const expectedCommand = expected.role === "n8n-setup"
    ? [
        "import:workflow",
        `--input=${
          expected.importFailure
            ? "/run/rehearsal/workflow/missing.json"
            : CONTAINER_WORKFLOW_PATH
        }`,
      ]
    : expected.role === "n8n-publish"
      ? ["publish:workflow", `--id=${expected.workflowId}`]
    : expected.role === "n8n-runner"
      ? [
        "execute",
        "--id",
        RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
        "--rawOutput",
      ]
      : expected.role === "n8n-server"
        ? ["start"]
      : [
        "export:entities",
        `--outputDir=${CONTAINER_EXPORT_PATH}`,
        "--includeExecutionHistoryDataTables=true",
      ];
  if (canonicalJson(inspect.Config?.Cmd ?? []) !== canonicalJson(expectedCommand)) {
    throw new ReleaseRehearsalN8nError("N8N_COMMAND_SURFACE_UNEXPECTED", "FAILED");
  }
  return Object.freeze({
    privileged: false,
    readOnlyRootFilesystem: true,
    capabilityDrop: ["ALL"],
    capabilityAdd: [],
    noNewPrivileges: true,
    seccompUnconfined: false,
    user: "1000:1000",
    memoryBytes: host.Memory,
    nanoCpus: host.NanoCpus,
    pidsLimit: host.PidsLimit,
    environmentNames: environmentNames.filter(
      (name) => name !== "N8N_ENCRYPTION_KEY",
    ),
    environmentVariableCount: environmentNames.length,
    syntheticEncryptionKeyConfigured: true,
    proxyEnvironmentPresent: false,
    externalHooksConfigured: false,
    telemetryDisabled: true,
    communityPackagesDisabled: true,
    taskRunnerDisableRequested: true,
    dockerSocketMounted: false,
    mountDestinations: expected.mounts
      .map((mount) => mount.destination)
      .sort(stableCompare),
    networkMode: expected.logicalNetworkMode,
    publishedPorts: false,
    imageDeclaredExposedPorts: exposedPorts,
  });
}

export function validateReleaseRehearsalN8nImageIdentity(inspect) {
  if (
    !inspect ||
    inspect.Id !== RELEASE_REHEARSAL_N8N_IMAGE.localImageId ||
    inspect.Os !== "linux" ||
    inspect.Architecture !== "amd64" ||
    !(inspect.RepoDigests ?? []).includes(RELEASE_REHEARSAL_N8N_IMAGE.repositoryDigest)
  ) {
    throw new ReleaseRehearsalN8nError(
      "N8N_IMAGE_IDENTITY_CHANGED",
      "N8N_IMAGE_IDENTITY_CHANGED",
    );
  }
  return Object.freeze({ ...RELEASE_REHEARSAL_N8N_IMAGE });
}

export function inspectReleaseRehearsalN8nVolume(inspect, expected) {
  if (
    !inspect ||
    inspect.Name !== expected.volumeName ||
    inspect.Driver !== "local" ||
    inspect.Scope !== "local" ||
    !isEmptyObject(inspect.Options)
  ) {
    throw new ReleaseRehearsalN8nError("N8N_VOLUME_INSPECT_INVALID", "FAILED");
  }
  verifyOwnershipLabels(inspect.Labels, {
    ownerId: expected.ownerId,
    runId: expected.runId,
    role: "n8n-volume",
  });
  return Object.freeze({
    driver: "local",
    scope: "local",
    optionsPresent: false,
    ownershipLabelsVerified: true,
  });
}

async function resolvePinnedN8nImage() {
  const inspect = await inspectReleaseRehearsalDockerObject(
    "image",
    RELEASE_REHEARSAL_N8N_IMAGE.requestedTag,
    { allowMissing: true, code: "N8N_IMAGE_INSPECT_FAILED" },
  );
  if (!inspect) {
    throw new ReleaseRehearsalN8nError(
      "N8N_IMAGE_IDENTITY_CHANGED",
      "N8N_IMAGE_IDENTITY_CHANGED",
    );
  }
  return validateReleaseRehearsalN8nImageIdentity(inspect);
}

async function createN8nVolume({ volumeName, ownerId, runId }) {
  const labels = labelsFor({ ownerId, runId, role: "n8n-volume" });
  const result = await runReleaseRehearsalDockerCommand(
    ["volume", "create", ...labelArguments(labels), volumeName],
    { code: "N8N_VOLUME_CREATE_FAILED", timeoutMs: 10_000 },
  );
  if (result.stdout.trim() !== volumeName) {
    throw new ReleaseRehearsalN8nError("N8N_VOLUME_CREATE_RESULT_INVALID", "FAILED");
  }
  const inspect = await inspectReleaseRehearsalDockerObject("volume", volumeName, {
    code: "N8N_VOLUME_INSPECT_FAILED",
  });
  return inspectReleaseRehearsalN8nVolume(inspect, {
    volumeName,
    ownerId,
    runId,
  });
}

async function cleanupN8nVolume(volumeName, expected) {
  if (!volumeName) return { removed: true, remainingName: null };
  try {
    const inspect = await inspectReleaseRehearsalDockerObject("volume", volumeName, {
      allowMissing: true,
      code: "N8N_VOLUME_INSPECT_FAILED",
    });
    if (!inspect) return { removed: true, remainingName: null };
    inspectReleaseRehearsalN8nVolume(inspect, { volumeName, ...expected });
    await runReleaseRehearsalDockerCommand(["volume", "rm", volumeName], {
      code: "N8N_VOLUME_REMOVE_FAILED",
      timeoutMs: 10_000,
    });
    const remaining = await inspectReleaseRehearsalDockerObject("volume", volumeName, {
      allowMissing: true,
      code: "N8N_VOLUME_REINSPECT_FAILED",
    });
    if (remaining) throw new Error("volume remains");
    return { removed: true, remainingName: null };
  } catch {
    return { removed: false, remainingName: volumeName };
  }
}

async function prepareCaseFiles(template, runId, scenario) {
  const runDirectory = await createReleaseRehearsalPrivateRunDirectory(runId);
  try {
    const configDirectory = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "config"),
    );
    const outputDirectory = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "output"),
    );
    const workflowDirectory = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "workflow"),
    );
    await Promise.all([
      mkdir(configDirectory, { mode: 0o700 }),
      mkdir(outputDirectory, { mode: 0o700 }),
      mkdir(workflowDirectory, { mode: 0o700 }),
    ]);
    const metadata = {
      runId,
      caseId: `case-${scenario}`,
      variant: "baseline",
      fixtureId: `fixture-${scenario}`,
      correlationId: `correlation-${scenario}`,
    };
    const workflowBuild = buildReleaseRehearsalN8nWorkflow(template, metadata);
    const captureMetadata = scenario === "capture-mismatch"
      ? { ...metadata, correlationId: `expected-${scenario}` }
      : metadata;
    const captureConfig = createReleaseRehearsalN8nCaptureConfig({
      metadata: captureMetadata,
      workflowCanonicalSha256: workflowBuild.workflowCanonicalSha256,
    });
    const configPath = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(configDirectory, "config.json"),
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
      writeFile(workflowPath, canonicalJson(workflowBuild.workflow) + "\n", {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      }),
      writeFile(resolverPath, RESOLVER_CONTENT, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      }),
    ]);
    return Object.freeze({
      runDirectory,
      configPath,
      outputDirectory,
      workflowPath,
      resolverPath,
      workflowBuild,
      captureMetadata,
    });
  } catch (error) {
    await removeReleaseRehearsalPrivateRunDirectory(runDirectory);
    throw error;
  }
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
  return Object.freeze(Object.fromEntries(names.map((name, index) => [name, values[index]])));
}

function scanProcessStream(value, encryptionKey, label) {
  const text = String(value ?? "");
  const bytes = Buffer.byteLength(text, "utf8");
  if (bytes > LOG_LIMIT_BYTES) {
    throw new ReleaseRehearsalN8nError(`${label}_BYTE_LIMIT_EXCEEDED`, "FAILED");
  }
  if (
    text.includes(encryptionKey) ||
    /-----BEGIN [^-\r\n]{0,64}PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9+/=_-]{8,}|\b(?:ghp|github_pat|sk|xox[baprs])[_-][A-Za-z0-9_-]{8,}/iu.test(
      text,
    )
  ) {
    throw new ReleaseRehearsalN8nError(`${label}_REDACTION_VIOLATION`, "FAILED");
  }
  return Object.freeze({
    bytes,
    encryptionKeyAbsent: true,
    credentialPatternAbsent: true,
    retained: false,
  });
}

function analyzeRawFraming(value) {
  const text = String(value ?? "");
  const trimmed = text.trim();
  const firstBrace = text.indexOf("{");
  const lastBrace = text.lastIndexOf("}");
  return Object.freeze({
    bytes: Buffer.byteLength(text, "utf8"),
    lineCount: text === "" ? 0 : text.split(/\r?\n/u).length,
    firstNonWhitespaceCodePoint:
      trimmed.length > 0 ? trimmed.codePointAt(0) : null,
    lastNonWhitespaceCodePoint:
      trimmed.length > 0 ? trimmed.codePointAt(trimmed.length - 1) : null,
    firstBraceByteOffset:
      firstBrace < 0 ? null : Buffer.byteLength(text.slice(0, firstBrace), "utf8"),
    suffixBytes:
      lastBrace < 0
        ? null
        : Buffer.byteLength(text.slice(lastBrace + 1), "utf8"),
    extractionAttempted: false,
    retained: false,
  });
}

async function scanContainerLogs(containerId, encryptionKey, label) {
  if (!containerId) {
    return Object.freeze({
      stdout: scanProcessStream("", encryptionKey, `${label}_LOG_STDOUT`),
      stderr: scanProcessStream("", encryptionKey, `${label}_LOG_STDERR`),
    });
  }
  const logs = await runReleaseRehearsalDockerCommand(
    ["container", "logs", containerId],
    { code: `${label}_LOG_READ_FAILED`, maxBuffer: LOG_LIMIT_BYTES, timeoutMs: 5_000 },
  );
  return Object.freeze({
    stdout: scanProcessStream(logs.stdout, encryptionKey, `${label}_LOG_STDOUT`),
    stderr: scanProcessStream(logs.stderr, encryptionKey, `${label}_LOG_STDERR`),
  });
}

async function runN8nCase({ docker, n8nImage, captureImage, ownerId, template, scenario }) {
  const runId = createReleaseRehearsalDockerIdentifier("n8n");
  const suffix = runId.slice(-16);
  const captureName = `capture-${runId}`;
  const setupName = `setup-${runId}`;
  const runnerName = `runner-${runId}`;
  const volumeName = `csint-n8n-${suffix}`;
  const encryptionKeyBytes = randomBytes(32);
  let encryptionKey = encryptionKeyBytes.toString("hex");
  const caseController = new AbortController();
  const caseTimer = setTimeout(() => caseController.abort(), 60_000);
  caseTimer.unref();
  const caseRunDocker = (args, options = {}) =>
    runReleaseRehearsalDockerCommand(args, {
      ...options,
      signal: caseController.signal,
      timeoutCode: options.timeoutCode ?? "N8N_CASE_TIMEOUT",
    });
  const caseInspect = (kind, id, options = {}) =>
    inspectReleaseRehearsalDockerObject(kind, id, {
      ...options,
      signal: caseController.signal,
      timeoutCode: options.timeoutCode ?? "N8N_CASE_TIMEOUT",
    });
  const captureOwnership = { ownerId, runId, role: "capture" };
  const setupOwnership = { ownerId, runId, role: "n8n-setup" };
  const runnerOwnership = { ownerId, runId, role: "n8n-runner" };
  let files = null;
  let captureId = null;
  let setupId = null;
  let runnerId = null;
  let captureSecurity = null;
  let setupSecurity = null;
  let runnerSecurity = null;
  let volumeSecurity = null;
  let trace = null;
  let correlation = null;
  let evidence = null;
  let importAttachedScan = null;
  let executeAttachedScan = null;
  let rawFraming = null;
  let setupLogScan = null;
  let logScans = null;
  let mainErrorOutcome = null;
  const errorCodes = [];
  let importSucceeded = false;
  let executionSucceeded = false;
  let captureStarted = false;
  let directoryRemoved = false;
  let volumeCreated = false;
  let setupRemoved = false;
  let cleanup = null;

  try {
    files = await prepareCaseFiles(template, runId, scenario);
    await createN8nVolume({ volumeName, ownerId, runId });
    volumeCreated = true;
    const volumeInspect = await caseInspect("volume", volumeName);
    volumeSecurity = inspectReleaseRehearsalN8nVolume(volumeInspect, {
      volumeName,
      ownerId,
      runId,
    });

    const captureCreate = await caseRunDocker(
      buildReleaseRehearsalCaptureCreateArgs({
        name: captureName,
        ownerId,
        runId,
        imageId: captureImage.imageId,
        runDirectory: files.runDirectory,
        configPath: files.configPath,
        outputPath: files.outputDirectory,
      }),
      { code: "N8N_CAPTURE_CREATE_FAILED", timeoutMs: 15_000 },
    );
    captureId = validateContainerId(captureCreate.stdout.trim());
    const captureInspect = await caseInspect("container", captureId);
    captureSecurity = inspectReleaseRehearsalContainer(captureInspect, {
      ...captureOwnership,
      imageId: captureImage.imageId,
      networkMode: "none",
      logicalNetworkMode: "none",
      mounts: [
        { source: files.configPath, destination: CONTAINER_CONFIG_PATH, readWrite: false },
        { source: files.outputDirectory, destination: CONTAINER_OUTPUT_PATH, readWrite: true },
      ],
    });
    await caseRunDocker(["container", "start", captureId], {
      code: "N8N_CAPTURE_START_FAILED",
      timeoutMs: 10_000,
    });
    captureStarted = true;
    await waitForReleaseRehearsalCaptureReady(captureId, caseController.signal);

    const setupCreate = await caseRunDocker(
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
        importFailure: scenario === "import-failure",
      }),
      { code: "N8N_SETUP_CREATE_FAILED", timeoutMs: 15_000 },
    );
    setupId = validateContainerId(setupCreate.stdout.trim());
    const setupInspect = await caseInspect("container", setupId);
    setupSecurity = inspectReleaseRehearsalN8nContainer(setupInspect, {
      ...setupOwnership,
      networkMode: "none",
      logicalNetworkMode: "none",
      importFailure: scenario === "import-failure",
      mounts: [
        { type: "volume", name: volumeName, destination: CONTAINER_N8N_HOME, readWrite: true },
        { type: "bind", source: files.resolverPath, destination: CONTAINER_RESOLVER_PATH, readWrite: false },
        { type: "bind", source: files.workflowPath, destination: CONTAINER_WORKFLOW_PATH, readWrite: false },
      ],
    });
    let importResult;
    try {
      importResult = await caseRunDocker(["container", "start", "--attach", setupId], {
        code: "N8N_IMPORT_FAILED",
        timeoutCode: "N8N_IMPORT_TIMEOUT",
        maxBuffer: LOG_LIMIT_BYTES,
        timeoutMs: 30_000,
      });
    } catch (error) {
      if (scenario === "import-failure") {
        errorCodes.push("N8N_IMPORT_FAILED");
      } else {
        throw error;
      }
    }
    if (scenario === "import-failure") {
      if (importResult) errorCodes.push("N8N_IMPORT_FAILURE_NOT_OBSERVED");
      throw new ReleaseRehearsalN8nError("EXPECTED_IMPORT_FAILURE_OBSERVED", "FAILED");
    }
    importSucceeded = true;
    importAttachedScan = Object.freeze({
      stdout: scanProcessStream(importResult.stdout, encryptionKey, "N8N_IMPORT_STDOUT"),
      stderr: scanProcessStream(importResult.stderr, encryptionKey, "N8N_IMPORT_STDERR"),
    });
    setupLogScan = await scanContainerLogs(setupId, encryptionKey, "N8N_SETUP");
    const setupCleanup = await cleanupReleaseRehearsalContainer(setupId, setupOwnership);
    setupRemoved = setupCleanup.removed;
    if (!setupRemoved) throw new ReleaseRehearsalN8nError("N8N_SETUP_CLEANUP_FAILED", "FAILED");
    setupId = null;

    const runnerCreate = await caseRunDocker(
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
      { code: "N8N_RUNNER_CREATE_FAILED", timeoutMs: 15_000 },
    );
    runnerId = validateContainerId(runnerCreate.stdout.trim());
    const runnerInspect = await caseInspect("container", runnerId);
    runnerSecurity = inspectReleaseRehearsalN8nContainer(runnerInspect, {
      ...runnerOwnership,
      networkMode: `container:${captureId}`,
      logicalNetworkMode: "container:<capture-container-id>",
      mounts: [
        { type: "volume", name: volumeName, destination: CONTAINER_N8N_HOME, readWrite: true },
        { type: "bind", source: files.resolverPath, destination: CONTAINER_RESOLVER_PATH, readWrite: false },
      ],
    });
    let executeResult;
    try {
      executeResult = await caseRunDocker(["container", "start", "--attach", runnerId], {
        code: "N8N_EXECUTION_FAILED",
        timeoutCode: "N8N_EXECUTION_TIMEOUT",
        maxBuffer: LOG_LIMIT_BYTES,
        timeoutMs: scenario === "execution-timeout" ? 250 : 30_000,
      });
    } catch (error) {
      if (
        scenario === "execution-timeout" &&
        error?.code === "N8N_EXECUTION_TIMEOUT"
      ) {
        errorCodes.push("N8N_EXECUTION_TIMEOUT");
        throw new ReleaseRehearsalN8nError("EXPECTED_EXECUTION_TIMEOUT_OBSERVED", "FAILED");
      }
      if (scenario === "capture-mismatch" && error?.code === "N8N_EXECUTION_FAILED") {
        errorCodes.push("N8N_EXECUTION_FAILED");
      } else {
        throw error;
      }
    }
    if (scenario === "capture-mismatch") {
      if (executeResult) errorCodes.push("CAPTURE_MISMATCH_NOT_OBSERVED");
      throw new ReleaseRehearsalN8nError("EXPECTED_CAPTURE_MISMATCH_OBSERVED", "FAILED");
    }
    executionSucceeded = true;
    executeAttachedScan = Object.freeze({
      stdout: scanProcessStream(executeResult.stdout, encryptionKey, "N8N_EXECUTE_STDOUT"),
      stderr: scanProcessStream(executeResult.stderr, encryptionKey, "N8N_EXECUTE_STDERR"),
    });
    rawFraming = analyzeRawFraming(executeResult.stdout);
    trace = parseReleaseRehearsalN8nRawOutput(
      Buffer.from(executeResult.stdout, "utf8"),
    );
  } catch (error) {
    const normalized = error instanceof ReleaseRehearsalN8nError
      ? error
      : new ReleaseRehearsalN8nError(error?.code ?? "N8N_CASE_FAILED", "FAILED");
    if (!normalized.code.startsWith("EXPECTED_")) errorCodes.push(normalized.code);
    mainErrorOutcome = normalized.outcome;
  } finally {
    clearTimeout(caseTimer);
    if (captureId) {
      try {
        const inspect = await inspectReleaseRehearsalDockerObject("container", captureId, {
          allowMissing: true,
        });
        if (inspect?.State?.Running) {
          await runReleaseRehearsalDockerCommand(
            ["container", "stop", "--time", "5", captureId],
            { code: "N8N_CAPTURE_STOP_FAILED", timeoutMs: 10_000 },
          );
        }
      } catch (error) {
        errorCodes.push(error?.code ?? "N8N_CAPTURE_STOP_FAILED");
      }
    }
    if (captureStarted && files) {
      try {
        evidence = await readCaptureEvidence(files.outputDirectory);
        if (!Array.isArray(evidence["dns-events.json"]) || evidence["dns-events.json"].length !== 0) {
          errorCodes.push("DNS_CONTAINMENT_VIOLATION");
        }
        correlation = correlateReleaseRehearsalN8nCapture({
          events: evidence["capture-events.json"],
          summary: evidence["capture-summary.json"],
          dnsSummary: evidence["dns-summary.json"],
          expected: {
            ...files.captureMetadata,
            workflowCanonicalSha256: files.workflowBuild.workflowCanonicalSha256,
          },
        });
        errorCodes.push(...correlation.errorCodes);
      } catch (error) {
        errorCodes.push(error?.code ?? "N8N_CAPTURE_EVIDENCE_INVALID");
      }
    }
    try {
      logScans = Object.freeze({
        setup:
          setupLogScan ??
          (await scanContainerLogs(setupId, encryptionKey, "N8N_SETUP")),
        runner: await scanContainerLogs(runnerId, encryptionKey, "N8N_RUNNER"),
        capture: await scanContainerLogs(captureId, encryptionKey, "N8N_CAPTURE"),
      });
    } catch (error) {
      errorCodes.push(error?.code ?? "N8N_LOG_SCAN_FAILED");
    }
    const [setupCleanup, runnerCleanup, captureCleanup] = await Promise.all([
      cleanupReleaseRehearsalContainer(setupId, setupOwnership),
      cleanupReleaseRehearsalContainer(runnerId, runnerOwnership),
      cleanupReleaseRehearsalContainer(captureId, captureOwnership),
    ]);
    setupRemoved = setupRemoved || setupCleanup.removed;
    const volumeCleanup = await cleanupN8nVolume(
      volumeCreated ? volumeName : null,
      { ownerId, runId },
    );
    if (files) {
      try {
        await removeReleaseRehearsalPrivateRunDirectory(files.runDirectory);
        directoryRemoved = true;
      } catch {
        errorCodes.push("N8N_TEMP_DIRECTORY_CLEANUP_FAILED");
      }
    } else {
      directoryRemoved = true;
    }
    const remainingResources = [
      setupCleanup.remainingId,
      runnerCleanup.remainingId,
      captureCleanup.remainingId,
      volumeCleanup.remainingName,
    ].filter(Boolean);
    cleanup = {
      status:
        setupRemoved &&
        runnerCleanup.removed &&
        captureCleanup.removed &&
        volumeCleanup.removed &&
        directoryRemoved
          ? "COMPLETE"
          : "FAILED",
      setupContainerRemoved: setupRemoved,
      runnerContainerRemoved: runnerCleanup.removed,
      captureContainerRemoved: captureCleanup.removed,
      n8nVolumeRemoved: volumeCleanup.removed,
      privateRunDirectoryRemoved: directoryRemoved,
      captureImageRemoved: false,
      remainingResourceCount: remainingResources.length,
      remainingResources,
    };
    if (cleanup.status !== "COMPLETE") errorCodes.push("N8N_CLEANUP_INCOMPLETE");
    encryptionKeyBytes.fill(0);
    encryptionKey = null;
  }

  const expectedFailureCode =
    scenario === "import-failure"
      ? "N8N_IMPORT_FAILED"
      : scenario === "execution-timeout"
        ? "N8N_EXECUTION_TIMEOUT"
        : scenario === "capture-mismatch"
          ? "CAPTURE_CORRELATION_MISMATCH"
          : null;
  const limitationCodes = uniqueSorted([
    ...FIXED_LIMITATIONS,
    ...(trace?.limitationCodes ?? []),
  ]);
  const success =
    scenario === "success" &&
    importSucceeded &&
    executionSucceeded &&
    trace?.traceStatus === "TRACE_AVAILABLE" &&
    correlation?.status === "CORRELATED" &&
    cleanup.status === "COMPLETE" &&
    errorCodes.length === 0;
  const status = success
    ? "PASS_MINIMAL_TRACE"
    : scenario === "success" && mainErrorOutcome === "EXECUTION_TRACE_UNAVAILABLE"
      ? "EXECUTION_TRACE_UNAVAILABLE"
      : "FAILED";
  const logical = {
    schemaVersion: RELEASE_REHEARSAL_N8N_DOCKER_SCHEMA_VERSION,
    status,
    image: { ...n8nImage },
    cli: {
      importCommand: "n8n import:workflow --input=<fixed-workflow-file>",
      executeCommand: `n8n execute --id ${RELEASE_REHEARSAL_N8N_WORKFLOW_ID} --rawOutput`,
      importSucceeded,
      executionSucceeded,
      rawOutputStrictJson: trace !== null,
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
    execution: trace,
    capture: correlation,
    containment: {
      docker,
      captureNetworkMode: captureSecurity?.networkMode ?? null,
      setupNetworkMode: setupSecurity?.networkMode ?? null,
      runnerNetworkMode: runnerSecurity?.networkMode ?? null,
      captureSecurity,
      setupSecurity,
      runnerSecurity,
      volumeSecurity,
      noPublishedPorts:
        captureSecurity?.publishedPorts === false &&
        setupSecurity?.publishedPorts === false &&
        runnerSecurity?.publishedPorts === false,
      noProxyEnvironment:
        setupSecurity?.proxyEnvironmentPresent === false &&
        runnerSecurity?.proxyEnvironmentPresent === false,
      externalHooksConfigured: false,
    },
    cleanup: {
      ...cleanup,
      remainingResourceCount: cleanup.remainingResourceCount,
      remainingResources: undefined,
    },
    capabilityCodes: success ? [...RELEASE_REHEARSAL_N8N_CAPABILITY_CODES] : [],
    limitationCodes,
    errorCodes: uniqueSorted(errorCodes),
  };
  const operational = {
    comparisonExcluded: true,
    runLabel: runId,
    captureContainerId: captureId,
    setupContainerId: setupId,
    runnerContainerId: runnerId,
    volumeName,
    exactRunnerNetworkMode: captureId ? `container:${captureId}` : null,
    streamScans: {
      importAttached: importAttachedScan,
      executeAttached: executeAttachedScan,
      dockerLogs: logScans,
    },
    rawFraming,
    rawValuesRetained: false,
    remainingResources: cleanup.remainingResources,
  };
  return {
    ...logical,
    operational,
    expectedFailureScenario: expectedFailureCode ? scenario : null,
    expectedFailureCode,
  };
}

function finalizeCase(result, imageCleanup) {
  const errorCodes = [...result.errorCodes];
  if (imageCleanup.status !== "COMPLETE") errorCodes.push("CAPTURE_IMAGE_CLEANUP_INCOMPLETE");
  const remaining = uniqueSorted([
    ...(result.operational?.remainingResources ?? []),
    ...imageCleanup.remainingIds,
  ]);
  const cleanup = {
    ...result.cleanup,
    status:
      result.cleanup.status === "COMPLETE" && imageCleanup.status === "COMPLETE"
        ? "COMPLETE"
        : "FAILED",
    captureImageRemoved: imageCleanup.status === "COMPLETE",
    remainingResourceCount: remaining.length,
  };
  return {
    ...result,
    status:
      result.status === "PASS_MINIMAL_TRACE" && cleanup.status === "COMPLETE"
        ? "PASS_MINIMAL_TRACE"
        : result.status === "EXECUTION_TRACE_UNAVAILABLE"
          ? "EXECUTION_TRACE_UNAVAILABLE"
          : "FAILED",
    cleanup,
    errorCodes: uniqueSorted(errorCodes),
    operational: {
      ...result.operational,
      remainingResources: remaining,
    },
  };
}

export async function runReleaseRehearsalN8nIntegrationSuite(options = {}) {
  const scenarios = options.scenarios ?? [
    "success",
    "import-failure",
    "execution-timeout",
    "capture-mismatch",
  ];
  if (
    !Array.isArray(scenarios) ||
    scenarios.length < 1 ||
    scenarios[0] !== "success" ||
    scenarios.some(
      (scenario) =>
        !new Set([
          "success",
          "import-failure",
          "execution-timeout",
          "capture-mismatch",
        ]).has(scenario),
    ) ||
    new Set(scenarios).size !== scenarios.length
  ) {
    throw new TypeError("n8n integration scenarios are invalid.");
  }
  let docker;
  let n8nImage;
  let nodeImage;
  try {
    docker = await getReleaseRehearsalDockerRuntime();
    n8nImage = await resolvePinnedN8nImage();
    nodeImage = await resolveReleaseRehearsalNodeImage();
  } catch (error) {
    const normalized = error instanceof ReleaseRehearsalN8nError
      ? error
      : new ReleaseRehearsalN8nError(error?.code ?? "N8N_PREREQUISITE_FAILED", "FAILED");
    return Object.freeze({
      schemaVersion: RELEASE_REHEARSAL_N8N_DOCKER_SCHEMA_VERSION,
      status: normalized.outcome,
      primary: null,
      failureCases: [],
      errorCodes: [normalized.code],
    });
  }
  const before = await listReleaseRehearsalDockerInventory();
  const ownerId = createReleaseRehearsalDockerIdentifier("n8n-owner");
  const template = await loadReleaseRehearsalN8nWorkflowTemplate();
  let captureImage = null;
  let imageCleanup = { status: "COMPLETE", remainingIds: [] };
  const cases = [];
  try {
    captureImage = await buildReleaseRehearsalCaptureImage(nodeImage, ownerId);
    for (const scenario of scenarios) {
      cases.push(
        await runN8nCase({
          docker,
          n8nImage,
          captureImage,
          ownerId,
          template,
          scenario,
        }),
      );
    }
  } finally {
    imageCleanup = await removeReleaseRehearsalCaptureImage(captureImage, ownerId);
  }
  const after = await listReleaseRehearsalDockerInventory();
  const inventoryUnchanged = releaseRehearsalDockerInventoriesEqual(before, after);
  const finalized = cases.map((result) => finalizeCase(result, imageCleanup));
  const primary = finalized[0] ?? null;
  const failureCases = finalized.slice(1);
  const expectedFailuresObserved =
    failureCases.length === scenarios.length - 1 && failureCases.every(
    (result) =>
      result.status === "FAILED" &&
      result.cleanup.status === "COMPLETE" &&
      result.expectedFailureCode &&
      result.errorCodes.includes(result.expectedFailureCode),
  );
  let status =
    primary?.status === "PASS_MINIMAL_TRACE" &&
    expectedFailuresObserved &&
    inventoryUnchanged &&
    imageCleanup.status === "COMPLETE"
      ? "PASS_MINIMAL_TRACE"
      : primary?.status === "EXECUTION_TRACE_UNAVAILABLE"
        ? "EXECUTION_TRACE_UNAVAILABLE"
        : "FAILED";
  const errorCodes = [];
  if (!inventoryUnchanged) errorCodes.push("DOCKER_INVENTORY_CHANGED");
  if (imageCleanup.status !== "COMPLETE") errorCodes.push("CAPTURE_IMAGE_CLEANUP_INCOMPLETE");
  if (!expectedFailuresObserved) errorCodes.push("EXPECTED_FAILURE_CASE_MISSING");
  if (primary) {
    try {
      serializeReleaseRehearsalN8nLogicalResult(primary);
    } catch (error) {
      status = "FAILED";
      errorCodes.push(error?.code ?? "N8N_RESULT_REDACTION_VIOLATION");
    }
  }
  return Object.freeze({
    schemaVersion: RELEASE_REHEARSAL_N8N_DOCKER_SCHEMA_VERSION,
    status,
    primary,
    failureCases,
    imageCleanup: {
      status: imageCleanup.status,
      remainingResourceCount: imageCleanup.remainingIds.length,
    },
    inventory: {
      unchanged: inventoryUnchanged,
      beforeCounts: Object.fromEntries(
        Object.entries(before).map(([key, values]) => [key, values.length]),
      ),
      afterCounts: Object.fromEntries(
        Object.entries(after).map(([key, values]) => [key, values.length]),
      ),
    },
    errorCodes: uniqueSorted(errorCodes),
  });
}

// Narrow internal reuse for the Phase 5A documented entity-export probe. The
// existing Phase 4 lifecycle and security checks remain the source of truth.
export {
  cleanupN8nVolume as cleanupReleaseRehearsalN8nVolume,
  createN8nVolume as createReleaseRehearsalN8nVolume,
  prepareCaseFiles as prepareReleaseRehearsalN8nCaseFiles,
  readCaptureEvidence as readReleaseRehearsalN8nCaptureEvidence,
  resolvePinnedN8nImage as resolveReleaseRehearsalPinnedN8nImage,
  scanContainerLogs as scanReleaseRehearsalN8nContainerLogs,
  scanProcessStream as scanReleaseRehearsalN8nProcessStream,
  validateContainerId as validateReleaseRehearsalN8nContainerId,
};
