import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "./evidence-fingerprint.mjs";
import {
  validateReleaseRehearsalCaptureConfig,
} from "./release-rehearsal-fixture.mjs";
import { normalizeHttpDestination } from "./release-rehearsal-normalize.mjs";
import { readBoundedJsonFile } from "./safe-json.mjs";

export const RELEASE_REHEARSAL_DOCKER_RESULT_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_NODE_IMAGE_TAG = "node:24.19.0-alpine3.23";
export const RELEASE_REHEARSAL_DOCKER_LABELS = Object.freeze({
  managed: "com.csint.release-rehearsal.managed",
  owner: "com.csint.release-rehearsal.owner-id",
  run: "com.csint.release-rehearsal.run-id",
  role: "com.csint.release-rehearsal.role",
});

const execFileAsync = promisify(execFile);
const REPOSITORY_ROOT = fileURLToPath(new URL("../", import.meta.url));
const CONTAINERFILE_PATH = path.join(
  REPOSITORY_ROOT,
  "lab",
  "release-rehearsal-capture",
  "Containerfile",
);
const CONTAINER_CONFIG_PATH = "/run/rehearsal/config/config.json";
const CONTAINER_FIXTURE_PATH = "/run/rehearsal/fixture/fixture-set.json";
const CONTAINER_RESOLVER_PATH = "/etc/resolv.conf";
const CONTAINER_OUTPUT_PATH = "/run/rehearsal/output";
const PROBE_ENTRYPOINT = "/app/lab/release-rehearsal-capture/probe.mjs";
const RESOLVER_CONTENT =
  "nameserver 127.0.0.1\noptions timeout:1 attempts:1 ndots:1\n";
const IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/u;
const IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const DIGEST_PATTERN = /^(?:docker\.io\/library\/)?node@sha256:[a-f0-9]{64}$/u;
const ALLOWED_ENVIRONMENT_NAMES = Object.freeze([
  "NODE_ENV",
  "NODE_VERSION",
  "PATH",
  "YARN_VERSION",
]);
const LOG_LIMIT_BYTES = 64 * 1024;
const JSON_LIMITS = Object.freeze({
  maxBytes: 256 * 1024,
  maxDepth: 32,
  maxValues: 20_000,
});
const LOGICAL_LIMITATIONS = Object.freeze([
  "Synthetic Docker containment probes only.",
  "No n8n or workflow execution was performed.",
  "No HTTP-node semantic equivalence was established.",
  "No runtime action or approval evidence was produced.",
  "This is not production-safety, sandbox, or Milestone 1 evidence.",
]);

class DockerHarnessError extends Error {
  constructor(code, status = "FAILED", diagnostic = "") {
    super(code);
    this.code = code;
    this.status = status;
    Object.defineProperty(this, "diagnostic", {
      value: diagnostic,
      enumerable: false,
    });
  }
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(stableCompare);
}

export function assertReleaseRehearsalDockerIdentifier(value, label = "identifier") {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new TypeError(`${label} is unsafe.`);
  }
  return value;
}

export function assertReleaseRehearsalPrivatePath(rootPath, candidatePath) {
  if (typeof rootPath !== "string" || typeof candidatePath !== "string") {
    throw new TypeError("Private paths must be strings.");
  }
  if (rootPath.includes(",") || candidatePath.includes(",")) {
    throw new TypeError("Private paths must not contain commas.");
  }
  const root = path.resolve(rootPath);
  const candidate = path.resolve(candidatePath);
  const relative = path.relative(root, candidate);
  if (!relative || relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) {
    throw new TypeError("Path escapes its private run directory.");
  }
  return candidate;
}

function validateContainerId(value, label = "container ID") {
  if (typeof value !== "string" || !CONTAINER_ID_PATTERN.test(value)) {
    throw new TypeError(`${label} must be an exact 64-character container ID.`);
  }
  return value;
}

function validateImageId(value) {
  if (typeof value !== "string" || !IMAGE_ID_PATTERN.test(value)) {
    throw new TypeError("Image ID must be an exact SHA-256 image ID.");
  }
  return value;
}

function labelsFor({ ownerId, runId, role }) {
  assertReleaseRehearsalDockerIdentifier(ownerId, "owner ID");
  assertReleaseRehearsalDockerIdentifier(runId, "run ID");
  if (
    ![
      "capture",
      "probe",
      "image",
      "n8n-setup",
      "n8n-publish",
      "n8n-runner",
      "n8n-server",
      "n8n-export",
      "n8n-volume",
    ].includes(role)
  ) {
    throw new TypeError("Docker role is unsupported.");
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
  const fields = ["type=bind", `source=${source}`, `target=${target}`];
  if (readOnly) fields.push("readonly");
  return fields.join(",");
}

function commonCreateArguments({
  name,
  ownerId,
  runId,
  role,
  imageId,
  runDirectory,
  configPath,
  fixturePath,
  outputPath,
}) {
  assertReleaseRehearsalDockerIdentifier(name, "container name");
  validateImageId(imageId);
  assertReleaseRehearsalPrivatePath(tmpdir(), runDirectory);
  if (!path.basename(runDirectory).startsWith("csint-")) {
    throw new TypeError("Run directory is not privately owned by this harness.");
  }
  assertReleaseRehearsalPrivatePath(runDirectory, configPath);
  if (fixturePath !== undefined) {
    assertReleaseRehearsalPrivatePath(runDirectory, fixturePath);
  }
  assertReleaseRehearsalPrivatePath(runDirectory, outputPath);
  const labels = labelsFor({ ownerId, runId, role });
  const args = [
    "container",
    "create",
    "--name",
    name,
    ...labelArguments(labels),
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
    "128m",
    "--memory-swap",
    "128m",
    "--cpus",
    "0.50",
    "--pids-limit",
    "64",
    "--stop-timeout",
    "5",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=16777216,uid=1000,gid=1000,mode=0700",
    "--log-driver",
    "local",
    "--log-opt",
    "max-size=1m",
    "--log-opt",
    "max-file=1",
    "--log-opt",
    "compress=false",
    "--env",
    "NODE_ENV=production",
    "--mount",
    bindMount(configPath, CONTAINER_CONFIG_PATH, true),
    "--mount",
    bindMount(outputPath, CONTAINER_OUTPUT_PATH, false),
  ];
  if (fixturePath !== undefined) {
    args.push(
      "--mount",
      bindMount(fixturePath, CONTAINER_FIXTURE_PATH, true),
    );
  }
  return args;
}

export function buildReleaseRehearsalCaptureCreateArgs(options) {
  return [
    ...commonCreateArguments({ ...options, role: "capture" }),
    "--network",
    "none",
    options.imageId,
  ];
}

export function buildReleaseRehearsalProbeCreateArgs(options) {
  validateContainerId(options.captureContainerId, "capture container ID");
  assertReleaseRehearsalPrivatePath(options.runDirectory, options.resolverPath);
  if (!["normal", "synthetic-failure", "timeout"].includes(options.mode)) {
    throw new TypeError("Probe mode is unsupported.");
  }
  return [
    ...commonCreateArguments({ ...options, role: "probe" }),
    "--network",
    `container:${options.captureContainerId}`,
    "--mount",
    bindMount(options.resolverPath, CONTAINER_RESOLVER_PATH, true),
    "--entrypoint",
    "node",
    options.imageId,
    PROBE_ENTRYPOINT,
    "--mode",
    options.mode,
  ];
}

export function verifyReleaseRehearsalOwnership(inspect, expected) {
  if (!inspect || typeof inspect !== "object") {
    throw new DockerHarnessError("OWNERSHIP_INSPECT_INVALID");
  }
  const expectedLabels = labelsFor(expected);
  const actualLabels = inspect.Config?.Labels ?? {};
  for (const [name, value] of Object.entries(expectedLabels)) {
    if (actualLabels[name] !== value) {
      throw new DockerHarnessError("OWNERSHIP_LABEL_MISMATCH");
    }
  }
  return true;
}

function isEmptyObject(value) {
  return !value || Object.keys(value).length === 0;
}

function equivalentMountSource(actual, expected) {
  const normalizedActual = String(actual).replaceAll("\\", "/").toLowerCase();
  const normalizedExpected = path.resolve(expected).replaceAll("\\", "/").toLowerCase();
  if (normalizedActual === normalizedExpected) return true;
  const driveMatch = normalizedExpected.match(/^([a-z]):\/(.*)$/u);
  if (!driveMatch) return false;
  const [, drive, tail] = driveMatch;
  return [
    `/run/desktop/mnt/host/${drive}/${tail}`,
    `/host_mnt/${drive}/${tail}`,
    `/mnt/${drive}/${tail}`,
  ].includes(normalizedActual);
}

function inspectMounts(inspect, expectedMounts) {
  const mounts = Array.isArray(inspect.Mounts) ? inspect.Mounts : [];
  if (mounts.length !== expectedMounts.length) {
    throw new DockerHarnessError("MOUNT_SET_UNEXPECTED");
  }
  for (const expected of expectedMounts) {
    const actual = mounts.find((mount) => mount.Destination === expected.destination);
    if (
      !actual ||
      actual.Type !== "bind" ||
      actual.RW !== expected.readWrite ||
      !equivalentMountSource(actual.Source, expected.source)
    ) {
      throw new DockerHarnessError("MOUNT_SET_UNEXPECTED");
    }
  }
  if (
    mounts.some((mount) =>
      `${mount.Source ?? ""}\n${mount.Destination ?? ""}`
        .toLowerCase()
        .includes("docker.sock"),
    )
  ) {
    throw new DockerHarnessError("DOCKER_SOCKET_MOUNT_FORBIDDEN");
  }
}

export function inspectReleaseRehearsalContainer(inspect, expected) {
  verifyReleaseRehearsalOwnership(inspect, expected);
  validateContainerId(String(inspect.Id ?? ""));
  if (inspect.Config?.Image !== expected.imageId) {
    throw new DockerHarnessError("IMAGE_ID_MISMATCH");
  }
  const host = inspect.HostConfig ?? {};
  const securityOptions = host.SecurityOpt ?? [];
  const environmentNames = uniqueSorted(
    (inspect.Config?.Env ?? []).map((entry) => String(entry).split("=", 1)[0]),
  );
  if (canonicalJson(environmentNames) !== canonicalJson(ALLOWED_ENVIRONMENT_NAMES)) {
    throw new DockerHarnessError("ENVIRONMENT_ALLOWLIST_VIOLATION");
  }
  if (
    host.Privileged !== false ||
    host.ReadonlyRootfs !== true ||
    canonicalJson(host.CapDrop ?? []) !== canonicalJson(["ALL"]) ||
    (host.CapAdd ?? []).length !== 0 ||
    !securityOptions.includes("no-new-privileges=true") ||
    securityOptions.some((value) => value === "seccomp=unconfined") ||
    inspect.Config?.User !== "1000:1000" ||
    host.Memory !== 134_217_728 ||
    host.MemorySwap !== 134_217_728 ||
    host.NanoCpus !== 500_000_000 ||
    host.PidsLimit !== 64 ||
    !isEmptyObject(host.PortBindings) ||
    !isEmptyObject(inspect.Config?.ExposedPorts) ||
    !isEmptyObject(inspect.NetworkSettings?.Ports) ||
    (host.ExtraHosts ?? []).length !== 0 ||
    (host.Dns ?? []).length !== 0 ||
    (host.Devices ?? []).length !== 0
  ) {
    throw new DockerHarnessError("CONTAINER_SECURITY_PROFILE_INVALID");
  }
  if (host.NetworkMode !== expected.networkMode) {
    throw new DockerHarnessError("NETWORK_MODE_MISMATCH");
  }
  const networkNames = Object.keys(inspect.NetworkSettings?.Networks ?? {}).sort(stableCompare);
  if (
    (expected.role === "capture" &&
      canonicalJson(networkNames) !== canonicalJson(["none"])) ||
    (expected.role === "probe" && networkNames.length !== 0)
  ) {
    throw new DockerHarnessError("NETWORK_ATTACHMENT_UNEXPECTED");
  }
  inspectMounts(inspect, expected.mounts);
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
    environmentNames,
    dockerSocketMounted: false,
    mountDestinations: expected.mounts
      .map((mount) => mount.destination)
      .sort(stableCompare),
    networkMode: expected.logicalNetworkMode,
    approvedNetworkAttachmentOnly: true,
    publishedPorts: false,
  });
}

export function validateReleaseRehearsalImageIdentity(inspect, requestedTag) {
  if (!inspect || typeof inspect !== "object") {
    throw new DockerHarnessError("IMAGE_INSPECT_INVALID", "ISOLATION_UNAVAILABLE");
  }
  const repositoryDigest = (inspect.RepoDigests ?? []).find((value) =>
    DIGEST_PATTERN.test(value),
  );
  if (
    requestedTag !== RELEASE_REHEARSAL_NODE_IMAGE_TAG ||
    !repositoryDigest ||
    !IMAGE_ID_PATTERN.test(inspect.Id ?? "") ||
    inspect.Os !== "linux" ||
    typeof inspect.Architecture !== "string" ||
    inspect.Architecture.length === 0
  ) {
    throw new DockerHarnessError("IMAGE_IDENTITY_INVALID", "ISOLATION_UNAVAILABLE");
  }
  return Object.freeze({
    requestedTag,
    repositoryDigest,
    platform: `${inspect.Os}/${inspect.Architecture}`,
    localImageId: inspect.Id,
  });
}

export function buildReleaseRehearsalCleanupTarget(inspect, expected) {
  verifyReleaseRehearsalOwnership(inspect, expected);
  return validateContainerId(String(inspect.Id ?? ""));
}

function assertLogicalResultRedacted(value, keyPath = "result") {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      assertLogicalResultRedacted(value[index], `${keyPath}[${index}]`);
    }
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (
        !/Sha256$/u.test(key) &&
        /(?:body|headers?|environmentvalues|dnsname|hostname|hostpath|timestamp)/iu.test(key)
      ) {
        throw new DockerHarnessError("RESULT_REDACTION_VIOLATION");
      }
      assertLogicalResultRedacted(child, `${keyPath}.${key}`);
    }
    return;
  }
  if (typeof value !== "string") return;
  if (
    /[A-Za-z]:[\\/]|\/(?:Users|home)\/|\.invalid\b|host\.docker\.internal|Bearer\s|authorization|cookie|password|api[_-]?key/iu.test(
      value,
    )
  ) {
    throw new DockerHarnessError("RESULT_REDACTION_VIOLATION");
  }
}

export function serializeReleaseRehearsalLogicalResult(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new TypeError("Containment result must be an object.");
  }
  const { operational: _operational, ...logical } = result;
  assertLogicalResultRedacted(logical);
  return canonicalJson(logical) + "\n";
}

async function runDocker(args, options = {}) {
  try {
    const { stdout = "", stderr = "" } = await execFileAsync("docker", args, {
      cwd: REPOSITORY_ROOT,
      encoding: "utf8",
      maxBuffer: options.maxBuffer ?? 1024 * 1024,
      signal: options.signal,
      timeout: options.timeoutMs ?? 15_000,
      windowsHide: true,
    });
    return { stdout, stderr };
  } catch (error) {
    const timedOut =
      error?.code === "ETIMEDOUT" ||
      error?.killed === true ||
      options.signal?.aborted === true;
    throw new DockerHarnessError(
      timedOut ? options.timeoutCode ?? "DOCKER_COMMAND_TIMEOUT" : options.code ?? "DOCKER_COMMAND_FAILED",
      options.status ?? "FAILED",
      String(error?.stderr ?? "").slice(0, 16 * 1024),
    );
  }
}

async function inspectDockerObject(kind, id, options = {}) {
  try {
    const result = await runDocker([kind, "inspect", id], {
      code: options.code ?? "DOCKER_INSPECT_FAILED",
      signal: options.signal,
      timeoutMs: 10_000,
      timeoutCode: options.timeoutCode,
    });
    const parsed = JSON.parse(result.stdout);
    if (!Array.isArray(parsed) || parsed.length !== 1) {
      throw new Error("inspect shape");
    }
    return parsed[0];
  } catch (error) {
    if (
      options.allowMissing &&
      error instanceof DockerHarnessError &&
      /No such (?:container|image|object|volume|network)/iu.test(error.diagnostic)
    ) {
      return null;
    }
    if (error instanceof DockerHarnessError) throw error;
    throw new DockerHarnessError(options.code ?? "DOCKER_INSPECT_FAILED");
  }
}

async function getDockerRuntime() {
  let version;
  let info;
  try {
    const [versionResult, infoResult] = await Promise.all([
      runDocker(["version", "--format", "{{json .}}"], {
        code: "DOCKER_DAEMON_UNAVAILABLE",
        status: "ISOLATION_UNAVAILABLE",
      }),
      runDocker(["info", "--format", "{{json .}}"], {
        code: "DOCKER_DAEMON_UNAVAILABLE",
        status: "ISOLATION_UNAVAILABLE",
      }),
    ]);
    version = JSON.parse(versionResult.stdout);
    info = JSON.parse(infoResult.stdout);
  } catch (error) {
    if (error instanceof DockerHarnessError) throw error;
    throw new DockerHarnessError("DOCKER_DAEMON_UNAVAILABLE", "ISOLATION_UNAVAILABLE");
  }
  if (info.OSType !== "linux") {
    throw new DockerHarnessError("DOCKER_LINUX_MODE_REQUIRED", "ISOLATION_UNAVAILABLE");
  }
  const daemonSecurityOptions = (info.SecurityOptions ?? []).map((value) =>
    typeof value === "string" ? value : canonicalJson(value),
  );
  if (
    !daemonSecurityOptions.some(
      (value) => value.includes("name=seccomp") && value.includes("profile=builtin"),
    )
  ) {
    throw new DockerHarnessError(
      "DOCKER_BUILTIN_SECCOMP_REQUIRED",
      "ISOLATION_UNAVAILABLE",
    );
  }
  return Object.freeze({
    clientVersion: version.Client?.Version ?? "unknown",
    serverVersion: version.Server?.Version ?? "unknown",
    serverOs: info.OSType,
    architecture: info.Architecture ?? "unknown",
    seccompProfile: "builtin",
  });
}

async function resolveOfficialNodeImage() {
  let inspect = await inspectDockerObject("image", RELEASE_REHEARSAL_NODE_IMAGE_TAG, {
    allowMissing: true,
  });
  let pulled = false;
  if (!inspect) {
    await runDocker(["image", "pull", RELEASE_REHEARSAL_NODE_IMAGE_TAG], {
      code: "OFFICIAL_IMAGE_PULL_FAILED",
      status: "ISOLATION_UNAVAILABLE",
      timeoutMs: 120_000,
    });
    pulled = true;
    inspect = await inspectDockerObject("image", RELEASE_REHEARSAL_NODE_IMAGE_TAG, {
      code: "OFFICIAL_IMAGE_INSPECT_FAILED",
    });
  }
  return Object.freeze({
    ...validateReleaseRehearsalImageIdentity(
      inspect,
      RELEASE_REHEARSAL_NODE_IMAGE_TAG,
    ),
    pulled,
  });
}

async function createPrivateRunDirectory(label) {
  assertReleaseRehearsalDockerIdentifier(label, "run label");
  const root = await mkdtemp(path.join(tmpdir(), `csint-${label}-`));
  assertReleaseRehearsalPrivatePath(tmpdir(), root);
  await chmod(root, 0o700);
  return root;
}

async function removePrivateRunDirectory(directory) {
  assertReleaseRehearsalPrivatePath(tmpdir(), directory);
  if (!path.basename(directory).startsWith("csint-")) {
    throw new DockerHarnessError("TEMP_DIRECTORY_OWNERSHIP_INVALID");
  }
  await rm(directory, { recursive: true, force: false });
}

function randomIdentifier(prefix) {
  return `${prefix}-${randomBytes(8).toString("hex")}`;
}

async function buildCaptureImage(baseImage, ownerId) {
  const buildRunId = randomIdentifier("build");
  const buildDirectory = await createPrivateRunDirectory(buildRunId);
  const imageTag = `csint-release-rehearsal-capture:${ownerId}`;
  const imageIdFile = assertReleaseRehearsalPrivatePath(
    buildDirectory,
    path.join(buildDirectory, "image.id"),
  );
  const labels = labelsFor({ ownerId, runId: buildRunId, role: "image" });
  try {
    await runDocker(
      [
        "build",
        "--file",
        CONTAINERFILE_PATH,
        "--pull=false",
        "--network=none",
        "--build-arg",
        `BASE_IMAGE=${baseImage.repositoryDigest}`,
        ...labelArguments(labels),
        "--iidfile",
        imageIdFile,
        "--tag",
        imageTag,
        REPOSITORY_ROOT,
      ],
      { code: "CAPTURE_IMAGE_BUILD_FAILED", timeoutMs: 120_000 },
    );
    const imageId = (await readFile(imageIdFile, "utf8")).trim();
    validateImageId(imageId);
    const inspect = await inspectDockerObject("image", imageId, {
      code: "CAPTURE_IMAGE_INSPECT_FAILED",
    });
    verifyReleaseRehearsalOwnership(inspect, {
      ownerId,
      runId: buildRunId,
      role: "image",
    });
    if (inspect.Os !== "linux" || inspect.Id !== imageId) {
      throw new DockerHarnessError("CAPTURE_IMAGE_IDENTITY_INVALID");
    }
    return Object.freeze({ imageId, imageTag, buildRunId });
  } finally {
    await removePrivateRunDirectory(buildDirectory);
  }
}

async function removeCaptureImage(image, ownerId) {
  const cleanup = { status: "COMPLETE", remainingIds: [] };
  if (!image) return cleanup;
  try {
    const inspect = await inspectDockerObject("image", image.imageId, {
      allowMissing: true,
    });
    if (inspect) {
      verifyReleaseRehearsalOwnership(inspect, {
        ownerId,
        runId: image.buildRunId,
        role: "image",
      });
      if (inspect.Id !== image.imageId) {
        throw new DockerHarnessError("IMAGE_CLEANUP_ID_MISMATCH");
      }
      await runDocker(["image", "rm", image.imageId], {
        code: "IMAGE_CLEANUP_FAILED",
        timeoutMs: 30_000,
      });
    }
    const remaining = await inspectDockerObject("image", image.imageId, {
      allowMissing: true,
    });
    if (remaining) throw new DockerHarnessError("IMAGE_CLEANUP_INCOMPLETE");
  } catch {
    cleanup.status = "FAILED";
    cleanup.remainingIds.push(image.imageId);
  }
  return cleanup;
}

function syntheticCaptureConfig(runId, caseId) {
  return validateReleaseRehearsalCaptureConfig({
    schemaVersion: 1,
    kind: "csint-release-rehearsal-capture-config",
    runId,
    caseId,
    variant: "baseline",
    fixtureId: "synthetic-fixture",
    fixtureCanonicalSha256: "a".repeat(64),
    correlationId: "synthetic-correlation",
    workflowCanonicalSha256: "b".repeat(64),
    allowedNodeIds: ["synthetic-node"],
    nodes: [
      {
        nodeId: "synthetic-node",
        method: "POST",
        destination: normalizeHttpDestination(
          "https://capture-target.example.invalid/v1/synthetic-node",
        ),
        minimumOccurrences: 1,
        maximumOccurrences: 1,
        responseStubs: [
          {
            status: 200,
            headers: {
              "content-type": "application/json; charset=utf-8",
              "x-synthetic-response": "accepted",
            },
            json: { result: "accepted" },
          },
        ],
      },
    ],
  });
}

async function prepareCaseFiles(runId, scenario) {
  const runDirectory = await createPrivateRunDirectory(runId);
  try {
    const configDirectory = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "config"),
    );
    const outputDirectory = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "output"),
    );
    await Promise.all([
      mkdir(configDirectory, { mode: 0o700 }),
      mkdir(outputDirectory, { mode: 0o700 }),
    ]);
    const configPath = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(configDirectory, "config.json"),
    );
    const resolverPath = assertReleaseRehearsalPrivatePath(
      runDirectory,
      path.join(runDirectory, "resolv.conf"),
    );
    const config = syntheticCaptureConfig(runId, `case-${scenario}`);
    await Promise.all([
      writeFile(configPath, canonicalJson(config) + "\n", {
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
      resolverPath,
      outputDirectory,
    });
  } catch (error) {
    await removePrivateRunDirectory(runDirectory);
    throw error;
  }
}

async function waitForCaptureReady(containerId, signal) {
  const deadline = Date.now() + 6_000;
  while (Date.now() < deadline) {
    const logs = await runDocker(["container", "logs", containerId], {
      code: "CAPTURE_LOG_READ_FAILED",
      maxBuffer: LOG_LIMIT_BYTES,
      signal,
      timeoutMs: 3_000,
      timeoutCode: "CASE_TIMEOUT",
    });
    const combined = `${logs.stdout}${logs.stderr}`;
    if (Buffer.byteLength(combined, "utf8") > LOG_LIMIT_BYTES) {
      throw new DockerHarnessError("CAPTURE_LOG_LIMIT_EXCEEDED");
    }
    if (combined.includes('"code":"CAPTURE_READY"')) return combined;
    if (combined.includes('"code":"DNS_BIND_FAILED"')) {
      throw new DockerHarnessError("DNS_BIND_FAILED", "ISOLATION_UNAVAILABLE");
    }
    const inspect = await inspectDockerObject("container", containerId, {
      signal,
      timeoutCode: "CASE_TIMEOUT",
    });
    if (inspect.State?.Running === false) {
      throw new DockerHarnessError("CAPTURE_CRASHED");
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new DockerHarnessError("CAPTURE_READY_TIMEOUT");
}

async function readCaseEvidence(outputDirectory) {
  const names = [
    "capture-events.json",
    "capture-summary.json",
    "dns-events.json",
    "dns-summary.json",
    "probe-result.json",
  ];
  const values = await Promise.all(
    names.map((name) =>
      readBoundedJsonFile(path.join(outputDirectory, name), {
        ...JSON_LIMITS,
        label: name,
      }),
    ),
  );
  return Object.freeze(Object.fromEntries(names.map((name, index) => [name, values[index]])));
}

function validateSuccessfulEvidence(evidence) {
  const captureEvents = evidence["capture-events.json"];
  const captureSummary = evidence["capture-summary.json"];
  const dnsEvents = evidence["dns-events.json"];
  const dnsSummary = evidence["dns-summary.json"];
  const probe = evidence["probe-result.json"];
  if (
    !Array.isArray(captureEvents) ||
    captureEvents.length !== 1 ||
    captureEvents[0].forwarded !== false ||
    captureSummary?.status !== "COMPLETE" ||
    captureSummary?.eventCount !== 1 ||
    probe?.status !== "PASS" ||
    probe?.interfaces?.onlyLoopback !== true ||
    probe?.interfaces?.procAgreement !== true ||
    probe?.routes?.ipv4Default !== false ||
    probe?.routes?.ipv6Default !== false ||
    probe?.http?.succeeded !== true ||
    probe?.dns?.resolverIsLocalOnly !== true ||
    probe?.dns?.ordinaryQuery?.nxdomain !== true ||
    probe?.hostAccess?.blocked !== true ||
    probe?.blockedDestinations?.length !== 4 ||
    probe.blockedDestinations.some((destination) => destination.blocked !== true) ||
    !Array.isArray(dnsEvents) ||
    dnsEvents.length < 1 ||
    dnsEvents.length > 2 ||
    dnsEvents.some(
      (event) =>
        event.queryType !== 1 ||
        !/^[a-f0-9]{64}$/u.test(event.queryNameSha256 ?? "") ||
        Object.keys(event).some((key) => /name$/iu.test(key) && key !== "queryNameSha256"),
    ) ||
    dnsSummary?.status !== "COMPLETE" ||
    dnsSummary?.queryCount !== dnsEvents.length ||
    dnsSummary?.forwarded !== false
  ) {
    throw new DockerHarnessError("CONTAINMENT_EVIDENCE_INVALID");
  }
  const serializedDns = canonicalJson({ dnsEvents, dnsSummary });
  if (/\.invalid\b|host\.docker\.internal/iu.test(serializedDns)) {
    throw new DockerHarnessError("DNS_RESULT_REDACTION_FAILED");
  }
  const queryCounts = new Map();
  for (const event of dnsEvents) {
    const key = `${event.queryType}:${event.queryNameSha256}`;
    queryCounts.set(key, (queryCounts.get(key) ?? 0) + 1);
  }
  return Object.freeze({
    probe,
    capture: {
      status: captureSummary.status,
      eventCount: captureSummary.eventCount,
      bodySha256: captureEvents[0].bodySha256,
      headerSetSha256: captureEvents[0].headerSetSha256,
      jsonShapeSha256: captureEvents[0].jsonShapeSha256,
      forwarded: captureEvents[0].forwarded,
    },
    dnsSink: {
      status: dnsSummary.status,
      queryCount: dnsSummary.queryCount,
      queryTypeCounts: dnsSummary.queryTypeCounts,
      queries: [...queryCounts.entries()]
        .map(([key, count]) => {
          const separator = key.indexOf(":");
          return {
            queryType: Number.parseInt(key.slice(0, separator), 10),
            queryNameSha256: key.slice(separator + 1),
            count,
          };
        })
        .sort((left, right) => {
          const typeOrder = left.queryType - right.queryType;
          return typeOrder || stableCompare(left.queryNameSha256, right.queryNameSha256);
        }),
      forwarded: dnsSummary.forwarded,
    },
  });
}

async function cleanupContainer(containerId, expected) {
  if (!containerId) return { removed: true, remainingId: null };
  try {
    let inspect = await inspectDockerObject("container", containerId, {
      allowMissing: true,
    });
    if (!inspect) return { removed: true, remainingId: null };
    buildReleaseRehearsalCleanupTarget(inspect, expected);
    if (inspect.State?.Running) {
      await runDocker(["container", "stop", "--time", "5", containerId], {
        code: "CONTAINER_STOP_FAILED",
        timeoutMs: 10_000,
      });
    }
    inspect = await inspectDockerObject("container", containerId, {
      code: "CLEANUP_REINSPECT_FAILED",
    });
    buildReleaseRehearsalCleanupTarget(inspect, expected);
    await runDocker(["container", "rm", containerId], {
      code: "CONTAINER_REMOVE_FAILED",
      timeoutMs: 10_000,
    });
    const remaining = await inspectDockerObject("container", containerId, {
      allowMissing: true,
    });
    if (remaining) throw new DockerHarnessError("CONTAINER_REMOVE_INCOMPLETE");
    return { removed: true, remainingId: null };
  } catch {
    return { removed: false, remainingId: containerId };
  }
}

function safeContainerLogs(value) {
  const text = String(value ?? "");
  if (
    Buffer.byteLength(text, "utf8") > LOG_LIMIT_BYTES ||
    /\.invalid\b|host\.docker\.internal|x-csint-rehearsal|authorization|cookie|password|Bearer\s/iu.test(
      text,
    )
  ) {
    throw new DockerHarnessError("DOCKER_LOG_REDACTION_FAILED");
  }
  return text;
}

function baseLogicalResult({
  status,
  docker,
  baseImage,
  security,
  probe,
  captureEvidence,
  dnsSink,
  cleanup,
  errorCodes,
}) {
  return {
    schemaVersion: RELEASE_REHEARSAL_DOCKER_RESULT_SCHEMA_VERSION,
    status,
    docker,
    image: {
      requestedTag: baseImage.requestedTag,
      repositoryDigest: baseImage.repositoryDigest,
      platform: baseImage.platform,
      localImageId: baseImage.localImageId,
    },
    security,
    network: {
      captureMode: "none",
      probeMode: "container:<capture-container-id>",
      captureModeVerified: security?.capture?.networkMode === "none",
      probeModeVerified:
        security?.probe?.networkMode === "container:<capture-container-id>",
      onlyApprovedAttachments: Boolean(
        security?.capture?.approvedNetworkAttachmentOnly &&
          security?.probe?.approvedNetworkAttachmentOnly,
      ),
    },
    interfaces: probe?.interfaces ?? null,
    routes: probe?.routes ?? null,
    http: probe?.http ?? null,
    capture: captureEvidence,
    dns: probe?.dns ?? null,
    dnsSink,
    hostAccess: probe?.hostAccess ?? null,
    blockedDestinations: probe?.blockedDestinations ?? [],
    publishedPorts: {
      capture: security?.capture?.publishedPorts === false,
      probe: security?.probe?.publishedPorts === false,
    },
    cleanup,
    errorCodes: uniqueSorted(errorCodes),
    limitations: [...LOGICAL_LIMITATIONS],
  };
}

async function runContainmentCase({ docker, baseImage, image, ownerId, scenario }) {
  const runId = randomIdentifier("run");
  const captureName = `capture-${runId}`;
  const probeName = `probe-${runId}`;
  const caseController = new AbortController();
  const caseTimer = setTimeout(() => caseController.abort(), 45_000);
  caseTimer.unref();
  const caseRunDocker = (args, options = {}) =>
    runDocker(args, {
      ...options,
      signal: caseController.signal,
      timeoutCode: options.timeoutCode ?? "CASE_TIMEOUT",
    });
  const caseInspect = (kind, id, options = {}) =>
    inspectDockerObject(kind, id, {
      ...options,
      signal: caseController.signal,
      timeoutCode: options.timeoutCode ?? "CASE_TIMEOUT",
    });
  let files = null;
  let captureId = null;
  let probeId = null;
  let captureSecurity = null;
  let probeSecurity = null;
  let probeResult = null;
  let captureEvidence = null;
  let dnsSink = null;
  let containerLogs = "";
  const errorCodes = [];
  let status = "FAILED";
  let cleanup = {
    status: "FAILED",
    containersRemoved: false,
    privateRunDirectoryRemoved: false,
    imageRemoved: false,
    remainingIds: [],
  };

  const captureOwnership = { ownerId, runId, role: "capture" };
  const probeOwnership = { ownerId, runId, role: "probe" };
  try {
    files = await prepareCaseFiles(runId, scenario);
    const captureCreate = await caseRunDocker(
      buildReleaseRehearsalCaptureCreateArgs({
        name: captureName,
        ownerId,
        runId,
        imageId: image.imageId,
        runDirectory: files.runDirectory,
        configPath: files.configPath,
        outputPath: files.outputDirectory,
      }),
      { code: "CAPTURE_CREATE_FAILED", timeoutMs: 15_000 },
    );
    captureId = validateContainerId(captureCreate.stdout.trim());
    const captureInspect = await caseInspect("container", captureId);
    captureSecurity = inspectReleaseRehearsalContainer(captureInspect, {
      ...captureOwnership,
      imageId: image.imageId,
      networkMode: "none",
      logicalNetworkMode: "none",
      mounts: [
        { source: files.configPath, destination: CONTAINER_CONFIG_PATH, readWrite: false },
        { source: files.outputDirectory, destination: CONTAINER_OUTPUT_PATH, readWrite: true },
      ],
    });
    await caseRunDocker(["container", "start", captureId], {
      code: "CAPTURE_START_FAILED",
      timeoutMs: 10_000,
    });
    containerLogs += await waitForCaptureReady(captureId, caseController.signal);

    if (scenario === "capture-crash") {
      await caseRunDocker(["container", "kill", "--signal", "KILL", captureId], {
        code: "CAPTURE_CRASH_TRIGGER_FAILED",
        timeoutMs: 10_000,
      });
      const exit = await caseRunDocker(["container", "wait", captureId], {
        code: "CAPTURE_CRASH_WAIT_FAILED",
        timeoutMs: 10_000,
      });
      if (Number.parseInt(exit.stdout.trim(), 10) === 0) {
        throw new DockerHarnessError("CAPTURE_CRASH_NOT_OBSERVED");
      }
      errorCodes.push("CAPTURE_CRASHED");
    } else {
      const mode =
        scenario === "probe-failure"
          ? "synthetic-failure"
          : scenario === "timeout"
            ? "timeout"
            : "normal";
      const probeCreate = await caseRunDocker(
        buildReleaseRehearsalProbeCreateArgs({
          name: probeName,
          ownerId,
          runId,
          imageId: image.imageId,
          captureContainerId: captureId,
          runDirectory: files.runDirectory,
          configPath: files.configPath,
          resolverPath: files.resolverPath,
          outputPath: files.outputDirectory,
          mode,
        }),
        { code: "PROBE_CREATE_FAILED", timeoutMs: 15_000 },
      );
      probeId = validateContainerId(probeCreate.stdout.trim());
      const probeInspect = await caseInspect("container", probeId);
      probeSecurity = inspectReleaseRehearsalContainer(probeInspect, {
        ...probeOwnership,
        imageId: image.imageId,
        networkMode: `container:${captureId}`,
        logicalNetworkMode: "container:<capture-container-id>",
        mounts: [
          { source: files.configPath, destination: CONTAINER_CONFIG_PATH, readWrite: false },
          { source: files.outputDirectory, destination: CONTAINER_OUTPUT_PATH, readWrite: true },
          { source: files.resolverPath, destination: CONTAINER_RESOLVER_PATH, readWrite: false },
        ],
      });
      await caseRunDocker(["container", "start", probeId], {
        code: "PROBE_START_FAILED",
        timeoutMs: 10_000,
      });
      try {
        const wait = await caseRunDocker(["container", "wait", probeId], {
          code: "PROBE_WAIT_FAILED",
          timeoutCode: "PROBE_TIMEOUT",
          timeoutMs: scenario === "timeout" ? 1_000 : 10_000,
        });
        const exitCode = Number.parseInt(wait.stdout.trim(), 10);
        if (scenario === "normal" && exitCode !== 0) {
          throw new DockerHarnessError("PROBE_FAILED");
        }
        if (scenario === "probe-failure" && exitCode === 0) {
          throw new DockerHarnessError("PROBE_FAILURE_NOT_OBSERVED");
        }
        if (scenario === "probe-failure") errorCodes.push("PROBE_FAILED");
      } catch (error) {
        if (scenario === "timeout" && error instanceof DockerHarnessError && error.code === "PROBE_TIMEOUT") {
          errorCodes.push("PROBE_TIMEOUT");
        } else {
          throw error;
        }
      }
      const probeLogs = await caseRunDocker(["container", "logs", probeId], {
        code: "PROBE_LOG_READ_FAILED",
        maxBuffer: LOG_LIMIT_BYTES,
        timeoutMs: 5_000,
      });
      containerLogs += `${probeLogs.stdout}${probeLogs.stderr}`;
    }

    const captureState = await caseInspect("container", captureId);
    if (captureState.State?.Running) {
      await caseRunDocker(["container", "stop", "--time", "5", captureId], {
        code: "CAPTURE_STOP_FAILED",
        timeoutMs: 10_000,
      });
    }
    const captureLogs = await caseRunDocker(["container", "logs", captureId], {
      code: "CAPTURE_LOG_READ_FAILED",
      maxBuffer: LOG_LIMIT_BYTES,
      timeoutMs: 5_000,
    });
    containerLogs += `${captureLogs.stdout}${captureLogs.stderr}`;
    safeContainerLogs(containerLogs);

    if (scenario === "normal") {
      const evidence = await readCaseEvidence(files.outputDirectory);
      const validatedEvidence = validateSuccessfulEvidence(evidence);
      probeResult = validatedEvidence.probe;
      captureEvidence = validatedEvidence.capture;
      dnsSink = validatedEvidence.dnsSink;
      status = "PASS";
    }
  } catch (error) {
    const normalized =
      error instanceof DockerHarnessError
        ? error
        : new DockerHarnessError("CONTAINMENT_CASE_FAILED");
    errorCodes.push(normalized.code);
    status = normalized.status;
  } finally {
    clearTimeout(caseTimer);
    const [probeCleanup, captureCleanup] = await Promise.all([
      cleanupContainer(probeId, probeOwnership),
      cleanupContainer(captureId, captureOwnership),
    ]);
    const remainingIds = [probeCleanup.remainingId, captureCleanup.remainingId].filter(Boolean);
    let directoryRemoved = files === null;
    if (files) {
      try {
        await removePrivateRunDirectory(files.runDirectory);
        directoryRemoved = true;
      } catch {
        errorCodes.push("TEMP_DIRECTORY_CLEANUP_FAILED");
      }
    }
    cleanup = {
      status:
        probeCleanup.removed && captureCleanup.removed && directoryRemoved
          ? "COMPLETE"
          : "FAILED",
      containersRemoved: probeCleanup.removed && captureCleanup.removed,
      privateRunDirectoryRemoved: directoryRemoved,
      imageRemoved: false,
      remainingIds,
    };
    if (cleanup.status !== "COMPLETE") {
      status = "FAILED";
      errorCodes.push("CLEANUP_INCOMPLETE");
    }
  }

  const security = { capture: captureSecurity, probe: probeSecurity };
  const remainingResourceIds = [...cleanup.remainingIds];
  const logicalCleanup = {
    status: cleanup.status,
    containersRemoved: cleanup.containersRemoved,
    privateRunDirectoryRemoved: cleanup.privateRunDirectoryRemoved,
    imageRemoved: cleanup.imageRemoved,
    remainingResourceCount: remainingResourceIds.length,
  };
  const logical = baseLogicalResult({
    status,
    docker,
    baseImage,
    security,
    probe: probeResult,
    captureEvidence,
    dnsSink,
    cleanup: logicalCleanup,
    errorCodes,
  });
  return {
    ...logical,
    operational: {
      comparisonExcluded: true,
      runLabel: runId,
      captureContainerId: captureId,
      probeContainerId: probeId,
      builtImageId: image.imageId,
      exactProbeNetworkMode: captureId ? `container:${captureId}` : null,
      containerLogs: safeContainerLogs(containerLogs),
      remainingResourceIds,
    },
    expectedFailureScenario: scenario === "normal" ? null : scenario,
  };
}

async function inventoryCommand(args) {
  const result = await runDocker(args, {
    code: "DOCKER_INVENTORY_FAILED",
    timeoutMs: 10_000,
  });
  return uniqueSorted(result.stdout.split(/\r?\n/u).map((value) => value.trim()).filter(Boolean));
}

export async function listReleaseRehearsalDockerInventory() {
  const [containers, images, volumes, networks] = await Promise.all([
    inventoryCommand(["container", "ls", "--all", "--quiet", "--no-trunc"]),
    inventoryCommand(["image", "ls", "--all", "--quiet", "--no-trunc"]),
    inventoryCommand(["volume", "ls", "--quiet"]),
    inventoryCommand(["network", "ls", "--quiet", "--no-trunc"]),
  ]);
  return Object.freeze({ containers, images, volumes, networks });
}

export async function listReleaseRehearsalManagedDockerInventory() {
  const filter = `label=${RELEASE_REHEARSAL_DOCKER_LABELS.managed}=true`;
  const [containers, images, volumes, networks] = await Promise.all([
    inventoryCommand(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", filter]),
    inventoryCommand(["image", "ls", "--all", "--quiet", "--no-trunc", "--filter", filter]),
    inventoryCommand(["volume", "ls", "--quiet", "--filter", filter]),
    inventoryCommand(["network", "ls", "--quiet", "--no-trunc", "--filter", filter]),
  ]);
  return Object.freeze({ containers, images, volumes, networks });
}

function inventoriesEqual(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function finalizeCaseImageCleanup(result, imageCleanup) {
  const errorCodes = [...result.errorCodes];
  if (imageCleanup.status !== "COMPLETE") errorCodes.push("IMAGE_CLEANUP_INCOMPLETE");
  const remainingResourceIds = uniqueSorted([
    ...(result.operational?.remainingResourceIds ?? []),
    ...imageCleanup.remainingIds,
  ]);
  const cleanup = {
    ...result.cleanup,
    status:
      result.cleanup.status === "COMPLETE" && imageCleanup.status === "COMPLETE"
        ? "COMPLETE"
        : "FAILED",
    imageRemoved: imageCleanup.status === "COMPLETE",
    remainingResourceCount: remainingResourceIds.length,
  };
  return {
    ...result,
    status:
      result.status === "PASS" && cleanup.status === "COMPLETE"
        ? "PASS"
        : result.status === "ISOLATION_UNAVAILABLE"
          ? "ISOLATION_UNAVAILABLE"
          : "FAILED",
    cleanup,
    errorCodes: uniqueSorted(errorCodes),
    operational: {
      ...result.operational,
      remainingResourceIds,
    },
  };
}

async function prepareHarnessPrerequisites() {
  const docker = await getDockerRuntime();
  const baseImage = await resolveOfficialNodeImage();
  const ownerId = randomIdentifier("owner");
  return { docker, baseImage, ownerId };
}

async function prepareHarness(prerequisites) {
  const { docker, baseImage, ownerId } = prerequisites;
  const image = await buildCaptureImage(baseImage, ownerId);
  return { docker, baseImage, ownerId, image };
}

export async function runReleaseRehearsalDockerProbe() {
  const prerequisites = await prepareHarnessPrerequisites();
  const before = await listReleaseRehearsalDockerInventory();
  let prepared = null;
  let result = null;
  let imageCleanup = { status: "COMPLETE", remainingIds: [] };
  try {
    prepared = await prepareHarness(prerequisites);
    result = await runContainmentCase({ ...prepared, scenario: "normal" });
  } finally {
    imageCleanup = await removeCaptureImage(prepared?.image, prepared?.ownerId);
  }
  const after = await listReleaseRehearsalDockerInventory();
  result = finalizeCaseImageCleanup(result, imageCleanup);
  if (!inventoriesEqual(before, after)) {
    result.status = "FAILED";
    result.errorCodes = uniqueSorted([...result.errorCodes, "DOCKER_INVENTORY_CHANGED"]);
  }
  serializeReleaseRehearsalLogicalResult(result);
  return result;
}

export async function runReleaseRehearsalDockerIntegrationSuite() {
  const prerequisites = await prepareHarnessPrerequisites();
  const before = await listReleaseRehearsalDockerInventory();
  let prepared = null;
  const cases = [];
  let imageCleanup = { status: "COMPLETE", remainingIds: [] };
  try {
    prepared = await prepareHarness(prerequisites);
    for (const scenario of ["normal", "capture-crash", "probe-failure", "timeout"]) {
      cases.push(await runContainmentCase({ ...prepared, scenario }));
    }
  } finally {
    imageCleanup = await removeCaptureImage(prepared?.image, prepared?.ownerId);
  }
  const after = await listReleaseRehearsalDockerInventory();
  const inventoryUnchanged = inventoriesEqual(before, after);
  const finalizedCases = cases.map((result) =>
    finalizeCaseImageCleanup(result, imageCleanup),
  );
  const primary = finalizedCases[0];
  const failureCases = finalizedCases.slice(1);
  const expectedFailuresObserved = failureCases.every(
    (result) =>
      result.status === "FAILED" &&
      result.cleanup.status === "COMPLETE" &&
      ((result.expectedFailureScenario === "capture-crash" &&
        result.errorCodes.includes("CAPTURE_CRASHED")) ||
        (result.expectedFailureScenario === "probe-failure" &&
          result.errorCodes.includes("PROBE_FAILED")) ||
        (result.expectedFailureScenario === "timeout" &&
          result.errorCodes.includes("PROBE_TIMEOUT"))),
  );
  const status =
    primary?.status === "PASS" &&
    expectedFailuresObserved &&
    inventoryUnchanged &&
    imageCleanup.status === "COMPLETE"
      ? "PASS"
      : primary?.status === "ISOLATION_UNAVAILABLE"
        ? "ISOLATION_UNAVAILABLE"
        : "FAILED";
  if (primary) serializeReleaseRehearsalLogicalResult(primary);
  return Object.freeze({
    schemaVersion: 1,
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
    operational: {
      comparisonExcluded: true,
      imageCleanupRemainingIds: [...imageCleanup.remainingIds],
    },
  });
}

// Narrow internal reuse for the Phase 4 n8n CLI harness. These primitives keep
// Docker invocation, image ownership, and exact-ID cleanup aligned with Phase 3.
export {
  buildCaptureImage as buildReleaseRehearsalCaptureImage,
  cleanupContainer as cleanupReleaseRehearsalContainer,
  createPrivateRunDirectory as createReleaseRehearsalPrivateRunDirectory,
  getDockerRuntime as getReleaseRehearsalDockerRuntime,
  inspectDockerObject as inspectReleaseRehearsalDockerObject,
  inventoriesEqual as releaseRehearsalDockerInventoriesEqual,
  randomIdentifier as createReleaseRehearsalDockerIdentifier,
  removeCaptureImage as removeReleaseRehearsalCaptureImage,
  removePrivateRunDirectory as removeReleaseRehearsalPrivateRunDirectory,
  resolveOfficialNodeImage as resolveReleaseRehearsalNodeImage,
  runDocker as runReleaseRehearsalDockerCommand,
  waitForCaptureReady as waitForReleaseRehearsalCaptureReady,
};
