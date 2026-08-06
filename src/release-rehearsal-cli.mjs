import {
  chmod,
  lstat,
  mkdtemp,
  open,
  readdir,
  rename,
  rm,
  rmdir,
} from "node:fs/promises";
import path from "node:path";

import { fingerprintJson } from "./evidence-fingerprint.mjs";
import { runReleaseRehearsalActionPairInDocker } from "./release-rehearsal-action-docker.mjs";
import {
  buildReleaseRehearsalEvidenceBundle,
  normalizeReleaseRehearsalGeneratedAt,
  releaseRehearsalFixtureSetMaterial,
  verifyReleaseRehearsalEvidenceBundle,
} from "./release-rehearsal-evidence.mjs";
import { loadReleaseRehearsalFixtureSet } from "./release-rehearsal-fixture.mjs";
import {
  preflightReleaseRehearsalActionWorkflow,
  RELEASE_REHEARSAL_MAX_TOTAL_NODES,
} from "./release-rehearsal-preflight.mjs";
import { readWorkflowFile } from "./workflow-input.mjs";

export const RELEASE_REHEARSAL_CLI_EXIT_CODES = Object.freeze({
  USAGE_OR_INPUT_ERROR: 64,
  RUNTIME_ERROR: 70,
  INTERRUPTED: 130,
});

const VALUE_FLAGS = Object.freeze({
  "--baseline": "baseline",
  "--candidate": "candidate",
  "--fixtures": "fixtures",
  "--output": "output",
  "--timestamp": "timestamp",
});
const BOOLEAN_FLAGS = Object.freeze({
  "--synthetic-example": "syntheticExample",
});
const REQUIRED_KEYS = Object.freeze(["baseline", "candidate", "fixtures", "output"]);
const MAX_ARGUMENT_TOKENS = 12;
const MAX_PATH_LENGTH = 4_096;
const WORKFLOW_FILE_LIMITS = Object.freeze({
  maxBytes: 2 * 1024 * 1024,
  maxDepth: 40,
  maxValues: 50_000,
  maxNodes: RELEASE_REHEARSAL_MAX_TOTAL_NODES,
});
const PATH_UNSAFE_TEXT = /[\u0000-\u001F\u007F-\u009F]/u;

class ReleaseRehearsalCliError extends Error {
  constructor(code, message = code) {
    super(message);
    this.code = code;
    this.exitCode = RELEASE_REHEARSAL_CLI_EXIT_CODES.USAGE_OR_INPUT_ERROR;
  }
}

function inputError(code, message = code) {
  return new ReleaseRehearsalCliError(code, message);
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertPathValue(value, flag) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_PATH_LENGTH ||
    PATH_UNSAFE_TEXT.test(value)
  ) {
    throw inputError("CLI_ARGUMENT_INVALID", `${flag} requires a bounded path.`);
  }
  return value;
}

export function renderReleaseRehearsalUsage() {
  return [
    "Release Rehearsal local evidence command",
    "",
    "Usage:",
    "  node bin/rehearse.mjs --baseline <baseline.json> --candidate <candidate.json> --fixtures <fixtures.json> --output <empty-or-new-directory> [options]",
    "",
    "Options:",
    "  --timestamp <UTC>       Caller-supplied canonical timestamp, for example 2026-08-06T12:00:00.000Z",
    "  --synthetic-example     Label the bundle as synthetic example evidence",
    "  --help                  Show this help",
    "",
    "The command accepts only the closed Phase 6 workflow subset. It does not use credentials, production access, analytics, telemetry, or an AI API.",
    "The human makes the release decision.",
    "",
  ].join("\n");
}

export function parseReleaseRehearsalArguments(argv) {
  if (!Array.isArray(argv) || argv.some((value) => typeof value !== "string")) {
    throw inputError("CLI_ARGUMENT_INVALID", "Arguments must be strings.");
  }
  if (argv.length === 1 && new Set(["--help", "-h"]).has(argv[0])) {
    return { help: true };
  }
  if (argv.length > MAX_ARGUMENT_TOKENS) {
    throw inputError("CLI_ARGUMENT_LIMIT_EXCEEDED", "Too many arguments.");
  }
  if (argv.some((value) => new Set(["--help", "-h"]).has(value))) {
    throw inputError("CLI_HELP_COMBINATION_INVALID", "--help must be used alone.");
  }

  const parsed = {
    help: false,
    baseline: "",
    candidate: "",
    fixtures: "",
    output: "",
    timestamp: null,
    syntheticExample: false,
  };
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    const equalsIndex = token.indexOf("=");
    const flag = equalsIndex === -1 ? token : token.slice(0, equalsIndex);
    const inlineValue = equalsIndex === -1 ? undefined : token.slice(equalsIndex + 1);

    if (Object.hasOwn(BOOLEAN_FLAGS, flag)) {
      if (inlineValue !== undefined) {
        throw inputError("CLI_ARGUMENT_INVALID", `${flag} does not accept a value.`);
      }
      if (seen.has(flag)) {
        throw inputError("CLI_ARGUMENT_DUPLICATE", `${flag} was provided more than once.`);
      }
      seen.add(flag);
      parsed[BOOLEAN_FLAGS[flag]] = true;
      continue;
    }

    const key = VALUE_FLAGS[flag];
    if (!key) throw inputError("CLI_ARGUMENT_UNKNOWN", `Unknown argument: ${flag}`);
    if (seen.has(flag)) {
      throw inputError("CLI_ARGUMENT_DUPLICATE", `${flag} was provided more than once.`);
    }
    seen.add(flag);
    const value = inlineValue ?? argv[index + 1];
    if (!value || (inlineValue === undefined && value.startsWith("--"))) {
      throw inputError("CLI_ARGUMENT_MISSING_VALUE", `${flag} requires a value.`);
    }
    if (inlineValue === undefined) index += 1;
    parsed[key] = key === "timestamp" ? value : assertPathValue(value, flag);
  }

  const missing = REQUIRED_KEYS.filter((key) => !parsed[key]);
  if (missing.length > 0) {
    throw inputError(
      "CLI_ARGUMENT_REQUIRED",
      `Missing required argument(s): ${missing.join(", ")}.`,
    );
  }
  parsed.timestamp = normalizeReleaseRehearsalGeneratedAt(parsed.timestamp);
  return parsed;
}

function sameDirectoryIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function inspectOutputTarget(outputPath) {
  const parentPath = path.dirname(outputPath);
  const parent = await lstat(parentPath, { bigint: true }).catch(() => null);
  if (!parent || parent.isSymbolicLink() || !parent.isDirectory()) {
    throw inputError(
      "OUTPUT_PARENT_INVALID",
      "The output parent must be an existing regular directory, not a symbolic link.",
    );
  }
  let entry;
  try {
    entry = await lstat(outputPath, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        exists: false,
        parentPath,
        parentIdentity: { dev: parent.dev, ino: parent.ino },
      };
    }
    throw inputError("OUTPUT_INSPECTION_FAILED", "The output target could not be inspected.");
  }
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    throw inputError(
      "OUTPUT_TARGET_INVALID",
      "The output target must be absent or an empty regular directory.",
    );
  }
  const names = await readdir(outputPath);
  if (names.length > 0) {
    throw inputError(
      "OUTPUT_DIRECTORY_NOT_EMPTY",
      "The existing output directory is not empty and was preserved.",
    );
  }
  return {
    exists: true,
    parentPath,
    parentIdentity: { dev: parent.dev, ino: parent.ino },
    identity: { dev: entry.dev, ino: entry.ino },
  };
}

async function revalidateOutputTarget(outputPath, snapshot) {
  const parent = await lstat(snapshot.parentPath, { bigint: true }).catch(
    () => null,
  );
  if (
    !parent ||
    parent.isSymbolicLink() ||
    !parent.isDirectory() ||
    !sameDirectoryIdentity(parent, snapshot.parentIdentity)
  ) {
    throw inputError("OUTPUT_PARENT_CHANGED", "The output parent changed during execution.");
  }
  if (!snapshot.exists) {
    try {
      await lstat(outputPath);
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw inputError("OUTPUT_TARGET_CHANGED", "The output target changed during execution.");
    }
    throw inputError("OUTPUT_TARGET_CHANGED", "The output target appeared during execution.");
  }
  const entry = await lstat(outputPath, { bigint: true }).catch(() => null);
  if (
    !entry ||
    entry.isSymbolicLink() ||
    !entry.isDirectory() ||
    !sameDirectoryIdentity(entry, snapshot.identity) ||
    (await readdir(outputPath)).length !== 0
  ) {
    throw inputError("OUTPUT_TARGET_CHANGED", "The output target changed during execution.");
  }
}

async function writePrivateFile(directory, name, content) {
  const filePath = path.join(directory, name);
  const handle = await open(filePath, "wx", 0o600);
  try {
    await handle.writeFile(content, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function publishEvidenceBundleAtomically(outputPath, snapshot, files) {
  await revalidateOutputTarget(outputPath, snapshot);
  const baseName = path.basename(outputPath);
  const stagingPath = await mkdtemp(
    path.join(snapshot.parentPath, `.${baseName}.rehearsal-tmp-`),
  );
  await chmod(stagingPath, 0o700);
  let stagingPublished = false;
  let backupPath = null;
  try {
    for (const name of Object.keys(files).sort(stableCompare)) {
      await writePrivateFile(stagingPath, name, files[name]);
    }
    await verifyReleaseRehearsalEvidenceBundle(stagingPath);
    await revalidateOutputTarget(outputPath, snapshot);
    if (snapshot.exists) {
      backupPath = `${stagingPath}.empty-output`;
      await rename(outputPath, backupPath);
      try {
        await rename(stagingPath, outputPath);
        stagingPublished = true;
      } catch (error) {
        await rename(backupPath, outputPath).catch(() => {});
        backupPath = null;
        throw error;
      }
      await rmdir(backupPath);
      backupPath = null;
    } else {
      await rename(stagingPath, outputPath);
      stagingPublished = true;
    }
    return verifyReleaseRehearsalEvidenceBundle(outputPath);
  } finally {
    if (!stagingPublished) {
      await rm(stagingPath, { recursive: true, force: true }).catch(() => {});
    }
    if (backupPath) {
      await rename(backupPath, outputPath).catch(async () => {
        await rm(backupPath, { recursive: true, force: true }).catch(() => {});
      });
    }
  }
}

function collectScalarStrings(value, output) {
  if (typeof value === "string") {
    output.add(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const child of value) collectScalarStrings(child, output);
    return;
  }
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) collectScalarStrings(child, output);
  }
}

function collectWorkflowPayloadValues(workflow, output) {
  for (const node of workflow.nodes) {
    const parameters = node.parameters ?? {};
    if (node.type === "n8n-nodes-base.set") {
      collectScalarStrings(parameters, output);
    }
    if (typeof parameters.url === "string") {
      output.add(parameters.url);
      try {
        const url = new URL(parameters.url);
        for (const value of url.searchParams.values()) output.add(value);
      } catch {
        // Preflight handles invalid or dynamic destinations.
      }
    }
    if (typeof parameters.jsonBody === "string") {
      output.add(parameters.jsonBody);
      try {
        collectScalarStrings(JSON.parse(parameters.jsonBody), output);
      } catch {
        // Preflight handles malformed JSON bodies.
      }
    }
    for (const header of parameters.headerParameters?.parameters ?? []) {
      if (typeof header?.value === "string") output.add(header.value);
    }
    for (const query of parameters.queryParameters?.parameters ?? []) {
      if (typeof query?.value === "string") output.add(query.value);
    }
  }
}

function collectForbiddenValues(baselineWorkflow, candidateWorkflow, fixtureSet) {
  const values = new Set();
  collectWorkflowPayloadValues(baselineWorkflow, values);
  collectWorkflowPayloadValues(candidateWorkflow, values);
  for (const fixture of fixtureSet.fixtures) {
    values.add(fixture.correlationId);
    collectScalarStrings(fixture.webhook.headers, values);
    collectScalarStrings(fixture.webhook.json, values);
    for (const node of fixture.nodes) {
      for (const response of node.responses) {
        collectScalarStrings(response.headers, values);
        collectScalarStrings(response.json, values);
      }
    }
  }
  return [...values];
}

function classifyInputFailure(error) {
  const message = String(error?.message ?? "");
  if (/symbolic link|regular file/iu.test(message)) return "UNSAFE_FILE_TYPE";
  if (/limit|exceeds/iu.test(message)) return "INPUT_LIMIT_EXCEEDED";
  return "INPUT_INVALID";
}

function normalizeDependencies(dependencies) {
  if (!dependencies || typeof dependencies !== "object" || Array.isArray(dependencies)) {
    throw new TypeError("CLI dependencies must be an object.");
  }
  const allowed = new Set(["runPair", "signal"]);
  if (Object.keys(dependencies).some((key) => !allowed.has(key))) {
    throw new TypeError("CLI dependencies contain unknown fields.");
  }
  return {
    runPair: dependencies.runPair ?? runReleaseRehearsalActionPairInDocker,
    signal: dependencies.signal ?? null,
  };
}

function interruptedResult() {
  return {
    status: "INTERRUPTED",
    exitCode: RELEASE_REHEARSAL_CLI_EXIT_CODES.INTERRUPTED,
    errorCode: "REHEARSAL_INTERRUPTED",
    overallResult: null,
    outputPath: null,
  };
}

export async function executeReleaseRehearsalCommand(argv, dependencies = {}) {
  let options;
  try {
    options = parseReleaseRehearsalArguments(argv);
  } catch (error) {
    return {
      status: "REJECTED",
      exitCode: error?.exitCode ?? RELEASE_REHEARSAL_CLI_EXIT_CODES.USAGE_OR_INPUT_ERROR,
      errorCode: error?.code ?? "CLI_ARGUMENT_INVALID",
      message: error?.message ?? "Arguments were rejected.",
      overallResult: null,
      outputPath: null,
    };
  }
  if (options.help) {
    return {
      status: "HELP",
      exitCode: 0,
      usage: renderReleaseRehearsalUsage(),
      overallResult: null,
      outputPath: null,
    };
  }

  let runtime;
  try {
    runtime = normalizeDependencies(dependencies);
  } catch {
    return {
      status: "FAILED",
      exitCode: RELEASE_REHEARSAL_CLI_EXIT_CODES.RUNTIME_ERROR,
      errorCode: "CLI_INTERNAL_CONFIGURATION_INVALID",
      overallResult: null,
      outputPath: null,
    };
  }
  if (runtime.signal?.aborted) return interruptedResult();

  const paths = {
    baseline: path.resolve(options.baseline),
    candidate: path.resolve(options.candidate),
    fixtures: path.resolve(options.fixtures),
    output: path.resolve(options.output),
  };
  let outputSnapshot;
  try {
    outputSnapshot = await inspectOutputTarget(paths.output);
  } catch (error) {
    return {
      status: "REJECTED",
      exitCode: RELEASE_REHEARSAL_CLI_EXIT_CODES.USAGE_OR_INPUT_ERROR,
      errorCode: error?.code ?? "OUTPUT_TARGET_INVALID",
      message: error?.message ?? "The output target was rejected.",
      overallResult: null,
      outputPath: null,
    };
  }

  let baselineWorkflow;
  let candidateWorkflow;
  let fixtureSet;
  try {
    [baselineWorkflow, candidateWorkflow, fixtureSet] = await Promise.all([
      readWorkflowFile(paths.baseline, {
        ...WORKFLOW_FILE_LIMITS,
        label: "Baseline workflow",
      }),
      readWorkflowFile(paths.candidate, {
        ...WORKFLOW_FILE_LIMITS,
        label: "Candidate workflow",
      }),
      loadReleaseRehearsalFixtureSet(paths.fixtures, {
        label: "Sanitized fixture set",
      }),
    ]);
  } catch (error) {
    return {
      status: "REJECTED",
      exitCode: RELEASE_REHEARSAL_CLI_EXIT_CODES.USAGE_OR_INPUT_ERROR,
      errorCode: classifyInputFailure(error),
      message: "One or more bounded inputs were rejected.",
      overallResult: null,
      outputPath: null,
    };
  }
  if (runtime.signal?.aborted) return interruptedResult();

  const fixtureMaterial = releaseRehearsalFixtureSetMaterial(fixtureSet);
  const preflight = {
    baseline: preflightReleaseRehearsalActionWorkflow(baselineWorkflow, {
      variant: "baseline",
    }),
    candidate: preflightReleaseRehearsalActionWorkflow(candidateWorkflow, {
      variant: "candidate",
    }),
  };
  const evidenceIdentitySeed = fingerprintJson({
    kind: "csint-release-rehearsal-evidence-identity-v1",
    baselineCanonicalSha256: fingerprintJson(baselineWorkflow),
    candidateCanonicalSha256: fingerprintJson(candidateWorkflow),
    fixtureSetCanonicalSha256: fingerprintJson(fixtureMaterial),
  });

  try {
    const coreResult = await runtime.runPair(
      {
        baselineWorkflow,
        candidateWorkflow,
        fixtureSet: fixtureMaterial,
      },
      { evidenceIdentitySeed, signal: runtime.signal },
    );
    if (runtime.signal?.aborted) return interruptedResult();
    const bundle = buildReleaseRehearsalEvidenceBundle({
      baselineWorkflow,
      candidateWorkflow,
      fixtureSet,
      preflight,
      coreResult,
      generatedAt: options.timestamp,
      syntheticExample: options.syntheticExample,
      forbiddenValues: collectForbiddenValues(
        baselineWorkflow,
        candidateWorkflow,
        fixtureSet,
      ),
    });
    const verification = await publishEvidenceBundleAtomically(
      paths.output,
      outputSnapshot,
      bundle.files,
    );
    return {
      status: "COMPLETED",
      exitCode: bundle.exitCode,
      errorCode: null,
      overallResult: bundle.overallResult,
      outputPath: paths.output,
      verification,
      redactionScan: bundle.redactionScan,
    };
  } catch (error) {
    if (runtime.signal?.aborted || error?.code === "ACTION_INTERRUPTED") {
      return interruptedResult();
    }
    if (error instanceof ReleaseRehearsalCliError) {
      return {
        status: "REJECTED",
        exitCode: error.exitCode,
        errorCode: error.code,
        message: error.message,
        overallResult: null,
        outputPath: null,
      };
    }
    return {
      status: "FAILED",
      exitCode: RELEASE_REHEARSAL_CLI_EXIT_CODES.RUNTIME_ERROR,
      errorCode: "REHEARSAL_RUNTIME_ERROR",
      overallResult: null,
      outputPath: null,
    };
  }
}
