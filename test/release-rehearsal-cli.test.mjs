import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../src/evidence-fingerprint.mjs";
import { executeReleaseRehearsalCommand } from "../src/release-rehearsal-cli.mjs";
import {
  verifyReleaseRehearsalEvidenceBundle,
} from "../src/release-rehearsal-evidence.mjs";
import {
  listReleaseRehearsalDockerInventory,
  listReleaseRehearsalManagedDockerInventory,
} from "../src/release-rehearsal-docker.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const cliPath = path.join(repositoryRoot, "bin", "rehearse.mjs");
const inputRoot = path.join(repositoryRoot, "examples", "release-rehearsal", "inputs");
const baselinePath = path.join(inputRoot, "baseline.json");
const candidatePath = path.join(inputRoot, "candidate.json");
const fixturePath = path.join(inputRoot, "fixtures.json");
const fixedTimestamp = "2026-08-06T12:00:00.000Z";
const MAX_CLI_OUTPUT_BYTES = 64 * 1024;

function commandArgs(baseline, candidate, output, additions = []) {
  return [
    cliPath,
    "--baseline",
    baseline,
    "--candidate",
    candidate,
    "--fixtures",
    fixturePath,
    "--output",
    output,
    "--timestamp",
    fixedTimestamp,
    ...additions,
  ];
}

function runCli(args, timeoutMs = 240_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: repositoryRoot,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("PHASE7_CLI_TIMEOUT"));
    }, timeoutMs);
    timer.unref();
    const append = (current, chunk) => {
      const next = Buffer.concat([current, chunk]);
      if (next.length > MAX_CLI_OUTPUT_BYTES) {
        child.kill();
        reject(new Error("PHASE7_CLI_OUTPUT_LIMIT_EXCEEDED"));
      }
      return next;
    };
    child.stdout.on("data", (chunk) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = append(stderr, chunk);
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        code,
        signal,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
      });
    });
  });
}

async function bundleBuffers(directory) {
  const names = (await readdir(directory)).sort();
  return {
    names,
    buffers: await Promise.all(
      names.map((name) => readFile(path.join(directory, name))),
    ),
  };
}

function managedTotal(inventory) {
  return Object.values(inventory).reduce((sum, values) => sum + values.length, 0);
}

async function waitForManagedVolume(timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const managed = await listReleaseRehearsalManagedDockerInventory();
    if (managed.volumes.length > 0) return managed;
    await delay(250);
  }
  throw new Error("PHASE7_INTERRUPT_VOLUME_NOT_OBSERVED");
}

async function waitForCleanupInventory(expected, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let managed = await listReleaseRehearsalManagedDockerInventory();
  let inventory = await listReleaseRehearsalDockerInventory();
  while (
    Date.now() < deadline &&
    (managedTotal(managed) !== 0 ||
      canonicalJson(inventory) !== canonicalJson(expected))
  ) {
    await delay(250);
    managed = await listReleaseRehearsalManagedDockerInventory();
    inventory = await listReleaseRehearsalDockerInventory();
  }
  return { managed, inventory };
}

const root = await mkdtemp(path.join(os.tmpdir(), "csint-phase7-cli-integration-"));
const before = await listReleaseRehearsalDockerInventory();
try {
  const completeOutput = path.join(root, "complete");
  const complete = await runCli(
    commandArgs(baselinePath, baselinePath, completeOutput),
  );
  assert.equal(complete.code, 0, complete.stderr);
  assert.match(complete.stdout, /Result: REHEARSAL_COMPLETE/u);
  assert.equal(complete.stderr, "");
  const completeVerification = await verifyReleaseRehearsalEvidenceBundle(
    completeOutput,
  );
  assert.equal(completeVerification.overallResult, "REHEARSAL_COMPLETE");

  const reviewOutput = path.join(root, "review");
  const review = await runCli(
    commandArgs(baselinePath, candidatePath, reviewOutput, [
      "--synthetic-example",
    ]),
  );
  assert.equal(review.code, 2, review.stderr);
  assert.match(review.stdout, /Result: REVIEW_REQUIRED/u);
  assert.equal(review.stderr, "");
  const reviewVerification = await verifyReleaseRehearsalEvidenceBundle(
    reviewOutput,
  );
  assert.equal(reviewVerification.overallResult, "REVIEW_REQUIRED");
  const summary = JSON.parse(
    await readFile(path.join(reviewOutput, "summary.json"), "utf8"),
  );
  assert.equal(summary.actionDiff.summary.method_changed, 1);
  assert.equal(summary.evidenceCounts.observed.total, 2);
  assert.equal(summary.cleanup.status, "COMPLETE");
  assert.equal(summary.containment.status, "COMPLETE");

  const deterministicOutput = path.join(root, "deterministic");
  const deterministic = await runCli(
    commandArgs(baselinePath, candidatePath, deterministicOutput, [
      "--synthetic-example",
    ]),
  );
  assert.equal(deterministic.code, 2, deterministic.stderr);
  const firstBundle = await bundleBuffers(reviewOutput);
  const secondBundle = await bundleBuffers(deterministicOutput);
  assert.deepEqual(firstBundle.names, [
    "evidence-manifest.json",
    "report.md",
    "summary.json",
  ]);
  assert.deepEqual(firstBundle, secondBundle);

  const retainedText = firstBundle.buffers
    .map((buffer) => buffer.toString("utf8"))
    .join("\n");
  assert.match(
    retainedText,
    /Generated from synthetic fixtures\. Not customer or production evidence\./u,
  );
  for (const rawValue of [
    "example-query-value-32fd",
    "example-workflow-payload-41f2",
    "example-fixture-header-73ca",
    "example-fixture-payload-84db",
    "example-stub-payload-95ec",
  ]) {
    assert.doesNotMatch(retainedText, new RegExp(rawValue, "u"));
  }
  assert.doesNotMatch(
    retainedText,
    /Bearer\s|-----BEGIN [^-]{0,64}PRIVATE KEY-----|rawStdout|rawStderr|jsonBody|N8N_ENCRYPTION_KEY/iu,
  );
  assert.doesNotMatch(
    await readFile(path.join(reviewOutput, "report.md"), "utf8"),
    /\bsecure\b|security guarantee|penetration test passed|production safe/iu,
  );

  const dynamicCandidate = JSON.parse(await readFile(candidatePath, "utf8"));
  dynamicCandidate.nodes.find(
    (node) => node.type === "n8n-nodes-base.httpRequest",
  ).parameters.url = "={{$json.destination}}";
  const dynamicPath = path.join(root, "dynamic-candidate.json");
  await writeFile(dynamicPath, JSON.stringify(dynamicCandidate), "utf8");
  const beforeUnsupported = await listReleaseRehearsalDockerInventory();
  const unsupportedOutput = path.join(root, "unsupported");
  const unsupported = await runCli(
    commandArgs(baselinePath, dynamicPath, unsupportedOutput),
  );
  const afterUnsupported = await listReleaseRehearsalDockerInventory();
  assert.equal(unsupported.code, 3, unsupported.stderr);
  assert.match(unsupported.stdout, /Result: BLOCKED_UNSUPPORTED/u);
  assert.equal(
    canonicalJson(afterUnsupported),
    canonicalJson(beforeUnsupported),
    "unsupported input must not change Docker inventory",
  );
  const unsupportedSummary = JSON.parse(
    await readFile(path.join(unsupportedOutput, "summary.json"), "utf8"),
  );
  assert.equal(unsupportedSummary.containment.status, "NOT_RUN");
  assert.equal(unsupportedSummary.evidenceCounts.observed.total, 0);

  const interruptOutput = path.join(root, "interrupted");
  const controller = new AbortController();
  const interruptedPromise = executeReleaseRehearsalCommand(
    commandArgs(baselinePath, baselinePath, interruptOutput).slice(1),
    { signal: controller.signal },
  );
  await waitForManagedVolume();
  controller.abort();
  const interrupted = await interruptedPromise;
  assert.equal(interrupted.exitCode, 130);
  assert.equal(interrupted.status, "INTERRUPTED");
  assert.equal(
    await lstat(interruptOutput).then(
      () => true,
      (error) => {
        if (error?.code !== "ENOENT") throw error;
        return false;
      },
    ),
    false,
  );

  const stabilized = await waitForCleanupInventory(before);
  const after = stabilized.inventory;
  const managedAfter = stabilized.managed;
  assert.equal(canonicalJson(after), canonicalJson(before));
  assert.equal(managedTotal(managedAfter), 0);
  assert.deepEqual(managedAfter, {
    containers: [],
    images: [],
    volumes: [],
    networks: [],
  });
  assert.deepEqual(
    (await readdir(root)).filter((name) => name.includes(".rehearsal-tmp-")),
    [],
  );

  process.stdout.write(
    "release rehearsal customer CLI integration: REHEARSAL_COMPLETE + REVIEW_REQUIRED (6 completed cases, 1 unsupported preflight, 1 interrupted case)\n",
  );
  process.stdout.write(
    "deterministic bundle hashes, redaction, atomic output, interrupt cleanup, and zero managed resources: COMPLETE\n",
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
