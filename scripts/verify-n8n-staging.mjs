#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  buildDynamicLabReceipt,
  renderDynamicLabMarkdown,
} from "../src/dynamic-lab-report.mjs";
import { buildEvidenceSubject } from "../src/evidence-fingerprint.mjs";
import { runSecurityRegressionGate } from "../src/runtime-gate.mjs";
import { readBoundedJsonFile } from "../src/safe-json.mjs";
import { readWorkflowFile } from "../src/workflow-input.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const image = process.env.N8N_IMAGE ?? "docker.n8n.io/n8nio/n8n:2.21.5";
const suffix = `${process.pid}-${Date.now().toString(36)}`.toLowerCase();
const containerName = `csint-n8n-gate-${suffix}`;
const volumeName = `csint_n8n_gate_${suffix}`;
const encryptionKey = "csint-isolated-regression-gate-key";
const stagingSignature = "demo-staging-signature";
const approvalToken = "demo-approval-token";
let containerCreated = false;
let volumeCreated = false;
let verification = null;

function runDocker(args, { allowFailure = false, quiet = false } = {}) {
  const result = spawnSync("docker", args, {
    cwd: root,
    encoding: "utf8",
    stdio: quiet ? "pipe" : "inherit",
    windowsHide: true,
  });

  if (result.error) throw result.error;
  if (!allowFailure && result.status !== 0) {
    const detail = quiet
      ? [result.stdout, result.stderr].filter(Boolean).join("\n").trim()
      : "";
    throw new Error(
      `docker ${args[0]} failed with exit code ${result.status}${detail ? `: ${detail}` : ""}`,
    );
  }

  return result;
}

async function reserveLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    server.close();
    throw new Error("Could not reserve a loopback port for isolated n8n.");
  }
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  return address.port;
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2_000);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function waitForHealth(baseUrl) {
  const deadline = Date.now() + 60_000;
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const response = await fetchWithTimeout(`${baseUrl}/healthz`);
      await response.arrayBuffer();
      if (response.ok) return;
      lastError = new Error(`Health endpoint returned ${response.status}.`);
    } catch (error) {
      lastError = error;
    }
    await delay(1_000);
  }

  throw new Error(`Isolated n8n did not become healthy: ${lastError?.message ?? "timeout"}`);
}

async function waitForWebhook(baseUrl) {
  const deadline = Date.now() + 60_000;
  let lastStatus = "no response";

  while (Date.now() < deadline) {
    try {
      const response = await fetchWithTimeout(
        `${baseUrl}/webhook/security-regression-support-agent/state`,
        {
          headers: {
            "x-staging-signature": stagingSignature,
          },
        },
      );
      await response.arrayBuffer();
      lastStatus = String(response.status);
      if (response.status === 200) return;
    } catch (error) {
      lastStatus = error.message;
    }
    await delay(1_000);
  }

  throw new Error(`Published staging webhook did not become ready: ${lastStatus}`);
}

async function readFinalState(baseUrl) {
  const response = await fetchWithTimeout(
    `${baseUrl}/webhook/security-regression-support-agent/state`,
    {
      headers: { "x-staging-signature": stagingSignature },
    },
  );
  const payload = await response.json();
  if (!response.ok || !Number.isInteger(payload.actions_executed)) {
    throw new Error("The isolated action counter could not be verified.");
  }
  if (payload.actions_executed !== 0) {
    throw new Error(`The isolated workflow recorded ${payload.actions_executed} action(s).`);
  }
  return payload;
}

async function verify() {
  runDocker(["info"], { quiet: true });
  const hostPort = await reserveLoopbackPort();
  const workflowMount = `${path.join(root, "workflows")}:/fixtures:ro`;

  process.stdout.write(`Using isolated n8n image: ${image}\n`);
  runDocker(["volume", "create", volumeName], { quiet: true });
  volumeCreated = true;

  const sharedArgs = [
    "-e",
    `N8N_ENCRYPTION_KEY=${encryptionKey}`,
    "-v",
    `${volumeName}:/home/node/.n8n`,
  ];

  runDocker([
    "run",
    "--rm",
    ...sharedArgs,
    "-v",
    workflowMount,
    image,
    "import:workflow",
    "--input=/fixtures/security-regression-staging-target.json",
  ]);
  runDocker([
    "run",
    "--rm",
    ...sharedArgs,
    image,
    "publish:workflow",
    "--id=CsintGateStgV1a2",
  ]);

  runDocker(
    [
      "run",
      "-d",
      "--name",
      containerName,
      "-p",
      `127.0.0.1:${hostPort}:5678`,
      ...sharedArgs,
      "-e",
      `N8N_STAGING_SIGNATURE=${stagingSignature}`,
      "-e",
      `N8N_STAGING_APPROVAL_TOKEN=${approvalToken}`,
      "-e",
      "N8N_BLOCK_ENV_ACCESS_IN_NODE=false",
      "-e",
      "N8N_DIAGNOSTICS_ENABLED=false",
      "-e",
      "N8N_VERSION_NOTIFICATIONS_ENABLED=false",
      "-e",
      "N8N_TEMPLATES_ENABLED=false",
      "-e",
      "N8N_SECURE_COOKIE=false",
      image,
      "start",
    ],
    { quiet: true },
  );
  containerCreated = true;

  const baseUrl = `http://127.0.0.1:${hostPort}`;
  await waitForHealth(baseUrl);
  await waitForWebhook(baseUrl);

  const [workflow, executedWorkflow, contract] = await Promise.all([
    readWorkflowFile(path.join(root, "workflows", "hardened-support-agent.json"), {
      label: "Static review workflow",
    }),
    readWorkflowFile(path.join(root, "workflows", "security-regression-staging-target.json"), {
      label: "Executed staging workflow",
    }),
    readBoundedJsonFile(path.join(root, "contracts", "n8n-staging.contract.json"), {
      label: "n8n staging contract",
      maxBytes: 1024 * 1024,
      maxValues: 50_000,
    }),
  ]);
  const result = await runSecurityRegressionGate({
    workflow,
    contract,
    sourcePath: "workflows/hardened-support-agent.json",
    targetOverride: baseUrl,
    environment: {
      ...process.env,
      N8N_STAGING_SIGNATURE: stagingSignature,
    },
  });

  if (!result.passed) {
    for (const test of result.runtime.tests.filter((item) => !item.passed)) {
      const failedChecks = test.checks
        .filter((check) => !check.passed)
        .map((check) => check.name)
        .join("; ");
      process.stderr.write(
        `${test.id}: HTTP ${test.status ?? "none"}${test.error ? `, ${test.error}` : ""}${failedChecks ? `, ${failedChecks}` : ""}\n`,
      );
    }
    const failedTests = result.runtime.tests
      .filter((test) => !test.passed)
      .map((test) => test.id)
      .join(", ");
    throw new Error(`Regression gate failed in n8n: ${failedTests || "static blocker"}`);
  }

  const finalState = await readFinalState(baseUrl);

  process.stdout.write(
    [
      "Isolated n8n verification passed.",
      `Static audit: ${result.static.score}/100 (${result.static.grade})`,
      `Runtime contract: ${result.runtime.passed}/${result.runtime.total} passed`,
      `External actions executed: ${finalState.actions_executed}`,
      "",
    ].join("\n"),
  );

  return {
    result,
    finalState,
    subjects: {
      staticWorkflow: buildEvidenceSubject(
        "Static review input",
        "workflows/hardened-support-agent.json",
        workflow,
      ),
      executedWorkflow: buildEvidenceSubject(
        "Executed staging workflow",
        "workflows/security-regression-staging-target.json",
        executedWorkflow,
      ),
      securityContract: buildEvidenceSubject(
        "Runtime security contract",
        "contracts/n8n-staging.contract.json",
        contract,
      ),
    },
  };
}

const cleanup = { containerRemoved: false, volumeRemoved: false };
try {
  verification = await verify();
} finally {
  if (containerCreated) {
    cleanup.containerRemoved =
      runDocker(["rm", "-f", containerName], { allowFailure: true, quiet: true }).status === 0;
  }
  if (volumeCreated) {
    cleanup.volumeRemoved =
      runDocker(["volume", "rm", volumeName], { allowFailure: true, quiet: true }).status === 0;
  }
}

if (verification) {
  const receipt = buildDynamicLabReceipt(verification.result, {
    image,
    finalState: verification.finalState,
    subjects: verification.subjects,
    cleanup,
  });
  const reportDir = path.join(root, "reports");
  await mkdir(reportDir, { recursive: true });
  await Promise.all([
    writeFile(
      path.join(reportDir, "dynamic-workflow-lab.json"),
      `${JSON.stringify(receipt, null, 2)}\n`,
      "utf8",
    ),
    writeFile(
      path.join(reportDir, "dynamic-workflow-lab.md"),
      renderDynamicLabMarkdown(receipt),
      "utf8",
    ),
  ]);
  process.stdout.write("Dynamic lab receipt written to reports/dynamic-workflow-lab.{json,md}\n");

  if (!cleanup.containerRemoved || !cleanup.volumeRemoved) {
    throw new Error("The isolated n8n container or volume was not removed cleanly.");
  }
}
