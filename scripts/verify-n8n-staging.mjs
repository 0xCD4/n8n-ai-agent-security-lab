#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { runSecurityRegressionGate } from "../src/runtime-gate.mjs";

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

  const [workflow, contract] = await Promise.all([
    readFile(path.join(root, "workflows", "hardened-support-agent.json"), "utf8").then(
      JSON.parse,
    ),
    readFile(path.join(root, "contracts", "n8n-staging.contract.json"), "utf8").then(
      JSON.parse,
    ),
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

  process.stdout.write(
    [
      "Isolated n8n verification passed.",
      `Static audit: ${result.static.score}/100 (${result.static.grade})`,
      `Runtime contract: ${result.runtime.passed}/${result.runtime.total} passed`,
      "External actions executed: 0",
      "",
    ].join("\n"),
  );
}

try {
  await verify();
} finally {
  if (containerCreated) {
    runDocker(["rm", "-f", containerName], { allowFailure: true, quiet: true });
  }
  if (volumeCreated) {
    runDocker(["volume", "rm", volumeName], { allowFailure: true, quiet: true });
  }
}
