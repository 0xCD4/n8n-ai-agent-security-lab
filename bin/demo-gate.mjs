#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { startDemoStagingServer } from "../examples/staging-target.mjs";
import {
  renderGateJUnit,
  renderGateMarkdown,
  renderGateSarif,
} from "../src/reporters.mjs";
import { runSecurityRegressionGate } from "../src/runtime-gate.mjs";
import { readBoundedJsonFile } from "../src/safe-json.mjs";
import { readWorkflowFile } from "../src/workflow-input.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function main() {
  const workflowPath = path.join(root, "workflows", "hardened-support-agent.json");
  const contractPath = path.join(
    root,
    "contracts",
    "hardened-support-agent.contract.json",
  );
  const [workflow, contract] = await Promise.all([
    readWorkflowFile(workflowPath, { label: "Demo workflow export" }),
    readBoundedJsonFile(contractPath, {
      label: "Demo security contract",
      maxBytes: 1024 * 1024,
      maxValues: 50_000,
    }),
  ]);
  const staging = await startDemoStagingServer();

  try {
    const result = await runSecurityRegressionGate({
      workflow,
      contract,
      sourcePath: "workflows/hardened-support-agent.json",
      targetOverride: staging.baseUrl,
    });
    const reportResult = JSON.parse(
      JSON.stringify(result, (key, value) => (key === "durationMs" ? 0 : value)),
    );
    reportResult.target = "http://127.0.0.1:PORT/";
    const reportDirectory = path.join(root, "reports");
    await mkdir(reportDirectory, { recursive: true });
    await Promise.all([
      writeFile(
        path.join(reportDirectory, "runtime-gate-demo.md"),
        renderGateMarkdown(reportResult),
        "utf8",
      ),
      writeFile(
        path.join(reportDirectory, "runtime-gate-demo.json"),
        `${JSON.stringify(reportResult, null, 2)}\n`,
        "utf8",
      ),
      writeFile(
        path.join(reportDirectory, "runtime-gate-demo.junit.xml"),
        renderGateJUnit(reportResult),
        "utf8",
      ),
      writeFile(
        path.join(reportDirectory, "runtime-gate-demo.sarif"),
        renderGateSarif(reportResult),
        "utf8",
      ),
    ]);

    process.stdout.write(
      [
        `Decision: ${result.decision.toUpperCase()}`,
        `Static audit: ${result.static.score}/100 (${result.static.grade})`,
        `Runtime tests: ${result.runtime.passed}/${result.runtime.total} passed`,
        `Reports: ${reportDirectory}`,
        "",
      ].join("\n"),
    );
    process.exitCode = result.passed ? 0 : 1;
  } finally {
    await staging.close();
  }
}

main().catch((error) => {
  process.stderr.write(`Regression gate demo failed: ${error.message}\n`);
  process.exitCode = 2;
});
