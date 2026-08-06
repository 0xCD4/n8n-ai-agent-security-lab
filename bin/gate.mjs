#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { runSecurityRegressionGate } from "../src/runtime-gate.mjs";
import {
  renderGateJUnit,
  renderGateMarkdown,
  renderGateSarif,
} from "../src/reporters.mjs";
import { buildRuntimeGateReceipt } from "../src/runtime-receipt.mjs";
import { readBoundedJsonFile } from "../src/safe-json.mjs";
import { readWorkflowFile } from "../src/workflow-input.mjs";

const FORMATS = new Set(["markdown", "json", "junit", "sarif", "receipt"]);

function printUsage() {
  process.stdout.write(
    [
      "n8n AI Security Regression Gate",
      "",
      "Usage:",
      "  node bin/gate.mjs --workflow <workflow.json> --contract <contract.json> [options]",
      "",
      "Options:",
      "  --target <url>       Override contract.target.baseUrl",
      "  --allow-remote       Permit an exact allowlisted remote test webhook",
      "  --format <format>    markdown, json, junit, sarif or receipt",
      "  --out <file>         Write the report to a file",
      "  --help               Show this help",
      "",
      "Safety:",
      "  Loopback targets are allowed by default. Remote targets require both",
      "  --allow-remote and an exact target.allowedHosts entry in the contract.",
      "  Remote paths must match target.allowedPathPrefixes in the contract.",
      "",
      "Example:",
      "  node bin/gate.mjs --workflow workflows/hardened-support-agent.json \\",
      "    --contract contracts/hardened-support-agent.contract.json \\",
      "    --target http://127.0.0.1:47111 --out reports/runtime-gate.md",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = {
    workflow: "",
    contract: "",
    target: "",
    format: "markdown",
    out: "",
    allowRemote: false,
    help: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--allow-remote") {
      options.allowRemote = true;
      continue;
    }
    if (value === "--help" || value === "-h") {
      options.help = true;
      continue;
    }

    const [flag, inlineValue] = value.split("=", 2);
    const key = {
      "--workflow": "workflow",
      "--contract": "contract",
      "--target": "target",
      "--format": "format",
      "--out": "out",
    }[flag];
    if (!key) throw new Error(`Unknown argument: ${value}`);

    const nextValue = inlineValue ?? argv[index + 1];
    if (!nextValue || nextValue.startsWith("--")) {
      throw new Error(`${flag} requires a value.`);
    }
    options[key] = nextValue;
    if (inlineValue === undefined) index += 1;
  }

  return options;
}

function inferFormat(outputPath, requestedFormat) {
  if (requestedFormat === "receipt") return "receipt";
  if (!outputPath) return requestedFormat;
  const extension = path.extname(outputPath).toLowerCase();
  if (extension === ".json") return "json";
  if (extension === ".xml") return "junit";
  if (extension === ".sarif") return "sarif";
  return requestedFormat;
}

function render(result, format) {
  if (format === "json") return `${JSON.stringify(result, null, 2)}\n`;
  if (format === "junit") return renderGateJUnit(result);
  if (format === "sarif") return renderGateSarif(result);
  return renderGateMarkdown(result);
}

export async function runGateCommand(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    printUsage();
    return 0;
  }
  if (!options.workflow || !options.contract) {
    printUsage();
    return 2;
  }

  options.format = inferFormat(options.out, options.format);
  if (!FORMATS.has(options.format)) {
    throw new Error("--format must be markdown, json, junit, sarif or receipt.");
  }

  const workflowPath = path.resolve(options.workflow);
  const contractPath = path.resolve(options.contract);
  const [workflow, contract] = await Promise.all([
    readWorkflowFile(workflowPath, { label: "Workflow export" }),
    readBoundedJsonFile(contractPath, {
      label: "Security contract",
      maxBytes: 1024 * 1024,
      maxValues: 50_000,
    }),
  ]);
  const sourcePath = path.relative(process.cwd(), workflowPath).split(path.sep).join("/");
  const result = await runSecurityRegressionGate({
    workflow,
    contract,
    sourcePath,
    targetOverride: options.target,
    allowRemote: options.allowRemote,
  });
  const receipt =
    options.format === "receipt"
      ? buildRuntimeGateReceipt({
          result,
          workflow,
          contract,
          workflowSource: sourcePath || path.basename(workflowPath),
          contractSource: path.relative(process.cwd(), contractPath).split(path.sep).join("/"),
        })
      : null;
  const output = receipt ? `${JSON.stringify(receipt, null, 2)}\n` : render(result, options.format);

  if (options.out) {
    const outputPath = path.resolve(options.out);
    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, output, "utf8");
    process.stdout.write(`Regression gate report written to ${outputPath}\n`);
  } else {
    process.stdout.write(output);
  }

  return (receipt ? receipt.outcome.passed : result.passed) ? 0 : 1;
}

runGateCommand()
  .then((exitCode) => {
    process.exitCode = exitCode;
  })
  .catch((error) => {
    process.stderr.write(`Regression gate failed: ${error.message}\n`);
    process.exitCode = 2;
  });
