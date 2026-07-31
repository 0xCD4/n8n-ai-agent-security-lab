#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { auditN8nWorkflow, renderMarkdownReport } from "../src/rules.mjs";

function printUsage() {
  process.stdout.write(
    [
      "Usage:",
      "  node tools/ai-agent-auditor/audit.mjs <workflow.json> [output-file] [--format markdown|json]",
      "",
      "Examples:",
      "  npm run audit:ai-agent -- automation/n8n/workflows/release-announce.json",
      "  npm run audit:ai-agent -- workflow.json reports/workflow-audit.md",
      "  npm run audit:ai-agent -- workflow.json reports/workflow-audit.json",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = { input: "", format: "markdown", out: "" };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!options.input && !value.startsWith("--")) {
      options.input = value;
      continue;
    }
    if (options.input && !options.out && !value.startsWith("--")) {
      options.out = value;
      continue;
    }
    if (options.input && options.out && ["markdown", "json"].includes(value)) {
      options.format = value;
      continue;
    }
    if (value.startsWith("--format=")) {
      options.format = value.slice("--format=".length);
      continue;
    }
    if (value.startsWith("--out=")) {
      options.out = value.slice("--out=".length);
      continue;
    }
    if (value === "--format") {
      options.format = argv[index + 1] || "";
      index += 1;
      continue;
    }
    if (value === "--out") {
      options.out = argv[index + 1] || "";
      index += 1;
      continue;
    }
    if (value === "--help" || value === "-h") {
      options.help = true;
      continue;
    }
    throw new Error(`Unknown argument: ${value}`);
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help || !options.input) {
    printUsage();
    process.exitCode = options.help ? 0 : 2;
    return;
  }
  if (!["markdown", "json"].includes(options.format)) {
    throw new Error("--format must be markdown or json.");
  }
  if (options.out && path.extname(options.out).toLowerCase() === ".json") {
    options.format = "json";
  }

  const inputPath = path.resolve(options.input);
  const raw = await readFile(inputPath, "utf8");
  const workflow = JSON.parse(raw);
  const result = auditN8nWorkflow(workflow);
  const output =
    options.format === "json"
      ? `${JSON.stringify(result, null, 2)}\n`
      : renderMarkdownReport(result, path.relative(process.cwd(), inputPath));

  if (options.out) {
    const outputPath = path.resolve(options.out);
    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, output, "utf8");
    process.stdout.write(`Audit written to ${outputPath}\n`);
  } else {
    process.stdout.write(output);
  }

  process.exitCode = result.findings.some((item) => item.severity === "critical") ? 3 : 0;
}

main().catch((error) => {
  process.stderr.write(`AI agent audit failed: ${error.message}\n`);
  process.exitCode = 1;
});
