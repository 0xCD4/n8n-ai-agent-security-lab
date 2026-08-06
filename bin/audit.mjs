#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { auditN8nWorkflow, renderMarkdownReport } from "../src/rules.mjs";
import { readWorkflowFile } from "../src/workflow-input.mjs";
import {
  renderExposureGraphMermaid,
  renderExposureGraphSvg,
} from "../src/exposure-graph.mjs";

function printUsage() {
  process.stdout.write(
    [
      "Usage:",
      "  node bin/audit.mjs <workflow.json> [output-file] [--format markdown|json] [--graph <path-prefix>]",
      "",
      "Examples:",
      "  node bin/audit.mjs workflow.json reports/workflow-audit.md",
      "  node bin/audit.mjs workflow.json reports/workflow-audit.json",
      "  node bin/audit.mjs workflow.json reports/workflow-audit.md --graph reports/workflow-exposure",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = { input: "", format: "markdown", out: "", graphPrefix: "" };
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
    if (value.startsWith("--graph=")) {
      options.graphPrefix = value.slice("--graph=".length);
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
    if (value === "--graph") {
      const graphPrefix = argv[index + 1];
      if (!graphPrefix || graphPrefix.startsWith("--")) {
        throw new Error("--graph requires a path prefix.");
      }
      options.graphPrefix = graphPrefix;
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
  const workflow = await readWorkflowFile(inputPath, { label: "Workflow export" });
  const result = auditN8nWorkflow(workflow);
  let graphPathForReport = "";

  if (options.graphPrefix) {
    const graphPrefix = path.resolve(options.graphPrefix);
    await mkdir(path.dirname(graphPrefix), { recursive: true });
    await Promise.all([
      writeFile(
        `${graphPrefix}.json`,
        `${JSON.stringify(result.exposureGraph, null, 2)}\n`,
        "utf8",
      ),
      writeFile(
        `${graphPrefix}.mmd`,
        renderExposureGraphMermaid(result.exposureGraph),
        "utf8",
      ),
      writeFile(
        `${graphPrefix}.svg`,
        renderExposureGraphSvg(result.exposureGraph),
        "utf8",
      ),
    ]);
    process.stdout.write(`Exposure graph written to ${graphPrefix}.{json,mmd,svg}\n`);

    if (options.out) {
      graphPathForReport = path
        .relative(path.dirname(path.resolve(options.out)), `${graphPrefix}.svg`)
        .split(path.sep)
        .map((segment) => encodeURIComponent(segment))
        .join("/");
    }
  }

  const output =
    options.format === "json"
      ? `${JSON.stringify(result, null, 2)}\n`
      : renderMarkdownReport(
          result,
          path.relative(process.cwd(), inputPath).split(path.sep).join("/"),
          { exposureGraphPath: graphPathForReport },
        );

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
