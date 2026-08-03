#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import {
  analyzeWorkflowSet,
  loadWorkflowSet,
  publicWorkflowSetResult,
  renderWorkflowSetMarkdown,
  renderWorkflowSetSarif,
} from "../src/multi-workflow.mjs";
import {
  renderExposureGraphMermaid,
  renderExposureGraphSvg,
} from "../src/exposure-graph.mjs";

function usage() {
  process.stdout.write(
    [
      "Usage:",
      "  node bin/map.mjs <directory-or-json> [--out <path-prefix>] [--name <label>]",
      "",
      "Writes JSON, Markdown, SARIF, Mermaid and SVG outputs when --out is set.",
      "Workflow exports stay local and are never executed.",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = { input: "", out: "", name: "n8n workflow set", help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!options.input && !value.startsWith("--")) options.input = value;
    else if (value === "--out") options.out = argv[++index] ?? "";
    else if (value.startsWith("--out=")) options.out = value.slice(6);
    else if (value === "--name") options.name = argv[++index] ?? "";
    else if (value.startsWith("--name=")) options.name = value.slice(7);
    else if (value === "--help" || value === "-h") options.help = true;
    else throw new Error(`Unknown argument: ${value}`);
  }
  if (options.out === "" && argv.includes("--out")) throw new Error("--out requires a path prefix.");
  if (options.name === "") throw new Error("--name requires a label.");
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help || !options.input) {
    usage();
    process.exitCode = options.help ? 0 : 2;
    return;
  }

  const entries = await loadWorkflowSet(options.input);
  if (entries.length === 0) throw new Error("No n8n workflow exports were found.");
  const result = analyzeWorkflowSet(entries, { name: options.name });
  const publicResult = publicWorkflowSetResult(result);

  if (!options.out) {
    process.stdout.write(renderWorkflowSetMarkdown(publicResult, options.input));
  } else {
    const prefix = path.resolve(options.out);
    await mkdir(path.dirname(prefix), { recursive: true });
    const graphPath = `${prefix}-exposure.svg`;
    await Promise.all([
      writeFile(`${prefix}.json`, `${JSON.stringify(publicResult, null, 2)}\n`, "utf8"),
      writeFile(
        `${prefix}.md`,
        renderWorkflowSetMarkdown(publicResult, options.input, {
          exposureGraphPath: path.basename(graphPath),
        }),
        "utf8",
      ),
      writeFile(`${prefix}.sarif`, `${JSON.stringify(renderWorkflowSetSarif(publicResult), null, 2)}\n`, "utf8"),
      writeFile(`${prefix}-exposure.json`, `${JSON.stringify(publicResult.exposureGraph, null, 2)}\n`, "utf8"),
      writeFile(`${prefix}-exposure.mmd`, renderExposureGraphMermaid(publicResult.exposureGraph), "utf8"),
      writeFile(`${prefix}-exposure.svg`, renderExposureGraphSvg(publicResult.exposureGraph), "utf8"),
    ]);
    process.stdout.write(`Trust boundary report written to ${prefix}.{json,md,sarif}\n`);
    process.stdout.write(`Exposure graph written to ${prefix}-exposure.{json,mmd,svg}\n`);
  }

  process.exitCode = publicResult.summary.highFindings > 0 ? 3 : 0;
}

main().catch((error) => {
  process.stderr.write(`Multi-workflow audit failed: ${error.message}\n`);
  process.exitCode = 1;
});
