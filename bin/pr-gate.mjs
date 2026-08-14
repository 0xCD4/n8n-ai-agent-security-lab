#!/usr/bin/env node

import process from "node:process";
import { pathToFileURL } from "node:url";
import { runGithubPrGate } from "../src/github-pr-gate.mjs";

function usage() {
  return [
    "Usage:",
    "  node bin/pr-gate.mjs <directory-or-json> --out <path-prefix> [--name <label>] [--fail-on high|never]",
    "",
    "Writes JSON, Markdown, SARIF, Mermaid and SVG evidence without executing a workflow.",
    "",
  ].join("\n");
}

function parseArgs(argv) {
  const options = { input: "", outputPrefix: "", name: "n8n workflow pull request", failOn: "high", help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!options.input && !value.startsWith("--")) options.input = value;
    else if (value === "--out") options.outputPrefix = argv[++index] ?? "";
    else if (value.startsWith("--out=")) options.outputPrefix = value.slice(6);
    else if (value === "--name") options.name = argv[++index] ?? "";
    else if (value.startsWith("--name=")) options.name = value.slice(7);
    else if (value === "--fail-on") options.failOn = argv[++index] ?? "";
    else if (value.startsWith("--fail-on=")) options.failOn = value.slice(10);
    else if (value === "--help" || value === "-h") options.help = true;
    else throw new Error(`Unknown argument: ${value}`);
  }
  return options;
}

export async function runPrGateCommand(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help || !options.input || !options.outputPrefix) {
    process.stdout.write(usage());
    return options.help ? 0 : 2;
  }
  const run = await runGithubPrGate(options);
  process.stdout.write(`ReleaseGuard PR evidence written to ${run.files.markdown}\n`);
  process.stdout.write(`Decision: ${run.decision.toUpperCase()} (${run.result.summary.highFindings} high finding(s))\n`);
  return run.exitCode;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runPrGateCommand()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      process.stderr.write(`ReleaseGuard PR Gate failed: ${error.message}\n`);
      process.exitCode = 1;
    });
}
