import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runGithubPrGate } from "../src/github-pr-gate.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temp = await mkdtemp(path.join(os.tmpdir(), "releaseguard-pr-gate-"));

try {
  const outputPrefix = path.join(temp, "reports", "pull-request");
  const githubOutput = path.join(temp, "github-output.txt");
  const githubStepSummary = path.join(temp, "step-summary.md");
  const run = await runGithubPrGate({
    input: path.join(root, "workflows", "multi-workflow-demo"),
    outputPrefix,
    name: "Synthetic pull request",
    failOn: "never",
    githubOutput,
    githubStepSummary,
    githubWorkspace: temp,
  });

  assert.equal(run.decision, "review");
  assert.equal(run.exitCode, 0);
  assert.equal(run.result.summary.highFindings > 0, true);
  for (const suffix of [".json", ".md", ".sarif", "-exposure.json", "-exposure.mmd", "-exposure.svg"]) {
    assert.equal((await readFile(`${outputPrefix}${suffix}`)).length > 0, true, `${suffix} was written`);
  }
  const outputs = await readFile(githubOutput, "utf8");
  assert.match(outputs, /decision=review/);
  assert.match(outputs, /sarif=reports\/pull-request\.sarif/);
  const summary = await readFile(githubStepSummary, "utf8");
  assert.match(summary, /REVIEW REQUIRED/);
  assert.match(summary, /does not execute the workflow/);

  const blocking = await runGithubPrGate({
    input: path.join(root, "workflows", "multi-workflow-demo"),
    outputPrefix: path.join(temp, "blocking", "pull-request"),
    name: "Blocking synthetic pull request",
    failOn: "high",
    githubOutput: "",
    githubStepSummary: "",
  });
  assert.equal(blocking.exitCode, 3);

  await assert.rejects(
    () => runGithubPrGate({ input: path.join(root, "workflows"), outputPrefix, failOn: "critical" }),
    /fail-on must be high or never/,
  );
} finally {
  await rm(temp, { recursive: true, force: true });
}

console.log("GitHub PR Gate tests passed");
