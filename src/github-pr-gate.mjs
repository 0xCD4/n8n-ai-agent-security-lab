import { appendFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  analyzeWorkflowSet,
  loadWorkflowSet,
  publicWorkflowSetResult,
  renderWorkflowSetMarkdown,
  renderWorkflowSetSarif,
} from "./multi-workflow.mjs";
import {
  renderExposureGraphMermaid,
  renderExposureGraphSvg,
} from "./exposure-graph.mjs";

function safeLabel(value) {
  const label = String(value ?? "").trim();
  if (!label || label.length > 160 || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(label)) {
    throw new Error("PR gate name must be 1 to 160 plain-text characters.");
  }
  return label;
}

function actionValue(value) {
  return String(value).replace(/[\r\n]/gu, "");
}

function actionPath(value, workspace) {
  if (!workspace) return value;
  const relative = path.relative(path.resolve(workspace), value);
  return !relative.startsWith("..") && !path.isAbsolute(relative)
    ? relative.split(path.sep).join("/")
    : value;
}

async function writeActionOutputs(file, outputs) {
  if (!file) return;
  const lines = Object.entries(outputs).map(([key, value]) => `${key}=${actionValue(value)}`);
  await appendFile(file, `${lines.join("\n")}\n`, "utf8");
}

function stepSummary(result, files) {
  const decision = result.summary.highFindings > 0 ? "REVIEW REQUIRED" : "NO HIGH FINDING";
  return [
    "# ReleaseGuard PR Gate",
    "",
    `**${decision}**`,
    "",
    `- Workflows reviewed: ${result.summary.workflows}`,
    `- Nodes reviewed: ${result.summary.nodes}`,
    `- High findings: ${result.summary.highFindings}`,
    `- Other review findings: ${result.summary.otherFindings}`,
    `- Unresolved workflow calls: ${result.summary.unresolvedCalls}`,
    "",
    "## Evidence files",
    "",
    `- Markdown: \`${files.markdown}\``,
    `- SARIF: \`${files.sarif}\``,
    `- JSON: \`${files.json}\``,
    `- Exposure figure: \`${files.svg}\``,
    "",
    "> This result is a static review aid. It does not execute the workflow, verify production settings, or approve a release.",
    "",
  ].join("\n");
}

export async function runGithubPrGate({
  input,
  outputPrefix,
  name = "n8n workflow pull request",
  failOn = "high",
  githubOutput = process.env.GITHUB_OUTPUT ?? "",
  githubStepSummary = process.env.GITHUB_STEP_SUMMARY ?? "",
  githubWorkspace = process.env.GITHUB_WORKSPACE ?? "",
} = {}) {
  if (!input) throw new Error("PR gate input path is required.");
  if (!outputPrefix) throw new Error("PR gate output prefix is required.");
  if (!new Set(["high", "never"]).has(failOn)) {
    throw new Error("PR gate fail-on must be high or never.");
  }

  const label = safeLabel(name);
  const entries = await loadWorkflowSet(input);
  if (entries.length === 0) throw new Error("No n8n workflow exports were found.");
  const result = publicWorkflowSetResult(analyzeWorkflowSet(entries, { name: label }));
  const prefix = path.resolve(outputPrefix);
  await mkdir(path.dirname(prefix), { recursive: true });

  const files = {
    json: `${prefix}.json`,
    markdown: `${prefix}.md`,
    sarif: `${prefix}.sarif`,
    graphJson: `${prefix}-exposure.json`,
    mermaid: `${prefix}-exposure.mmd`,
    svg: `${prefix}-exposure.svg`,
  };
  await Promise.all([
    writeFile(files.json, `${JSON.stringify(result, null, 2)}\n`, "utf8"),
    writeFile(
      files.markdown,
      renderWorkflowSetMarkdown(result, input, { exposureGraphPath: path.basename(files.svg) }),
      "utf8",
    ),
    writeFile(files.sarif, `${JSON.stringify(renderWorkflowSetSarif(result), null, 2)}\n`, "utf8"),
    writeFile(files.graphJson, `${JSON.stringify(result.exposureGraph, null, 2)}\n`, "utf8"),
    writeFile(files.mermaid, renderExposureGraphMermaid(result.exposureGraph), "utf8"),
    writeFile(files.svg, renderExposureGraphSvg(result.exposureGraph), "utf8"),
  ]);

  const publicFiles = Object.fromEntries(
    Object.entries(files).map(([key, value]) => [key, actionPath(value, githubWorkspace)]),
  );
  const decision = result.summary.highFindings > 0 ? "review" : "pass";
  await writeActionOutputs(githubOutput, {
    decision,
    high_findings: result.summary.highFindings,
    report_json: publicFiles.json,
    report_markdown: publicFiles.markdown,
    sarif: publicFiles.sarif,
    exposure_svg: publicFiles.svg,
  });
  if (githubStepSummary) {
    await appendFile(githubStepSummary, stepSummary(result, publicFiles), "utf8");
  }

  return {
    decision,
    exitCode: failOn === "high" && result.summary.highFindings > 0 ? 3 : 0,
    result,
    files,
  };
}
