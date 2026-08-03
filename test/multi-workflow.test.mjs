import assert from "node:assert/strict";
import path from "node:path";
import process from "node:process";
import {
  analyzeWorkflowSet,
  loadWorkflowSet,
  publicWorkflowSetResult,
  renderWorkflowSetMarkdown,
  renderWorkflowSetSarif,
} from "../src/multi-workflow.mjs";

const fixturePath = path.join(process.cwd(), "workflows", "multi-workflow-demo");
const entries = await loadWorkflowSet(fixturePath);
assert.equal(entries.length, 2);

const result = publicWorkflowSetResult(
  analyzeWorkflowSet(entries, { name: "Multi-workflow demo" }),
);
assert.deepEqual(result.summary, {
  workflows: 2,
  nodes: 6,
  workflowCalls: 1,
  resolvedCalls: 1,
  unresolvedCalls: 0,
  credentialAliases: 2,
  findings: 3,
  highFindings: 2,
});
assert.deepEqual(
  result.findings.map((finding) => finding.id),
  ["MW-001", "MW-002", "MW-003-01"],
);
assert.deepEqual(result.findings[0].path, [
  "Public support intake / Public Webhook",
  "Public support intake / Support Agent",
  "Public support intake / Run Privileged Action",
  "Privileged action / Called by Another Workflow",
  "Privileged action / Privileged Model Lookup",
  "Privileged action / Send External Email",
]);
assert.equal(result.exposureGraph.paths.length, 2);

const serialized = JSON.stringify(result);
assert.doesNotMatch(serialized, /demo-shared-credential/i);
assert.doesNotMatch(serialized, /public-intake-01/i);
assert.doesNotMatch(serialized, /privileged-action-01/i);
assert.doesNotMatch(serialized, /Demo shared credential/);
assert.doesNotMatch(serialized, /Demo SMTP credential/);
assert.match(serialized, /credential-01/);

const markdown = renderWorkflowSetMarkdown(result, "workflows/multi-workflow-demo", {
  exposureGraphPath: "multi-workflow-demo-exposure.svg",
});
assert.match(markdown, /MW-001/);
assert.match(markdown, /multi-workflow-demo-exposure\.svg/);
assert.doesNotMatch(markdown, /demo-shared-credential/i);

const sarif = renderWorkflowSetSarif(result);
assert.equal(sarif.version, "2.1.0");
assert.equal(sarif.runs[0].results.length, 3);

const dynamicEntries = [
  {
    source: "dynamic.json",
    workflow: {
      id: "dynamic",
      name: "Dynamic caller",
      nodes: [
        {
          name: "Choose at runtime",
          type: "n8n-nodes-base.executeWorkflow",
          parameters: { workflowId: "={{ $json.workflowId }}" },
        },
      ],
      connections: {},
    },
  },
];
const dynamicResult = publicWorkflowSetResult(analyzeWorkflowSet(dynamicEntries));
assert.equal(dynamicResult.summary.unresolvedCalls, 1);
assert.equal(dynamicResult.findings[0].id, "MW-004-01");
assert.equal(dynamicResult.calls[0].status, "dynamic");

const approvedEntries = structuredClone(entries);
const intake = approvedEntries.find((entry) => entry.workflow.id === "public-intake-01").workflow;
intake.nodes.push({
  name: "Human Approval",
  type: "n8n-nodes-base.wait",
  parameters: {},
});
intake.connections["Support Agent"] = {
  main: [[{ node: "Human Approval", type: "main", index: 0 }]],
};
intake.connections["Human Approval"] = {
  main: [[{ node: "Run Privileged Action", type: "main", index: 0 }]],
};
delete intake.connections["Run Privileged Action"].ai_tool;
const approvedResult = publicWorkflowSetResult(analyzeWorkflowSet(approvedEntries));
assert.equal(approvedResult.findings.some((finding) => finding.id === "MW-001"), false);
assert.equal(approvedResult.findings.some((finding) => finding.id === "MW-002"), false);

process.stdout.write("multi-workflow tests passed\n");
