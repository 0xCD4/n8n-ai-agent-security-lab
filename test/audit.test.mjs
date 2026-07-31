import assert from "node:assert/strict";
import { auditN8nWorkflow, renderMarkdownReport } from "../src/rules.mjs";
import {
  renderExposureGraphMermaid,
  renderExposureGraphSvg,
} from "../src/exposure-graph.mjs";

function connection(target) {
  return { main: [[{ node: target, type: "main", index: 0 }]] };
}

const vulnerableWorkflow = {
  name: "Unsafe support agent",
  nodes: [
    {
      name: "Public Webhook",
      type: "n8n-nodes-base.webhook",
      parameters: { authentication: "none" },
    },
    {
      name: "OpenAI Agent",
      type: "@n8n/n8n-nodes-langchain.agent",
      parameters: { apiKey: "sk-exampleexampleexample12345" },
    },
    {
      name: "Send Email",
      type: "n8n-nodes-base.emailSend",
      parameters: {},
    },
    {
      name: "Fetch User URL",
      type: "n8n-nodes-base.httpRequest",
      parameters: { method: "POST", url: "={{ $json.url }}" },
    },
  ],
  connections: {
    "Public Webhook": connection("OpenAI Agent"),
    "OpenAI Agent": connection("Send Email"),
    "Send Email": connection("Fetch User URL"),
  },
};

const result = auditN8nWorkflow(vulnerableWorkflow);
const ids = new Set(result.findings.map((item) => item.id));

for (const expected of ["AA-001", "AA-002", "AA-003", "AA-004", "AA-006", "AA-007", "AA-009"]) {
  assert.equal(ids.has(expected), true, `Expected ${expected}`);
}
assert.equal(result.grade, "F");
assert.deepEqual(
  result.findings.find((item) => item.id === "AA-003").path,
  ["Public Webhook", "OpenAI Agent"],
);
assert.equal(result.exposureGraph.paths.length, 3);
assert.equal(
  result.exposureGraph.edges.some(
    (edge) => edge.source === "Public Webhook" && edge.target === "OpenAI Agent",
  ),
  true,
);

const report = renderMarkdownReport(result, "unsafe.json", {
  exposureGraphPath: "unsafe-exposure.svg",
});
assert.match(report, /AI Agent Security and Reliability Audit/);
assert.match(report, /!\[Risky workflow paths\]\(unsafe-exposure\.svg\)/);
assert.doesNotMatch(report, /sk-exampleexampleexample12345/);
assert.match(report, /\[REDACTED OpenAI-style API key\]/);

const graphMermaid = renderExposureGraphMermaid(result.exposureGraph);
const graphSvg = renderExposureGraphSvg(result.exposureGraph);
assert.match(graphMermaid, /flowchart LR/);
assert.match(graphMermaid, /Public Webhook/);
assert.match(graphSvg, /Agent Exposure Graph/);
assert.match(graphSvg, /stroke="#ef4444"/);
assert.doesNotMatch(graphSvg, /sk-exampleexampleexample12345/);
assert.equal(graphSvg, renderExposureGraphSvg(result.exposureGraph));

const escapedGraph = {
  ...result.exposureGraph,
  workflow: 'Unsafe\n"] graph',
  paths: [
    {
      ...result.exposureGraph.paths[0],
      nodes: ['Webhook <script>alert("x")</script>', "Agent"],
    },
  ],
};
assert.doesNotMatch(renderExposureGraphSvg(escapedGraph), /<script>/);
assert.doesNotMatch(renderExposureGraphMermaid(escapedGraph), /\n"\] graph/);

const saferWorkflow = {
  name: "Approval-first assistant",
  settings: { errorWorkflow: "error-handler" },
  nodes: [
    {
      name: "Authenticated Webhook",
      type: "n8n-nodes-base.webhook",
      parameters: { authentication: "headerAuth" },
    },
    {
      name: "Rate Limit and Validate Input",
      type: "n8n-nodes-base.code",
      parameters: { jsCode: "return validate($json);" },
    },
    {
      name: "OpenAI Agent",
      type: "@n8n/n8n-nodes-langchain.agent",
      parameters: {},
    },
    {
      name: "Validate Output Schema",
      type: "n8n-nodes-base.code",
      parameters: { jsCode: "return schema.parse($json);" },
    },
    {
      name: "Human Approval",
      type: "n8n-nodes-base.wait",
      parameters: {},
    },
    {
      name: "Send Email",
      type: "n8n-nodes-base.emailSend",
      parameters: {},
    },
    {
      name: "Audit Log",
      type: "n8n-nodes-base.postgres",
      parameters: {},
    },
  ],
  connections: {
    "Authenticated Webhook": connection("Rate Limit and Validate Input"),
    "Rate Limit and Validate Input": connection("OpenAI Agent"),
    "OpenAI Agent": connection("Validate Output Schema"),
    "Validate Output Schema": connection("Human Approval"),
    "Human Approval": connection("Send Email"),
    "Send Email": connection("Audit Log"),
  },
};

const saferResult = auditN8nWorkflow(saferWorkflow);
assert.equal(saferResult.exposureGraph.paths.length, 0);
assert.equal(
  saferResult.findings.some((item) => ["critical", "high"].includes(item.severity)),
  false,
);

assert.throws(
  () => auditN8nWorkflow({ name: "not a workflow" }),
  /nodes array/,
);

console.log("AI agent auditor: all checks passed");
