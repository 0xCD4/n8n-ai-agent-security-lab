import assert from "node:assert/strict";
import { auditN8nWorkflow, renderMarkdownReport } from "../src/rules.mjs";

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

const report = renderMarkdownReport(result, "unsafe.json");
assert.match(report, /AI Agent Security and Reliability Audit/);
assert.doesNotMatch(report, /sk-exampleexampleexample12345/);
assert.match(report, /\[REDACTED OpenAI-style API key\]/);

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
assert.equal(
  saferResult.findings.some((item) => ["critical", "high"].includes(item.severity)),
  false,
);

assert.throws(
  () => auditN8nWorkflow({ name: "not a workflow" }),
  /nodes array/,
);

console.log("AI agent auditor: all checks passed");
