import assert from "node:assert/strict";
import { auditN8nWorkflow, renderMarkdownReport } from "../src/rules.mjs";
import {
  buildExposureGraph,
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
assert.match(graphSvg, /stroke="#b91c1c"/);
assert.match(graphSvg, /ENTRY POINT/);
assert.match(graphSvg, /FINDINGS/);
assert.doesNotMatch(graphSvg, /sk-exampleexampleexample12345/);
assert.equal(graphSvg, renderExposureGraphSvg(result.exposureGraph));

// Shared nodes are drawn once in the merged flow, not repeated per finding.
assert.equal(graphSvg.match(/>OpenAI Agent</g).length, 1);

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

// Hostile, clipping-sensitive labels: a long unbroken name must be wrapped and
// truncated instead of overflowing its card, and markup must stay escaped.
const hostileGraph = buildExposureGraph("Hostile workflow", [
  {
    id: "AA-003",
    severity: "high",
    title: "T".repeat(220),
    path: [`${"A".repeat(90)}<script>alert("x")</script>`, "Agent"],
  },
]);
const hostileSvg = renderExposureGraphSvg(hostileGraph);
assert.doesNotMatch(hostileSvg, /<script>/);
assert.doesNotMatch(hostileSvg, /A{40}/);
assert.match(hostileSvg, /…/);
const hostileTextChunks = [...hostileSvg.matchAll(/<text[^>]*>([^<]*)<\/text>/g)].map(
  (match) => match[1],
);
assert.ok(hostileTextChunks.length > 0);
for (const chunk of hostileTextChunks) {
  assert.ok(chunk.length <= 130, `text chunk too long for its layout budget: ${chunk}`);
}
assert.equal(hostileSvg, renderExposureGraphSvg(hostileGraph));

// Six findings with up to eight nodes per path must stay readable: every node
// appears exactly once in the merged flow and the canvas widens to fit.
const wideNodes = [
  "Intake Webhook",
  "Queue Normalizer",
  "Support Agent",
  "Policy Retriever",
  "Ticket Classifier",
  "Escalation Agent",
  "Send Refund Email",
  "External Billing API",
];
const wideGraph = buildExposureGraph(
  "Scale check",
  [
    { id: "AA-101", severity: "critical", title: "Full chain", path: wideNodes },
    { id: "AA-102", severity: "high", title: "Input to model", path: wideNodes.slice(0, 3) },
    { id: "AA-103", severity: "high", title: "Model to write", path: wideNodes.slice(2, 7) },
    { id: "AA-104", severity: "medium", title: "Classifier hop", path: wideNodes.slice(3, 6) },
    { id: "AA-105", severity: "medium", title: "Refund boundary", path: wideNodes.slice(5, 8) },
    { id: "AA-106", severity: "low", title: "Billing egress", path: wideNodes.slice(6, 8) },
  ],
);
const wideSvg = renderExposureGraphSvg(wideGraph);
for (const label of wideNodes) {
  assert.match(wideSvg, new RegExp(label.split(" ")[0]));
}
const wideWidth = Number(wideSvg.match(/<svg[^>]* width="(\d+)"/)[1]);
assert.ok(wideWidth >= 8 * 190, "canvas must widen for an eight-node path");
assert.equal(wideSvg, renderExposureGraphSvg(wideGraph));

// The empty state stays a calm, explicit placeholder.
const emptySvg = renderExposureGraphSvg(buildExposureGraph("Clean workflow", []));
assert.match(emptySvg, /No structured risky paths were detected\./);
assert.match(emptySvg, /Manual review is still required\./);

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

// AI tool connections are stored from tool -> agent in n8n exports, but the
// agent can invoke the tool. The risk graph must therefore follow agent -> tool.
const toolCallingWorkflow = {
  name: "Tool-calling agent",
  nodes: [
    {
      name: "Public Chat",
      type: "@n8n/n8n-nodes-langchain.chatTrigger",
      parameters: {},
    },
    {
      name: "Support Agent",
      type: "@n8n/n8n-nodes-langchain.agent",
      parameters: {},
    },
    {
      name: "Send Gmail",
      type: "n8n-nodes-base.gmailTool",
      parameters: { operation: "send" },
    },
  ],
  connections: {
    "Public Chat": connection("Support Agent"),
    "Send Gmail": { ai_tool: [[{ node: "Support Agent", type: "ai_tool", index: 0 }]] },
  },
};
const toolCallingResult = auditN8nWorkflow(toolCallingWorkflow);
assert.deepEqual(
  toolCallingResult.findings.find((item) => item.id === "AA-003").path,
  ["Public Chat", "Support Agent"],
);
assert.equal(toolCallingResult.findings.find((item) => item.id === "AA-003").severity, "high");
assert.deepEqual(
  toolCallingResult.findings.find((item) => item.id === "AA-004").path,
  ["Support Agent", "Send Gmail"],
);

// A read-only tool must not be promoted to an external write action.
const readToolWorkflow = structuredClone(toolCallingWorkflow);
readToolWorkflow.nodes[2].name = "Read Gmail";
readToolWorkflow.nodes[2].parameters.operation = "getAll";
readToolWorkflow.connections = {
  "Public Chat": connection("Support Agent"),
  "Read Gmail": { ai_tool: [[{ node: "Support Agent", type: "ai_tool", index: 0 }]] },
};
const readToolResult = auditN8nWorkflow(readToolWorkflow);
assert.equal(readToolResult.findings.some((item) => item.id === "AA-004"), false);
assert.equal(readToolResult.findings.find((item) => item.id === "AA-003").severity, "medium");
assert.equal(readToolResult.findings.find((item) => item.id === "AA-006").severity, "high");

// Baserow defaults to getAll when an export omits the operation. A missing
// operation must not be interpreted as a write.
const baserowReadWorkflow = structuredClone(toolCallingWorkflow);
baserowReadWorkflow.nodes[2].name = "Tasks";
baserowReadWorkflow.nodes[2].type = "n8n-nodes-base.baserowTool";
baserowReadWorkflow.nodes[2].parameters = {};
baserowReadWorkflow.connections = {
  "Public Chat": connection("Support Agent"),
  Tasks: { ai_tool: [[{ node: "Support Agent", type: "ai_tool", index: 0 }]] },
};
const baserowReadResult = auditN8nWorkflow(baserowReadWorkflow);
assert.equal(baserowReadResult.findings.some((item) => item.id === "AA-004"), false);
assert.equal(baserowReadResult.findings.find((item) => item.id === "AA-003").severity, "medium");

// A sub-workflow tool with explicit read-only intent should not become an
// external write solely because its operation is hidden behind the tool.
const readWorkflowTool = structuredClone(toolCallingWorkflow);
readWorkflowTool.nodes[2].name = "Fetch page";
readWorkflowTool.nodes[2].type = "@n8n/n8n-nodes-langchain.toolWorkflow";
readWorkflowTool.nodes[2].parameters = {
  description: "Fetch and read a webpage, then remove image URLs from the returned content",
};
readWorkflowTool.connections = {
  "Public Chat": connection("Support Agent"),
  "Fetch page": { ai_tool: [[{ node: "Support Agent", type: "ai_tool", index: 0 }]] },
};
const readWorkflowToolResult = auditN8nWorkflow(readWorkflowTool);
assert.equal(readWorkflowToolResult.findings.some((item) => item.id === "AA-004"), false);

const writeWorkflowTool = structuredClone(readWorkflowTool);
writeWorkflowTool.nodes[2].name = "Create record";
writeWorkflowTool.nodes[2].parameters.description = "Create and update a customer record";
writeWorkflowTool.connections = {
  "Public Chat": connection("Support Agent"),
  "Create record": { ai_tool: [[{ node: "Support Agent", type: "ai_tool", index: 0 }]] },
};
assert.equal(
  auditN8nWorkflow(writeWorkflowTool).findings.some((item) => item.id === "AA-004"),
  true,
);

// A WhatsApp media URL is resolved by the provider node, not supplied as an
// arbitrary destination by the incoming user. Keep the dynamic URL visible,
// but do not promote it to a high-severity unvalidated path.
const providerMediaWorkflow = {
  name: "Provider media download",
  nodes: [
    { name: "WhatsApp Trigger", type: "n8n-nodes-base.whatsAppTrigger", parameters: {} },
    {
      name: "Get Media URL",
      type: "n8n-nodes-base.whatsApp",
      parameters: { resource: "media", operation: "mediaUrlGet" },
    },
    {
      name: "Download Media",
      type: "n8n-nodes-base.httpRequest",
      parameters: { url: "={{ $json.url }}" },
    },
  ],
  connections: {
    "WhatsApp Trigger": connection("Get Media URL"),
    "Get Media URL": connection("Download Media"),
  },
};
const providerMediaResult = auditN8nWorkflow(providerMediaWorkflow);
assert.equal(providerMediaResult.findings.find((item) => item.id === "AA-007").severity, "medium");

// Raw model-derived destinations stay high priority, while a fixed
// allowlisted enum or lookup table is treated as a visible URL boundary.
const rawModelUrlWorkflow = {
  name: "Raw model URL",
  nodes: [
    { name: "Public Chat", type: "@n8n/n8n-nodes-langchain.chatTrigger", parameters: {} },
    { name: "Support Agent", type: "@n8n/n8n-nodes-langchain.agent", parameters: {} },
    {
      name: "Fetch Destination",
      type: "n8n-nodes-base.httpRequest",
      parameters: { url: "={{ $json.url }}" },
    },
  ],
  connections: {
    "Public Chat": connection("Support Agent"),
    "Support Agent": connection("Fetch Destination"),
  },
};
assert.equal(
  auditN8nWorkflow(rawModelUrlWorkflow).findings.find((item) => item.id === "AA-007")
    .severity,
  "high",
);

const allowlistedUrlWorkflow = structuredClone(rawModelUrlWorkflow);
allowlistedUrlWorkflow.name = "Allowlisted URL lookup";
allowlistedUrlWorkflow.nodes.splice(2, 0, {
  name: "Destination URL Lookup",
  type: "n8n-nodes-base.set",
  parameters: {
    values: {
      string: [
        { name: "support", value: "https://support.example.test/api" },
        { name: "billing", value: "https://billing.example.test/api" },
      ],
    },
  },
});
allowlistedUrlWorkflow.connections = {
  "Public Chat": connection("Support Agent"),
  "Support Agent": connection("Destination URL Lookup"),
  "Destination URL Lookup": connection("Fetch Destination"),
};
const allowlistedUrlResult = auditN8nWorkflow(allowlistedUrlWorkflow);
assert.equal(
  allowlistedUrlResult.findings.find((item) => item.id === "AA-007").severity,
  "medium",
);

const untrustedLookupWorkflow = structuredClone(allowlistedUrlWorkflow);
untrustedLookupWorkflow.nodes[2].name = "Copy Requested URL";
untrustedLookupWorkflow.nodes[2].parameters = { value: "={{ $json.url }}" };
untrustedLookupWorkflow.connections = {
  "Public Chat": connection("Support Agent"),
  "Support Agent": connection("Copy Requested URL"),
  "Copy Requested URL": connection("Fetch Destination"),
};
assert.equal(
  auditN8nWorkflow(untrustedLookupWorkflow).findings.find((item) => item.id === "AA-007")
    .severity,
  "high",
);

const opaqueLookupWorkflow = structuredClone(allowlistedUrlWorkflow);
opaqueLookupWorkflow.nodes[2].name = "Destination URL Lookup";
opaqueLookupWorkflow.nodes[2].parameters = { value: "={{ $json.url }}" };
assert.equal(
  auditN8nWorkflow(opaqueLookupWorkflow).findings.find((item) => item.id === "AA-007")
    .severity,
  "high",
);

// Reusing one credential reference before and after human approval weakens the
// trust boundary. Reports name the nodes but never expose the credential ID.
const sharedCredentialWorkflow = {
  name: "Shared credential lanes",
  settings: { errorWorkflow: "error-handler" },
  nodes: [
    {
      name: "Slack Intake",
      type: "n8n-nodes-base.slackTrigger",
      parameters: {},
      credentials: {
        slackApi: { id: "shared-lane-credential", name: "Shared Slack account" },
      },
    },
    { name: "Human Approval", type: "n8n-nodes-base.wait", parameters: {} },
    {
      name: "Approved Slack Send",
      type: "n8n-nodes-base.slack",
      parameters: { operation: "postMessage" },
      credentials: {
        slackApi: { id: "shared-lane-credential", name: "Shared Slack account" },
      },
    },
  ],
  connections: {
    "Slack Intake": connection("Human Approval"),
    "Human Approval": connection("Approved Slack Send"),
  },
};
const sharedCredentialResult = auditN8nWorkflow(sharedCredentialWorkflow);
const sharedCredentialFinding = sharedCredentialResult.findings.find(
  (item) => item.id === "AA-011",
);
assert.equal(sharedCredentialFinding.severity, "medium");
assert.match(sharedCredentialFinding.evidence, /Slack Intake/);
assert.match(sharedCredentialFinding.evidence, /Approved Slack Send/);
assert.doesNotMatch(sharedCredentialFinding.evidence, /shared-lane-credential/);

const separatedCredentialWorkflow = structuredClone(sharedCredentialWorkflow);
separatedCredentialWorkflow.nodes[2].credentials.slackApi = {
  id: "approved-send-credential",
  name: "Approved Slack sender",
};
assert.equal(
  auditN8nWorkflow(separatedCredentialWorkflow).findings.some((item) => item.id === "AA-011"),
  false,
);

const noApprovalWorkflow = structuredClone(sharedCredentialWorkflow);
noApprovalWorkflow.nodes[1].name = "Queue Work";
noApprovalWorkflow.connections = {
  "Slack Intake": connection("Queue Work"),
  "Queue Work": connection("Approved Slack Send"),
};
assert.equal(
  auditN8nWorkflow(noApprovalWorkflow).findings.some((item) => item.id === "AA-011"),
  false,
);

const cyclicCredentialWorkflow = structuredClone(sharedCredentialWorkflow);
cyclicCredentialWorkflow.nodes[0].name = "Slack Lane A";
cyclicCredentialWorkflow.nodes[0].type = "n8n-nodes-base.slackTrigger";
cyclicCredentialWorkflow.nodes.splice(1, 0, {
  name: "Slack Lane B",
  type: "n8n-nodes-base.slack",
  parameters: { operation: "get" },
  credentials: {
    slackApi: { id: "shared-lane-credential", name: "Shared Slack account" },
  },
});
cyclicCredentialWorkflow.nodes[3].credentials.slackApi = {
  id: "approved-send-credential",
  name: "Approved Slack sender",
};
cyclicCredentialWorkflow.connections = {
  "Slack Lane A": connection("Slack Lane B"),
  "Slack Lane B": connection("Human Approval"),
  "Human Approval": connection("Slack Lane A"),
};
assert.equal(
  auditN8nWorkflow(cyclicCredentialWorkflow).findings.some((item) => item.id === "AA-011"),
  false,
);

// An HTTP call to a model endpoint can be both model-like and POST-capable. It
// is not, by itself, a model-to-external-action path.
const directModelHttpWorkflow = {
  name: "Direct model request",
  nodes: [
    {
      name: "Gemini Audio",
      type: "n8n-nodes-base.httpRequest",
      parameters: { method: "POST", url: "https://generativelanguage.googleapis.com/v1/models" },
    },
  ],
  connections: {},
};
const directModelHttpResult = auditN8nWorkflow(directModelHttpWorkflow);
assert.equal(directModelHttpResult.findings.some((item) => item.id === "AA-004"), false);

assert.throws(
  () => auditN8nWorkflow({ name: "not a workflow" }),
  /nodes array/,
);

console.log("AI agent auditor: all checks passed");
