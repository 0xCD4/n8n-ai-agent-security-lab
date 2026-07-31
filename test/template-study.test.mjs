import assert from "node:assert/strict";
import {
  buildAggregateSummary,
  buildStudyManifest,
  hashWorkflow,
  isStudyManualReviewFinding,
  renderAggregateMarkdown,
  selectStudyCandidates,
} from "../src/template-study.mjs";

const listings = [
  {
    id: 3,
    name: "Paid agent",
    totalViews: 500,
    price: 5,
    purchaseUrl: "https://example.test/buy",
    nodes: [{ name: "@n8n/n8n-nodes-langchain.agent", displayName: "AI Agent" }],
  },
  {
    id: 2,
    name: "Free agent B",
    totalViews: 100,
    price: 0,
    purchaseUrl: null,
    nodes: [{ name: "@n8n/n8n-nodes-langchain.agent", displayName: "AI Agent" }],
  },
  {
    id: 1,
    name: "Free agent A",
    totalViews: 100,
    purchaseUrl: null,
    nodes: [{ name: "@n8n/n8n-nodes-langchain.agent", displayName: "AI Agent" }],
  },
  {
    id: 4,
    name: "Not an agent",
    totalViews: 900,
    price: 0,
    purchaseUrl: null,
    nodes: [{ name: "n8n-nodes-base.code", displayName: "Code" }],
  },
];

assert.deepEqual(
  selectStudyCandidates(listings).map((listing) => listing.id),
  [1, 2],
);

const workflow = {
  nodes: [{ name: "Trigger", type: "n8n-nodes-base.manualTrigger" }],
  connections: {},
};
assert.equal(hashWorkflow(workflow), hashWorkflow(workflow));
assert.equal(hashWorkflow(workflow).length, 64);

const collection = {
  retrievedAt: "2026-07-31T00:00:00.000Z",
  requestedCount: 3,
  scannedCount: 3,
  failedDownloads: 0,
  searchUrl: "https://api.n8n.io/api/templates/search?example=1",
  selection: "Fixture selection",
  rawWorkflowStorage: false,
};

function record(templateId, score, grade, findings, activeNodes) {
  return {
    templateId,
    title: `Private title ${templateId}`,
    sourceUrl: `https://n8n.io/workflows/${templateId}-fixture/`,
    apiUrl: `https://api.n8n.io/workflows/templates/${templateId}`,
    totalViews: templateId * 100,
    sha256: String(templateId).repeat(64).slice(0, 64),
    audit: {
      score,
      grade,
      findings,
      workflow: { totalNodes: activeNodes + 1, activeNodes },
    },
  };
}

const records = [
  record(
    10,
    40,
    "D",
    [
      { id: "AA-003", severity: "high", title: "Untrusted input path" },
      { id: "AA-010", severity: "low", title: "No failure route" },
    ],
    5,
  ),
  record(
    20,
    80,
    "B",
    [
      { id: "AA-003", severity: "medium", title: "Untrusted input path" },
      { id: "AA-006", severity: "high", title: "No rate or cost boundary" },
    ],
    9,
  ),
  record(30, 100, "A", [], 15),
];

const manifest = buildStudyManifest(records, collection);
assert.equal(manifest.templates.length, 3);
assert.equal(manifest.templates[0].rank, 1);
assert.equal("score" in manifest.templates[0], false);
assert.equal("findings" in manifest.templates[0], false);

const summary = buildAggregateSummary(records, collection);
assert.equal(summary.scores.median, 80);
assert.equal(summary.sample.activeNodes.median, 9);
assert.equal(summary.templates.withHighOrCritical, 2);
assert.equal(summary.templates.withHighOrCriticalPercent, 66.7);
assert.equal(summary.templates.withStudyPriority, 1);
assert.equal(summary.templates.withStudyPriorityPercent, 33.3);
assert.equal(summary.manualReviewQueue.findings, 1);
assert.deepEqual(summary.findingInstancesBySeverity, {
  critical: 0,
  high: 2,
  medium: 1,
  low: 1,
});
assert.equal(summary.signals.find((signal) => signal.id === "AA-003").templateCount, 2);
assert.equal(summary.signals.find((signal) => signal.id === "AA-003").severity, "high");
assert.deepEqual(summary.signals.find((signal) => signal.id === "AA-003").severityCounts, {
  critical: 0,
  high: 1,
  medium: 1,
  low: 0,
});
assert.equal(isStudyManualReviewFinding({ id: "AA-004", severity: "high" }), true);
assert.equal(isStudyManualReviewFinding({ id: "AA-006", severity: "high" }), false);

const markdown = renderAggregateMarkdown(summary);
assert.match(markdown, /Public n8n AI Agent template static scan/);
assert.match(markdown, /1 \(33\.3%\)/);
assert.match(markdown, /path-level manual review/);
assert.match(markdown, /high: 1, medium: 1/);
assert.doesNotMatch(markdown, /Private title/);
assert.doesNotMatch(markdown, /n8n\.io\/workflows\/10/);

console.log("Public template study helpers: all checks passed");
