import { createHash } from "node:crypto";

const SEVERITY_ORDER = Object.freeze({
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
});

const STUDY_PATH_REVIEW_RULES = new Set(["AA-003", "AA-004", "AA-007"]);

export function isStudyManualReviewFinding(finding) {
  if (!finding || typeof finding !== "object") return false;
  if (finding.severity === "critical") return true;
  return finding.severity === "high" && STUDY_PATH_REVIEW_RULES.has(finding.id);
}

function round(value, digits = 1) {
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function median(values) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const midpoint = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[midpoint];
  return round((sorted[midpoint - 1] + sorted[midpoint]) / 2);
}

function percentage(count, total) {
  if (total === 0) return 0;
  return round((count / total) * 100);
}

export function isFreeTemplateListing(listing) {
  if (!listing || typeof listing !== "object") return false;
  const price = listing.price == null || listing.price === "" ? 0 : Number(listing.price);
  return !listing.purchaseUrl && Number.isFinite(price) && price === 0;
}

export function hasAiAgentNode(listing) {
  return Array.isArray(listing?.nodes) && listing.nodes.some((node) => {
    const name = String(node?.name ?? "").toLowerCase();
    const displayName = String(node?.displayName ?? "").toLowerCase();
    return name === "@n8n/n8n-nodes-langchain.agent" || displayName === "ai agent";
  });
}

export function selectStudyCandidates(listings) {
  const byId = new Map();
  for (const listing of listings ?? []) {
    if (!isFreeTemplateListing(listing) || !hasAiAgentNode(listing)) continue;
    const templateId = Number(listing.id);
    if (!Number.isInteger(templateId) || templateId <= 0 || byId.has(templateId)) continue;
    byId.set(templateId, listing);
  }

  return [...byId.values()].sort((a, b) => {
    const viewDifference = Number(b.totalViews ?? 0) - Number(a.totalViews ?? 0);
    return viewDifference || Number(a.id) - Number(b.id);
  });
}

export function hashWorkflow(workflow) {
  return createHash("sha256").update(JSON.stringify(workflow)).digest("hex");
}

export function buildStudyManifest(records, collection) {
  return {
    schemaVersion: 1,
    collection,
    templates: records.map((record, index) => ({
      rank: index + 1,
      templateId: record.templateId,
      title: record.title,
      sourceUrl: record.sourceUrl,
      apiUrl: record.apiUrl,
      totalViews: record.totalViews,
      sha256: record.sha256,
      totalNodes: record.audit.workflow.totalNodes,
      activeNodes: record.audit.workflow.activeNodes,
    })),
  };
}

export function buildAggregateSummary(records, collection) {
  const totalTemplates = records.length;
  const scores = records.map((record) => record.audit.score);
  const nodeCounts = records.map((record) => record.audit.workflow.activeNodes);
  const gradeCounts = {};
  const severityInstances = { critical: 0, high: 0, medium: 0, low: 0 };
  const findingCounts = new Map();
  let templatesWithAnySignal = 0;
  let templatesWithCritical = 0;
  let templatesWithHighOrCritical = 0;
  let templatesWithStudyPriority = 0;
  let manualReviewFindings = 0;

  for (const record of records) {
    const findings = record.audit.findings ?? [];
    gradeCounts[record.audit.grade] = (gradeCounts[record.audit.grade] ?? 0) + 1;
    if (findings.length > 0) templatesWithAnySignal += 1;
    if (findings.some((finding) => finding.severity === "critical")) {
      templatesWithCritical += 1;
    }
    if (findings.some((finding) => ["critical", "high"].includes(finding.severity))) {
      templatesWithHighOrCritical += 1;
    }
    const studyPriorityFindings = findings.filter(isStudyManualReviewFinding);
    if (studyPriorityFindings.length > 0) {
      templatesWithStudyPriority += 1;
      manualReviewFindings += studyPriorityFindings.length;
    }

    for (const finding of findings) {
      severityInstances[finding.severity] = (severityInstances[finding.severity] ?? 0) + 1;
      const current = findingCounts.get(finding.id) ?? {
        id: finding.id,
        severity: finding.severity,
        title: finding.title,
        templateCount: 0,
        severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
      };
      if (SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[current.severity]) {
        current.severity = finding.severity;
      }
      current.templateCount += 1;
      current.severityCounts[finding.severity] += 1;
      findingCounts.set(finding.id, current);
    }
  }

  const signals = [...findingCounts.values()]
    .map((finding) => ({
      ...finding,
      sharePercent: percentage(finding.templateCount, totalTemplates),
    }))
    .sort((a, b) => {
      return (
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        b.templateCount - a.templateCount ||
        a.id.localeCompare(b.id)
      );
    });

  return {
    schemaVersion: 2,
    collection,
    sample: {
      templatesScanned: totalTemplates,
      totalViewsAtCollection: records.reduce(
        (total, record) => total + Number(record.totalViews ?? 0),
        0,
      ),
      activeNodes: {
        minimum: nodeCounts.length > 0 ? Math.min(...nodeCounts) : 0,
        median: median(nodeCounts),
        maximum: nodeCounts.length > 0 ? Math.max(...nodeCounts) : 0,
      },
    },
    scores: {
      minimum: scores.length > 0 ? Math.min(...scores) : 0,
      median: median(scores),
      mean:
        scores.length > 0
          ? round(scores.reduce((sum, score) => sum + score, 0) / scores.length)
          : 0,
      maximum: scores.length > 0 ? Math.max(...scores) : 0,
      grades: Object.fromEntries(
        Object.entries(gradeCounts).sort(([a], [b]) => a.localeCompare(b)),
      ),
    },
    templates: {
      withAnySignal: templatesWithAnySignal,
      withAnySignalPercent: percentage(templatesWithAnySignal, totalTemplates),
      withCritical: templatesWithCritical,
      withCriticalPercent: percentage(templatesWithCritical, totalTemplates),
      withHighOrCritical: templatesWithHighOrCritical,
      withHighOrCriticalPercent: percentage(templatesWithHighOrCritical, totalTemplates),
      withStudyPriority: templatesWithStudyPriority,
      withStudyPriorityPercent: percentage(templatesWithStudyPriority, totalTemplates),
    },
    findingInstancesBySeverity: severityInstances,
    manualReviewQueue: {
      templates: templatesWithStudyPriority,
      findings: manualReviewFindings,
      policy:
        "Critical findings and high-severity AA-003, AA-004 or AA-007 path findings require template-level validation.",
    },
    signals,
    limitations: [
      "These are heuristic static-analysis signals, not confirmed vulnerabilities.",
      "No community workflow was imported, activated or executed.",
      "Public exports cannot prove runtime authorization, credential scopes, upstream controls or model behavior.",
      "Critical findings and high-severity path findings require manual validation before publication.",
      "AA-006 remains an aggregate scanner signal, but it is not a template-level publication target because exports cannot reveal instance-level rate or cost controls.",
      "AA-011 compares credential references within one export; it cannot prove real credential scopes or correlate credentials hidden across separate workflows.",
      "The sample represents the most-viewed free AI Agent templates returned by the official API at collection time, not the entire template library.",
    ],
  };
}

export function renderAggregateMarkdown(summary) {
  const lines = [
    "# Public n8n AI Agent template static scan",
    "",
    `Collected: ${summary.collection.retrievedAt}`,
    `Sample: ${summary.sample.templatesScanned} most-viewed free AI Agent templates available through the official n8n template API at collection time.`,
    "",
    "## Method",
    "",
    "- Source: official n8n template search and workflow-template APIs.",
    "- Filter: AI category, AI Agent node, free public templates only.",
    "- Order: public view count descending, then template ID ascending for deterministic ties.",
    "- Analysis: local static scan of each downloaded export; no workflow was imported or executed.",
    "- Publication boundary: this aggregate report contains no template-level score or finding list.",
    "",
    "## Study result",
    "",
    "| Metric | Result |",
    "| --- | ---: |",
    `| Templates scanned | ${summary.sample.templatesScanned} |`,
    `| Median active nodes | ${summary.sample.activeNodes.median} |`,
    `| Median heuristic score | ${summary.scores.median}/100 |`,
    `| Templates with any signal | ${summary.templates.withAnySignal} (${summary.templates.withAnySignalPercent}%) |`,
    `| Templates queued for path-level manual review | ${summary.manualReviewQueue.templates} (${summary.templates.withStudyPriorityPercent}%) |`,
    `| Path-level finding instances to validate | ${summary.manualReviewQueue.findings} |`,
    "",
    "## Aggregate signals",
    "",
    "| Rule | Highest severity | Severity breakdown | Templates | Share |",
    "| --- | --- | --- | ---: | ---: |",
  ];

  if (summary.signals.length === 0) {
    lines.push("| None | - | - | 0 | 0% |");
  } else {
    for (const signal of summary.signals) {
      const breakdown = Object.entries(signal.severityCounts)
        .filter(([, count]) => count > 0)
        .map(([severity, count]) => `${severity}: ${count}`)
        .join(", ");
      lines.push(
        `| ${signal.id}: ${signal.title} | ${signal.severity} | ${breakdown} | ${signal.templateCount} | ${signal.sharePercent}% |`,
      );
    }
  }

  lines.push(
    "",
    "## Interpretation limits",
    "",
    ...summary.limitations.map((limitation) => `- ${limitation}`),
    "",
  );

  return `${lines.join("\n").replace(/\n+$/, "")}\n`;
}
