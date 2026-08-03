import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { buildExposureGraph } from "./exposure-graph.mjs";
import {
  classifyWorkflowNode,
  workflowAdjacency,
  workflowCredentialReferenceKeys,
} from "./rules.mjs";

const EXECUTE_WORKFLOW_TYPES = new Set([
  "n8n-nodes-base.executeworkflow",
  "@n8n/n8n-nodes-langchain.toolworkflow",
]);

function normalize(value) {
  return String(value ?? "").trim().toLowerCase();
}

function slash(value) {
  return String(value).split(path.sep).join("/");
}

function safeWorkflowName(workflow, fallback) {
  return String(workflow?.name ?? "").trim() || fallback;
}

function workflowReference(node) {
  const raw = node?.parameters?.workflowId;
  if (raw && typeof raw === "object") {
    return {
      value: String(raw.value ?? "").trim(),
      cachedName: String(raw.cachedResultName ?? "").trim(),
      dynamic: String(raw.value ?? "").includes("{{"),
    };
  }
  const value = String(raw ?? "").trim();
  return { value, cachedName: "", dynamic: value.includes("{{") };
}

function isWorkflowCall(node) {
  return !node?.disabled && EXECUTE_WORKFLOW_TYPES.has(normalize(node?.type));
}

function isWorkflowTrigger(node) {
  return !node?.disabled && normalize(node?.type).includes("executeworkflowtrigger");
}

function qualify(workflowKey, nodeName) {
  return `${workflowKey}::${nodeName}`;
}

function publicNodeLabel(workflow, nodeName) {
  return `${workflow.name} / ${nodeName}`;
}

function findPath(
  adjacency,
  starts,
  targets,
  blocked = new Set(),
  maxDepth = 80,
  requireWorkflowBoundary = false,
) {
  const queue = [...starts].map((start) => ({ origin: start, nodes: [start] }));
  const visited = new Set([...starts].map((start) => `${start}\0${start}`));

  while (queue.length > 0) {
    const currentPath = queue.shift();
    const current = currentPath.nodes.at(-1);
    if (
      targets.has(current) &&
      (!requireWorkflowBoundary || pathCrossesWorkflow(currentPath.nodes))
    ) {
      return currentPath.nodes;
    }
    if (currentPath.nodes.length >= maxDepth) continue;

    for (const next of adjacency.get(current) ?? []) {
      const visitKey = `${currentPath.origin}\0${next}`;
      if (visited.has(visitKey) || blocked.has(next)) continue;
      visited.add(visitKey);
      queue.push({ origin: currentPath.origin, nodes: [...currentPath.nodes, next] });
    }
  }
  return null;
}

function pathCrossesWorkflow(pathNodes) {
  const workflows = new Set(pathNodes.map((item) => item.split("::", 1)[0]));
  return workflows.size > 1;
}

function addEdge(adjacency, source, target) {
  const targets = adjacency.get(source) ?? [];
  if (!targets.includes(target)) adjacency.set(source, [...targets, target]);
}

function stableCredentialAliases(workflows) {
  const references = new Set();
  for (const workflow of workflows) {
    for (const node of workflow.nodes) {
      for (const reference of node.credentialReferences) references.add(reference);
    }
  }
  return new Map(
    [...references]
      .sort()
      .map((reference, index) => [reference, `credential-${String(index + 1).padStart(2, "0")}`]),
  );
}

function resolveTarget(call, workflows) {
  if (call.reference.dynamic) return { status: "dynamic", target: null };
  const value = normalize(call.reference.value);
  const cachedName = normalize(call.reference.cachedName);
  if (!value && !cachedName) return { status: "missing", target: null };

  const exact = workflows.filter(
    (workflow) =>
      (value && normalize(workflow.id) === value) ||
      (value && normalize(workflow.name) === value) ||
      (cachedName && normalize(workflow.name) === cachedName),
  );
  if (exact.length === 1) return { status: "resolved", target: exact[0] };
  return { status: exact.length > 1 ? "ambiguous" : "unresolved", target: null };
}

function createFinding(id, severity, title, description, remediation, pathNodes = []) {
  return { id, severity, title, description, remediation, path: pathNodes };
}

function workflowPublicSummary(workflow, credentialAliases, index) {
  return {
    key: `workflow-${String(index + 1).padStart(2, "0")}`,
    name: workflow.name,
    source: workflow.source,
    nodeCount: workflow.nodes.length,
    credentialAliases: [
      ...new Set(
        workflow.nodes.flatMap((node) =>
          node.credentialReferences.map((reference) => credentialAliases.get(reference)),
        ),
      ),
    ].sort(),
  };
}

function renderCall(call) {
  return {
    sourceWorkflow: call.sourceWorkflow.name,
    sourceNode: call.node.name,
    targetWorkflow: call.target?.name ?? null,
    status: call.status,
  };
}

export async function loadWorkflowSet(inputPath) {
  const absoluteInput = path.resolve(inputPath);
  const inputStat = await stat(absoluteInput);
  const files = [];

  async function visit(current) {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const item = path.join(current, entry.name);
      if (entry.isDirectory()) await visit(item);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith(".json")) files.push(item);
    }
  }

  if (inputStat.isDirectory()) await visit(absoluteInput);
  else files.push(absoluteInput);

  const root = inputStat.isDirectory() ? absoluteInput : path.dirname(absoluteInput);
  const workflows = [];
  for (const file of files) {
    let parsed;
    try {
      parsed = JSON.parse(await readFile(file, "utf8"));
    } catch {
      continue;
    }
    const candidates = Array.isArray(parsed) ? parsed : [parsed];
    for (let index = 0; index < candidates.length; index += 1) {
      const workflow = candidates[index];
      if (!workflow || !Array.isArray(workflow.nodes)) continue;
      const relative = slash(path.relative(root, file)) || path.basename(file);
      workflows.push({
        workflow,
        source: candidates.length > 1 ? `${relative}#${index + 1}` : relative,
      });
    }
  }
  return workflows;
}

export function analyzeWorkflowSet(entries, options = {}) {
  const baseName = String(options.name ?? "n8n workflow set");
  const usedKeys = new Set();
  const workflows = entries.map((entry, index) => {
    const workflow = entry.workflow;
    const source = String(entry.source ?? `workflow-${index + 1}.json`);
    const preferredKey = String(workflow.id ?? "").trim() || source;
    let key = preferredKey;
    let suffix = 2;
    while (usedKeys.has(key)) key = `${preferredKey}#${suffix++}`;
    usedKeys.add(key);
    return {
      key,
      id: String(workflow.id ?? "").trim(),
      name: safeWorkflowName(workflow, path.basename(source, path.extname(source))),
      source,
      raw: workflow,
      nodes: (workflow.nodes ?? []).map((node) => ({
        ...node,
        classification: classifyWorkflowNode(node),
        credentialReferences: workflowCredentialReferenceKeys(node),
      })),
    };
  });

  const workflowByKey = new Map(workflows.map((workflow) => [workflow.key, workflow]));
  const nodeByQualifiedName = new Map();
  const adjacency = new Map();
  const calls = [];

  for (const workflow of workflows) {
    const localAdjacency = workflowAdjacency(workflow.raw);
    for (const node of workflow.nodes) {
      const qualified = qualify(workflow.key, node.name);
      nodeByQualifiedName.set(qualified, { workflow, node });
      adjacency.set(qualified, []);
    }
    for (const [source, targets] of localAdjacency) {
      for (const target of targets) {
        addEdge(adjacency, qualify(workflow.key, source), qualify(workflow.key, target));
      }
    }
    for (const node of workflow.nodes.filter(isWorkflowCall)) {
      calls.push({ sourceWorkflow: workflow, node, reference: workflowReference(node) });
    }
  }

  for (const call of calls) {
    const resolution = resolveTarget(call, workflows);
    call.status = resolution.status;
    call.target = resolution.target;
    if (!call.target) continue;
    const triggers = call.target.nodes.filter(isWorkflowTrigger);
    if (triggers.length === 0) {
      call.status = "target-without-trigger";
      call.target = null;
      continue;
    }
    for (const trigger of triggers) {
      addEdge(
        adjacency,
        qualify(call.sourceWorkflow.key, call.node.name),
        qualify(resolution.target.key, trigger.name),
      );
    }
  }

  const credentialAliases = stableCredentialAliases(workflows);
  const approvals = new Set();
  const untrustedInputs = new Set();
  const models = new Set();
  const credentialedActions = new Set();

  for (const [qualified, item] of nodeByQualifiedName) {
    if (item.node.classification.explicitApproval) approvals.add(qualified);
    if (item.node.classification.untrustedInput) untrustedInputs.add(qualified);
    if (item.node.classification.model) models.add(qualified);
    if (item.node.classification.sideEffect && item.node.credentialReferences.length > 0) {
      credentialedActions.add(qualified);
    }
  }

  const publicPath = (qualifiedPath) =>
    qualifiedPath.map((qualified) => {
      const item = nodeByQualifiedName.get(qualified);
      return item ? publicNodeLabel(item.workflow, item.node.name) : qualified;
    });

  const findings = [];
  const inputPath = findPath(adjacency, untrustedInputs, credentialedActions, approvals, 80, true);
  if (inputPath) {
    findings.push(
      createFinding(
        "MW-001",
        "high",
        "Public input reaches a credentialed action across workflows",
        "The exported call graph contains a cross-workflow path from an untrusted trigger to a credentialed side effect without an explicit approval boundary.",
        "Authenticate the entry point, add an explicit approval gate before the action, and use a narrow credential in the called workflow.",
        publicPath(inputPath),
      ),
    );
  }

  const modelPath = findPath(adjacency, models, credentialedActions, approvals, 80, true);
  if (modelPath) {
    findings.push(
      createFinding(
        "MW-002",
        "high",
        "Model output reaches a credentialed action across workflows",
        "The exported call graph contains a cross-workflow path from a model node to a credentialed side effect without an explicit approval boundary.",
        "Constrain model output, add a human approval boundary, and separate read credentials from write credentials.",
        publicPath(modelPath),
      ),
    );
  }

  const credentialUsage = new Map();
  for (const workflow of workflows) {
    for (const node of workflow.nodes) {
      for (const reference of node.credentialReferences) {
        const usage = credentialUsage.get(reference) ?? [];
        usage.push({ workflow, node });
        credentialUsage.set(reference, usage);
      }
    }
  }
  for (const [reference, usage] of credentialUsage) {
    const workflowNames = [...new Set(usage.map((item) => item.workflow.name))].sort();
    if (workflowNames.length < 2) continue;
    const alias = credentialAliases.get(reference);
    findings.push(
      createFinding(
        `MW-003-${alias.split("-").at(-1)}`,
        "medium",
        `${alias} is reused across ${workflowNames.length} workflows`,
        `The same exported credential reference appears in: ${workflowNames.join(", ")}. The report intentionally omits its raw name and ID.`,
        "Review the real permission scope and split intake/read credentials from approved send/write credentials.",
      ),
    );
  }

  calls
    .filter((call) => call.status !== "resolved")
    .forEach((call, index) => {
      findings.push(
        createFinding(
          `MW-004-${String(index + 1).padStart(2, "0")}`,
          "medium",
          `Sub-workflow target could not be resolved (${call.status})`,
          `${call.sourceWorkflow.name} / ${call.node.name} refers to a workflow that is not uniquely present in this export set.`,
          "Export the complete workflow set with stable workflow IDs, then review the unresolved call before deployment.",
        ),
      );
    });

  findings.sort((left, right) => left.id.localeCompare(right.id));
  const graph = buildExposureGraph(baseName, findings);
  graph.note = "Only cross-workflow risky paths proven from the supplied exports are included.";

  return {
    schemaVersion: 1,
    name: baseName,
    summary: {
      workflows: workflows.length,
      nodes: workflows.reduce((sum, workflow) => sum + workflow.nodes.length, 0),
      workflowCalls: calls.length,
      resolvedCalls: calls.filter((call) => call.status === "resolved").length,
      unresolvedCalls: calls.filter((call) => call.status !== "resolved").length,
      credentialAliases: credentialAliases.size,
      findings: findings.length,
      highFindings: findings.filter((finding) => finding.severity === "high").length,
    },
    workflows: workflows.map((workflow, index) =>
      workflowPublicSummary(workflow, credentialAliases, index),
    ),
    calls: calls.map(renderCall),
    findings,
    exposureGraph: graph,
    limitations: [
      "Static exports do not reveal the real permissions granted to a credential.",
      "Dynamic or missing workflow targets require manual review.",
      "A clean result is not proof that the workflows are secure.",
    ],
    _internal: { workflowByKey, nodeByQualifiedName, adjacency },
  };
}

export function publicWorkflowSetResult(result) {
  const { _internal, ...publicResult } = result;
  return publicResult;
}

export function renderWorkflowSetMarkdown(result, sourceLabel = "workflow export set", options = {}) {
  const graphLine = options.exposureGraphPath
    ? `\n![Cross-workflow exposure graph](${options.exposureGraphPath})\n`
    : "";
  const lines = [
    `# n8n multi-workflow trust boundary report`,
    "",
    `Source: \`${sourceLabel}\``,
    "",
    "## Summary",
    "",
    "| Metric | Count |",
    "| --- | ---: |",
    `| Workflows | ${result.summary.workflows} |`,
    `| Nodes | ${result.summary.nodes} |`,
    `| Workflow calls | ${result.summary.workflowCalls} |`,
    `| Resolved calls | ${result.summary.resolvedCalls} |`,
    `| Unresolved calls | ${result.summary.unresolvedCalls} |`,
    `| Credential aliases | ${result.summary.credentialAliases} |`,
    `| Findings | ${result.summary.findings} |`,
    graphLine,
    "## Findings",
    "",
  ];

  if (result.findings.length === 0) {
    lines.push("No cross-workflow findings were detected. Manual review is still required.", "");
  } else {
    for (const finding of result.findings) {
      lines.push(`### ${finding.id} — ${finding.title}`, "");
      lines.push(`Severity: **${finding.severity.toUpperCase()}**`, "");
      lines.push(finding.description, "", `Remediation: ${finding.remediation}`, "");
      if (finding.path.length > 0) lines.push(`Path: ${finding.path.join(" → ")}`, "");
    }
  }

  lines.push("## Limitations", "");
  for (const limitation of result.limitations) lines.push(`- ${limitation}`);
  return `${lines.join("\n")}\n`;
}

export function renderWorkflowSetSarif(result) {
  const rules = [...new Map(result.findings.map((finding) => [finding.id, finding])).values()];
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "n8n-ai-sec-map",
            informationUri: "https://github.com/0xCD4/n8n-ai-agent-security-lab",
            rules: rules.map((finding) => ({
              id: finding.id,
              shortDescription: { text: finding.title },
              help: { text: finding.remediation },
            })),
          },
        },
        results: result.findings.map((finding) => ({
          ruleId: finding.id,
          level: finding.severity === "high" ? "error" : "warning",
          message: { text: finding.description },
        })),
      },
    ],
  };
}
