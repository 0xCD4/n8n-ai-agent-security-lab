import { buildExposureGraph } from "./exposure-graph.mjs";

const SEVERITY_WEIGHT = Object.freeze({
  critical: 25,
  high: 15,
  medium: 7,
  low: 2,
});

const SECRET_PATTERNS = [
  { label: "OpenAI-style API key", pattern: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  { label: "GitHub token", pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/g },
  { label: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "Telegram bot token", pattern: /\b\d{6,12}:[A-Za-z0-9_-]{20,}\b/g },
  {
    label: "Bearer token",
    pattern: /\bBearer\s+(?!\{\{|=\{\{|\$env\b)[A-Za-z0-9._~+/=-]{20,}\b/gi,
  },
];

const UNTRUSTED_INPUT_TYPES = [
  "webhook",
  "formtrigger",
  "telegramtrigger",
  "rssfeedread",
  "emailreadimap",
  "gmailtrigger",
  "slacktrigger",
  "discordtrigger",
];

const MODEL_TYPE_MARKERS = [
  "openai",
  "anthropic",
  "gemini",
  "ollama",
  "lmchat",
  "languagemodel",
  "agent",
  "chainllm",
];

const SIDE_EFFECT_TYPE_MARKERS = [
  "emailsend",
  "telegram",
  "slack",
  "discord",
  "github",
  "googlesheets",
  "postgres",
  "mysql",
  "mssql",
  "notion",
  "airtable",
];

const VALIDATION_MARKERS = [
  "validate",
  "verify",
  "sanitize",
  "guard",
  "allowlist",
  "schema",
  "moderation",
  "policy",
  "rate limit",
  "ratelimit",
];

const APPROVAL_MARKERS = [
  "approval",
  "approve",
  "review",
  "confirm",
  "human",
  "manual decision",
  "onay",
  "incele",
];

const LOGGING_MARKERS = [
  "audit",
  "log",
  "history",
  "store pending",
  "record",
  "journal",
  "iz kaydı",
];

function normalize(value) {
  return String(value ?? "").trim().toLowerCase();
}

function nodeText(node) {
  return normalize(`${node.name ?? ""} ${node.type ?? ""} ${JSON.stringify(node.parameters ?? {})}`);
}

function isDisabled(node) {
  return node?.disabled === true;
}

function includesAny(value, markers) {
  const text = normalize(value);
  return markers.some((marker) => text.includes(marker));
}

function isUntrustedInput(node) {
  return !isDisabled(node) && includesAny(node.type, UNTRUSTED_INPUT_TYPES);
}

function isModelNode(node) {
  if (isDisabled(node)) return false;
  if (normalize(node.type).includes("stickynote")) return false;
  const text = nodeText(node);
  if (includesAny(node.type, MODEL_TYPE_MARKERS)) return true;
  return (
    includesAny(text, ["chat/completions", "api.openai.com", "api.anthropic.com", "api.deepseek.com"]) ||
    /\b(?:openai|anthropic|deepseek|gemini)\b/.test(text)
  );
}

function isHttpSideEffect(node) {
  if (!normalize(node.type).includes("httprequest")) return false;
  const method = normalize(node.parameters?.method || "get");
  return !["get", "head", "options"].includes(method);
}

function isSideEffect(node) {
  if (isDisabled(node)) return false;
  if (isHttpSideEffect(node)) return true;
  if (!includesAny(node.type, SIDE_EFFECT_TYPE_MARKERS)) return false;

  const operation = normalize(node.parameters?.operation);
  const name = normalize(node.name);
  if (["read", "get", "getall", "lookup", "search", "list"].includes(operation)) return false;
  if (!operation && /^(read|get|list|lookup|search)\b/.test(name)) return false;
  return true;
}

function isHighImpactSideEffect(node) {
  if (!isSideEffect(node)) return false;
  const text = normalize(node.name);
  if (includesAny(text, ["notify", "notification", "review", "approval", "draft", "audit", "log"])) {
    return false;
  }
  if (includesAny(node.type, ["googlesheets", "postgres", "mysql", "mssql"])) return false;
  return true;
}

function isValidator(node) {
  return !isDisabled(node) && includesAny(nodeText(node), VALIDATION_MARKERS);
}

function isApproval(node) {
  return !isDisabled(node) && includesAny(nodeText(node), APPROVAL_MARKERS);
}

function isLogger(node) {
  return !isDisabled(node) && includesAny(nodeText(node), LOGGING_MARKERS);
}

function hasInlineOutputValidation(node) {
  if (!isModelNode(node)) return false;
  const code = String(node.parameters?.jsCode ?? "");
  const parsesJson = /JSON\.parse|parseJson|response_format/.test(code);
  const constrainsValues = /allowed\s*=\s*new Set|schema\.parse|safeParse|normalizeResult/.test(code);
  const boundsOutput = /\.slice\(|Math\.(?:min|max)/.test(code);
  return parsesJson && constrainsValues && boundsOutput;
}

function redact(text) {
  let output = String(text ?? "");
  for (const item of SECRET_PATTERNS) {
    output = output.replace(item.pattern, `[REDACTED ${item.label}]`);
  }
  return output.replace(
    /((?:api[_-]?key|token|secret|password)\s*["']?\s*[:=]\s*["']?)([^"',\s}]{8,})/gi,
    "$1[REDACTED]",
  );
}

function findEmbeddedSecrets(workflow) {
  const serialized = JSON.stringify(workflow);
  const matches = [];

  for (const item of SECRET_PATTERNS) {
    item.pattern.lastIndex = 0;
    for (const match of serialized.matchAll(item.pattern)) {
      matches.push({
        label: item.label,
        preview: redact(match[0]),
      });
    }
  }

  return matches;
}

function buildAdjacency(workflow) {
  const adjacency = new Map();
  for (const node of workflow.nodes ?? []) adjacency.set(node.name, []);

  for (const [source, outputs] of Object.entries(workflow.connections ?? {})) {
    const targets = [];
    for (const channel of Object.values(outputs ?? {})) {
      if (!Array.isArray(channel)) continue;
      for (const branch of channel) {
        if (!Array.isArray(branch)) continue;
        for (const edge of branch) {
          if (edge?.node) targets.push(edge.node);
        }
      }
    }
    adjacency.set(source, [...new Set([...(adjacency.get(source) ?? []), ...targets])]);
  }

  return adjacency;
}

function findPath(adjacency, start, targetNames, maxDepth = 30) {
  const queue = [[start]];
  const visited = new Set([start]);

  while (queue.length > 0) {
    const path = queue.shift();
    const current = path.at(-1);
    if (targetNames.has(current)) return path;
    if (path.length >= maxDepth) continue;

    for (const next of adjacency.get(current) ?? []) {
      if (visited.has(next)) continue;
      visited.add(next);
      queue.push([...path, next]);
    }
  }

  return null;
}

function findPathAvoiding(adjacency, start, targetNames, blockedNames) {
  const queue = [[start]];
  const visited = new Set([start]);

  while (queue.length > 0) {
    const path = queue.shift();
    const current = path.at(-1);
    if (targetNames.has(current)) return path;
    if (path.length >= 30) continue;

    for (const next of adjacency.get(current) ?? []) {
      if (visited.has(next) || blockedNames.has(next)) continue;
      visited.add(next);
      queue.push([...path, next]);
    }
  }

  return null;
}

function finding(id, severity, title, evidence, recommendation, standard, path = []) {
  const item = {
    id,
    severity,
    title,
    evidence: redact(evidence),
    recommendation,
    standard,
  };
  if (path.length > 0) item.path = path.map((nodeName) => redact(nodeName));
  return item;
}

function findDynamicUrlNodes(nodes) {
  return nodes.filter((node) => {
    if (isDisabled(node) || !normalize(node.type).includes("httprequest")) return false;
    const url = String(node.parameters?.url ?? "");
    return /\{\{[^}]*\$json/i.test(url) || /\{\{[^}]*\$input/i.test(url);
  });
}

function hasNativeWebhookAuth(node) {
  const auth = normalize(node.parameters?.authentication);
  return auth && !["none", "false", "noauth"].includes(auth);
}

function hasRetryOrTimeout(node) {
  const timeout = Number(node.parameters?.options?.timeout ?? node.parameters?.timeout ?? 0);
  return node.retryOnFail === true || timeout > 0;
}

export function auditN8nWorkflow(workflow) {
  if (!workflow || typeof workflow !== "object" || !Array.isArray(workflow.nodes)) {
    throw new TypeError("Expected an exported n8n workflow JSON object with a nodes array.");
  }

  const nodes = workflow.nodes.filter((node) => node && typeof node === "object");
  const activeNodes = nodes.filter((node) => !isDisabled(node));
  const nodeByName = new Map(activeNodes.map((node) => [node.name, node]));
  const adjacency = buildAdjacency(workflow);
  const inputs = activeNodes.filter(isUntrustedInput);
  const models = activeNodes.filter(isModelNode);
  const sideEffects = activeNodes.filter(isSideEffect);
  const highImpactSideEffects = activeNodes.filter(isHighImpactSideEffect);
  const validators = new Set(
    activeNodes
      .filter((node) => !isModelNode(node) && isValidator(node))
      .map((node) => node.name),
  );
  const approvals = new Set(activeNodes.filter(isApproval).map((node) => node.name));
  const loggers = activeNodes.filter(isLogger);
  const findings = [];

  const embeddedSecrets = findEmbeddedSecrets(workflow);
  if (embeddedSecrets.length > 0) {
    findings.push(
      finding(
        "AA-001",
        "critical",
        "A credential-like value is embedded in the workflow export",
        embeddedSecrets.map((item) => `${item.label}: ${item.preview}`).join("; "),
        "Revoke exposed credentials, replace literals with n8n credentials or environment references, and remove secrets from workflow history.",
        "OWASP LLM02: Sensitive Information Disclosure",
      ),
    );
  }

  const unauthenticatedWebhooks = inputs.filter(
    (node) => normalize(node.type).includes("webhook") && !hasNativeWebhookAuth(node),
  );
  if (unauthenticatedWebhooks.length > 0) {
    findings.push(
      finding(
        "AA-002",
        "medium",
        "Public webhook authentication is not enforced by the trigger",
        `Webhook nodes without native authentication: ${unauthenticatedWebhooks.map((node) => node.name).join(", ")}.`,
        "Use header, JWT, or basic authentication at the webhook boundary. If custom validation is retained, reject before processing and rate-limit failures.",
        "OWASP LLM07: System Prompt Leakage and access control",
      ),
    );
  }

  const modelNames = new Set(models.map((node) => node.name));
  for (const input of inputs) {
    const path = findPathAvoiding(adjacency, input.name, modelNames, validators);
    if (!path) continue;
    findings.push(
      finding(
        "AA-003",
        "high",
        "Untrusted input can reach a model without a visible validation boundary",
        `Path: ${path.join(" -> ")}.`,
        "Add a deterministic validation step before the model. Enforce size, type and allowlist rules, separate instructions from data, and test direct and indirect prompt injection cases.",
        "OWASP LLM01: Prompt Injection",
        path,
      ),
    );
    break;
  }

  const sideEffectNames = new Set(highImpactSideEffects.map((node) => node.name));
  for (const model of models) {
    const path = findPathAvoiding(adjacency, model.name, sideEffectNames, approvals);
    if (!path) continue;
    findings.push(
      finding(
        "AA-004",
        "high",
        "A model can reach an external write action without an approval step",
        `Path: ${path.join(" -> ")}.`,
        "Require explicit human approval for messages, writes, deletions, purchases, account changes and other high-impact actions. Use least-privilege credentials for the final action.",
        "OWASP LLM06: Excessive Agency",
        path,
      ),
    );
    break;
  }

  const hasOutputValidation =
    activeNodes.some((node) => !isModelNode(node) && isValidator(node)) ||
    models.every(hasInlineOutputValidation);
  if (models.length > 0 && !hasOutputValidation) {
    findings.push(
      finding(
        "AA-005",
        "medium",
        "No structured model-output validation was detected",
        `Model-related nodes: ${models.map((node) => node.name).join(", ")}.`,
        "Validate model output against a strict schema before it is parsed, stored or passed to another tool. Reject unknown fields and unsafe values.",
        "OWASP LLM05: Improper Output Handling",
      ),
    );
  }

  if (inputs.length > 0 && models.length > 0) {
    const hasRateLimit = activeNodes.some((node) =>
      includesAny(nodeText(node), ["rate limit", "ratelimit", "throttle", "quota", "cooldown"]),
    );
    if (!hasRateLimit) {
      findings.push(
        finding(
          "AA-006",
          "high",
          "No rate or cost boundary was detected before model usage",
          `External inputs: ${inputs.map((node) => node.name).join(", ")}.`,
          "Add per-user and per-origin limits, a maximum input size, a model-call budget, timeouts, and a bounded retry policy.",
          "OWASP LLM10: Unbounded Consumption",
        ),
      );
    }
  }

  const dynamicUrlNodes = findDynamicUrlNodes(activeNodes);
  if (dynamicUrlNodes.length > 0) {
    const dynamicNames = new Set(dynamicUrlNodes.map((node) => node.name));
    const unvalidatedPath = inputs
      .map((input) => findPathAvoiding(adjacency, input.name, dynamicNames, validators))
      .find(Boolean);
    const severity = unvalidatedPath ? "high" : "medium";
    findings.push(
      finding(
        "AA-007",
        severity,
        "Review HTTP request URLs derived from workflow data",
        unvalidatedPath
          ? `Unvalidated path: ${unvalidatedPath.join(" -> ")}.`
          : `Dynamic URL nodes behind a visible validation boundary: ${dynamicUrlNodes.map((node) => node.name).join(", ")}.`,
        "Parse URLs with a real URL parser, allowlist schemes and destinations, block private and metadata IP ranges, and disable redirects unless required.",
        "OWASP LLM06: Excessive Agency and SSRF boundary",
        unvalidatedPath ?? [],
      ),
    );
  }

  const unreliableHttpNodes = activeNodes.filter(
    (node) => normalize(node.type).includes("httprequest") && !hasRetryOrTimeout(node),
  );
  if (unreliableHttpNodes.length > 0) {
    findings.push(
      finding(
        "AA-008",
        "medium",
        "Outbound requests do not show an explicit timeout or retry policy",
        `HTTP nodes: ${unreliableHttpNodes.map((node) => node.name).join(", ")}.`,
        "Set short timeouts and bounded retries with backoff. Make write actions idempotent so a retry cannot publish or charge twice.",
        "NIST AI RMF: Measure and Manage",
      ),
    );
  }

  if (sideEffects.length > 0 && loggers.length === 0) {
    findings.push(
      finding(
        "AA-009",
        "medium",
        "External actions have no visible audit record",
        `Write-capable nodes: ${sideEffects.map((node) => node.name).join(", ")}.`,
        "Record actor, request ID, approved action, destination, result, time and error without storing secrets or unnecessary personal data.",
        "NIST AI RMF: Govern and Manage",
      ),
    );
  }

  const hasErrorWorkflow = Boolean(workflow.settings?.errorWorkflow);
  const hasErrorNode = activeNodes.some((node) =>
    includesAny(node.type, ["errortrigger", "stopanderror"]),
  );
  if (!hasErrorWorkflow && !hasErrorNode) {
    findings.push(
      finding(
        "AA-010",
        "low",
        "No workflow-level failure route was detected",
        "The export has no errorWorkflow setting or explicit error node.",
        "Add a failure route that records the error, alerts the operator and prevents partial actions from being treated as success.",
        "NIST AI RMF: Manage",
      ),
    );
  }

  findings.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.severity] - order[b.severity] || a.id.localeCompare(b.id);
  });

  const score = Math.max(
    0,
    100 - findings.reduce((total, item) => total + SEVERITY_WEIGHT[item.severity], 0),
  );
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  const workflowName = String(workflow.name || "Unnamed workflow");
  return {
    schemaVersion: 1,
    workflow: {
      name: workflowName,
      totalNodes: nodes.length,
      activeNodes: activeNodes.length,
      inputNodes: inputs.map((node) => node.name),
      modelNodes: models.map((node) => node.name),
      sideEffectNodes: sideEffects.map((node) => node.name),
    },
    score,
    grade,
    findings,
    exposureGraph: buildExposureGraph(workflowName, findings),
    limitations: [
      "Static analysis cannot prove runtime authorization, credential scopes, upstream controls or model behavior.",
      "A clean report is not a penetration-test result or a guarantee of security.",
      "Review production logs, permissions, model prompts and failure handling before release.",
    ],
  };
}

export function renderMarkdownReport(result, sourcePath = "", options = {}) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of result.findings) counts[item.severity] += 1;

  const lines = [
    "# AI Agent Security and Reliability Audit",
    "",
    `Workflow: ${result.workflow.name}`,
    sourcePath ? `Source: ${sourcePath}` : null,
    `Score: ${result.score}/100 (${result.grade})`,
    "",
    "## Executive summary",
    "",
    `The static review found ${result.findings.length} item(s): ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium and ${counts.low} low.`,
    "",
    "## Workflow inventory",
    "",
    `- Nodes: ${result.workflow.activeNodes} active, ${result.workflow.totalNodes} total`,
    `- External inputs: ${result.workflow.inputNodes.join(", ") || "None detected"}`,
    `- Model nodes: ${result.workflow.modelNodes.join(", ") || "None detected"}`,
    `- Write-capable nodes: ${result.workflow.sideEffectNodes.join(", ") || "None detected"}`,
    "",
    ...(options.exposureGraphPath
      ? [
          "## Exposure graph",
          "",
          `![Risky workflow paths](${options.exposureGraphPath})`,
          "",
          "Only structured risky paths found by the static scanner are shown. Manual review remains required.",
          "",
        ]
      : []),
    "## Findings",
    "",
  ].filter((line) => line !== null);

  if (result.findings.length === 0) {
    lines.push("No heuristic findings were produced. Manual review is still required.", "");
  }

  for (const item of result.findings) {
    lines.push(
      `### ${item.id} | ${item.severity.toUpperCase()} | ${item.title}`,
      "",
      `Evidence: ${item.evidence}`,
      "",
      `Recommended action: ${item.recommendation}`,
      "",
      `Reference: ${item.standard}`,
      "",
    );
  }

  lines.push(
    "## Review limits",
    "",
    ...result.limitations.map((item) => `- ${item}`),
    "",
    "## Reference baseline",
    "",
    "- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/",
    "- OWASP Excessive Agency guidance: https://owasp.org/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM06_ExcessiveAgency.html",
    "- NIST AI RMF Generative AI Profile: https://doi.org/10.6028/NIST.AI.600-1",
    "",
  );

  return `${lines.join("\n").replace(/\n+$/, "")}\n`;
}
