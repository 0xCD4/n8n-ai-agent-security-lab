import {
  canonicalJson,
  EVIDENCE_FINGERPRINT_ALGORITHM,
  fingerprintJson,
} from "./evidence-fingerprint.mjs";
import {
  auditN8nWorkflow,
  workflowCredentialReferenceKeys,
} from "./rules.mjs";
import { validateReleaseRehearsalSanitizedJson } from "./release-rehearsal-fixture.mjs";
import {
  normalizeHttpDestination,
  normalizeSupportedHttpMethod,
  RELEASE_REHEARSAL_SUPPORTED_METHODS,
} from "./release-rehearsal-normalize.mjs";
import { readWorkflowFile, validateWorkflowExport } from "./workflow-input.mjs";

export const RELEASE_REHEARSAL_PREFLIGHT_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_MAX_ACTIVE_NODES = 20;
export const RELEASE_REHEARSAL_MAX_TOTAL_NODES = 100;
export const RELEASE_REHEARSAL_HTTP_NODE_TYPE = "n8n-nodes-base.httpRequest";
export const RELEASE_REHEARSAL_HTTP_TYPE_VERSIONS = Object.freeze([4.2]);
export const RELEASE_REHEARSAL_ACTION_CONTROL_VERSIONS = Object.freeze({
  "n8n-nodes-base.webhook": Object.freeze([2.1]),
  "n8n-nodes-base.set": Object.freeze([3.4]),
});
export const RELEASE_REHEARSAL_NODE_CLASSIFICATIONS = Object.freeze([
  "SUPPORTED_CAPTURE",
  "STRUCTURAL_CONTROL",
  "DISABLED_EXCLUDED",
  "UNSUPPORTED_BLOCKED",
]);

const SUPPORTED_METHODS = new Set(RELEASE_REHEARSAL_SUPPORTED_METHODS);
const SUPPORTED_HTTP_TYPE_VERSIONS = new Set(RELEASE_REHEARSAL_HTTP_TYPE_VERSIONS);
const SUPPORTED_CONTROL_TYPES = new Set([
  "n8n-nodes-base.webhook",
  "n8n-nodes-base.respondToWebhook",
  "n8n-nodes-base.set",
  "n8n-nodes-base.if",
  "n8n-nodes-base.switch",
]);
const DANGEROUS_NODE_TYPES = new Set([
  "n8n-nodes-base.code",
  "n8n-nodes-base.executecommand",
]);
const SUBWORKFLOW_NODE_TYPES = new Set([
  "n8n-nodes-base.executeworkflow",
  "@n8n/n8n-nodes-langchain.toolworkflow",
]);
const VARIANTS = new Set(["baseline", "candidate"]);
const UNSAFE_IDENTIFIER_CHARACTERS =
  /[\u0000-\u001F\u007F-\u009F\u200B\u200E\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/u;
const EXPRESSION_MARKER = /\{\{|\}\}/u;
const WEBHOOK_ID_PATTERN =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const WEBHOOK_PATH_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u;
const WORKFLOW_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u;
const ACTION_SUPPORTED_TYPES = new Set([
  "n8n-nodes-base.webhook",
  "n8n-nodes-base.set",
  RELEASE_REHEARSAL_HTTP_NODE_TYPE,
]);
const ACTION_HTTP_OPTIONS = Object.freeze({
  redirect: Object.freeze({ followRedirects: false }),
  response: Object.freeze({
    response: Object.freeze({
      fullResponse: false,
      responseFormat: "json",
    }),
  }),
  timeout: 5_000,
});
const ACTION_REASONS = Object.freeze({
  ACTION_NODE_REQUIRED: "At least one supported HTTP action is required.",
  ACTION_PARAMETERS_UNSUPPORTED:
    "The HTTP action parameters are outside the literal JSON-only Phase 6 profile.",
  ACTION_RETRY_UNSUPPORTED:
    "Retry, continue-on-error, execute-once, and alternate error modes are outside Phase 6.",
  ENTRY_TRIGGER_COUNT_UNSUPPORTED:
    "Exactly one active built-in webhook trigger is required.",
  ENTRY_TRIGGER_PARAMETERS_UNSUPPORTED:
    "The webhook entry must be one literal credential-free POST path with a last-node response.",
  PATH_CYCLE_UNSUPPORTED: "Cycles and loop paths are outside Phase 6.",
  PATH_DISCONNECTED:
    "Every active node must be reachable from the single supported webhook entry.",
  PATH_OUTPUT_UNSUPPORTED:
    "Phase 6 accepts only main output zero in the supported acyclic graph.",
  STATIC_BLOCKER_PRESENT:
    "The existing static audit found a critical blocker in the workflow export.",
  STRUCTURAL_PARAMETERS_UNSUPPORTED:
    "The structural node parameters are outside the literal Phase 6 profile.",
  STRUCTURAL_VERSION_UNSUPPORTED:
    "The structural node type version is outside the Phase 6 compatibility profile.",
  TRANSFORMATION_FIDELITY_UNPROVEN:
    "This otherwise approved structural node has no Phase 6 transformation-fidelity evidence.",
  WORKFLOW_ID_INVALID: "A stable bounded workflow ID is required for contained import and publish.",
  WORKFLOW_STATE_UNSUPPORTED:
    "The exported workflow must be inactive and use the supported v1 execution order.",
});

const REASONS = Object.freeze({
  HTTP_CAPTURE_SUPPORTED:
    "The official HTTP Request node has a supported literal method and destination.",
  CONTROL_IN_SCOPE:
    "This built-in control node is in scope for structural planning only.",
  DISABLED_NODE_EXCLUDED:
    "This disabled built-in node is excluded from active planning.",
  CREDENTIAL_REFERENCE_PRESENT:
    "Credential references are blocked before any workflow execution.",
  CODE_NODE_BLOCKED: "Code nodes are blocked, including when disabled.",
  EXECUTE_COMMAND_NODE_BLOCKED:
    "Execute Command nodes are blocked, including when disabled.",
  COMMUNITY_OR_CUSTOM_NODE_BLOCKED:
    "Community and custom nodes are blocked, including when disabled.",
  SUBWORKFLOW_UNSUPPORTED:
    "Sub-workflow execution is outside the inspected single-workflow scope.",
  NODE_UNSUPPORTED: "This active node type is outside the closed planning subset.",
  NODE_VERSION_UNSUPPORTED:
    "This HTTP Request node version is outside the current source compatibility entry.",
  METHOD_MISSING: "An explicit HTTP method is required.",
  METHOD_DYNAMIC: "Dynamic HTTP methods are unsupported and are not evaluated.",
  METHOD_DELETE_BLOCKED: "DELETE is explicitly blocked by the spike policy.",
  METHOD_READ_ONLY_UNSUPPORTED:
    "GET, HEAD, and OPTIONS are outside the capture-action scope and fail closed.",
  METHOD_UNSUPPORTED: "This HTTP method is outside POST, PUT, and PATCH.",
  DESTINATION_MISSING: "An explicit HTTP destination is required.",
  DESTINATION_DYNAMIC:
    "Dynamic HTTP destinations are unresolved because expressions are not evaluated.",
  DESTINATION_INVALID: "The HTTP destination is not a valid absolute URL.",
  DESTINATION_SCHEME_UNSUPPORTED:
    "Only literal HTTP and HTTPS destinations are supported.",
  DESTINATION_CREDENTIALS_BLOCKED:
    "Credentials embedded in an HTTP destination are blocked.",
  DESTINATION_FRAGMENT_UNSUPPORTED: "HTTP destination fragments are unsupported.",
  PATH_UNSUPPORTED:
    "The workflow contains an unsupported connection channel, edge, error workflow, or pinned-data path.",
  ACTIVE_NODE_LIMIT_EXCEEDED: "The workflow exceeds the 20 active-node spike limit.",
  NODE_ID_MISSING: "Every node requires a stable non-empty identifier.",
  NODE_ID_DUPLICATE: "Node identifiers must be unique within the workflow.",
});

function normalizeType(value) {
  return String(value ?? "").trim().toLowerCase();
}

function isSafeIdentifier(value) {
  return (
    typeof value === "string" &&
    Boolean(value.trim()) &&
    value.length <= 512 &&
    !UNSAFE_IDENTIFIER_CHARACTERS.test(value)
  );
}

function isOfficialBuiltInType(type) {
  return type.startsWith("n8n-nodes-base.") || type.startsWith("@n8n/");
}

function result(
  classification,
  reasonCode,
  {
    method = null,
    destination = null,
    requiredAdapterCapability = null,
  } = {},
) {
  return {
    classification,
    reasonCode,
    reason: REASONS[reasonCode],
    requiredAdapterCapability,
    method,
    destination,
  };
}

function classifyHttpNode(node) {
  if (!SUPPORTED_HTTP_TYPE_VERSIONS.has(node.typeVersion)) {
    return result("UNSUPPORTED_BLOCKED", "NODE_VERSION_UNSUPPORTED");
  }

  const rawMethod = node.parameters?.method;
  if (typeof rawMethod !== "string" || !rawMethod.trim()) {
    return result("UNSUPPORTED_BLOCKED", "METHOD_MISSING");
  }
  if (rawMethod.includes("{{") || rawMethod.includes("}}")) {
    return result("UNSUPPORTED_BLOCKED", "METHOD_DYNAMIC");
  }

  const method = rawMethod.trim().toUpperCase();
  if (method === "DELETE") {
    return result("UNSUPPORTED_BLOCKED", "METHOD_DELETE_BLOCKED", { method });
  }
  if (["GET", "HEAD", "OPTIONS"].includes(method)) {
    return result("UNSUPPORTED_BLOCKED", "METHOD_READ_ONLY_UNSUPPORTED", { method });
  }
  if (!SUPPORTED_METHODS.has(method)) {
    return result("UNSUPPORTED_BLOCKED", "METHOD_UNSUPPORTED", { method });
  }
  try {
    normalizeSupportedHttpMethod(rawMethod);
  } catch {
    return result("UNSUPPORTED_BLOCKED", "METHOD_UNSUPPORTED");
  }

  let destination;
  try {
    destination = normalizeHttpDestination(node.parameters?.url);
  } catch (error) {
    const reasonCode = Object.hasOwn(REASONS, error?.code)
      ? error.code
      : "DESTINATION_INVALID";
    return result("UNSUPPORTED_BLOCKED", reasonCode, { method });
  }

  return result("SUPPORTED_CAPTURE", "HTTP_CAPTURE_SUPPORTED", {
    method,
    destination,
    requiredAdapterCapability: "HTTP_CAPTURE_" + method + "_V1",
  });
}

export function classifyReleaseRehearsalNode(node) {
  const type = String(node?.type ?? "").trim();
  const normalizedType = normalizeType(type);
  const disabled = node?.disabled === true;

  if (workflowCredentialReferenceKeys(node).length > 0) {
    return result("UNSUPPORTED_BLOCKED", "CREDENTIAL_REFERENCE_PRESENT");
  }
  if (DANGEROUS_NODE_TYPES.has(normalizedType)) {
    return result(
      "UNSUPPORTED_BLOCKED",
      normalizedType.endsWith(".code")
        ? "CODE_NODE_BLOCKED"
        : "EXECUTE_COMMAND_NODE_BLOCKED",
    );
  }
  if (!isOfficialBuiltInType(normalizedType)) {
    return result("UNSUPPORTED_BLOCKED", "COMMUNITY_OR_CUSTOM_NODE_BLOCKED");
  }
  if (disabled) {
    return result("DISABLED_EXCLUDED", "DISABLED_NODE_EXCLUDED");
  }
  if (SUBWORKFLOW_NODE_TYPES.has(normalizedType)) {
    return result("UNSUPPORTED_BLOCKED", "SUBWORKFLOW_UNSUPPORTED");
  }
  if (type === RELEASE_REHEARSAL_HTTP_NODE_TYPE) {
    return classifyHttpNode(node);
  }
  if (SUPPORTED_CONTROL_TYPES.has(type)) {
    return result("STRUCTURAL_CONTROL", "CONTROL_IN_SCOPE");
  }
  return result("UNSUPPORTED_BLOCKED", "NODE_UNSUPPORTED");
}

function stableUnique(values) {
  return [...new Set(values)].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

function hasUnsupportedPath(workflow) {
  if (workflow.settings?.errorWorkflow) return true;
  if (workflow.pinData !== undefined && workflow.pinData !== null) {
    if (
      typeof workflow.pinData !== "object" ||
      Array.isArray(workflow.pinData) ||
      Object.keys(workflow.pinData).length > 0
    ) {
      return true;
    }
  }

  for (const outputs of Object.values(workflow.connections ?? {})) {
    for (const [channelName, branches] of Object.entries(outputs ?? {})) {
      if (branches === null) continue;
      const hasEdges =
        Array.isArray(branches) &&
        branches.some(
          (branch) => Array.isArray(branch) && branch.some((edge) => edge !== null),
        );
      if (channelName !== "main" && hasEdges) return true;
      if (channelName !== "main" || !Array.isArray(branches)) continue;
      for (const branch of branches) {
        if (!Array.isArray(branch)) continue;
        for (const edge of branch) {
          if (
            edge !== null &&
            (edge.type !== "main" ||
              !Number.isInteger(edge.index) ||
              edge.index < 0)
          ) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

export function preflightReleaseRehearsalWorkflow(workflow, { variant } = {}) {
  if (!VARIANTS.has(variant)) {
    throw new TypeError("variant must be baseline or candidate.");
  }
  validateWorkflowExport(workflow, {
    label: "Release rehearsal workflow",
    maxNodes: RELEASE_REHEARSAL_MAX_TOTAL_NODES,
  });

  const workflowCanonicalSha256 = fingerprintJson(workflow);
  const activeNodeCount = workflow.nodes.filter((node) => node.disabled !== true).length;
  const issues = [];
  if (activeNodeCount > RELEASE_REHEARSAL_MAX_ACTIVE_NODES) {
    issues.push({
      code: "ACTIVE_NODE_LIMIT_EXCEEDED",
      reason: REASONS.ACTIVE_NODE_LIMIT_EXCEEDED,
      nodeIndex: null,
    });
  }
  if (hasUnsupportedPath(workflow)) {
    issues.push({
      code: "PATH_UNSUPPORTED",
      reason: REASONS.PATH_UNSUPPORTED,
      nodeIndex: null,
    });
  }

  const nodeIds = new Map();
  for (const [index, node] of workflow.nodes.entries()) {
    if (!isSafeIdentifier(node.id)) {
      issues.push({
        code: "NODE_ID_MISSING",
        reason: REASONS.NODE_ID_MISSING,
        nodeIndex: index,
      });
      continue;
    }
    const nodeId = node.id.trim();
    if (nodeIds.has(nodeId)) {
      issues.push({
        code: "NODE_ID_DUPLICATE",
        reason: REASONS.NODE_ID_DUPLICATE,
        nodeIndex: index,
      });
    } else {
      nodeIds.set(nodeId, index);
    }
  }

  const nodes = workflow.nodes.map((node, index) => {
    const classification = classifyReleaseRehearsalNode(node);
    return {
      sequence: index + 1,
      nodeId: isSafeIdentifier(node.id) ? node.id.trim() : null,
      nodeName: node.name,
      nodeType: node.type,
      typeVersion:
        typeof node.typeVersion === "number" && Number.isFinite(node.typeVersion)
          ? node.typeVersion
          : null,
      active: node.disabled !== true,
      ...classification,
    };
  });

  const unsupportedReasonCodes = stableUnique([
    ...issues.map((issue) => issue.code),
    ...nodes
      .filter((node) => node.classification === "UNSUPPORTED_BLOCKED")
      .map((node) => node.reasonCode),
  ]);
  const coverageStatus = unsupportedReasonCodes.length === 0 ? "COMPLETE" : "UNSUPPORTED";

  return {
    schemaVersion: RELEASE_REHEARSAL_PREFLIGHT_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-preflight",
    variant,
    workflow: {
      fingerprintAlgorithm: EVIDENCE_FINGERPRINT_ALGORITHM,
      canonicalSha256: workflowCanonicalSha256,
    },
    limits: {
      maxActiveNodes: RELEASE_REHEARSAL_MAX_ACTIVE_NODES,
      maxTotalNodes: RELEASE_REHEARSAL_MAX_TOTAL_NODES,
    },
    counts: {
      totalNodes: workflow.nodes.length,
      activeNodes: activeNodeCount,
      supportedCaptureNodes: nodes.filter(
        (node) => node.classification === "SUPPORTED_CAPTURE",
      ).length,
      disabledExcludedNodes: nodes.filter(
        (node) => node.classification === "DISABLED_EXCLUDED",
      ).length,
      unsupportedNodes: nodes.filter(
        (node) => node.classification === "UNSUPPORTED_BLOCKED",
      ).length,
    },
    status: coverageStatus === "COMPLETE" ? "PLANNABLE" : "UNSUPPORTED",
    coverage: {
      status: coverageStatus,
      reasonCodes: unsupportedReasonCodes,
    },
    issues,
    nodes,
  };
}

function containsExpression(value) {
  if (typeof value === "string") return EXPRESSION_MARKER.test(value);
  if (Array.isArray(value)) return value.some(containsExpression);
  if (value && typeof value === "object") {
    return Object.values(value).some(containsExpression);
  }
  return false;
}

function actionIssue(code, nodeIndex = null) {
  return {
    code,
    reason: ACTION_REASONS[code],
    nodeIndex,
  };
}

function validateWebhookEntry(node) {
  const parameters = node.parameters;
  return (
    node.typeVersion === 2.1 &&
    isSafeIdentifier(node.webhookId) &&
    WEBHOOK_ID_PATTERN.test(node.webhookId) &&
    parameters &&
    typeof parameters === "object" &&
    !Array.isArray(parameters) &&
    parameters.httpMethod === "POST" &&
    typeof parameters.path === "string" &&
    WEBHOOK_PATH_PATTERN.test(parameters.path) &&
    !parameters.path.includes("..") &&
    parameters.responseMode === "lastNode" &&
    (parameters.authentication === undefined || parameters.authentication === "none") &&
    canonicalJson(parameters.options ?? {}) === canonicalJson({}) &&
    Object.keys(parameters).every((key) =>
      new Set(["httpMethod", "path", "responseMode", "authentication", "options"]).has(
        key,
      ),
    ) &&
    !containsExpression(parameters)
  );
}

function validateLiteralSetNode(node) {
  if (node.typeVersion !== 3.4 || containsExpression(node.parameters)) return false;
  try {
    validateReleaseRehearsalSanitizedJson(node.parameters ?? {});
    return true;
  } catch {
    return false;
  }
}

function hasUnsupportedActionRuntimeFlags(node) {
  return [
    "alwaysOutputData",
    "continueOnFail",
    "executeOnce",
    "maxTries",
    "onError",
    "retryOnFail",
    "waitBetweenTries",
  ].some((key) => Object.hasOwn(node, key));
}

function validateLiteralJsonHttpAction(node) {
  if (hasUnsupportedActionRuntimeFlags(node)) return "ACTION_RETRY_UNSUPPORTED";
  const parameters = node.parameters;
  if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) {
    return "ACTION_PARAMETERS_UNSUPPORTED";
  }
  const knownKeys = new Set([
    "authentication",
    "contentType",
    "jsonBody",
    "method",
    "options",
    "sendBody",
    "specifyBody",
    "url",
  ]);
  if (
    Object.keys(parameters).some((key) => !knownKeys.has(key)) ||
    parameters.authentication !== "none" ||
    parameters.sendBody !== true ||
    parameters.contentType !== "json" ||
    parameters.specifyBody !== "json" ||
    typeof parameters.jsonBody !== "string" ||
    containsExpression(parameters.jsonBody) ||
    canonicalJson(parameters.options) !== canonicalJson(ACTION_HTTP_OPTIONS)
  ) {
    return "ACTION_PARAMETERS_UNSUPPORTED";
  }
  let parsedBody;
  try {
    parsedBody = JSON.parse(parameters.jsonBody);
  } catch {
    return "ACTION_PARAMETERS_UNSUPPORTED";
  }
  if (canonicalJson(parsedBody) !== parameters.jsonBody) {
    return "ACTION_PARAMETERS_UNSUPPORTED";
  }
  try {
    validateReleaseRehearsalSanitizedJson(parsedBody);
  } catch {
    return "ACTION_PARAMETERS_UNSUPPORTED";
  }
  return null;
}

function activeGraphIssues(workflow, triggerName) {
  const activeNodes = workflow.nodes.filter((node) => node.disabled !== true);
  const activeNames = new Set(activeNodes.map((node) => node.name));
  const adjacency = new Map(activeNodes.map((node) => [node.name, []]));
  const issues = [];

  for (const [sourceName, outputs] of Object.entries(workflow.connections ?? {})) {
    for (const [channelName, branches] of Object.entries(outputs ?? {})) {
      if (!Array.isArray(branches)) continue;
      for (const [branchIndex, branch] of branches.entries()) {
        if (!Array.isArray(branch)) continue;
        for (const edge of branch) {
          if (!edge) continue;
          if (
            channelName !== "main" ||
            branchIndex !== 0 ||
            edge.type !== "main" ||
            edge.index !== 0 ||
            !activeNames.has(sourceName) ||
            !activeNames.has(edge.node)
          ) {
            issues.push(actionIssue("PATH_OUTPUT_UNSUPPORTED"));
            continue;
          }
          adjacency.get(sourceName).push(edge.node);
        }
      }
    }
  }

  const reachable = new Set();
  const queue = [triggerName];
  while (queue.length > 0) {
    const name = queue.shift();
    if (reachable.has(name)) continue;
    reachable.add(name);
    queue.push(...(adjacency.get(name) ?? []));
  }
  if (activeNodes.some((node) => !reachable.has(node.name))) {
    issues.push(actionIssue("PATH_DISCONNECTED"));
  }

  const visiting = new Set();
  const visited = new Set();
  function visit(name) {
    if (visiting.has(name)) return true;
    if (visited.has(name)) return false;
    visiting.add(name);
    for (const target of adjacency.get(name) ?? []) {
      if (visit(target)) return true;
    }
    visiting.delete(name);
    visited.add(name);
    return false;
  }
  if (activeNodes.some((node) => visit(node.name))) {
    issues.push(actionIssue("PATH_CYCLE_UNSUPPORTED"));
  }
  return issues;
}

export function preflightReleaseRehearsalActionWorkflow(
  workflow,
  { variant } = {},
) {
  const base = preflightReleaseRehearsalWorkflow(workflow, { variant });
  const issues = [];
  if (
    !isSafeIdentifier(workflow.id) ||
    !WORKFLOW_ID_PATTERN.test(workflow.id)
  ) {
    issues.push(actionIssue("WORKFLOW_ID_INVALID"));
  }
  if (
    workflow.active !== false ||
    canonicalJson(workflow.settings ?? {}) !== canonicalJson({ executionOrder: "v1" })
  ) {
    issues.push(actionIssue("WORKFLOW_STATE_UNSUPPORTED"));
  }

  const activeNodes = workflow.nodes.filter((node) => node.disabled !== true);
  const triggerNodes = activeNodes.filter(
    (node) => node.type === "n8n-nodes-base.webhook",
  );
  if (triggerNodes.length !== 1) {
    issues.push(actionIssue("ENTRY_TRIGGER_COUNT_UNSUPPORTED"));
  } else if (!validateWebhookEntry(triggerNodes[0])) {
    issues.push(
      actionIssue(
        triggerNodes[0].typeVersion === 2.1
          ? "ENTRY_TRIGGER_PARAMETERS_UNSUPPORTED"
          : "STRUCTURAL_VERSION_UNSUPPORTED",
        workflow.nodes.indexOf(triggerNodes[0]),
      ),
    );
  }

  for (const [index, node] of workflow.nodes.entries()) {
    if (node.disabled === true) continue;
    if (!ACTION_SUPPORTED_TYPES.has(node.type)) {
      if (base.nodes[index]?.classification === "STRUCTURAL_CONTROL") {
        issues.push(actionIssue("TRANSFORMATION_FIDELITY_UNPROVEN", index));
      }
      continue;
    }
    if (node.type === "n8n-nodes-base.set" && !validateLiteralSetNode(node)) {
      issues.push(
        actionIssue(
          node.typeVersion === 3.4
            ? "STRUCTURAL_PARAMETERS_UNSUPPORTED"
            : "STRUCTURAL_VERSION_UNSUPPORTED",
          index,
        ),
      );
    }
    if (node.type === RELEASE_REHEARSAL_HTTP_NODE_TYPE) {
      const code = validateLiteralJsonHttpAction(node);
      if (code) issues.push(actionIssue(code, index));
    }
  }

  const actions = base.nodes
    .filter((node) => node.classification === "SUPPORTED_CAPTURE")
    .map((node) => ({
      sequence: node.sequence,
      nodeId: node.nodeId,
      nodeName: node.nodeName,
      method: node.method,
      destination: node.destination,
    }));
  if (actions.length === 0) issues.push(actionIssue("ACTION_NODE_REQUIRED"));
  if (triggerNodes.length === 1) {
    issues.push(...activeGraphIssues(workflow, triggerNodes[0].name));
  }

  const audit = auditN8nWorkflow(workflow);
  const criticalFindingCount = audit.findings.filter(
    (finding) => finding.severity === "critical",
  ).length;
  if (criticalFindingCount > 0) {
    issues.push(actionIssue("STATIC_BLOCKER_PRESENT"));
  }

  const reasonCodes = stableUnique([
    ...base.coverage.reasonCodes,
    ...issues.map((issue) => issue.code),
  ]);
  const plannable = reasonCodes.length === 0;
  const trigger = triggerNodes.length === 1 ? triggerNodes[0] : null;
  return {
    schemaVersion: RELEASE_REHEARSAL_PREFLIGHT_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-action-preflight",
    variant,
    workflow: {
      ...base.workflow,
      id:
        isSafeIdentifier(workflow.id) && WORKFLOW_ID_PATTERN.test(workflow.id)
          ? workflow.id
          : null,
    },
    status: plannable ? "PLANNABLE" : "UNSUPPORTED",
    coverage: {
      status: plannable ? "COMPLETE" : "UNSUPPORTED",
      reasonCodes,
    },
    counts: { ...base.counts },
    entry: trigger
      ? {
          nodeId: isSafeIdentifier(trigger.id) ? trigger.id : null,
          nodeName: trigger.name,
          method: trigger.parameters?.httpMethod === "POST" ? "POST" : null,
          pathCanonicalSha256:
            typeof trigger.parameters?.path === "string"
              ? fingerprintJson({ path: trigger.parameters.path })
              : null,
        }
      : null,
    actions,
    issues: [...base.issues, ...issues],
    staticAudit: {
      criticalFindingCount,
      findingDetailsRetained: false,
    },
    limitations: [
      "Only accepted local capture events can become observed actions.",
      "Structural reachability is preflight context, not node-execution evidence.",
      "No node order, item linking, downstream completion, retry, or loop claim is produced.",
    ],
  };
}

export async function loadReleaseRehearsalPreflight(filePath, options = {}) {
  const allowedKeys = new Set(["variant", "label", "maxBytes", "maxDepth", "maxValues"]);
  if (
    !options ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    Object.keys(options).some((key) => !allowedKeys.has(key))
  ) {
    throw new TypeError("Release rehearsal loader options contain unknown fields.");
  }
  const workflow = await readWorkflowFile(filePath, {
    label: options.label || "Release rehearsal workflow",
    maxNodes: RELEASE_REHEARSAL_MAX_TOTAL_NODES,
    maxBytes: options.maxBytes,
    maxDepth: options.maxDepth,
    maxValues: options.maxValues,
  });
  return preflightReleaseRehearsalWorkflow(workflow, { variant: options.variant });
}
