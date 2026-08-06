import { Buffer } from "node:buffer";
import path from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

import { canonicalJson, fingerprintJson } from "./evidence-fingerprint.mjs";
import {
  RELEASE_REHEARSAL_CAPTURE_HEADERS,
} from "./release-rehearsal-capture.mjs";
import {
  validateReleaseRehearsalCaptureConfig,
  validateReleaseRehearsalSanitizedJson,
} from "./release-rehearsal-fixture.mjs";
import { normalizeHttpDestination } from "./release-rehearsal-normalize.mjs";
import { readBoundedJsonFile } from "./safe-json.mjs";

export const RELEASE_REHEARSAL_N8N_RESULT_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_N8N_IMAGE = Object.freeze({
  requestedTag: "docker.n8n.io/n8nio/n8n:2.21.5",
  repositoryDigest:
    "docker.n8n.io/n8nio/n8n@sha256:34df96d9a7e14c21c70dea69dc2d9c62f920ffe56238f03861ce5ea4ba56481e",
  localImageId:
    "sha256:34df96d9a7e14c21c70dea69dc2d9c62f920ffe56238f03861ce5ea4ba56481e",
  platform: "linux/amd64",
});
export const RELEASE_REHEARSAL_N8N_WORKFLOW_ID = "csint-n8n-trace-probe-v1";
export const RELEASE_REHEARSAL_N8N_CAPTURE_URL =
  "http://127.0.0.1:18080/v1/rehearsal/capture";
export const RELEASE_REHEARSAL_N8N_NODE_BINDINGS = Object.freeze([
  Object.freeze({
    id: "csint-manual-trigger",
    name: "CSINT Manual Trigger",
    type: "n8n-nodes-base.manualTrigger",
    typeVersion: 1,
    role: "trigger",
  }),
  Object.freeze({
    id: "csint-synthetic-input",
    name: "CSINT Synthetic Input",
    type: "n8n-nodes-base.set",
    typeVersion: 3.4,
    role: "synthetic-input",
  }),
  Object.freeze({
    id: "csint-capture-http",
    name: "CSINT Loopback Capture",
    type: "n8n-nodes-base.httpRequest",
    typeVersion: 4.2,
    role: "http",
  }),
  Object.freeze({
    id: "csint-downstream-proof",
    name: "CSINT Downstream Proof",
    type: "n8n-nodes-base.set",
    typeVersion: 3.4,
    role: "downstream",
  }),
]);
export const RELEASE_REHEARSAL_N8N_RAW_LIMITS = Object.freeze({
  maxBytes: 2 * 1024 * 1024,
  maxDepth: 40,
  maxValues: 50_000,
  maxNodes: 8,
  maxRuns: 32,
  maxBranches: 64,
  maxItems: 256,
});
export const RELEASE_REHEARSAL_N8N_CAPABILITY_CODES = Object.freeze([
  "CLI_IMPORT_AVAILABLE",
  "CLI_RAW_OUTPUT_AVAILABLE",
  "CLI_WORKFLOW_ID_EXECUTION_AVAILABLE",
  "MINIMAL_EXECUTION_TRACE_AVAILABLE",
]);
export const RELEASE_REHEARSAL_N8N_LIMITATION_CODES = Object.freeze([
  "ARBITRARY_WORKFLOW_SUPPORT_UNIMPLEMENTED",
  "CUSTOMER_WORKFLOW_EXECUTION_UNIMPLEMENTED",
  "EXECUTION_ORDER_UNAVAILABLE",
  "FULL_EXECUTION_ADAPTER_UNIMPLEMENTED",
  "ITEM_LINK_VISIBILITY_UNKNOWN",
  "RETRY_VISIBILITY_UNIMPLEMENTED",
  "LOOP_VISIBILITY_UNIMPLEMENTED",
  "WEBHOOK_EXECUTION_UNIMPLEMENTED",
]);

const REPOSITORY_ROOT = fileURLToPath(new URL("../", import.meta.url));
export const RELEASE_REHEARSAL_N8N_TEMPLATE_PATH = path.join(
  REPOSITORY_ROOT,
  "fixtures",
  "release-rehearsal",
  "n8n-cli-trace-probe.json",
);
const TEMPLATE_LIMITS = Object.freeze({
  maxBytes: 64 * 1024,
  maxDepth: 20,
  maxValues: 2_000,
});
const METADATA_PLACEHOLDERS = Object.freeze({
  [RELEASE_REHEARSAL_CAPTURE_HEADERS.runId]: "csint-placeholder-run",
  [RELEASE_REHEARSAL_CAPTURE_HEADERS.caseId]: "csint-placeholder-case",
  [RELEASE_REHEARSAL_CAPTURE_HEADERS.variant]: "baseline",
  [RELEASE_REHEARSAL_CAPTURE_HEADERS.fixtureId]: "csint-placeholder-fixture",
  [RELEASE_REHEARSAL_CAPTURE_HEADERS.correlationId]:
    "csint-placeholder-correlation",
  [RELEASE_REHEARSAL_CAPTURE_HEADERS.nodeId]: "csint-capture-http",
});
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const EXPRESSION_PATTERN = /\{\{|\}\}/u;
const OUTCOMES = new Set([
  "PASS_MINIMAL_TRACE",
  "EXECUTION_TRACE_UNAVAILABLE",
  "N8N_CLI_CAPABILITY_UNAVAILABLE",
  "N8N_IMAGE_IDENTITY_CHANGED",
  "FAILED",
]);

export class ReleaseRehearsalN8nError extends Error {
  constructor(code, outcome = "EXECUTION_TRACE_UNAVAILABLE") {
    super(code);
    this.code = code;
    this.outcome = OUTCOMES.has(outcome) ? outcome : "FAILED";
  }
}

function fail(code, outcome) {
  throw new ReleaseRehearsalN8nError(code, outcome);
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(stableCompare);
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function containsExpressionString(value) {
  if (typeof value === "string") return EXPRESSION_PATTERN.test(value);
  if (Array.isArray(value)) return value.some(containsExpressionString);
  if (value && typeof value === "object") {
    return Object.values(value).some(containsExpressionString);
  }
  return false;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a bounded synthetic identifier.`);
  }
  return value;
}

function assertSha256(value, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 value.`);
  }
  return value;
}

function assertExactNodeBindings(bindings) {
  if (!Array.isArray(bindings) || bindings.length !== RELEASE_REHEARSAL_N8N_NODE_BINDINGS.length) {
    fail("NODE_BINDING_SET_INVALID");
  }
  const names = new Set();
  const ids = new Set();
  for (const binding of bindings) {
    if (
      !isPlainObject(binding) ||
      typeof binding.name !== "string" ||
      typeof binding.id !== "string" ||
      names.has(binding.name) ||
      ids.has(binding.id)
    ) {
      fail("DUPLICATE_NODE_BINDING");
    }
    names.add(binding.name);
    ids.add(binding.id);
  }
  return new Map(bindings.map((binding) => [binding.name, binding]));
}

function inspectBoundedJson(value, limits) {
  const stack = [{ value, depth: 0 }];
  let values = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    values += 1;
    if (values > limits.maxValues) fail("RAW_OUTPUT_VALUE_LIMIT_EXCEEDED");
    if (current.depth > limits.maxDepth) fail("RAW_OUTPUT_DEPTH_LIMIT_EXCEEDED");
    if (!current.value || typeof current.value !== "object") continue;
    for (const child of Object.values(current.value)) {
      stack.push({ value: child, depth: current.depth + 1 });
    }
  }
}

function assertNoDuplicateJsonKeys(text) {
  let index = 0;

  function scanError() {
    const error = new Error("invalid JSON scan");
    error.scanInvalid = true;
    throw error;
  }

  function skipWhitespace() {
    while (index < text.length && /[\u0009\u000A\u000D\u0020]/u.test(text[index])) {
      index += 1;
    }
  }

  function parseString() {
    if (text[index] !== '"') scanError();
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === '"') {
        index += 1;
        try {
          return JSON.parse(text.slice(start, index));
        } catch {
          scanError();
        }
      }
      if (character === "\\") {
        index += 1;
        if (index >= text.length) scanError();
        if (text[index] === "u") {
          const escape = text.slice(index + 1, index + 5);
          if (!/^[a-f0-9]{4}$/iu.test(escape)) scanError();
          index += 5;
        } else {
          if (!/["\\/bfnrt]/u.test(text[index])) scanError();
          index += 1;
        }
        continue;
      }
      if (character.codePointAt(0) <= 0x1f) scanError();
      index += 1;
    }
    scanError();
  }

  function parseObject() {
    index += 1;
    skipWhitespace();
    const keys = new Set();
    if (text[index] === "}") {
      index += 1;
      return;
    }
    while (index < text.length) {
      const key = parseString();
      if (keys.has(key)) fail("RAW_OUTPUT_DUPLICATE_KEY");
      keys.add(key);
      skipWhitespace();
      if (text[index] !== ":") scanError();
      index += 1;
      parseValue();
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      if (text[index] !== ",") scanError();
      index += 1;
      skipWhitespace();
    }
    scanError();
  }

  function parseArray() {
    index += 1;
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return;
    }
    while (index < text.length) {
      parseValue();
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      if (text[index] !== ",") scanError();
      index += 1;
      skipWhitespace();
    }
    scanError();
  }

  function parseValue() {
    skipWhitespace();
    const character = text[index];
    if (character === "{") return parseObject();
    if (character === "[") return parseArray();
    if (character === '"') {
      parseString();
      return;
    }
    for (const literal of ["true", "false", "null"]) {
      if (text.startsWith(literal, index)) {
        index += literal.length;
        return;
      }
    }
    const number = text.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u)?.[0];
    if (!number) scanError();
    index += number.length;
  }

  try {
    parseValue();
    skipWhitespace();
    if (index !== text.length) scanError();
  } catch (error) {
    if (error instanceof ReleaseRehearsalN8nError) throw error;
    if (!error?.scanInvalid) throw error;
  }
}

function decodeStrictJson(raw, limits) {
  let bytes;
  if (typeof raw === "string") {
    bytes = Buffer.from(raw, "utf8");
  } else if (raw instanceof Uint8Array) {
    bytes = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  } else {
    throw new TypeError("Raw n8n output must be a string or byte buffer.");
  }
  if (bytes.length > limits.maxBytes) fail("RAW_OUTPUT_BYTE_LIMIT_EXCEEDED");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("RAW_OUTPUT_UTF8_INVALID");
  }
  assertNoDuplicateJsonKeys(text);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail("RAW_OUTPUT_JSON_INVALID");
  }
  inspectBoundedJson(parsed, limits);
  return parsed;
}

function normalizeTerminalStatus(raw) {
  const value = typeof raw.status === "string" ? raw.status.toLowerCase() : null;
  const statuses = new Map([
    ["success", "SUCCESS"],
    ["error", "ERROR"],
    ["canceled", "CANCELED"],
    ["cancelled", "CANCELED"],
    ["crashed", "CRASHED"],
    ["running", "RUNNING"],
    ["waiting", "WAITING"],
    ["new", "NEW"],
  ]);
  return statuses.get(value) ?? "UNKNOWN";
}

function normalizePairedItemPresence(items) {
  if (items.length === 0) return "NOT_APPLICABLE";
  let present = 0;
  for (const item of items) {
    if (!isPlainObject(item)) fail("RAW_OUTPUT_ITEM_INVALID");
    if (Object.hasOwn(item, "pairedItem")) present += 1;
  }
  if (present === 0) return "ABSENT";
  if (present === items.length) return "PRESENT";
  return "PARTIAL";
}

function normalizeRunOutputs(run, state) {
  if (!isPlainObject(run.data)) fail("RAW_OUTPUT_RUN_DATA_INVALID");
  const outputTypes = Object.keys(run.data);
  if (outputTypes.length !== 1 || outputTypes[0] !== "main") {
    fail("RAW_OUTPUT_CHANNEL_SET_UNEXPECTED");
  }
  if (!Array.isArray(run.data.main)) fail("RAW_OUTPUT_BRANCH_SET_INVALID");
  const branches = run.data.main.map((branch, branchIndex) => {
    state.branches += 1;
    if (state.branches > state.limits.maxBranches) {
      fail("RAW_OUTPUT_BRANCH_LIMIT_EXCEEDED");
    }
    const items = branch === null ? [] : branch;
    if (!Array.isArray(items)) fail("RAW_OUTPUT_BRANCH_INVALID");
    state.items += items.length;
    if (state.items > state.limits.maxItems) fail("RAW_OUTPUT_ITEM_LIMIT_EXCEEDED");
    return {
      branchIndex,
      itemCount: items.length,
      pairedItemMetadata: normalizePairedItemPresence(items),
    };
  });
  return branches;
}

export function parseReleaseRehearsalN8nRawOutput(raw, options = {}) {
  const limits = Object.freeze({
    ...RELEASE_REHEARSAL_N8N_RAW_LIMITS,
    ...(options.limits ?? {}),
  });
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isInteger(value) || value < 1) {
      throw new TypeError(`${name} must be a positive integer.`);
    }
  }
  const bindings = options.nodeBindings ?? RELEASE_REHEARSAL_N8N_NODE_BINDINGS;
  const bindingByName = assertExactNodeBindings(bindings);
  const parsed = decodeStrictJson(raw, limits);
  if (!isPlainObject(parsed)) fail("RAW_OUTPUT_ROOT_INVALID");
  const runData = parsed.data?.resultData?.runData;
  if (!isPlainObject(runData)) fail("RAW_OUTPUT_RUN_DATA_MISSING");

  const names = Object.keys(runData);
  if (names.length > limits.maxNodes) fail("RAW_OUTPUT_NODE_LIMIT_EXCEEDED");
  const errorCodes = [];
  const state = { branches: 0, items: 0, runs: 0, limits };
  const nodeExecutions = [];
  const actualNodeIds = [];
  for (const name of names) {
    const binding = bindingByName.get(name);
    const runs = runData[name];
    if (!Array.isArray(runs) || runs.length < 1) fail("RAW_OUTPUT_NODE_RUNS_INVALID");
    state.runs += runs.length;
    if (state.runs > limits.maxRuns) fail("RAW_OUTPUT_RUN_LIMIT_EXCEEDED");
    const normalizedRuns = runs.map((run, runIndex) => {
      if (!isPlainObject(run)) fail("RAW_OUTPUT_RUN_INVALID");
      const executionIndex = Object.hasOwn(run, "executionIndex")
        ? run.executionIndex
        : null;
      if (executionIndex !== null && (!Number.isInteger(executionIndex) || executionIndex < 0)) {
        fail("RAW_OUTPUT_EXECUTION_INDEX_INVALID");
      }
      return {
        runIndex,
        executionIndex,
        outputBranches: normalizeRunOutputs(run, state),
        errorPresent: Object.hasOwn(run, "error"),
      };
    });
    if (!binding) {
      errorCodes.push("UNEXPECTED_EXECUTED_NODE");
      continue;
    }
    actualNodeIds.push(binding.id);
    nodeExecutions.push({
      nodeId: binding.id,
      runCount: normalizedRuns.length,
      runs: normalizedRuns,
    });
  }

  const expectedNodeIds = bindings.map((binding) => binding.id).sort(stableCompare);
  const actualIds = uniqueSorted(actualNodeIds);
  const missingNodeIds = expectedNodeIds.filter((id) => !actualIds.includes(id));
  if (missingNodeIds.length > 0) errorCodes.push("EXPECTED_NODE_MISSING");
  const httpId = bindings.find((binding) => binding.role === "http")?.id;
  const downstreamId = bindings.find((binding) => binding.role === "downstream")?.id;
  const httpNodeExecuted = actualIds.includes(httpId);
  const downstreamNodeExecuted = actualIds.includes(downstreamId);
  if (!httpNodeExecuted) errorCodes.push("HTTP_NODE_EXECUTION_MISSING");
  if (!downstreamNodeExecuted) errorCodes.push("DOWNSTREAM_NODE_EXECUTION_MISSING");

  nodeExecutions.sort((left, right) => stableCompare(left.nodeId, right.nodeId));
  const allRuns = nodeExecutions.flatMap((node) =>
    node.runs.map((run) => ({ nodeId: node.nodeId, ...run })),
  );
  const explicitOrderAvailable =
    allRuns.length > 0 &&
    allRuns.every((run) => run.executionIndex !== null) &&
    new Set(allRuns.map((run) => run.executionIndex)).size === allRuns.length;
  const executionOrder = explicitOrderAvailable
    ? allRuns
        .map((run) => ({
          executionIndex: run.executionIndex,
          nodeId: run.nodeId,
          runIndex: run.runIndex,
        }))
        .sort((left, right) => left.executionIndex - right.executionIndex)
    : null;
  const pairedStates = allRuns.flatMap((run) =>
    run.outputBranches.map((branch) => branch.pairedItemMetadata),
  );
  const pairedItemMetadataPresent =
    pairedStates.length > 0 &&
    pairedStates
      .filter((value) => value !== "NOT_APPLICABLE")
      .every((value) => value === "PRESENT");
  const limitationCodes = [];
  if (!explicitOrderAvailable) limitationCodes.push("EXECUTION_ORDER_UNAVAILABLE");
  if (!pairedItemMetadataPresent) limitationCodes.push("ITEM_LINK_VISIBILITY_UNKNOWN");
  const terminalStatus = normalizeTerminalStatus(parsed);
  const executionMode = typeof parsed.mode === "string" && parsed.mode.length <= 64
    ? parsed.mode
    : null;
  if (terminalStatus !== "SUCCESS") errorCodes.push("TERMINAL_STATUS_NOT_SUCCESS");
  if (executionMode !== "cli") errorCodes.push("EXECUTION_MODE_UNEXPECTED");
  const traceAvailable =
    errorCodes.length === 0 &&
    actualIds.length === expectedNodeIds.length &&
    canonicalJson(actualIds) === canonicalJson(expectedNodeIds);

  return Object.freeze({
    schemaVersion: RELEASE_REHEARSAL_N8N_RESULT_SCHEMA_VERSION,
    traceStatus: traceAvailable ? "TRACE_AVAILABLE" : "EXECUTION_TRACE_UNAVAILABLE",
    terminalStatus,
    executionMode,
    expectedNodeIds,
    actualNodeIds: actualIds,
    missingNodeIds,
    nodeExecutions,
    executionOrder,
    httpNodeExecuted,
    downstreamNodeExecuted,
    pairedItemMetadataPresent,
    errorCodes: uniqueSorted(errorCodes),
    limitationCodes: uniqueSorted(limitationCodes),
  });
}

function assertTemplate(template) {
  if (
    !isPlainObject(template) ||
    template.id !== RELEASE_REHEARSAL_N8N_WORKFLOW_ID ||
    template.active !== false ||
    !Array.isArray(template.nodes) ||
    template.nodes.length !== RELEASE_REHEARSAL_N8N_NODE_BINDINGS.length
  ) {
    fail("SYNTHETIC_WORKFLOW_TEMPLATE_INVALID", "FAILED");
  }
  const expectedById = new Map(RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map((node) => [node.id, node]));
  for (const node of template.nodes) {
    const expected = expectedById.get(node?.id);
    if (
      !expected ||
      node.name !== expected.name ||
      node.type !== expected.type ||
      node.typeVersion !== expected.typeVersion ||
      node.disabled === true ||
      node.credentials !== undefined
    ) {
      fail("SYNTHETIC_WORKFLOW_NODE_SET_INVALID", "FAILED");
    }
  }
  const httpNode = template.nodes.find((node) => node.id === "csint-capture-http");
  const parameters = httpNode.parameters;
  if (
    !isPlainObject(parameters) ||
    parameters.method !== "POST" ||
    parameters.url !== RELEASE_REHEARSAL_N8N_CAPTURE_URL ||
    EXPRESSION_PATTERN.test(parameters.method) ||
    EXPRESSION_PATTERN.test(parameters.url) ||
    parameters.authentication !== "none" ||
    parameters.sendBody !== true ||
    parameters.contentType !== "json" ||
    parameters.specifyBody !== "json" ||
    parameters.options?.redirect?.followRedirects !== false
  ) {
    fail("SYNTHETIC_HTTP_NODE_INVALID", "FAILED");
  }
  const headers = parameters.headerParameters?.parameters;
  if (!Array.isArray(headers) || headers.length !== Object.keys(METADATA_PLACEHOLDERS).length) {
    fail("SYNTHETIC_HTTP_METADATA_INVALID", "FAILED");
  }
  const headerMap = new Map();
  for (const header of headers) {
    if (
      !isPlainObject(header) ||
      typeof header.name !== "string" ||
      headerMap.has(header.name)
    ) {
      fail("SYNTHETIC_HTTP_METADATA_INVALID", "FAILED");
    }
    headerMap.set(header.name, header.value);
  }
  for (const [name, value] of Object.entries(METADATA_PLACEHOLDERS)) {
    if (headerMap.get(name) !== value) fail("SYNTHETIC_HTTP_METADATA_INVALID", "FAILED");
  }
  let body;
  try {
    body = JSON.parse(parameters.jsonBody);
  } catch {
    fail("SYNTHETIC_HTTP_BODY_INVALID", "FAILED");
  }
  validateReleaseRehearsalSanitizedJson(body);
  if (
    body.fixture !== METADATA_PLACEHOLDERS[RELEASE_REHEARSAL_CAPTURE_HEADERS.fixtureId] ||
    body.subject !== "probe@rehearsal.invalid" ||
    body.kind !== "synthetic-trace-probe" ||
    containsExpressionString(template)
  ) {
    fail("SYNTHETIC_HTTP_BODY_INVALID", "FAILED");
  }
  return { httpNode, headers };
}

export async function loadReleaseRehearsalN8nWorkflowTemplate(
  filePath = RELEASE_REHEARSAL_N8N_TEMPLATE_PATH,
) {
  const template = await readBoundedJsonFile(filePath, {
    ...TEMPLATE_LIMITS,
    label: "n8n CLI trace probe template",
  });
  assertTemplate(template);
  return template;
}

export function buildReleaseRehearsalN8nWorkflow(template, metadata) {
  assertTemplate(template);
  const normalized = {
    runId: assertIdentifier(metadata?.runId, "runId"),
    caseId: assertIdentifier(metadata?.caseId, "caseId"),
    variant: metadata?.variant,
    fixtureId: assertIdentifier(metadata?.fixtureId, "fixtureId"),
    correlationId: assertIdentifier(metadata?.correlationId, "correlationId"),
  };
  if (!new Set(["baseline", "candidate"]).has(normalized.variant)) {
    throw new TypeError("variant must be baseline or candidate.");
  }
  const workflow = structuredClone(template);
  const httpNode = workflow.nodes.find((node) => node.id === "csint-capture-http");
  const values = {
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.runId]: normalized.runId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.caseId]: normalized.caseId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.variant]: normalized.variant,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.fixtureId]: normalized.fixtureId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.correlationId]: normalized.correlationId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.nodeId]: "csint-capture-http",
  };
  for (const header of httpNode.parameters.headerParameters.parameters) {
    header.value = values[header.name];
  }
  const body = validateReleaseRehearsalSanitizedJson({
    fixture: normalized.fixtureId,
    kind: "synthetic-trace-probe",
    subject: "probe@rehearsal.invalid",
  });
  httpNode.parameters.jsonBody = canonicalJson(body);
  return Object.freeze({
    workflow,
    workflowId: RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
    workflowCanonicalSha256: fingerprintJson(workflow),
    metadata: Object.freeze(normalized),
    expectedNodeIds: RELEASE_REHEARSAL_N8N_NODE_BINDINGS
      .map((node) => node.id)
      .sort(stableCompare),
  });
}

export function createReleaseRehearsalN8nCaptureConfig({
  metadata,
  workflowCanonicalSha256,
}) {
  const runId = assertIdentifier(metadata?.runId, "runId");
  const caseId = assertIdentifier(metadata?.caseId, "caseId");
  const fixtureId = assertIdentifier(metadata?.fixtureId, "fixtureId");
  const correlationId = assertIdentifier(metadata?.correlationId, "correlationId");
  if (!new Set(["baseline", "candidate"]).has(metadata?.variant)) {
    throw new TypeError("variant must be baseline or candidate.");
  }
  return validateReleaseRehearsalCaptureConfig({
    schemaVersion: 1,
    kind: "csint-release-rehearsal-capture-config",
    runId,
    caseId,
    variant: metadata.variant,
    fixtureId,
    fixtureCanonicalSha256: fingerprintJson({
      fixtureId,
      correlationId,
      kind: "synthetic-n8n-cli-trace-probe",
    }),
    correlationId,
    workflowCanonicalSha256: assertSha256(
      workflowCanonicalSha256,
      "workflowCanonicalSha256",
    ),
    allowedNodeIds: ["csint-capture-http"],
    nodes: [
      {
        nodeId: "csint-capture-http",
        method: "POST",
        destination: normalizeHttpDestination(RELEASE_REHEARSAL_N8N_CAPTURE_URL),
        minimumOccurrences: 1,
        maximumOccurrences: 1,
        responseStubs: [
          {
            status: 200,
            headers: { "content-type": "application/json; charset=utf-8" },
            json: { result: "accepted" },
          },
        ],
      },
    ],
  });
}

export function correlateReleaseRehearsalN8nCapture({
  events,
  summary,
  dnsSummary,
  expected,
}) {
  const errorCodes = [];
  const event = Array.isArray(events) && events.length === 1 ? events[0] : null;
  if (!Array.isArray(events) || events.length !== 1) {
    errorCodes.push("CAPTURE_EVENT_COUNT_MISMATCH");
  }
  const expectedEvent = {
    runId: expected.runId,
    caseId: expected.caseId,
    variant: expected.variant,
    fixtureId: expected.fixtureId,
    correlationId: expected.correlationId,
    workflowCanonicalSha256: expected.workflowCanonicalSha256,
    nodeId: "csint-capture-http",
    method: "POST",
  };
  if (
    !isPlainObject(event) ||
    Object.entries(expectedEvent).some(([key, value]) => event[key] !== value) ||
    event.forwarded !== false
  ) {
    errorCodes.push("CAPTURE_CORRELATION_MISMATCH");
  }
  if (
    !isPlainObject(summary) ||
    summary.status !== "COMPLETE" ||
    summary.eventCount !== 1 ||
    summary.forwarded !== false ||
    !Array.isArray(summary.violationCodes) ||
    summary.violationCodes.length !== 0 ||
    Object.entries(expectedEvent)
      .filter(([key]) => key !== "nodeId" && key !== "method")
      .some(([key, value]) => summary[key] !== value)
  ) {
    errorCodes.push("CAPTURE_SUMMARY_INVALID");
  }
  if (
    !isPlainObject(dnsSummary) ||
    dnsSummary.status !== "COMPLETE" ||
    dnsSummary.queryCount !== 0 ||
    dnsSummary.forwarded !== false ||
    !Array.isArray(dnsSummary.violationCodes) ||
    dnsSummary.violationCodes.length !== 0
  ) {
    errorCodes.push("DNS_CONTAINMENT_VIOLATION");
  }
  return Object.freeze({
    status: errorCodes.length === 0 ? "CORRELATED" : "MISMATCH",
    eventCount: Array.isArray(events) ? events.length : null,
    nodeId: event?.nodeId === "csint-capture-http" ? event.nodeId : null,
    method: event?.method === "POST" ? event.method : null,
    forwarded: event?.forwarded === false ? false : null,
    captureStatus: summary?.status ?? null,
    dnsStatus: dnsSummary?.status ?? null,
    dnsQueryCount: Number.isInteger(dnsSummary?.queryCount)
      ? dnsSummary.queryCount
      : null,
    errorCodes: uniqueSorted(errorCodes),
  });
}

function assertLogicalResultRedacted(value) {
  const serialized = canonicalJson(value);
  if (
    /\.invalid\b|authorization|cookie|password|Bearer\s|api[_-]?key|N8N_ENCRYPTION_KEY|jsonBody|rawStdout|rawStderr/iu.test(
      serialized,
    )
  ) {
    fail("N8N_RESULT_REDACTION_VIOLATION", "FAILED");
  }
}

export function serializeReleaseRehearsalN8nLogicalResult(result) {
  if (!isPlainObject(result)) throw new TypeError("n8n result must be an object.");
  const { operational: _operational, ...logical } = result;
  assertLogicalResultRedacted(logical);
  return canonicalJson(logical) + "\n";
}
