import { Buffer } from "node:buffer";

import { canonicalJson, fingerprintJson } from "./evidence-fingerprint.mjs";
import {
  normalizeSupportedHttpMethod,
  RELEASE_REHEARSAL_SUPPORTED_METHODS,
} from "./release-rehearsal-normalize.mjs";
import { validateNormalizedHttpDestination } from "./release-rehearsal-schema.mjs";
import { readBoundedJsonFile } from "./safe-json.mjs";

export const RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_MAX_FIXTURES = 3;
export const RELEASE_REHEARSAL_MAX_FIXTURE_NODES = 20;
export const RELEASE_REHEARSAL_MAX_RESPONSE_STUBS = 20;
export const RELEASE_REHEARSAL_MAX_CAPTURE_BODY_BYTES = 64 * 1024;

const FIXTURE_FILE_LIMITS = Object.freeze({
  maxBytes: 256 * 1024,
  maxDepth: 20,
  maxValues: 10_000,
});
const SANITIZED_JSON_LIMITS = Object.freeze({
  maxDepth: 12,
  maxValues: 2_000,
  maxArrayLength: 100,
  maxObjectKeys: 100,
  maxStringLength: 2_048,
  maxBodyBytes: RELEASE_REHEARSAL_MAX_CAPTURE_BODY_BYTES,
});
const MAX_HEADERS = 32;
const MAX_HEADER_NAME_LENGTH = 128;
const MAX_HEADER_VALUE_LENGTH = 512;
const MAX_IDENTIFIER_LENGTH = 128;
const MAX_NODE_ID_LENGTH = 512;
const FIXTURE_SET_KEYS = new Set(["schemaVersion", "fixtures"]);
const FIXTURE_KEYS = new Set([
  "schemaVersion",
  "id",
  "correlationId",
  "webhook",
  "nodes",
]);
const VALIDATED_FIXTURE_KEYS = new Set([...FIXTURE_KEYS, "canonicalSha256"]);
const WEBHOOK_KEYS = new Set(["method", "path", "headers", "json"]);
const FIXTURE_NODE_KEYS = new Set([
  "nodeId",
  "minimumOccurrences",
  "maximumOccurrences",
  "responses",
]);
const RESPONSE_KEYS = new Set(["status", "headers", "json"]);
const CONFIG_INPUT_KEYS = new Set([
  "schemaVersion",
  "runId",
  "caseId",
  "variant",
  "fixture",
  "workflowCanonicalSha256",
  "plannedNodes",
]);
const PLANNED_NODE_KEYS = new Set(["nodeId", "method", "destination"]);
const CAPTURE_CONFIG_KEYS = new Set([
  "schemaVersion",
  "kind",
  "runId",
  "caseId",
  "variant",
  "fixtureId",
  "fixtureCanonicalSha256",
  "correlationId",
  "workflowCanonicalSha256",
  "allowedNodeIds",
  "nodes",
]);
const CAPTURE_NODE_KEYS = new Set([
  "nodeId",
  "method",
  "destination",
  "minimumOccurrences",
  "maximumOccurrences",
  "responseStubs",
]);
const VARIANTS = new Set(["baseline", "candidate"]);
const SUPPORTED_METHODS = new Set(RELEASE_REHEARSAL_SUPPORTED_METHODS);
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;
const HEADER_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const UNSAFE_TEXT =
  /[\u0000-\u001F\u007F-\u009F\u200B\u200E\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/u;
const URL_PREFIX = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//u;
const LIVE_IDENTIFIER_LITERAL = /^(?:live|prod|production)[_-][A-Za-z0-9]/iu;
const SECRET_LITERAL =
  /-----BEGIN [^-\r\n]{0,64}PRIVATE KEY-----|\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]{8,}|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|\b(?:ghp|github_pat|sk|xox[baprs])[_-][A-Za-z0-9_-]{8,}/iu;
const FORBIDDEN_HEADER_NAMES = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  "set-cookie",
]);
const FORBIDDEN_RESPONSE_HEADER_NAMES = new Set([
  "connection",
  "content-encoding",
  "content-length",
  "date",
  "link",
  "location",
  "proxy-authenticate",
  "refresh",
  "server",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function fail(code, message) {
  const error = new TypeError(message);
  error.code = code;
  throw error;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertKnownKeys(value, known, label) {
  if (!isPlainObject(value)) fail("INPUT_INVALID", label + " must be an object.");
  if (Object.keys(value).some((key) => !known.has(key))) {
    fail("INPUT_INVALID", label + " contains unknown fields.");
  }
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertIdentifier(value, label, maxLength = MAX_IDENTIFIER_LENGTH) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength ||
    !IDENTIFIER_PATTERN.test(value) ||
    UNSAFE_TEXT.test(value)
  ) {
    fail("INPUT_INVALID", label + " is not a valid bounded identifier.");
  }
  return value;
}

function assertSha256(value, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail("INPUT_INVALID", label + " must be a lowercase SHA-256 value.");
  }
  return value;
}

function normalizedFieldName(value) {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

function isForbiddenJsonField(name) {
  const normalized = normalizedFieldName(name);
  return (
    normalized === "auth" ||
    normalized.includes("authorization") ||
    normalized.includes("credential") ||
    normalized.includes("cookie") ||
    normalized.includes("password") ||
    normalized.includes("privatekey") ||
    normalized.includes("secret") ||
    normalized.includes("token") ||
    normalized.includes("apikey") ||
    normalized.includes("production") ||
    /^live(?:id|identifier|account|customer|tenant)/u.test(normalized)
  );
}

function assertSanitizedString(value) {
  if (
    value.length > SANITIZED_JSON_LIMITS.maxStringLength ||
    UNSAFE_TEXT.test(value)
  ) {
    fail("INPUT_LIMIT_EXCEEDED", "Sanitized JSON contains invalid or oversized text.");
  }
  if (SECRET_LITERAL.test(value)) {
    fail("SECRET_LIKE_LITERAL", "Sanitized JSON contains a secret-like literal.");
  }
  if (LIVE_IDENTIFIER_LITERAL.test(value)) {
    fail("INPUT_INVALID", "Sanitized JSON contains a live-style identifier.");
  }
  if (!URL_PREFIX.test(value)) return;

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail("INPUT_INVALID", "Sanitized JSON contains an invalid URL literal.");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    !(parsed.hostname === "invalid" || parsed.hostname.endsWith(".invalid"))
  ) {
    fail("INPUT_INVALID", "Sanitized JSON contains an unsupported external URL.");
  }
}

function normalizeSanitizedJson(value, state, depth) {
  state.values += 1;
  if (state.values > SANITIZED_JSON_LIMITS.maxValues) {
    fail("INPUT_LIMIT_EXCEEDED", "Sanitized JSON exceeds the value limit.");
  }
  if (depth > SANITIZED_JSON_LIMITS.maxDepth) {
    fail("INPUT_LIMIT_EXCEEDED", "Sanitized JSON exceeds the nesting limit.");
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    assertSanitizedString(value);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("INPUT_INVALID", "Sanitized JSON contains a non-finite number.");
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > SANITIZED_JSON_LIMITS.maxArrayLength) {
      fail("INPUT_LIMIT_EXCEEDED", "Sanitized JSON exceeds the array limit.");
    }
    return value.map((child) => normalizeSanitizedJson(child, state, depth + 1));
  }
  if (!isPlainObject(value)) {
    fail("INPUT_INVALID", "Sanitized JSON contains an unsupported value type.");
  }

  const keys = Object.keys(value);
  if (keys.length > SANITIZED_JSON_LIMITS.maxObjectKeys) {
    fail("INPUT_LIMIT_EXCEEDED", "Sanitized JSON exceeds the object-key limit.");
  }
  const normalized = {};
  for (const key of keys) {
    if (
      !key ||
      key.length > MAX_HEADER_VALUE_LENGTH ||
      UNSAFE_TEXT.test(key)
    ) {
      fail("INPUT_INVALID", "Sanitized JSON contains an invalid field name.");
    }
    if (isForbiddenJsonField(key)) {
      fail("SECRET_LIKE_LITERAL", "Sanitized JSON contains a forbidden field name.");
    }
    normalized[key] = normalizeSanitizedJson(value[key], state, depth + 1);
  }
  return normalized;
}

export function validateReleaseRehearsalSanitizedJson(value) {
  const normalized = normalizeSanitizedJson(value, { values: 0 }, 0);
  if (
    Buffer.byteLength(canonicalJson(normalized), "utf8") >
    SANITIZED_JSON_LIMITS.maxBodyBytes
  ) {
    fail("INPUT_LIMIT_EXCEEDED", "Sanitized JSON exceeds the body size limit.");
  }
  return deepFreeze(normalized);
}

function normalizeHeaders(value, { response }) {
  if (!isPlainObject(value)) {
    fail("INPUT_INVALID", "Sanitized headers must be an object.");
  }
  const entries = Object.entries(value);
  if (entries.length > MAX_HEADERS) {
    fail("INPUT_LIMIT_EXCEEDED", "Sanitized headers exceed the header-count limit.");
  }
  const normalized = new Map();
  for (const [rawName, rawValue] of entries) {
    if (
      rawName.length < 1 ||
      rawName.length > MAX_HEADER_NAME_LENGTH ||
      !HEADER_NAME_PATTERN.test(rawName)
    ) {
      fail("INPUT_INVALID", "Sanitized headers contain an invalid name.");
    }
    const name = rawName.toLowerCase();
    if (
      normalized.has(name) ||
      FORBIDDEN_HEADER_NAMES.has(name) ||
      isForbiddenJsonField(name) ||
      (response && FORBIDDEN_RESPONSE_HEADER_NAMES.has(name))
    ) {
      fail("SECRET_LIKE_LITERAL", "Sanitized headers contain a forbidden name.");
    }
    if (
      typeof rawValue !== "string" ||
      rawValue.length > MAX_HEADER_VALUE_LENGTH ||
      UNSAFE_TEXT.test(rawValue)
    ) {
      fail("INPUT_INVALID", "Sanitized headers contain an invalid value.");
    }
    assertSanitizedString(rawValue);
    if (
      name === "content-type" &&
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(rawValue)
    ) {
      fail("INPUT_INVALID", "Sanitized JSON uses an unsupported content type.");
    }
    normalized.set(name, rawValue);
  }
  return Object.fromEntries([...normalized.entries()].sort(([left], [right]) =>
    stableCompare(left, right),
  ));
}

function normalizeWebhook(value) {
  assertKnownKeys(value, WEBHOOK_KEYS, "Fixture webhook");
  const method = normalizeSupportedHttpMethod(value.method);
  if (
    typeof value.path !== "string" ||
    value.path.length < 1 ||
    value.path.length > 1_024 ||
    !value.path.startsWith("/") ||
    /[?#\\]/u.test(value.path) ||
    UNSAFE_TEXT.test(value.path)
  ) {
    fail("INPUT_INVALID", "Fixture webhook path is invalid.");
  }
  return {
    method,
    path: value.path,
    headers: normalizeHeaders(value.headers, { response: false }),
    json: validateReleaseRehearsalSanitizedJson(value.json),
  };
}

function normalizeResponseStub(value) {
  assertKnownKeys(value, RESPONSE_KEYS, "Fixture response stub");
  if (
    !Number.isInteger(value.status) ||
    value.status < 200 ||
    value.status > 599 ||
    (value.status >= 300 && value.status <= 399)
  ) {
    fail("INPUT_INVALID", "Fixture response status is unsupported.");
  }
  return {
    status: value.status,
    headers: normalizeHeaders(value.headers, { response: true }),
    json: validateReleaseRehearsalSanitizedJson(value.json),
  };
}

function normalizeFixtureNode(value) {
  assertKnownKeys(value, FIXTURE_NODE_KEYS, "Fixture node");
  const nodeId = assertIdentifier(value.nodeId, "Fixture node ID", MAX_NODE_ID_LENGTH);
  if (
    !Number.isInteger(value.minimumOccurrences) ||
    value.minimumOccurrences < 0 ||
    value.minimumOccurrences > RELEASE_REHEARSAL_MAX_RESPONSE_STUBS
  ) {
    fail("INPUT_INVALID", "Fixture minimum occurrences are invalid.");
  }
  if (
    !Number.isInteger(value.maximumOccurrences) ||
    value.maximumOccurrences < 1 ||
    value.maximumOccurrences > RELEASE_REHEARSAL_MAX_RESPONSE_STUBS ||
    value.maximumOccurrences < value.minimumOccurrences
  ) {
    fail("INPUT_INVALID", "Fixture maximum occurrences are invalid.");
  }
  if (
    !Array.isArray(value.responses) ||
    value.responses.length < 1 ||
    value.responses.length > RELEASE_REHEARSAL_MAX_RESPONSE_STUBS ||
    value.responses.length < value.minimumOccurrences ||
    value.responses.length > value.maximumOccurrences
  ) {
    fail("INPUT_INVALID", "Fixture response sequence is invalid.");
  }
  return {
    nodeId,
    minimumOccurrences: value.minimumOccurrences,
    maximumOccurrences: value.maximumOccurrences,
    responses: value.responses.map(normalizeResponseStub),
  };
}

function normalizeFixtureMaterial(value, { validated }) {
  assertKnownKeys(
    value,
    validated ? VALIDATED_FIXTURE_KEYS : FIXTURE_KEYS,
    "Release rehearsal fixture",
  );
  if (value.schemaVersion !== RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION) {
    fail("INPUT_INVALID", "Fixture schema version is unsupported.");
  }
  const id = assertIdentifier(value.id, "Fixture ID");
  const correlationId = assertIdentifier(value.correlationId, "Fixture correlation ID");
  if (
    !Array.isArray(value.nodes) ||
    value.nodes.length < 1 ||
    value.nodes.length > RELEASE_REHEARSAL_MAX_FIXTURE_NODES
  ) {
    fail("INPUT_LIMIT_EXCEEDED", "Fixture node count is outside the supported bounds.");
  }
  const nodes = value.nodes.map(normalizeFixtureNode);
  if (new Set(nodes.map((node) => node.nodeId)).size !== nodes.length) {
    fail("INPUT_INVALID", "Fixture contains duplicate node IDs.");
  }
  const material = {
    schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
    id,
    correlationId,
    webhook: normalizeWebhook(value.webhook),
    nodes,
  };
  if (validated) {
    assertSha256(value.canonicalSha256, "Fixture canonical fingerprint");
    if (fingerprintJson(material) !== value.canonicalSha256) {
      fail("INPUT_INVALID", "Fixture canonical fingerprint does not match its content.");
    }
  }
  return material;
}

export function validateReleaseRehearsalFixtureSet(value) {
  assertKnownKeys(value, FIXTURE_SET_KEYS, "Release rehearsal fixture set");
  if (value.schemaVersion !== RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION) {
    fail("INPUT_INVALID", "Fixture-set schema version is unsupported.");
  }
  if (
    !Array.isArray(value.fixtures) ||
    value.fixtures.length < 1 ||
    value.fixtures.length > RELEASE_REHEARSAL_MAX_FIXTURES
  ) {
    fail("INPUT_LIMIT_EXCEEDED", "Fixture set must contain between one and three fixtures.");
  }
  const fixtures = value.fixtures.map((fixture) => {
    const material = normalizeFixtureMaterial(fixture, { validated: false });
    return { ...material, canonicalSha256: fingerprintJson(material) };
  });
  if (
    Buffer.byteLength(
      canonicalJson({
        schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
        fixtures: fixtures.map(({ canonicalSha256: _fingerprint, ...fixture }) => fixture),
      }),
      "utf8",
    ) > FIXTURE_FILE_LIMITS.maxBytes
  ) {
    fail("INPUT_LIMIT_EXCEEDED", "Fixture set exceeds the total size limit.");
  }
  if (new Set(fixtures.map((fixture) => fixture.id)).size !== fixtures.length) {
    fail("INPUT_INVALID", "Fixture set contains duplicate fixture IDs.");
  }
  if (
    new Set(fixtures.map((fixture) => fixture.correlationId)).size !== fixtures.length
  ) {
    fail("INPUT_INVALID", "Fixture set contains duplicate correlation IDs.");
  }
  return deepFreeze({
    schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
    fixtures,
  });
}

export async function loadReleaseRehearsalFixtureSet(filePath, options = {}) {
  const allowedKeys = new Set(["label"]);
  if (
    !isPlainObject(options) ||
    Object.keys(options).some((key) => !allowedKeys.has(key))
  ) {
    fail("INPUT_INVALID", "Fixture loader options contain unknown fields.");
  }
  let parsed;
  try {
    parsed = await readBoundedJsonFile(filePath, {
      label: options.label || "Release rehearsal fixture set",
      ...FIXTURE_FILE_LIMITS,
    });
  } catch (error) {
    const message = String(error?.message ?? "");
    if (/size limit|nesting limit|value limit/iu.test(message)) {
      fail("INPUT_LIMIT_EXCEEDED", "Fixture file exceeds a configured input limit.");
    }
    if (/symbolic link|regular file/iu.test(message)) {
      fail("UNSAFE_FILE_TYPE", "Fixture input must be a safe regular file.");
    }
    fail("INPUT_INVALID", "Fixture file could not be loaded as bounded JSON.");
  }
  return validateReleaseRehearsalFixtureSet(parsed);
}

function normalizePlannedNode(value) {
  assertKnownKeys(value, PLANNED_NODE_KEYS, "Planned capture node");
  const nodeId = assertIdentifier(value.nodeId, "Planned node ID", MAX_NODE_ID_LENGTH);
  let method;
  try {
    method = normalizeSupportedHttpMethod(value.method);
  } catch {
    fail("METHOD_UNSUPPORTED", "Planned capture method is unsupported.");
  }
  let destination;
  try {
    destination = validateNormalizedHttpDestination(
      value.destination,
      "planned node destination",
    );
  } catch {
    fail("INPUT_INVALID", "Planned destination metadata is invalid.");
  }
  return {
    nodeId,
    method,
    destination,
  };
}

export function createReleaseRehearsalCaptureConfig(value) {
  assertKnownKeys(value, CONFIG_INPUT_KEYS, "Capture configuration input");
  if (value.schemaVersion !== RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION) {
    fail("INPUT_INVALID", "Capture configuration schema version is unsupported.");
  }
  const runId = assertIdentifier(value.runId, "Capture run ID");
  const caseId = assertIdentifier(value.caseId, "Capture case ID");
  if (!VARIANTS.has(value.variant)) {
    fail("INPUT_INVALID", "Capture variant must be baseline or candidate.");
  }
  const workflowCanonicalSha256 = assertSha256(
    value.workflowCanonicalSha256,
    "Workflow canonical fingerprint",
  );
  const fixtureMaterial = normalizeFixtureMaterial(value.fixture, { validated: true });
  if (
    !Array.isArray(value.plannedNodes) ||
    value.plannedNodes.length < 1 ||
    value.plannedNodes.length > RELEASE_REHEARSAL_MAX_FIXTURE_NODES
  ) {
    fail("INPUT_LIMIT_EXCEEDED", "Planned capture node count is invalid.");
  }
  const plannedNodes = value.plannedNodes.map(normalizePlannedNode);
  const plannedById = new Map();
  for (const node of plannedNodes) {
    if (plannedById.has(node.nodeId)) {
      fail("INPUT_INVALID", "Capture configuration contains duplicate node IDs.");
    }
    plannedById.set(node.nodeId, node);
  }
  const fixtureIds = fixtureMaterial.nodes.map((node) => node.nodeId).sort(stableCompare);
  const plannedIds = plannedNodes.map((node) => node.nodeId).sort(stableCompare);
  if (canonicalJson(fixtureIds) !== canonicalJson(plannedIds)) {
    fail("INPUT_INVALID", "Planned node IDs must exactly match the fixture node IDs.");
  }

  const nodes = fixtureMaterial.nodes
    .map((fixtureNode) => {
      const planned = plannedById.get(fixtureNode.nodeId);
      return {
        nodeId: fixtureNode.nodeId,
        method: planned.method,
        destination: planned.destination,
        minimumOccurrences: fixtureNode.minimumOccurrences,
        maximumOccurrences: fixtureNode.maximumOccurrences,
        responseStubs: fixtureNode.responses,
      };
    })
    .sort((left, right) => stableCompare(left.nodeId, right.nodeId));

  return validateReleaseRehearsalCaptureConfig({
    schemaVersion: RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-capture-config",
    runId,
    caseId,
    variant: value.variant,
    fixtureId: fixtureMaterial.id,
    fixtureCanonicalSha256: value.fixture.canonicalSha256,
    correlationId: fixtureMaterial.correlationId,
    workflowCanonicalSha256,
    allowedNodeIds: plannedIds,
    nodes,
  });
}

function normalizeCaptureNode(value) {
  assertKnownKeys(value, CAPTURE_NODE_KEYS, "Capture configuration node");
  const nodeId = assertIdentifier(value.nodeId, "Capture node ID", MAX_NODE_ID_LENGTH);
  if (!SUPPORTED_METHODS.has(value.method)) {
    fail("METHOD_UNSUPPORTED", "Capture configuration method is unsupported.");
  }
  if (
    !Number.isInteger(value.minimumOccurrences) ||
    value.minimumOccurrences < 0 ||
    !Number.isInteger(value.maximumOccurrences) ||
    value.maximumOccurrences < 1 ||
    value.maximumOccurrences > RELEASE_REHEARSAL_MAX_RESPONSE_STUBS ||
    value.minimumOccurrences > value.maximumOccurrences
  ) {
    fail("INPUT_INVALID", "Capture occurrence bounds are invalid.");
  }
  if (
    !Array.isArray(value.responseStubs) ||
    value.responseStubs.length < 1 ||
    value.responseStubs.length < value.minimumOccurrences ||
    value.responseStubs.length > value.maximumOccurrences
  ) {
    fail("INPUT_INVALID", "Capture response sequence is invalid.");
  }
  let destination;
  try {
    destination = validateNormalizedHttpDestination(
      value.destination,
      "capture node destination",
    );
  } catch {
    fail("INPUT_INVALID", "Capture destination metadata is invalid.");
  }
  return {
    nodeId,
    method: value.method,
    destination,
    minimumOccurrences: value.minimumOccurrences,
    maximumOccurrences: value.maximumOccurrences,
    responseStubs: value.responseStubs.map(normalizeResponseStub),
  };
}

export function validateReleaseRehearsalCaptureConfig(value) {
  assertKnownKeys(value, CAPTURE_CONFIG_KEYS, "Capture configuration");
  if (
    value.schemaVersion !== RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION ||
    value.kind !== "csint-release-rehearsal-capture-config"
  ) {
    fail("INPUT_INVALID", "Capture configuration identity is unsupported.");
  }
  const runId = assertIdentifier(value.runId, "Capture run ID");
  const caseId = assertIdentifier(value.caseId, "Capture case ID");
  const fixtureId = assertIdentifier(value.fixtureId, "Capture fixture ID");
  const correlationId = assertIdentifier(
    value.correlationId,
    "Capture correlation ID",
  );
  if (!VARIANTS.has(value.variant)) {
    fail("INPUT_INVALID", "Capture variant must be baseline or candidate.");
  }
  const fixtureCanonicalSha256 = assertSha256(
    value.fixtureCanonicalSha256,
    "Fixture canonical fingerprint",
  );
  const workflowCanonicalSha256 = assertSha256(
    value.workflowCanonicalSha256,
    "Workflow canonical fingerprint",
  );
  if (
    !Array.isArray(value.nodes) ||
    value.nodes.length < 1 ||
    value.nodes.length > RELEASE_REHEARSAL_MAX_FIXTURE_NODES
  ) {
    fail("INPUT_LIMIT_EXCEEDED", "Capture configuration node count is invalid.");
  }
  const nodes = value.nodes.map(normalizeCaptureNode).sort((left, right) =>
    stableCompare(left.nodeId, right.nodeId),
  );
  const nodeIds = nodes.map((node) => node.nodeId);
  if (new Set(nodeIds).size !== nodeIds.length) {
    fail("INPUT_INVALID", "Capture configuration contains duplicate node IDs.");
  }
  if (
    !Array.isArray(value.allowedNodeIds) ||
    value.allowedNodeIds.length !== nodes.length ||
    value.allowedNodeIds.length > RELEASE_REHEARSAL_MAX_FIXTURE_NODES ||
    value.allowedNodeIds.some(
      (nodeId) =>
        assertIdentifier(nodeId, "Allowed node ID", MAX_NODE_ID_LENGTH) !== nodeId,
    ) ||
    canonicalJson(value.allowedNodeIds) !== canonicalJson(nodeIds)
  ) {
    fail("INPUT_INVALID", "Allowed node IDs must be unique, sorted, and exact.");
  }

  return deepFreeze({
    schemaVersion: RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-capture-config",
    runId,
    caseId,
    variant: value.variant,
    fixtureId,
    fixtureCanonicalSha256,
    correlationId,
    workflowCanonicalSha256,
    allowedNodeIds: [...nodeIds],
    nodes,
  });
}
