import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { TextDecoder } from "node:util";

import { canonicalJson, fingerprintJson } from "./evidence-fingerprint.mjs";
import {
  RELEASE_REHEARSAL_MAX_CAPTURE_BODY_BYTES,
  validateReleaseRehearsalCaptureConfig,
  validateReleaseRehearsalSanitizedJson,
} from "./release-rehearsal-fixture.mjs";
import { RELEASE_REHEARSAL_SUPPORTED_METHODS } from "./release-rehearsal-normalize.mjs";

export const RELEASE_REHEARSAL_CAPTURE_EVENT_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_CAPTURE_SUMMARY_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_CAPTURE_ROUTE = "/v1/rehearsal/capture";
export const RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX = "x-csint-rehearsal-";
export const RELEASE_REHEARSAL_CAPTURE_HEADERS = Object.freeze({
  runId: RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX + "run",
  caseId: RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX + "case",
  variant: RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX + "variant",
  fixtureId: RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX + "fixture",
  correlationId: RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX + "correlation",
  nodeId: RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX + "node-id",
  workflowSha256: RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX + "workflow-sha256",
  actionId: RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX + "action-id",
});

const MAX_CAPTURE_HEADERS = 64;
const MAX_CAPTURE_HEADER_BYTES = 16 * 1024;
const MAX_CAPTURE_HEADER_VALUE_LENGTH = 1_024;
const MAX_CAPTURE_VIOLATIONS = 100;
const SUPPORTED_METHODS = new Set(RELEASE_REHEARSAL_SUPPORTED_METHODS);
const ALLOWED_METADATA_HEADERS = new Set(
  Object.values(RELEASE_REHEARSAL_CAPTURE_HEADERS),
);
const REQUIRED_METADATA_HEADERS = new Set([
  RELEASE_REHEARSAL_CAPTURE_HEADERS.runId,
  RELEASE_REHEARSAL_CAPTURE_HEADERS.caseId,
  RELEASE_REHEARSAL_CAPTURE_HEADERS.variant,
  RELEASE_REHEARSAL_CAPTURE_HEADERS.fixtureId,
  RELEASE_REHEARSAL_CAPTURE_HEADERS.correlationId,
  RELEASE_REHEARSAL_CAPTURE_HEADERS.nodeId,
]);
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;
const HEADER_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const INVALID_HEADER_VALUE = /[\u0000-\u0008\u000A-\u001F\u007F-\u009F]/u;
const FORBIDDEN_HEADER_NAMES = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  "set-cookie",
]);
const OMITTED_TRANSPORT_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

class CaptureRequestError extends Error {
  constructor(code, status) {
    super("Capture request rejected.");
    this.code = code;
    this.status = status;
  }
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isSensitiveHeaderName(name) {
  if (FORBIDDEN_HEADER_NAMES.has(name)) return true;
  const normalized = name.replace(/[^a-z0-9]/gu, "");
  return (
    normalized.includes("authorization") ||
    normalized.includes("credential") ||
    normalized.includes("cookie") ||
    normalized.includes("password") ||
    normalized.includes("privatekey") ||
    normalized.includes("secret") ||
    normalized.includes("token") ||
    normalized.includes("apikey")
  );
}

function assertMetadataIdentifier(value, maxLength) {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= maxLength &&
    IDENTIFIER_PATTERN.test(value)
  );
}

function inspectRequestHeaders(request, config) {
  const rawHeaders = request.rawHeaders;
  if (
    !Array.isArray(rawHeaders) ||
    rawHeaders.length % 2 !== 0 ||
    rawHeaders.length / 2 > MAX_CAPTURE_HEADERS
  ) {
    throw new CaptureRequestError("HEADER_LIMIT_EXCEEDED", 431);
  }

  let headerBytes = 0;
  const counts = new Map();
  const values = new Map();
  const hashPairs = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const rawName = rawHeaders[index];
    const rawValue = rawHeaders[index + 1];
    headerBytes += Buffer.byteLength(rawName + ": " + rawValue + "\r\n", "utf8");
    if (headerBytes > MAX_CAPTURE_HEADER_BYTES) {
      throw new CaptureRequestError("HEADER_LIMIT_EXCEEDED", 431);
    }
    if (
      rawName.length < 1 ||
      rawName.length > 128 ||
      !HEADER_NAME_PATTERN.test(rawName) ||
      rawValue.length > MAX_CAPTURE_HEADER_VALUE_LENGTH ||
      INVALID_HEADER_VALUE.test(rawValue)
    ) {
      throw new CaptureRequestError("HEADER_INVALID", 400);
    }

    const name = rawName.toLowerCase();
    counts.set(name, (counts.get(name) ?? 0) + 1);
    if (isSensitiveHeaderName(name)) {
      throw new CaptureRequestError("SENSITIVE_HEADER_FORBIDDEN", 400);
    }
    if (name.startsWith(RELEASE_REHEARSAL_CAPTURE_HEADER_PREFIX)) {
      if (!ALLOWED_METADATA_HEADERS.has(name)) {
        throw new CaptureRequestError("METADATA_UNEXPECTED", 400);
      }
      if (counts.get(name) !== 1) {
        throw new CaptureRequestError("METADATA_DUPLICATE", 400);
      }
      values.set(name, rawValue);
      continue;
    }
    if (!OMITTED_TRANSPORT_HEADERS.has(name)) hashPairs.push([name, rawValue]);
  }

  for (const name of REQUIRED_METADATA_HEADERS) {
    if (!values.has(name)) {
      throw new CaptureRequestError("METADATA_MISSING", 400);
    }
  }
  if ((counts.get("content-type") ?? 0) !== 1) {
    throw new CaptureRequestError("CONTENT_TYPE_UNSUPPORTED", 415);
  }

  const metadata = {
    runId: values.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.runId),
    caseId: values.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.caseId),
    variant: values.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.variant),
    fixtureId: values.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.fixtureId),
    correlationId: values.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.correlationId),
    nodeId: values.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.nodeId),
    workflowSha256: values.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.workflowSha256),
    actionId: values.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.actionId),
  };
  const hasWorkflowCorrelation = metadata.workflowSha256 !== undefined;
  const hasActionCorrelation = metadata.actionId !== undefined;
  if (hasWorkflowCorrelation !== hasActionCorrelation) {
    throw new CaptureRequestError("METADATA_MISSING", 400);
  }
  if (
    !assertMetadataIdentifier(metadata.runId, 128) ||
    !assertMetadataIdentifier(metadata.caseId, 128) ||
    !assertMetadataIdentifier(metadata.variant, 128) ||
    !assertMetadataIdentifier(metadata.fixtureId, 128) ||
    !assertMetadataIdentifier(metadata.correlationId, 128) ||
    !assertMetadataIdentifier(metadata.nodeId, 512) ||
    (hasWorkflowCorrelation &&
      (!/^[a-f0-9]{64}$/u.test(metadata.workflowSha256) ||
        !assertMetadataIdentifier(metadata.actionId, 768)))
  ) {
    throw new CaptureRequestError("METADATA_INVALID", 400);
  }
  if (
    metadata.runId !== config.runId ||
    metadata.caseId !== config.caseId ||
    metadata.variant !== config.variant ||
    metadata.fixtureId !== config.fixtureId ||
    metadata.correlationId !== config.correlationId ||
    (hasWorkflowCorrelation && metadata.workflowSha256 !== config.workflowCanonicalSha256)
  ) {
    throw new CaptureRequestError("METADATA_MISMATCH", 409);
  }

  const rawContentType = request.headers["content-type"];
  if (
    typeof rawContentType !== "string" ||
    !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(rawContentType)
  ) {
    throw new CaptureRequestError("CONTENT_TYPE_UNSUPPORTED", 415);
  }
  const rawContentLength = request.headers["content-length"];
  if (rawContentLength !== undefined) {
    if (
      typeof rawContentLength !== "string" ||
      !/^\d+$/u.test(rawContentLength) ||
      Number(rawContentLength) > RELEASE_REHEARSAL_MAX_CAPTURE_BODY_BYTES
    ) {
      throw new CaptureRequestError("BODY_LIMIT_EXCEEDED", 413);
    }
  }

  hashPairs.sort((left, right) => {
    const nameOrder = stableCompare(left[0], right[0]);
    return nameOrder || stableCompare(left[1], right[1]);
  });
  return {
    metadata,
    correlationProfile: hasWorkflowCorrelation ? "extended" : "base",
    headerNames: [...new Set(hashPairs.map(([name]) => name))].sort(stableCompare),
    headerSetSha256: fingerprintJson(hashPairs),
  };
}

async function readBoundedBody(request) {
  const chunks = [];
  let bytes = 0;
  let oversized = false;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > RELEASE_REHEARSAL_MAX_CAPTURE_BODY_BYTES) {
      oversized = true;
      continue;
    }
    chunks.push(chunk);
  }
  if (oversized) throw new CaptureRequestError("BODY_LIMIT_EXCEEDED", 413);
  return Buffer.concat(chunks, bytes);
}

function parseSanitizedJsonBody(body) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new CaptureRequestError("BODY_INVALID_UTF8", 400);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CaptureRequestError("BODY_JSON_INVALID", 400);
  }
  try {
    return validateReleaseRehearsalSanitizedJson(parsed);
  } catch {
    throw new CaptureRequestError("BODY_POLICY_VIOLATION", 400);
  }
}

function jsonShape(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return ["array", value.map(jsonShape)];
  if (typeof value === "object") {
    return [
      "object",
      Object.keys(value)
        .sort(stableCompare)
        .map((key) => [key, jsonShape(value[key])]),
    ];
  }
  return typeof value;
}

function sendJson(response, status, value, headers = {}) {
  if (response.destroyed || response.writableEnded) return;
  const body = Buffer.from(canonicalJson(value), "utf8");
  response.sendDate = false;
  for (const [name, headerValue] of Object.entries(headers)) {
    response.setHeader(name, headerValue);
  }
  if (!response.hasHeader("content-type")) {
    response.setHeader("content-type", "application/json; charset=utf-8");
  }
  response.setHeader("cache-control", "no-store");
  response.setHeader("content-length", body.length);
  response.statusCode = status;
  response.end(body);
}

function sendError(response, code, status) {
  sendJson(response, status, {
    error: {
      code,
      message: "Capture request rejected.",
    },
  });
}

function drainRequest(request) {
  if (!request.readableEnded && !request.destroyed) request.resume();
}

export function createReleaseRehearsalCaptureService(inputConfig) {
  const config = validateReleaseRehearsalCaptureConfig(inputConfig);
  const eventLedger = [];
  const violations = [];
  const nodeStates = new Map(
    config.nodes.map((node) => [
      node.nodeId,
      {
        config: node,
        attempts: 0,
        captured: 0,
        exhausted: false,
      },
    ]),
  );
  let violationOverflow = false;
  let finalized = false;
  let lateRequestDetected = false;
  let receiveOrder = 0;

  function recordViolation(code) {
    if (violations.length < MAX_CAPTURE_VIOLATIONS) {
      violations.push(code);
    } else {
      violationOverflow = true;
    }
  }

  function rejectRequest(request, response, error) {
    recordViolation(error.code);
    drainRequest(request);
    sendError(response, error.code, error.status);
  }

  async function handleRequest(request, response) {
    if (finalized) {
      lateRequestDetected = true;
      drainRequest(request);
      sendError(response, "REQUEST_AFTER_FINALIZATION", 409);
      return;
    }
    if (request.url !== RELEASE_REHEARSAL_CAPTURE_ROUTE) {
      rejectRequest(request, response, new CaptureRequestError("ROUTE_UNEXPECTED", 404));
      return;
    }
    const method = request.method ?? "";
    if (!SUPPORTED_METHODS.has(method)) {
      rejectRequest(
        request,
        response,
        new CaptureRequestError("METHOD_UNSUPPORTED", 405),
      );
      return;
    }

    let inspected;
    try {
      inspected = inspectRequestHeaders(request, config);
    } catch (error) {
      rejectRequest(
        request,
        response,
        error instanceof CaptureRequestError
          ? error
          : new CaptureRequestError("HEADER_INVALID", 400),
      );
      return;
    }
    const state = nodeStates.get(inspected.metadata.nodeId);
    if (!state) {
      rejectRequest(request, response, new CaptureRequestError("NODE_UNKNOWN", 409));
      return;
    }
    if (
      inspected.correlationProfile === "extended" &&
      inspected.metadata.actionId !== `${config.fixtureId}:${state.config.nodeId}`
    ) {
      rejectRequest(
        request,
        response,
        new CaptureRequestError("METADATA_MISMATCH", 409),
      );
      return;
    }
    if (method !== state.config.method) {
      rejectRequest(request, response, new CaptureRequestError("METHOD_MISMATCH", 409));
      return;
    }

    const occurrence = state.attempts + 1;
    if (occurrence > state.config.maximumOccurrences) {
      rejectRequest(
        request,
        response,
        new CaptureRequestError("OCCURRENCE_LIMIT_EXCEEDED", 409),
      );
      return;
    }
    state.attempts = occurrence;
    receiveOrder += 1;
    const eventReceiveOrder = receiveOrder;
    const responseStub = state.config.responseStubs[occurrence - 1];
    if (!responseStub) {
      state.exhausted = true;
      drainRequest(request);
      sendError(response, "RESPONSE_SEQUENCE_EXHAUSTED", 409);
      return;
    }

    let body;
    let parsed;
    try {
      body = await readBoundedBody(request);
      parsed = parseSanitizedJsonBody(body);
    } catch (error) {
      rejectRequest(
        request,
        response,
        error instanceof CaptureRequestError
          ? error
          : new CaptureRequestError("BODY_JSON_INVALID", 400),
      );
      return;
    }

    const event = deepFreeze({
      schemaVersion: RELEASE_REHEARSAL_CAPTURE_EVENT_SCHEMA_VERSION,
      runId: config.runId,
      caseId: config.caseId,
      variant: config.variant,
      fixtureId: config.fixtureId,
      correlationId: config.correlationId,
      workflowCanonicalSha256: config.workflowCanonicalSha256,
      nodeId: state.config.nodeId,
      occurrence,
      actionId: `${config.fixtureId}:${state.config.nodeId}`,
      correlationProfile: inspected.correlationProfile,
      method,
      destination: state.config.destination,
      headerNames: inspected.headerNames,
      headerSetSha256: inspected.headerSetSha256,
      bodyBytes: body.length,
      bodySha256: sha256(body),
      jsonShapeSha256: fingerprintJson(jsonShape(parsed)),
      responseStubIndex: occurrence - 1,
      responseStatus: responseStub.status,
      forwarded: false,
    });
    eventLedger.push({ receiveOrder: eventReceiveOrder, event });
    eventLedger.sort((left, right) => left.receiveOrder - right.receiveOrder);
    state.captured += 1;
    sendJson(response, responseStub.status, responseStub.json, responseStub.headers);
  }

  const server = createServer(
    { maxHeaderSize: MAX_CAPTURE_HEADER_BYTES },
    (request, response) => {
      handleRequest(request, response).catch(() => {
        if (finalized) {
          lateRequestDetected = true;
        } else {
          recordViolation("INTERNAL_ERROR");
        }
        drainRequest(request);
        sendError(response, "INTERNAL_ERROR", 500);
      });
    },
  );
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 1_000;
  server.on("clientError", (_error, socket) => {
    if (finalized) {
      lateRequestDetected = true;
    } else {
      recordViolation("HEADER_LIMIT_EXCEEDED");
    }
    if (socket.writable) {
      socket.end(
        "HTTP/1.1 431 Request Header Fields Too Large\r\n" +
          "Connection: close\r\nContent-Length: 0\r\n\r\n",
      );
    }
  });

  function getEvents() {
    return Object.freeze(eventLedger.map((entry) => entry.event));
  }

  function serializeEvents() {
    return canonicalJson(eventLedger.map((entry) => entry.event)) + "\n";
  }

  function finalize() {
    finalized = true;
    const nodeCounts = config.nodes.map((node) => {
      const state = nodeStates.get(node.nodeId);
      return {
        nodeId: node.nodeId,
        receivedOccurrences: state.captured,
        minimumOccurrences: node.minimumOccurrences,
        maximumOccurrences: node.maximumOccurrences,
      };
    });
    const missing = nodeCounts
      .filter((node) => node.receivedOccurrences < node.minimumOccurrences)
      .map((node) => ({
        nodeId: node.nodeId,
        receivedOccurrences: node.receivedOccurrences,
        minimumOccurrences: node.minimumOccurrences,
      }));
    const exhaustedNodeIds = [...nodeStates.values()]
      .filter((state) => state.exhausted)
      .map((state) => state.config.nodeId)
      .sort(stableCompare);
    const violationCodes = [...new Set([
      ...violations,
      ...(violationOverflow ? ["VIOLATION_LIMIT_EXCEEDED"] : []),
      ...(lateRequestDetected ? ["REQUEST_AFTER_FINALIZATION"] : []),
    ])].sort(stableCompare);
    const status =
      violationCodes.length > 0
        ? "FAILED"
        : missing.length > 0 || exhaustedNodeIds.length > 0
          ? "INCOMPLETE"
          : "COMPLETE";
    return deepFreeze({
      schemaVersion: RELEASE_REHEARSAL_CAPTURE_SUMMARY_SCHEMA_VERSION,
      status,
      runId: config.runId,
      caseId: config.caseId,
      variant: config.variant,
      fixtureId: config.fixtureId,
      fixtureCanonicalSha256: config.fixtureCanonicalSha256,
      correlationId: config.correlationId,
      workflowCanonicalSha256: config.workflowCanonicalSha256,
      eventCount: eventLedger.length,
      nodeCounts,
      missing,
      exhaustedNodeIds,
      violationCodes,
      forwarded: false,
    });
  }

  function serializeSummary() {
    return canonicalJson(finalize()) + "\n";
  }

  return Object.freeze({
    config,
    server,
    getEvents,
    serializeEvents,
    finalize,
    serializeSummary,
  });
}
