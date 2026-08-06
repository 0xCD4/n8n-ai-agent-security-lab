import { canonicalJson } from "./evidence-fingerprint.mjs";
import { RELEASE_REHEARSAL_SUPPORTED_METHODS } from "./release-rehearsal-normalize.mjs";

export const RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_EVIDENCE_STATUSES = Object.freeze([
  "observed",
  "planned",
  "unresolved",
]);
export const RELEASE_REHEARSAL_VARIANTS = Object.freeze(["baseline", "candidate"]);

const ACTION_KEYS = new Set([
  "schemaVersion",
  "evidenceStatus",
  "variant",
  "fixtureId",
  "workflowCanonicalSha256",
  "source",
  "sequence",
  "attempt",
  "intent",
  "resolutionCode",
]);
const SOURCE_KEYS = new Set(["nodeId", "nodeName"]);
const INTENT_KEYS = new Set(["kind", "method", "destination"]);
const DESTINATION_KEYS = new Set([
  "scheme",
  "host",
  "port",
  "path",
  "queryNames",
  "canonicalSha256",
]);
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const UNSAFE_TEXT =
  /[\u0000-\u001F\u007F-\u009F\u200B\u200E\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/u;
const SUPPORTED_METHODS = new Set(RELEASE_REHEARSAL_SUPPORTED_METHODS);
const EVIDENCE_STATUSES = new Set(RELEASE_REHEARSAL_EVIDENCE_STATUSES);
const VARIANTS = new Set(RELEASE_REHEARSAL_VARIANTS);

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertPlainObject(value, label) {
  if (!isPlainObject(value)) throw new TypeError(label + " must be an object.");
}

function assertKnownKeys(value, known, label) {
  assertPlainObject(value, label);
  if (Object.keys(value).some((key) => !known.has(key))) {
    throw new TypeError(label + " contains unknown fields.");
  }
}

function assertSafeText(value, label, maxLength = 512) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maxLength ||
    UNSAFE_TEXT.test(value)
  ) {
    throw new TypeError(
      label + " must be a bounded non-empty string without control text.",
    );
  }
}

function assertSha256(value, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new TypeError(label + " must be a lowercase SHA-256 value.");
  }
}

function assertPositiveInteger(value, label) {
  if (!Number.isInteger(value) || value < 1) {
    throw new TypeError(label + " must be a positive integer.");
  }
}

export function validateNormalizedHttpDestination(
  destination,
  label = "normalized HTTP destination",
) {
  assertKnownKeys(destination, DESTINATION_KEYS, label);
  if (!["http", "https"].includes(destination.scheme)) {
    throw new TypeError(label + ".scheme must be http or https.");
  }
  assertSafeText(destination.host, label + ".host", 253);
  if (/[@/?#\\\s]/u.test(destination.host)) {
    throw new TypeError(label + ".host contains invalid URL text.");
  }
  if (destination.port !== null) {
    if (
      typeof destination.port !== "string" ||
      !/^\d{1,5}$/u.test(destination.port) ||
      Number(destination.port) < 1 ||
      Number(destination.port) > 65_535
    ) {
      throw new TypeError(label + ".port must be null or a valid port.");
    }
  }
  if (
    typeof destination.path !== "string" ||
    !destination.path.startsWith("/") ||
    destination.path.length > 2048 ||
    UNSAFE_TEXT.test(destination.path) ||
    /[?#]/u.test(destination.path)
  ) {
    throw new TypeError(label + ".path must be a bounded absolute URL path.");
  }
  if (!Array.isArray(destination.queryNames) || destination.queryNames.length > 100) {
    throw new TypeError(label + ".queryNames must be a bounded array.");
  }
  for (const name of destination.queryNames) {
    assertSafeText(name, label + ".queryNames[]", 256);
  }
  const sortedNames = [...destination.queryNames].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  if (canonicalJson(sortedNames) !== canonicalJson(destination.queryNames)) {
    throw new TypeError(label + ".queryNames must be sorted.");
  }
  assertSha256(destination.canonicalSha256, label + ".canonicalSha256");

  return {
    scheme: destination.scheme,
    host: destination.host,
    port: destination.port,
    path: destination.path,
    queryNames: [...destination.queryNames],
    canonicalSha256: destination.canonicalSha256,
  };
}

export function validateIntendedActionRecord(action) {
  assertKnownKeys(action, ACTION_KEYS, "action");
  if (action.schemaVersion !== RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION) {
    throw new TypeError(
      "action.schemaVersion must be " +
        RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION +
        ".",
    );
  }
  if (!EVIDENCE_STATUSES.has(action.evidenceStatus)) {
    throw new TypeError("action.evidenceStatus is unsupported.");
  }
  if (!VARIANTS.has(action.variant)) {
    throw new TypeError("action.variant must be baseline or candidate.");
  }
  assertSafeText(action.fixtureId, "action.fixtureId", 128);
  assertSha256(action.workflowCanonicalSha256, "action.workflowCanonicalSha256");
  assertKnownKeys(action.source, SOURCE_KEYS, "action.source");
  assertSafeText(action.source.nodeId, "action.source.nodeId", 512);
  assertSafeText(action.source.nodeName, "action.source.nodeName", 512);
  assertPositiveInteger(action.sequence, "action.sequence");
  assertPositiveInteger(action.attempt, "action.attempt");

  if (action.evidenceStatus === "unresolved") {
    if (action.intent !== null) {
      throw new TypeError("An unresolved action must not contain resolved intent metadata.");
    }
    assertSafeText(action.resolutionCode, "action.resolutionCode", 128);
    if (!/^[A-Z][A-Z0-9_]{0,127}$/u.test(action.resolutionCode)) {
      throw new TypeError("action.resolutionCode must be a stable uppercase code.");
    }
    return {
      schemaVersion: RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION,
      evidenceStatus: "unresolved",
      variant: action.variant,
      fixtureId: action.fixtureId,
      workflowCanonicalSha256: action.workflowCanonicalSha256,
      source: {
        nodeId: action.source.nodeId,
        nodeName: action.source.nodeName,
      },
      sequence: action.sequence,
      attempt: action.attempt,
      intent: null,
      resolutionCode: action.resolutionCode,
    };
  }

  if (action.resolutionCode !== null) {
    throw new TypeError("A resolved action must use a null resolutionCode.");
  }
  assertKnownKeys(action.intent, INTENT_KEYS, "action.intent");
  if (action.intent.kind !== "http") {
    throw new TypeError("action.intent.kind must be http.");
  }
  if (!SUPPORTED_METHODS.has(action.intent.method)) {
    throw new TypeError("action.intent.method must be POST, PUT, or PATCH.");
  }

  return {
    schemaVersion: RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION,
    evidenceStatus: action.evidenceStatus,
    variant: action.variant,
    fixtureId: action.fixtureId,
    workflowCanonicalSha256: action.workflowCanonicalSha256,
    source: {
      nodeId: action.source.nodeId,
      nodeName: action.source.nodeName,
    },
    sequence: action.sequence,
    attempt: action.attempt,
    intent: {
      kind: "http",
      method: action.intent.method,
      destination: validateNormalizedHttpDestination(
        action.intent.destination,
        "action.intent.destination",
      ),
    },
    resolutionCode: null,
  };
}
