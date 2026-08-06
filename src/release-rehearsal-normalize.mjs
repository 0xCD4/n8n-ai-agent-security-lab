import { fingerprintJson } from "./evidence-fingerprint.mjs";

export const RELEASE_REHEARSAL_SUPPORTED_METHODS = Object.freeze(["POST", "PUT", "PATCH"]);

const SUPPORTED_METHODS = new Set(RELEASE_REHEARSAL_SUPPORTED_METHODS);
const EXPRESSION_MARKER = /\{\{|\}\}/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F-\u009F]/u;

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function normalizeSupportedHttpMethod(value) {
  if (typeof value !== "string" || !value.trim()) {
    fail("METHOD_MISSING", "An explicit HTTP method is required.");
  }
  if (EXPRESSION_MARKER.test(value)) {
    fail("METHOD_DYNAMIC", "Dynamic HTTP methods are unsupported.");
  }
  if (CONTROL_CHARACTERS.test(value)) {
    fail("METHOD_UNSUPPORTED", "HTTP methods must not contain control characters.");
  }

  const method = value.trim().toUpperCase();
  if (!SUPPORTED_METHODS.has(method)) {
    fail("METHOD_UNSUPPORTED", "Only POST, PUT, and PATCH can be planned for capture.");
  }
  return method;
}

export function normalizeHttpDestination(value) {
  if (typeof value !== "string" || !value.trim()) {
    fail("DESTINATION_MISSING", "An explicit HTTP destination is required.");
  }
  if (EXPRESSION_MARKER.test(value)) {
    fail("DESTINATION_DYNAMIC", "Dynamic HTTP destinations are unsupported.");
  }
  if (CONTROL_CHARACTERS.test(value)) {
    fail("DESTINATION_INVALID", "HTTP destinations must not contain control characters.");
  }

  let url;
  try {
    url = new URL(value.trim());
  } catch {
    fail("DESTINATION_INVALID", "The HTTP destination is not a valid absolute URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    fail("DESTINATION_SCHEME_UNSUPPORTED", "Only HTTP and HTTPS destinations are supported.");
  }
  if (url.username || url.password) {
    fail(
      "DESTINATION_CREDENTIALS_BLOCKED",
      "Credentials embedded in an HTTP destination are blocked.",
    );
  }
  if (url.hash) {
    fail("DESTINATION_FRAGMENT_UNSUPPORTED", "HTTP destination fragments are unsupported.");
  }

  const queryEntries = [...url.searchParams.entries()];
  const queryNames = queryEntries.map(([name]) => name).sort(stableCompare);
  const canonicalInput = {
    scheme: url.protocol.slice(0, -1).toLowerCase(),
    host: url.hostname.toLowerCase(),
    port: url.port || null,
    path: url.pathname || "/",
    query: queryEntries,
  };

  return {
    scheme: canonicalInput.scheme,
    host: canonicalInput.host,
    port: canonicalInput.port,
    path: canonicalInput.path,
    queryNames,
    canonicalSha256: fingerprintJson(canonicalInput),
  };
}
