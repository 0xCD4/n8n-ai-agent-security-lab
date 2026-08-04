import { auditN8nWorkflow } from "./rules.mjs";
import { assertTargetAllowed, resolveTestUrl, sanitizeTargetUrl } from "./target-policy.mjs";

const SEVERITY_RANK = {
  off: Number.POSITIVE_INFINITY,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const ALLOWED_METHODS = new Set(["GET", "POST"]);
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_RESPONSE_BYTES = 262_144;
const MAX_TESTS = 20;
const MAX_REQUESTS = 30;
const MAX_REQUEST_BODY_BYTES = 262_144;

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertKnownKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(`${label} contains an unsupported field: ${key}`);
    }
  }
}

function assertStatusExpectation(status, label) {
  const statuses = Array.isArray(status) ? status : [status];
  if (
    statuses.length === 0 ||
    statuses.some((value) => !Number.isInteger(value) || value < 100 || value > 599)
  ) {
    throw new Error(`${label}.status must contain valid HTTP status codes.`);
  }
}

function countRequests(contract) {
  return contract.tests.reduce((total, test) => total + 1 + (test.observe ? 1 : 0), 0);
}

export function validateSecurityContract(contract) {
  if (!isPlainObject(contract)) {
    throw new TypeError("Security contract must be a JSON object.");
  }

  assertKnownKeys(
    contract,
    new Set(["$schema", "schemaVersion", "name", "target", "gate", "receipt", "tests"]),
    "Security contract",
  );

  if (contract.schemaVersion !== 1) {
    throw new Error("Security contract schemaVersion must be 1.");
  }
  if (typeof contract.name !== "string" || !contract.name.trim()) {
    throw new Error("Security contract requires a name.");
  }
  if (!isPlainObject(contract.target)) {
    throw new Error("Security contract requires a target object.");
  }

  assertKnownKeys(
    contract.target,
    new Set([
      "baseUrl",
      "allowedHosts",
      "allowedPathPrefixes",
      "timeoutMs",
      "maxResponseBytes",
      "maxRequests",
    ]),
    "target",
  );

  if (typeof contract.target.baseUrl !== "string" || !contract.target.baseUrl.trim()) {
    throw new Error("target.baseUrl is required.");
  }
  if (
    contract.target.allowedHosts !== undefined &&
    (!Array.isArray(contract.target.allowedHosts) ||
      contract.target.allowedHosts.some((host) => typeof host !== "string" || !host.trim()))
  ) {
    throw new Error("target.allowedHosts must be an array of hostnames.");
  }
  if (
    contract.target.allowedPathPrefixes !== undefined &&
    (!Array.isArray(contract.target.allowedPathPrefixes) ||
      contract.target.allowedPathPrefixes.length === 0 ||
      contract.target.allowedPathPrefixes.some(
        (prefix) =>
          typeof prefix !== "string" || prefix === "/" || !prefix.startsWith("/"),
      ))
  ) {
    throw new Error(
      "target.allowedPathPrefixes must contain specific paths starting with '/'.",
    );
  }

  const timeoutMs = contract.target.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new Error("target.timeoutMs must be an integer between 100 and 30000.");
  }

  const maxResponseBytes = contract.target.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (
    !Number.isInteger(maxResponseBytes) ||
    maxResponseBytes < 1_024 ||
    maxResponseBytes > 1_048_576
  ) {
    throw new Error("target.maxResponseBytes must be between 1024 and 1048576.");
  }

  if (!isPlainObject(contract.gate)) {
    throw new Error("Security contract requires a gate object.");
  }
  assertKnownKeys(
    contract.gate,
    new Set(["failOnStaticSeverity", "requireRuntime"]),
    "gate",
  );
  if (!(contract.gate.failOnStaticSeverity in SEVERITY_RANK)) {
    throw new Error("gate.failOnStaticSeverity must be critical, high, medium, low or off.");
  }
  if (contract.gate.requireRuntime !== true) {
    throw new Error("gate.requireRuntime must be true for a regression gate.");
  }

  if (contract.receipt !== undefined) {
    if (!isPlainObject(contract.receipt)) {
      throw new Error("receipt must be an object.");
    }
    assertKnownKeys(contract.receipt, new Set(["externalActionEvidence"]), "receipt");
    const evidence = contract.receipt.externalActionEvidence;
    if (!isPlainObject(evidence)) {
      throw new Error("receipt.externalActionEvidence must be an object.");
    }
    assertKnownKeys(
      evidence,
      new Set(["testId", "source", "pointer"]),
      "receipt.externalActionEvidence",
    );
    if (typeof evidence.testId !== "string" || !/^[a-z0-9][a-z0-9-]{1,63}$/.test(evidence.testId)) {
      throw new Error("receipt.externalActionEvidence.testId must name a contract test.");
    }
    if (evidence.source !== "response" && evidence.source !== "observation") {
      throw new Error("receipt.externalActionEvidence.source must be response or observation.");
    }
    if (typeof evidence.pointer !== "string" || !evidence.pointer.startsWith("/")) {
      throw new Error("receipt.externalActionEvidence.pointer must be a JSON Pointer.");
    }
  }

  if (!Array.isArray(contract.tests) || contract.tests.length === 0) {
    throw new Error("Security contract requires at least one runtime test.");
  }
  if (contract.tests.length > MAX_TESTS) {
    throw new Error(`Security contract supports at most ${MAX_TESTS} runtime tests.`);
  }

  const ids = new Set();
  for (const [index, test] of contract.tests.entries()) {
    const label = `tests[${index}]`;
    if (!isPlainObject(test)) throw new Error(`${label} must be an object.`);
    assertKnownKeys(test, new Set(["id", "name", "request", "expect", "observe"]), label);

    if (typeof test.id !== "string" || !/^[a-z0-9][a-z0-9-]{1,63}$/.test(test.id)) {
      throw new Error(`${label}.id must be a lowercase, URL-safe identifier.`);
    }
    if (ids.has(test.id)) throw new Error(`Duplicate runtime test id: ${test.id}`);
    ids.add(test.id);

    if (typeof test.name !== "string" || !test.name.trim()) {
      throw new Error(`${label}.name is required.`);
    }
    validateRequest(test.request, `${label}.request`);
    validateExpectation(test.expect, `${label}.expect`);

    if (test.observe !== undefined) {
      if (!isPlainObject(test.observe)) throw new Error(`${label}.observe must be an object.`);
      assertKnownKeys(test.observe, new Set(["request", "expect"]), `${label}.observe`);
      validateRequest(test.observe.request, `${label}.observe.request`);
      validateExpectation(test.observe.expect, `${label}.observe.expect`);
    }
  }

  if (contract.receipt) {
    const evidence = contract.receipt.externalActionEvidence;
    const evidenceTest = contract.tests.find((test) => test.id === evidence.testId);
    if (!evidenceTest) {
      throw new Error("receipt.externalActionEvidence.testId does not match a contract test.");
    }
    const expectation =
      evidence.source === "observation" ? evidenceTest.observe?.expect : evidenceTest.expect;
    if (!expectation) {
      throw new Error("receipt.externalActionEvidence points to a missing observation.");
    }
    if (expectation.json?.equals?.[evidence.pointer] !== 0) {
      throw new Error("receipt.externalActionEvidence must point to a contract equality of zero.");
    }
  }

  const requestCount = countRequests(contract);
  const maxRequests = contract.target.maxRequests ?? MAX_REQUESTS;
  if (!Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > MAX_REQUESTS) {
    throw new Error(`target.maxRequests must be between 1 and ${MAX_REQUESTS}.`);
  }
  if (requestCount > maxRequests) {
    throw new Error(
      `Contract needs ${requestCount} requests but target.maxRequests is ${maxRequests}.`,
    );
  }

  return contract;
}

function validateRequest(request, label) {
  if (!isPlainObject(request)) throw new Error(`${label} must be an object.`);
  assertKnownKeys(request, new Set(["method", "path", "headers", "json"]), label);

  const method = String(request.method ?? "POST").toUpperCase();
  if (!ALLOWED_METHODS.has(method)) {
    throw new Error(`${label}.method must be GET or POST.`);
  }
  if (typeof request.path !== "string" || !request.path.startsWith("/")) {
    throw new Error(`${label}.path must start with '/'.`);
  }
  if (request.headers !== undefined && !isPlainObject(request.headers)) {
    throw new Error(`${label}.headers must be an object.`);
  }
  if (method === "GET" && request.json !== undefined) {
    throw new Error(`${label} must not send a JSON body with GET.`);
  }
}

function validateExpectation(expectation, label) {
  if (!isPlainObject(expectation)) throw new Error(`${label} must be an object.`);
  assertKnownKeys(
    expectation,
    new Set(["status", "maxDurationMs", "bodyIncludes", "bodyExcludes", "headers", "json"]),
    label,
  );
  assertStatusExpectation(expectation.status, label);

  if (
    expectation.maxDurationMs !== undefined &&
    (!Number.isInteger(expectation.maxDurationMs) ||
      expectation.maxDurationMs < 1 ||
      expectation.maxDurationMs > 30_000)
  ) {
    throw new Error(`${label}.maxDurationMs must be between 1 and 30000.`);
  }

  for (const key of ["bodyIncludes", "bodyExcludes"]) {
    if (
      expectation[key] !== undefined &&
      (!Array.isArray(expectation[key]) ||
        expectation[key].some((item) => typeof item !== "string"))
    ) {
      throw new Error(`${label}.${key} must be an array of strings.`);
    }
  }

  if (expectation.headers !== undefined && !isPlainObject(expectation.headers)) {
    throw new Error(`${label}.headers must be an object.`);
  }

  if (expectation.json !== undefined) {
    if (!isPlainObject(expectation.json)) throw new Error(`${label}.json must be an object.`);
    assertKnownKeys(
      expectation.json,
      new Set(["requiredPaths", "forbiddenPaths", "equals", "allowedTopLevelKeys"]),
      `${label}.json`,
    );
    for (const key of ["requiredPaths", "forbiddenPaths", "allowedTopLevelKeys"]) {
      if (
        expectation.json[key] !== undefined &&
        (!Array.isArray(expectation.json[key]) ||
          expectation.json[key].some((item) => typeof item !== "string"))
      ) {
        throw new Error(`${label}.json.${key} must be an array of strings.`);
      }
    }
    if (expectation.json.equals !== undefined && !isPlainObject(expectation.json.equals)) {
      throw new Error(`${label}.json.equals must be an object keyed by JSON Pointer.`);
    }
  }
}

function interpolateEnvironment(value, environment) {
  if (typeof value === "string") {
    return value.replace(/\$\{([A-Z][A-Z0-9_]*)\}/g, (_match, name) => {
      const replacement = environment[name];
      if (typeof replacement !== "string" || replacement.length === 0) {
        throw new Error(`Required environment variable is not set: ${name}`);
      }
      return replacement;
    });
  }
  if (Array.isArray(value)) {
    return value.map((item) => interpolateEnvironment(item, environment));
  }
  if (isPlainObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        interpolateEnvironment(item, environment),
      ]),
    );
  }
  return value;
}

function getJsonPointer(document, pointer) {
  if (pointer === "") return { exists: true, value: document };
  if (typeof pointer !== "string" || !pointer.startsWith("/")) {
    return { exists: false, value: undefined };
  }

  let current = document;
  for (const encodedPart of pointer.slice(1).split("/")) {
    const part = encodedPart.replace(/~1/g, "/").replace(/~0/g, "~");
    if (
      (Array.isArray(current) && /^\d+$/.test(part) && Number(part) < current.length) ||
      (isPlainObject(current) && Object.hasOwn(current, part))
    ) {
      current = current[part];
      continue;
    }
    return { exists: false, value: undefined };
  }
  return { exists: true, value: current };
}

function valuesEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function check(name, passed) {
  return { name, passed: Boolean(passed) };
}

function evaluateResponse(response, expectation) {
  const checks = [];
  const expectedStatuses = Array.isArray(expectation.status)
    ? expectation.status
    : [expectation.status];
  checks.push(check(`Status is one of ${expectedStatuses.join(", ")}`, expectedStatuses.includes(response.status)));

  if (expectation.maxDurationMs !== undefined) {
    checks.push(
      check(
        `Response completes within ${expectation.maxDurationMs} ms`,
        response.durationMs <= expectation.maxDurationMs,
      ),
    );
  }

  for (const value of expectation.bodyIncludes ?? []) {
    checks.push(check(`Response body contains required marker`, response.body.includes(value)));
  }
  for (const value of expectation.bodyExcludes ?? []) {
    checks.push(check(`Response body excludes forbidden marker`, !response.body.includes(value)));
  }
  for (const [name, expectedValue] of Object.entries(expectation.headers ?? {})) {
    checks.push(
      check(
        `Header ${name.toLowerCase()} matches contract`,
        response.headers.get(name) === String(expectedValue),
      ),
    );
  }

  if (expectation.json) {
    let parsed;
    try {
      parsed = JSON.parse(response.body);
      checks.push(check("Response body is valid JSON", true));
    } catch {
      checks.push(check("Response body is valid JSON", false));
      return checks;
    }

    for (const pointer of expectation.json.requiredPaths ?? []) {
      checks.push(check(`JSON path ${pointer} is present`, getJsonPointer(parsed, pointer).exists));
    }
    for (const pointer of expectation.json.forbiddenPaths ?? []) {
      checks.push(check(`JSON path ${pointer} is absent`, !getJsonPointer(parsed, pointer).exists));
    }
    for (const [pointer, expectedValue] of Object.entries(expectation.json.equals ?? {})) {
      const actual = getJsonPointer(parsed, pointer);
      checks.push(
        check(
          `JSON path ${pointer} matches contract`,
          actual.exists && valuesEqual(actual.value, expectedValue),
        ),
      );
    }
    if (expectation.json.allowedTopLevelKeys) {
      const allowed = new Set(expectation.json.allowedTopLevelKeys);
      const keys = isPlainObject(parsed) ? Object.keys(parsed) : [];
      checks.push(
        check(
          "Response has no unexpected top-level fields",
          isPlainObject(parsed) && keys.every((key) => allowed.has(key)),
        ),
      );
    }
  }

  return checks;
}

async function readResponseBody(response, maxBytes) {
  const contentLength = Number(response.headers.get("content-length") ?? 0);
  if (contentLength > maxBytes) {
    throw new Error("Staging response exceeds the configured response size limit.");
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("Staging response exceeds the configured response size limit.");
    }
    chunks.push(decoder.decode(value, { stream: true }));
  }
  chunks.push(decoder.decode());
  return chunks.join("");
}

function sanitizeRuntimeError(error) {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/https?:\/\/[^\s)]+/gi, "[staging-target]")
    .replace(
      /(authorization|token|secret|signature|cookie)=[^&\s]+/gi,
      "$1=[REDACTED]",
    )
    .slice(0, 300);
}

async function executeRequest({
  baseUrl,
  request,
  expectation,
  target,
  allowRemote,
  environment,
  fetchImpl,
}) {
  const interpolated = interpolateEnvironment(request, environment);
  const method = String(interpolated.method ?? "POST").toUpperCase();
  const url = resolveTestUrl(baseUrl, interpolated.path, {
    allowedHosts: target.allowedHosts ?? [],
    allowedPathPrefixes: target.allowedPathPrefixes ?? ["/webhook-test/"],
    allowRemote,
  });

  const headers = new Headers(interpolated.headers ?? {});
  let body;
  if (interpolated.json !== undefined) {
    body = JSON.stringify(interpolated.json);
    if (Buffer.byteLength(body, "utf8") > MAX_REQUEST_BODY_BYTES) {
      throw new Error("Runtime request body exceeds the local safety limit.");
    }
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
  }

  const controller = new AbortController();
  const timeoutMs = target.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = performance.now();

  try {
    const response = await fetchImpl(url, {
      method,
      headers,
      body,
      redirect: "manual",
      signal: controller.signal,
    });
    const durationMs = Math.round(performance.now() - startedAt);
    const responseBody = await readResponseBody(
      response,
      target.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    );
    const responseRecord = {
      status: response.status,
      durationMs,
      headers: response.headers,
      body: responseBody,
    };
    const checks = evaluateResponse(responseRecord, expectation);

    return {
      status: response.status,
      durationMs,
      passed: checks.every((item) => item.passed),
      checks,
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function runRuntimeTest(options) {
  const { test } = options;
  const result = {
    id: test.id,
    name: test.name,
    request: {
      method: String(test.request.method ?? "POST").toUpperCase(),
      path: test.request.path,
    },
    passed: false,
    status: null,
    durationMs: null,
    checks: [],
  };

  try {
    const primary = await executeRequest({
      ...options,
      request: test.request,
      expectation: test.expect,
    });
    Object.assign(result, primary);

    if (test.observe) {
      const observation = await executeRequest({
        ...options,
        request: test.observe.request,
        expectation: test.observe.expect,
      });
      result.observation = {
        status: observation.status,
        durationMs: observation.durationMs,
        passed: observation.passed,
        checks: observation.checks,
      };
      result.passed = result.passed && observation.passed;
    }
  } catch (error) {
    result.error = sanitizeRuntimeError(error);
    result.checks.push(check("Runtime request completed safely", false));
  }

  return result;
}

function getStaticBlockers(staticAudit, threshold) {
  if (threshold === "off") return [];
  return staticAudit.findings.filter(
    (finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[threshold],
  );
}

export async function runSecurityRegressionGate({
  workflow,
  contract,
  sourcePath = "",
  targetOverride = "",
  allowRemote = false,
  environment = process.env,
  fetchImpl = fetch,
}) {
  validateSecurityContract(contract);

  const baseUrl = targetOverride || contract.target.baseUrl;
  const targetUrl = assertTargetAllowed(baseUrl, {
    allowedHosts: contract.target.allowedHosts ?? [],
    allowedPathPrefixes: contract.target.allowedPathPrefixes ?? ["/webhook-test/"],
    allowRemote,
    requireAllowedPath: false,
  });
  const staticAudit = auditN8nWorkflow(workflow);
  const staticBlockers = getStaticBlockers(
    staticAudit,
    contract.gate.failOnStaticSeverity,
  );
  const runtimeTests = [];

  for (const test of contract.tests) {
    runtimeTests.push(
      await runRuntimeTest({
        test,
        baseUrl: targetUrl,
        target: contract.target,
        allowRemote,
        environment,
        fetchImpl,
      }),
    );
  }

  const runtimePassed = runtimeTests.every((test) => test.passed);
  const passed = staticBlockers.length === 0 && runtimePassed;

  return {
    schemaVersion: 1,
    contract: {
      name: contract.name,
      failOnStaticSeverity: contract.gate.failOnStaticSeverity,
    },
    workflow: {
      name: staticAudit.workflow.name,
      sourcePath,
    },
    target: sanitizeTargetUrl(targetUrl),
    passed,
    decision: passed ? "pass" : "fail",
    static: {
      score: staticAudit.score,
      grade: staticAudit.grade,
      findings: staticAudit.findings,
      blockers: staticBlockers.map((finding) => finding.id),
    },
    runtime: {
      total: runtimeTests.length,
      passed: runtimeTests.filter((test) => test.passed).length,
      failed: runtimeTests.filter((test) => !test.passed).length,
      tests: runtimeTests,
    },
    limitations: [
      "The gate only tests the supplied workflow export and explicitly allowlisted staging endpoints.",
      "Passing results do not prove model safety, credential scope, production authorization or absence of vulnerabilities.",
      "Use redacted fixtures and isolated test credentials. Never point the gate at production.",
    ],
  };
}
