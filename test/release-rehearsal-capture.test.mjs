import assert from "node:assert/strict";
import { request } from "node:http";

import { canonicalJson } from "../src/evidence-fingerprint.mjs";
import {
  createReleaseRehearsalCaptureService,
  RELEASE_REHEARSAL_CAPTURE_EVENT_SCHEMA_VERSION,
  RELEASE_REHEARSAL_CAPTURE_HEADERS,
  RELEASE_REHEARSAL_CAPTURE_ROUTE,
} from "../src/release-rehearsal-capture.mjs";
import {
  createReleaseRehearsalCaptureConfig,
  RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION,
  RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
  RELEASE_REHEARSAL_MAX_CAPTURE_BODY_BYTES,
  loadReleaseRehearsalFixtureSet,
  validateReleaseRehearsalCaptureConfig,
  validateReleaseRehearsalFixtureSet,
} from "../src/release-rehearsal-fixture.mjs";
import { normalizeHttpDestination } from "../src/release-rehearsal-normalize.mjs";

const tests = [];
const WORKFLOW_SHA256 = "a".repeat(64);

function test(name, callback) {
  tests.push({ name, callback });
}

function responseStub(status = 200, label = "accepted") {
  return {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "x-synthetic-response": label,
    },
    json: { result: label },
  };
}

function fixtureNode(
  nodeId = "node-post",
  {
    minimumOccurrences = 1,
    maximumOccurrences = 1,
    responses = [responseStub()],
  } = {},
) {
  return {
    nodeId,
    minimumOccurrences,
    maximumOccurrences,
    responses,
  };
}

function rawFixture(
  id = "fixture-one",
  correlationId = "correlation-one",
  nodes = [fixtureNode()],
) {
  return {
    schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
    id,
    correlationId,
    webhook: {
      method: "POST",
      path: "/synthetic-trigger",
      headers: { "content-type": "application/json" },
      json: {
        caseLabel: id,
        sourceUrl: "https://source.example.invalid/input",
      },
    },
    nodes,
  };
}

function validatedFixture(fixture = rawFixture()) {
  return validateReleaseRehearsalFixtureSet({
    schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
    fixtures: [fixture],
  }).fixtures[0];
}

function captureConfig({
  fixture = validatedFixture(),
  variant = "baseline",
  methods = {},
  runId = "run-one",
  caseId = "case-one",
} = {}) {
  return createReleaseRehearsalCaptureConfig({
    schemaVersion: RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION,
    runId,
    caseId,
    variant,
    fixture,
    workflowCanonicalSha256: WORKFLOW_SHA256,
    plannedNodes: fixture.nodes.map((node) => ({
      nodeId: node.nodeId,
      method: methods[node.nodeId] ?? "POST",
      destination: normalizeHttpDestination(
        "https://api.example.invalid/v1/" + encodeURIComponent(node.nodeId),
      ),
    })),
  });
}

function requestHeaders(config, nodeId, additions = {}) {
  return {
    "content-type": "application/json",
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.runId]: config.runId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.caseId]: config.caseId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.variant]: config.variant,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.fixtureId]: config.fixtureId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.correlationId]: config.correlationId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.nodeId]: nodeId,
    "x-synthetic-note": "bounded-note",
    ...additions,
  };
}

function sendCaptureRequest(
  service,
  {
    method = "POST",
    path = RELEASE_REHEARSAL_CAPTURE_ROUTE,
    nodeId = service.config.allowedNodeIds[0],
    headers = requestHeaders(service.config, nodeId),
    body = '{"value":"synthetic-value"}',
  } = {},
) {
  const address = service.server.address();
  return new Promise((resolve, reject) => {
    const outgoing = request(
      {
        host: "127.0.0.1",
        port: address.port,
        method,
        path,
        headers,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = null;
          if (text) {
            try {
              json = JSON.parse(text);
            } catch {
              json = null;
            }
          }
          resolve({ status: response.statusCode, headers: response.headers, text, json });
        });
      },
    );
    outgoing.on("error", reject);
    outgoing.end(body);
  });
}

async function withService(config, callback) {
  const service = createReleaseRehearsalCaptureService(config);
  await new Promise((resolve, reject) => {
    service.server.once("error", reject);
    service.server.listen(0, "127.0.0.1", resolve);
  });
  try {
    return await callback(service);
  } finally {
    await new Promise((resolve, reject) => {
      service.server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

test("fixture sets accept exactly one, two, and three sanitized fixtures", () => {
  for (const count of [1, 2, 3]) {
    const fixtures = Array.from({ length: count }, (_, index) =>
      rawFixture(
        "fixture-" + (index + 1),
        "correlation-" + (index + 1),
        [fixtureNode("node-" + (index + 1))],
      ),
    );
    const result = validateReleaseRehearsalFixtureSet({
      schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
      fixtures,
    });
    assert.equal(result.fixtures.length, count);
    assert.ok(result.fixtures.every((fixture) => /^[a-f0-9]{64}$/u.test(fixture.canonicalSha256)));
  }
});

test("fixture sets reject zero and four fixtures", () => {
  assert.throws(
    () =>
      validateReleaseRehearsalFixtureSet({
        schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
        fixtures: [],
      }),
    /between one and three fixtures/,
  );
  assert.throws(
    () =>
      validateReleaseRehearsalFixtureSet({
        schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
        fixtures: Array.from({ length: 4 }, (_, index) =>
          rawFixture(
            "fixture-" + index,
            "correlation-" + index,
            [fixtureNode("node-" + index)],
          ),
        ),
      }),
    /between one and three fixtures/,
  );
});

test("bounded fixture loading redacts file-system errors behind a stable code", async () => {
  const privatePathMarker = "synthetic-private-fixture-path-918273.json";
  await assert.rejects(
    loadReleaseRehearsalFixtureSet(privatePathMarker),
    (error) => {
      assert.equal(error.code, "INPUT_INVALID");
      assert.doesNotMatch(error.message, new RegExp(privatePathMarker));
      return true;
    },
  );
});

test("fixture validation rejects unknown, duplicate, secret-like, live, and unbounded data", () => {
  assert.throws(
    () =>
      validateReleaseRehearsalFixtureSet({
        schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
        fixtures: [{ ...rawFixture(), unknown: true }],
      }),
    /unknown fields/,
  );
  assert.throws(
    () =>
      validateReleaseRehearsalFixtureSet({
        schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
        fixtures: [rawFixture(), rawFixture()],
      }),
    /duplicate fixture IDs/,
  );
  assert.throws(
    () =>
      validateReleaseRehearsalFixtureSet({
        schemaVersion: RELEASE_REHEARSAL_FIXTURE_SET_SCHEMA_VERSION,
        fixtures: [
          rawFixture("fixture-one", "same-correlation"),
          rawFixture("fixture-two", "same-correlation", [fixtureNode("node-two")]),
        ],
      }),
    /duplicate correlation IDs/,
  );
  assert.throws(
    () =>
      validatedFixture(
        rawFixture("fixture-one", "correlation-one", [
          fixtureNode(),
          fixtureNode(),
        ]),
      ),
    /duplicate node IDs/,
  );

  const passwordFixture = rawFixture();
  passwordFixture.webhook.json = { password: "fake-but-forbidden" };
  assert.throws(() => validatedFixture(passwordFixture), /forbidden field name/);

  const externalUrlFixture = rawFixture();
  externalUrlFixture.nodes[0].responses[0].json = {
    nextUrl: "ftp://production.example.invalid/next",
  };
  assert.throws(() => validatedFixture(externalUrlFixture), /unsupported external URL/);

  const liveIdentifierFixture = rawFixture();
  liveIdentifierFixture.webhook.json = { label: "prod_customer_123" };
  assert.throws(() => validatedFixture(liveIdentifierFixture), /live-style identifier/);

  const oversizedFixture = rawFixture();
  oversizedFixture.webhook.json = { value: "x".repeat(2_049) };
  assert.throws(() => validatedFixture(oversizedFixture), /oversized text/);

  const redirectFixture = rawFixture();
  redirectFixture.nodes[0].responses[0].status = 302;
  assert.throws(() => validatedFixture(redirectFixture), /status is unsupported/);
});

test("capture configuration is strict, exact, immutable, and input preserving", () => {
  const fixture = validatedFixture();
  const plannedNodes = fixture.nodes.map((node) => ({
    nodeId: node.nodeId,
    method: "POST",
    destination: normalizeHttpDestination("https://api.example.invalid/v1/items"),
  }));
  const input = {
    schemaVersion: RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION,
    runId: "run-one",
    caseId: "case-one",
    variant: "baseline",
    fixture,
    workflowCanonicalSha256: WORKFLOW_SHA256,
    plannedNodes,
  };
  const before = canonicalJson(input);
  const config = createReleaseRehearsalCaptureConfig(input);
  assert.equal(canonicalJson(input), before);
  assert.ok(Object.isFrozen(config));
  assert.ok(Object.isFrozen(config.nodes[0].responseStubs[0].json));
  assert.throws(() => {
    config.runId = "changed";
  }, TypeError);
  assert.throws(
    () => createReleaseRehearsalCaptureConfig({ ...input, unknown: true }),
    /unknown fields/,
  );
  assert.throws(
    () =>
      createReleaseRehearsalCaptureConfig({
        ...input,
        plannedNodes: [plannedNodes[0], plannedNodes[0]],
      }),
    /duplicate node IDs/,
  );
  assert.throws(
    () => validateReleaseRehearsalCaptureConfig({ ...config, unknown: true }),
    /unknown fields/,
  );
});

test("baseline and candidate configurations preserve one fixture identity", () => {
  const fixture = validatedFixture();
  const baseline = captureConfig({ fixture, variant: "baseline" });
  const candidate = captureConfig({ fixture, variant: "candidate" });
  assert.equal(baseline.fixtureCanonicalSha256, candidate.fixtureCanonicalSha256);
  assert.equal(baseline.correlationId, candidate.correlationId);
});

test("valid POST, PUT, and PATCH use deterministic ordered stubs and occurrences", async () => {
  const fixture = validatedFixture(
    rawFixture("fixture-methods", "correlation-methods", [
      fixtureNode("node-post", {
        minimumOccurrences: 2,
        maximumOccurrences: 2,
        responses: [responseStub(201, "post-first"), responseStub(202, "post-second")],
      }),
      fixtureNode("node-put", { responses: [responseStub(200, "put-first")] }),
      fixtureNode("node-patch", { responses: [responseStub(200, "patch-first")] }),
    ]),
  );
  const config = captureConfig({
    fixture,
    methods: { "node-post": "POST", "node-put": "PUT", "node-patch": "PATCH" },
  });

  await withService(config, async (service) => {
    const firstPost = await sendCaptureRequest(service, { nodeId: "node-post" });
    const put = await sendCaptureRequest(service, {
      method: "PUT",
      nodeId: "node-put",
      headers: requestHeaders(config, "node-put"),
    });
    const secondPost = await sendCaptureRequest(service, { nodeId: "node-post" });
    const patch = await sendCaptureRequest(service, {
      method: "PATCH",
      nodeId: "node-patch",
      headers: requestHeaders(config, "node-patch"),
    });

    assert.equal(firstPost.status, 201);
    assert.deepEqual(firstPost.json, { result: "post-first" });
    assert.equal(secondPost.status, 202);
    assert.deepEqual(secondPost.json, { result: "post-second" });
    assert.equal(put.status, 200);
    assert.equal(patch.status, 200);

    const events = service.getEvents();
    assert.deepEqual(
      events.map((event) => [event.nodeId, event.occurrence, event.responseStubIndex]),
      [
        ["node-post", 1, 0],
        ["node-put", 1, 0],
        ["node-post", 2, 1],
        ["node-patch", 1, 0],
      ],
    );
    assert.ok(events.every((event) => event.forwarded === false));
    assert.ok(events.every((event) => event.schemaVersion === RELEASE_REHEARSAL_CAPTURE_EVENT_SCHEMA_VERSION));
    assert.ok(events.every((event) => !Object.hasOwn(event, "evidenceStatus")));
    assert.equal(service.finalize().status, "COMPLETE");
  });
});

test("missing expected captures finalize as INCOMPLETE", async () => {
  const fixture = validatedFixture(
    rawFixture("fixture-missing", "correlation-missing", [
      fixtureNode("node-post", {
        minimumOccurrences: 2,
        maximumOccurrences: 2,
        responses: [responseStub(200, "first"), responseStub(200, "second")],
      }),
    ]),
  );
  await withService(captureConfig({ fixture }), async (service) => {
    await sendCaptureRequest(service);
    const summary = service.finalize();
    assert.equal(summary.status, "INCOMPLETE");
    assert.deepEqual(summary.missing, [
      { nodeId: "node-post", receivedOccurrences: 1, minimumOccurrences: 2 },
    ]);
  });
});

test("response sequences exhaust without repeating the final stub", async () => {
  const fixture = validatedFixture(
    rawFixture("fixture-exhaust", "correlation-exhaust", [
      fixtureNode("node-post", {
        minimumOccurrences: 1,
        maximumOccurrences: 2,
        responses: [responseStub(200, "only-response")],
      }),
    ]),
  );
  await withService(captureConfig({ fixture }), async (service) => {
    const first = await sendCaptureRequest(service);
    const exhausted = await sendCaptureRequest(service);
    assert.equal(first.status, 200);
    assert.equal(exhausted.status, 409);
    assert.equal(exhausted.json.error.code, "RESPONSE_SEQUENCE_EXHAUSTED");
    assert.equal(service.getEvents().length, 1);
    const summary = service.finalize();
    assert.equal(summary.status, "INCOMPLETE");
    assert.deepEqual(summary.exhaustedNodeIds, ["node-post"]);
  });
});

test("occurrences beyond the configured ceiling fail closed", async () => {
  await withService(captureConfig(), async (service) => {
    await sendCaptureRequest(service);
    const rejected = await sendCaptureRequest(service);
    assert.equal(rejected.status, 409);
    assert.equal(rejected.json.error.code, "OCCURRENCE_LIMIT_EXCEEDED");
    assert.equal(service.finalize().status, "FAILED");
  });
});

test("unknown nodes and wrong correlation metadata fail with fixed codes", async () => {
  await withService(captureConfig(), async (service) => {
    const unknown = await sendCaptureRequest(service, {
      nodeId: "unknown-node",
      headers: requestHeaders(service.config, "unknown-node"),
    });
    assert.equal(unknown.json.error.code, "NODE_UNKNOWN");

    const metadataCases = [
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.runId, "wrong-run"],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.caseId, "wrong-case"],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.variant, "candidate"],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.fixtureId, "wrong-fixture"],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.correlationId, "wrong-correlation"],
    ];
    for (const [name, value] of metadataCases) {
      const response = await sendCaptureRequest(service, {
        headers: requestHeaders(service.config, "node-post", { [name]: value }),
      });
      assert.equal(response.status, 409);
      assert.equal(response.json.error.code, "METADATA_MISMATCH");
    }
    assert.equal(service.finalize().status, "FAILED");
  });
});

test("missing, duplicate, malformed, and unexpected reserved metadata are rejected", async () => {
  await withService(captureConfig(), async (service) => {
    const missingHeaders = requestHeaders(service.config, "node-post");
    delete missingHeaders[RELEASE_REHEARSAL_CAPTURE_HEADERS.correlationId];
    const missing = await sendCaptureRequest(service, { headers: missingHeaders });
    assert.equal(missing.json.error.code, "METADATA_MISSING");

    const duplicate = await sendCaptureRequest(service, {
      headers: requestHeaders(service.config, "node-post", {
        [RELEASE_REHEARSAL_CAPTURE_HEADERS.runId]: [
          service.config.runId,
          service.config.runId,
        ],
      }),
    });
    assert.equal(duplicate.json.error.code, "METADATA_DUPLICATE");

    const malformed = await sendCaptureRequest(service, {
      headers: requestHeaders(service.config, "node-post", {
        [RELEASE_REHEARSAL_CAPTURE_HEADERS.caseId]: "invalid case value",
      }),
    });
    assert.equal(malformed.json.error.code, "METADATA_INVALID");

    const unexpected = await sendCaptureRequest(service, {
      headers: requestHeaders(service.config, "node-post", {
        "x-csint-rehearsal-extra": "unexpected",
      }),
    });
    assert.equal(unexpected.json.error.code, "METADATA_UNEXPECTED");
    assert.equal(service.finalize().status, "FAILED");
  });
});

test("method mismatch, unknown route, GET, and DELETE are rejected", async () => {
  await withService(captureConfig(), async (service) => {
    const mismatch = await sendCaptureRequest(service, { method: "PUT" });
    assert.equal(mismatch.json.error.code, "METHOD_MISMATCH");
    const route = await sendCaptureRequest(service, {
      path: "/v1/rehearsal/unknown?raw=private-query-value",
    });
    assert.equal(route.status, 404);
    assert.equal(route.json.error.code, "ROUTE_UNEXPECTED");
    for (const method of ["GET", "DELETE"]) {
      const response = await sendCaptureRequest(service, { method });
      assert.equal(response.status, 405);
      assert.equal(response.json.error.code, "METHOD_UNSUPPORTED");
    }
    assert.equal(service.finalize().status, "FAILED");
  });
});

test("malformed JSON, oversized bodies, unsupported content types, and header limits fail", async () => {
  const fixture = validatedFixture(
    rawFixture("fixture-invalid", "correlation-invalid", [
      fixtureNode("node-post", {
        minimumOccurrences: 0,
        maximumOccurrences: 3,
        responses: [responseStub(), responseStub(), responseStub()],
      }),
    ]),
  );
  await withService(captureConfig({ fixture }), async (service) => {
    const malformed = await sendCaptureRequest(service, { body: "{" });
    assert.equal(malformed.json.error.code, "BODY_JSON_INVALID");

    const unsupported = await sendCaptureRequest(service, {
      headers: requestHeaders(service.config, "node-post", {
        "content-type": "text/plain",
      }),
    });
    assert.equal(unsupported.status, 415);
    assert.equal(unsupported.json.error.code, "CONTENT_TYPE_UNSUPPORTED");

    const oversized = await sendCaptureRequest(service, {
      body: JSON.stringify({ value: "x".repeat(RELEASE_REHEARSAL_MAX_CAPTURE_BODY_BYTES) }),
    });
    assert.equal(oversized.status, 413);
    assert.equal(oversized.json.error.code, "BODY_LIMIT_EXCEEDED");

    const manyHeaders = requestHeaders(service.config, "node-post");
    for (let index = 0; index < 70; index += 1) {
      manyHeaders["x-synthetic-" + index] = "value";
    }
    const headerLimit = await sendCaptureRequest(service, { headers: manyHeaders });
    assert.equal(headerLimit.status, 431);
    assert.equal(headerLimit.json.error.code, "HEADER_LIMIT_EXCEEDED");
    assert.equal(service.finalize().status, "FAILED");
  });
});

test("sensitive request headers and secret-bearing JSON fields are forbidden", async () => {
  const fixture = validatedFixture(
    rawFixture("fixture-sensitive", "correlation-sensitive", [
      fixtureNode("node-post", {
        minimumOccurrences: 0,
        maximumOccurrences: 1,
        responses: [responseStub()],
      }),
    ]),
  );
  await withService(captureConfig({ fixture }), async (service) => {
    const authorization = await sendCaptureRequest(service, {
      headers: requestHeaders(service.config, "node-post", {
        Authorization: "Bearer fake-private-value",
      }),
    });
    assert.equal(authorization.json.error.code, "SENSITIVE_HEADER_FORBIDDEN");

    const secretBody = await sendCaptureRequest(service, {
      body: '{"apiToken":"fake-private-value"}',
    });
    assert.equal(secretBody.json.error.code, "BODY_POLICY_VIOLATION");
    assert.equal(service.finalize().status, "FAILED");
  });
});

test("serialized events omit raw body, header, and query values", async () => {
  const rawBodyValue = "raw-body-value-123456";
  const rawHeaderValue = "raw-header-value-123456";
  const rawQueryValue = "raw-query-value-123456";
  await withService(captureConfig(), async (service) => {
    const response = await sendCaptureRequest(service, {
      headers: requestHeaders(service.config, "node-post", {
        "x-synthetic-note": rawHeaderValue,
      }),
      body: JSON.stringify({
        payload: rawBodyValue,
        callbackUrl:
          "https://callback.example.invalid/path?marker=" + rawQueryValue,
      }),
    });
    assert.equal(response.status, 200);
    const event = service.getEvents()[0];
    assert.deepEqual(event.headerNames, ["content-type", "x-synthetic-note"]);
    assert.equal(event.forwarded, false);
    const serialized = service.serializeEvents() + canonicalJson(service.finalize());
    assert.doesNotMatch(serialized, new RegExp(rawBodyValue));
    assert.doesNotMatch(serialized, new RegExp(rawHeaderValue));
    assert.doesNotMatch(serialized, new RegExp(rawQueryValue));
    assert.doesNotMatch(serialized, /authorization|cookie|set-cookie/i);
  });
});

test("error responses and summaries never reflect rejected request values", async () => {
  const rejectedValue = "raw-secret-node-marker-123456";
  await withService(captureConfig(), async (service) => {
    const response = await sendCaptureRequest(service, {
      nodeId: rejectedValue,
      headers: requestHeaders(service.config, rejectedValue),
    });
    assert.equal(response.json.error.code, "NODE_UNKNOWN");
    const serialized = response.text + canonicalJson(service.finalize());
    assert.doesNotMatch(serialized, new RegExp(rejectedValue));
  });
});

test("requests after finalization cannot mutate the capture ledger", async () => {
  const fixture = validatedFixture(
    rawFixture("fixture-late", "correlation-late", [
      fixtureNode("node-post", {
        minimumOccurrences: 1,
        maximumOccurrences: 2,
        responses: [responseStub(200, "first"), responseStub(200, "second")],
      }),
    ]),
  );
  await withService(captureConfig({ fixture }), async (service) => {
    await sendCaptureRequest(service);
    const before = service.serializeEvents();
    assert.equal(service.finalize().status, "COMPLETE");
    const late = await sendCaptureRequest(service);
    assert.equal(late.status, 409);
    assert.equal(late.json.error.code, "REQUEST_AFTER_FINALIZATION");
    assert.equal(service.serializeEvents(), before);
    const summary = service.finalize();
    assert.equal(summary.status, "FAILED");
    assert.deepEqual(summary.violationCodes, ["REQUEST_AFTER_FINALIZATION"]);
    assert.equal(summary.nodeCounts[0].receivedOccurrences, 1);
  });
});

test("capture event and summary serialization is byte-for-byte deterministic", async () => {
  const config = captureConfig();
  async function transcript() {
    return withService(config, async (service) => {
      await sendCaptureRequest(service, {
        body: '{"alpha":1,"nested":{"enabled":true}}',
      });
      return service.serializeEvents() + service.serializeSummary();
    });
  }
  const first = await transcript();
  const second = await transcript();
  assert.equal(first, second);
  assert.match(first, /"forwarded":false/u);
  assert.doesNotMatch(first, /timestamp|evidenceStatus/u);
});

for (const { name, callback } of tests) {
  try {
    await callback();
  } catch (error) {
    error.message = name + ": " + error.message;
    throw error;
  }
}

process.stdout.write(
  "release rehearsal local capture core: " + tests.length + " tests passed\n",
);
