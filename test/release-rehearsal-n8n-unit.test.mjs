import assert from "node:assert/strict";

import { canonicalJson } from "../src/evidence-fingerprint.mjs";
import {
  buildReleaseRehearsalN8nWorkflow,
  correlateReleaseRehearsalN8nCapture,
  createReleaseRehearsalN8nCaptureConfig,
  loadReleaseRehearsalN8nWorkflowTemplate,
  parseReleaseRehearsalN8nRawOutput,
  RELEASE_REHEARSAL_N8N_CAPABILITY_CODES,
  RELEASE_REHEARSAL_N8N_CAPTURE_URL,
  RELEASE_REHEARSAL_N8N_LIMITATION_CODES,
  RELEASE_REHEARSAL_N8N_NODE_BINDINGS,
  serializeReleaseRehearsalN8nLogicalResult,
} from "../src/release-rehearsal-n8n.mjs";

const tests = [];

function test(name, callback) {
  tests.push({ name, callback });
}

function taskData(executionIndex, items = [{ json: { value: "synthetic" }, pairedItem: { item: 0 } }]) {
  return {
    executionIndex,
    data: { main: [items] },
  };
}

function rawResult(overrides = {}) {
  const runData = Object.fromEntries(
    RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map((node, index) => [
      node.name,
      [taskData(index)],
    ]),
  );
  return {
    status: "success",
    mode: "cli",
    data: { resultData: { runData } },
    ...overrides,
  };
}

function parse(value, options) {
  return parseReleaseRehearsalN8nRawOutput(
    Buffer.from(JSON.stringify(value), "utf8"),
    options,
  );
}

function metadata(overrides = {}) {
  return {
    runId: "run-unit",
    caseId: "case-unit",
    variant: "baseline",
    fixtureId: "fixture-unit",
    correlationId: "correlation-unit",
    ...overrides,
  };
}

test("the fixed workflow builder preserves the exact synthetic boundary", async () => {
  const template = await loadReleaseRehearsalN8nWorkflowTemplate();
  const original = structuredClone(template);
  const built = buildReleaseRehearsalN8nWorkflow(template, metadata());
  assert.deepEqual(template, original, "the source template must not be mutated");
  assert.equal(built.workflow.nodes.length, 4);
  assert.deepEqual(
    built.workflow.nodes.map(({ id, type, typeVersion }) => ({ id, type, typeVersion })),
    RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map(({ id, type, typeVersion }) => ({
      id,
      type,
      typeVersion,
    })),
  );
  const http = built.workflow.nodes.find((node) => node.id === "csint-capture-http");
  assert.equal(http.parameters.method, "POST");
  assert.equal(http.parameters.url, RELEASE_REHEARSAL_N8N_CAPTURE_URL);
  assert.equal(http.parameters.authentication, "none");
  assert.equal(http.parameters.options.redirect.followRedirects, false);
  assert.equal(http.credentials, undefined);
  assert.doesNotMatch(http.parameters.method + http.parameters.url, /\{\{|\}\}/u);
  assert.deepEqual(JSON.parse(http.parameters.jsonBody), {
    fixture: "fixture-unit",
    kind: "synthetic-trace-probe",
    subject: "probe@rehearsal.invalid",
  });
  assert.match(built.workflowCanonicalSha256, /^[a-f0-9]{64}$/u);
});

test("strict UTF-8 JSON output normalizes only structural execution data", () => {
  const normalized = parse(rawResult());
  assert.equal(normalized.traceStatus, "TRACE_AVAILABLE");
  assert.equal(normalized.terminalStatus, "SUCCESS");
  assert.equal(normalized.executionMode, "cli");
  assert.deepEqual(
    normalized.actualNodeIds,
    RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map((node) => node.id).sort(),
  );
  assert.deepEqual(
    normalized.executionOrder.map(({ executionIndex, nodeId }) => ({
      executionIndex,
      nodeId,
    })),
    RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map((node, executionIndex) => ({
      executionIndex,
      nodeId: node.id,
    })),
  );
  assert.equal(normalized.httpNodeExecuted, true);
  assert.equal(normalized.downstreamNodeExecuted, true);
  assert.equal(normalized.pairedItemMetadataPresent, true);
});

test("prefix, suffix, and invalid UTF-8 are rejected without extraction", () => {
  const json = JSON.stringify(rawResult());
  for (const value of [`log prefix\n${json}`, `${json}\nlog suffix`]) {
    assert.throws(
      () => parseReleaseRehearsalN8nRawOutput(Buffer.from(value, "utf8")),
      (error) => error.code === "RAW_OUTPUT_JSON_INVALID",
    );
  }
  assert.throws(
    () => parseReleaseRehearsalN8nRawOutput(Buffer.from([0xc3, 0x28])),
    (error) => error.code === "RAW_OUTPUT_UTF8_INVALID",
  );
});

test("byte, depth, and value limits fail closed with stable codes", () => {
  assert.throws(
    () =>
      parseReleaseRehearsalN8nRawOutput(Buffer.from(JSON.stringify(rawResult())), {
        limits: { maxBytes: 8 },
      }),
    (error) => error.code === "RAW_OUTPUT_BYTE_LIMIT_EXCEEDED",
  );
  assert.throws(
    () =>
      parseReleaseRehearsalN8nRawOutput(
        Buffer.from(JSON.stringify({ nested: { again: { value: true } } })),
        { limits: { maxDepth: 1 } },
      ),
    (error) => error.code === "RAW_OUTPUT_DEPTH_LIMIT_EXCEEDED",
  );
  assert.throws(
    () =>
      parseReleaseRehearsalN8nRawOutput(
        Buffer.from(JSON.stringify({ values: [1, 2, 3] })),
        { limits: { maxValues: 2 } },
      ),
    (error) => error.code === "RAW_OUTPUT_VALUE_LIMIT_EXCEEDED",
  );
});

test("node, run, branch, and item limits apply before normalization", () => {
  const extraNode = rawResult();
  extraNode.data.resultData.runData["Unexpected Fifth Node"] = [taskData(4)];
  assert.throws(
    () => parse(extraNode, { limits: { maxNodes: 4 } }),
    (error) => error.code === "RAW_OUTPUT_NODE_LIMIT_EXCEEDED",
  );

  const extraRun = rawResult();
  extraRun.data.resultData.runData["CSINT Manual Trigger"].push(taskData(4));
  assert.throws(
    () => parse(extraRun, { limits: { maxRuns: 4 } }),
    (error) => error.code === "RAW_OUTPUT_RUN_LIMIT_EXCEEDED",
  );

  const extraBranch = rawResult();
  extraBranch.data.resultData.runData["CSINT Manual Trigger"][0].data.main.push([]);
  assert.throws(
    () => parse(extraBranch, { limits: { maxBranches: 4 } }),
    (error) => error.code === "RAW_OUTPUT_BRANCH_LIMIT_EXCEEDED",
  );

  const extraItem = rawResult();
  extraItem.data.resultData.runData["CSINT Manual Trigger"][0].data.main[0].push({
    json: { value: "bounded" },
  });
  assert.throws(
    () => parse(extraItem, { limits: { maxItems: 4 } }),
    (error) => error.code === "RAW_OUTPUT_ITEM_LIMIT_EXCEEDED",
  );
});

test("node names bind exactly while duplicate nodes and bindings are rejected", () => {
  const normalized = parse(rawResult());
  const byId = new Map(normalized.nodeExecutions.map((node) => [node.nodeId, node]));
  for (const binding of RELEASE_REHEARSAL_N8N_NODE_BINDINGS) {
    assert.equal(byId.get(binding.id).runCount, 1);
  }
  const duplicateBindings = RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map((node) => ({ ...node }));
  duplicateBindings[1].id = duplicateBindings[0].id;
  assert.throws(
    () => parse(rawResult(), { nodeBindings: duplicateBindings }),
    (error) => error.code === "DUPLICATE_NODE_BINDING",
  );
  const entries = RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map(
    (node, index) => `${JSON.stringify(node.name)}:${JSON.stringify([taskData(index)])}`,
  );
  const duplicateNodeJson =
    `{"status":"success","mode":"cli","data":{"resultData":{"runData":{` +
    `${entries[0]},${entries.join(",")}` +
    "}}}}";
  assert.throws(
    () =>
      parseReleaseRehearsalN8nRawOutput(
        Buffer.from(duplicateNodeJson, "utf8"),
      ),
    (error) => error.code === "RAW_OUTPUT_DUPLICATE_KEY",
  );
});

test("unknown executed nodes are rejected from the minimal trace", () => {
  const value = rawResult();
  value.data.resultData.runData["Unknown Node"] = [taskData(4)];
  const normalized = parse(value);
  assert.equal(normalized.traceStatus, "EXECUTION_TRACE_UNAVAILABLE");
  assert.ok(normalized.errorCodes.includes("UNEXPECTED_EXECUTED_NODE"));
});

test("branch indexes, item counts, run indexes, and paired metadata are structural", () => {
  const value = rawResult();
  value.data.resultData.runData["CSINT Loopback Capture"] = [
    {
      executionIndex: 2,
      data: {
        main: [
          [
            { json: { first: "value" }, pairedItem: { item: 0 } },
            { json: { second: "value" }, pairedItem: { item: 1 } },
          ],
          null,
        ],
      },
    },
  ];
  const normalized = parse(value);
  const http = normalized.nodeExecutions.find(
    (node) => node.nodeId === "csint-capture-http",
  );
  assert.equal(http.runs[0].runIndex, 0);
  assert.deepEqual(http.runs[0].outputBranches, [
    { branchIndex: 0, itemCount: 2, pairedItemMetadata: "PRESENT" },
    { branchIndex: 1, itemCount: 0, pairedItemMetadata: "NOT_APPLICABLE" },
  ]);
});

test("raw item values never enter normalized or serialized evidence", () => {
  const value = rawResult();
  value.data.resultData.runData["CSINT Synthetic Input"][0].data.main[0][0].json = {
    subject: "hidden@rehearsal.invalid",
    note: "Bearer fake-unit-value",
    nested: { raw: "must-not-survive" },
  };
  const normalized = parse(value);
  const serialized = serializeReleaseRehearsalN8nLogicalResult({
    schemaVersion: 1,
    status: "PASS_MINIMAL_TRACE",
    execution: normalized,
  });
  assert.doesNotMatch(
    serialized,
    /hidden|rehearsal\.invalid|Bearer|fake-unit-value|must-not-survive/iu,
  );
});

test("missing HTTP and downstream nodes receive distinct stable codes", () => {
  const withoutHttp = rawResult();
  delete withoutHttp.data.resultData.runData["CSINT Loopback Capture"];
  const httpResult = parse(withoutHttp);
  assert.ok(httpResult.errorCodes.includes("HTTP_NODE_EXECUTION_MISSING"));
  assert.ok(httpResult.errorCodes.includes("EXPECTED_NODE_MISSING"));

  const withoutDownstream = rawResult();
  delete withoutDownstream.data.resultData.runData["CSINT Downstream Proof"];
  const downstreamResult = parse(withoutDownstream);
  assert.ok(
    downstreamResult.errorCodes.includes("DOWNSTREAM_NODE_EXECUTION_MISSING"),
  );
  assert.ok(downstreamResult.errorCodes.includes("EXPECTED_NODE_MISSING"));
});

test("missing explicit order and paired-item metadata stay unknown", () => {
  const value = rawResult();
  for (const runs of Object.values(value.data.resultData.runData)) {
    delete runs[0].executionIndex;
    delete runs[0].data.main[0][0].pairedItem;
  }
  const normalized = parse(value);
  assert.equal(normalized.traceStatus, "TRACE_AVAILABLE");
  assert.equal(normalized.executionOrder, null);
  assert.equal(normalized.pairedItemMetadataPresent, false);
  assert.deepEqual(normalized.limitationCodes, [
    "EXECUTION_ORDER_UNAVAILABLE",
    "ITEM_LINK_VISIBILITY_UNKNOWN",
  ]);
});

test("capture correlation requires one exact event and a clean DNS summary", async () => {
  const template = await loadReleaseRehearsalN8nWorkflowTemplate();
  const built = buildReleaseRehearsalN8nWorkflow(template, metadata());
  const config = createReleaseRehearsalN8nCaptureConfig({
    metadata: built.metadata,
    workflowCanonicalSha256: built.workflowCanonicalSha256,
  });
  const event = {
    runId: config.runId,
    caseId: config.caseId,
    variant: config.variant,
    fixtureId: config.fixtureId,
    correlationId: config.correlationId,
    workflowCanonicalSha256: config.workflowCanonicalSha256,
    nodeId: "csint-capture-http",
    method: "POST",
    forwarded: false,
  };
  const summary = {
    ...event,
    status: "COMPLETE",
    eventCount: 1,
    violationCodes: [],
  };
  const dnsSummary = {
    status: "COMPLETE",
    queryCount: 0,
    violationCodes: [],
    forwarded: false,
  };
  const correlated = correlateReleaseRehearsalN8nCapture({
    events: [event],
    summary,
    dnsSummary,
    expected: event,
  });
  assert.equal(correlated.status, "CORRELATED");
  assert.deepEqual(correlated.errorCodes, []);

  const mismatch = correlateReleaseRehearsalN8nCapture({
    events: [{ ...event, correlationId: "wrong-correlation" }, event],
    summary: { ...summary, status: "FAILED", eventCount: 2 },
    dnsSummary: { ...dnsSummary, queryCount: 1 },
    expected: event,
  });
  assert.equal(mismatch.status, "MISMATCH");
  assert.deepEqual(mismatch.errorCodes, [
    "CAPTURE_CORRELATION_MISMATCH",
    "CAPTURE_EVENT_COUNT_MISMATCH",
    "CAPTURE_SUMMARY_INVALID",
    "DNS_CONTAINMENT_VIOLATION",
  ]);
});

test("logical serialization and stable code sets are deterministic", () => {
  const normalized = parse(rawResult());
  const left = serializeReleaseRehearsalN8nLogicalResult({
    schemaVersion: 1,
    status: "PASS_MINIMAL_TRACE",
    execution: normalized,
    operational: { rawStdout: "excluded" },
  });
  const right = serializeReleaseRehearsalN8nLogicalResult({
    operational: { rawStdout: "different excluded value" },
    execution: normalized,
    status: "PASS_MINIMAL_TRACE",
    schemaVersion: 1,
  });
  assert.equal(left, right);
  assert.deepEqual(RELEASE_REHEARSAL_N8N_CAPABILITY_CODES, [
    "CLI_IMPORT_AVAILABLE",
    "CLI_RAW_OUTPUT_AVAILABLE",
    "CLI_WORKFLOW_ID_EXECUTION_AVAILABLE",
    "MINIMAL_EXECUTION_TRACE_AVAILABLE",
  ]);
  assert.deepEqual(RELEASE_REHEARSAL_N8N_LIMITATION_CODES, [
    "ARBITRARY_WORKFLOW_SUPPORT_UNIMPLEMENTED",
    "CUSTOMER_WORKFLOW_EXECUTION_UNIMPLEMENTED",
    "EXECUTION_ORDER_UNAVAILABLE",
    "FULL_EXECUTION_ADAPTER_UNIMPLEMENTED",
    "ITEM_LINK_VISIBILITY_UNKNOWN",
    "RETRY_VISIBILITY_UNIMPLEMENTED",
    "LOOP_VISIBILITY_UNIMPLEMENTED",
    "WEBHOOK_EXECUTION_UNIMPLEMENTED",
  ]);
  assert.equal(canonicalJson(normalized), canonicalJson(parse(rawResult())));
});

for (const { name, callback } of tests) {
  try {
    await callback();
  } catch (error) {
    error.message = `${name}: ${error.message}`;
    throw error;
  }
}

process.stdout.write(`release rehearsal n8n unit core: ${tests.length} tests passed\n`);
