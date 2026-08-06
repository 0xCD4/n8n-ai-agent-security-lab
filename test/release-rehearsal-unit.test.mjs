import assert from "node:assert/strict";

import { canonicalJson, fingerprintJson } from "../src/evidence-fingerprint.mjs";
import {
  diffReleaseRehearsalActions,
  RELEASE_REHEARSAL_DIFF_CATEGORIES,
  serializeReleaseRehearsalDiff,
} from "../src/release-rehearsal-diff.mjs";
import { normalizeHttpDestination } from "../src/release-rehearsal-normalize.mjs";
import {
  classifyReleaseRehearsalNode,
  preflightReleaseRehearsalWorkflow,
  RELEASE_REHEARSAL_HTTP_NODE_TYPE,
  RELEASE_REHEARSAL_MAX_ACTIVE_NODES,
} from "../src/release-rehearsal-preflight.mjs";
import {
  RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION,
  validateIntendedActionRecord,
} from "../src/release-rehearsal-schema.mjs";
import {
  planReleaseRehearsalTransformations,
  serializeReleaseRehearsalPlan,
} from "../src/release-rehearsal-transform.mjs";

const tests = [];
const COMPLETE_COVERAGE = Object.freeze({ status: "COMPLETE", reasonCodes: [] });

function test(name, callback) {
  tests.push({ name, callback });
}

function httpNode(overrides = {}) {
  const node = {
    id: "http-action",
    name: "Synthetic HTTP Action",
    type: RELEASE_REHEARSAL_HTTP_NODE_TYPE,
    typeVersion: 4.2,
    parameters: {
      method: "POST",
      url: "https://api.example.invalid/v1/items",
    },
    ...overrides,
  };
  if (overrides.parameters) {
    node.parameters = { ...overrides.parameters };
  }
  return node;
}

function controlNode(index, overrides = {}) {
  return {
    id: "control-" + index,
    name: "Synthetic Control " + index,
    type: "n8n-nodes-base.set",
    parameters: {},
    ...overrides,
  };
}

function workflow(nodes) {
  return {
    name: "Synthetic release rehearsal fixture",
    nodes,
    connections: {},
  };
}

function classifyHttp(overrides = {}) {
  return classifyReleaseRehearsalNode(httpNode(overrides));
}

function action(overrides = {}) {
  const variant = overrides.variant ?? "baseline";
  const evidenceStatus = overrides.evidenceStatus ?? "observed";
  const unresolved = evidenceStatus === "unresolved";
  return validateIntendedActionRecord({
    schemaVersion: RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION,
    evidenceStatus,
    variant,
    fixtureId: overrides.fixtureId ?? "fixture-1",
    workflowCanonicalSha256:
      overrides.workflowCanonicalSha256 ??
      (variant === "baseline" ? "a".repeat(64) : "b".repeat(64)),
    source: {
      nodeId: overrides.nodeId ?? "http-action",
      nodeName: overrides.nodeName ?? "Synthetic HTTP Action",
    },
    sequence: overrides.sequence ?? 1,
    attempt: overrides.attempt ?? 1,
    intent: unresolved
      ? null
      : {
          kind: "http",
          method: overrides.method ?? "POST",
          destination: normalizeHttpDestination(
            overrides.url ?? "https://api.example.invalid/v1/items",
          ),
        },
    resolutionCode: unresolved
      ? overrides.resolutionCode ?? "DESTINATION_DYNAMIC"
      : null,
  });
}

function diff(baselineActions, candidateActions, overrides = {}) {
  return diffReleaseRehearsalActions({
    baselineActions,
    candidateActions,
    baselineCoverage: overrides.baselineCoverage ?? COMPLETE_COVERAGE,
    candidateCoverage: overrides.candidateCoverage ?? COMPLETE_COVERAGE,
  });
}

test("supported POST is classified for capture planning", () => {
  const result = classifyHttp();
  assert.equal(result.classification, "SUPPORTED_CAPTURE");
  assert.equal(result.method, "POST");
  assert.equal(result.requiredAdapterCapability, "HTTP_CAPTURE_POST_V1");
});

test("supported PUT is classified for capture planning", () => {
  const result = classifyHttp({
    parameters: { method: "put", url: "https://api.example.invalid/v1/items/1" },
  });
  assert.equal(result.classification, "SUPPORTED_CAPTURE");
  assert.equal(result.method, "PUT");
  assert.equal(result.requiredAdapterCapability, "HTTP_CAPTURE_PUT_V1");
});

test("supported PATCH is classified for capture planning", () => {
  const result = classifyHttp({
    parameters: { method: "PATCH", url: "http://api.example.invalid:8080/v1/items/1" },
  });
  assert.equal(result.classification, "SUPPORTED_CAPTURE");
  assert.equal(result.method, "PATCH");
  assert.equal(result.requiredAdapterCapability, "HTTP_CAPTURE_PATCH_V1");
});

test("DELETE is explicitly blocked", () => {
  const result = classifyHttp({
    parameters: { method: "DELETE", url: "https://api.example.invalid/v1/items/1" },
  });
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "METHOD_DELETE_BLOCKED");
});

test("GET and HEAD fail closed as unsupported read-only coverage", () => {
  for (const method of ["GET", "HEAD"]) {
    const result = classifyHttp({
      parameters: { method, url: "https://api.example.invalid/v1/items" },
    });
    assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
    assert.equal(result.reasonCode, "METHOD_READ_ONLY_UNSUPPORTED");
  }
});

test("OPTIONS and unrecognized methods also fail closed", () => {
  const optionsResult = classifyHttp({
    parameters: { method: "OPTIONS", url: "https://api.example.invalid/v1/items" },
  });
  assert.equal(optionsResult.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(optionsResult.reasonCode, "METHOD_READ_ONLY_UNSUPPORTED");

  const traceResult = classifyHttp({
    parameters: { method: "TRACE", url: "https://api.example.invalid/v1/items" },
  });
  assert.equal(traceResult.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(traceResult.reasonCode, "METHOD_UNSUPPORTED");
});

test("dynamic methods fail closed without evaluation", () => {
  const result = classifyHttp({
    parameters: {
      method: "={{ $json.method }}",
      url: "https://api.example.invalid/v1/items",
    },
  });
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "METHOD_DYNAMIC");
});

test("missing methods fail closed instead of using the n8n GET default", () => {
  const result = classifyHttp({
    parameters: { url: "https://api.example.invalid/v1/items" },
  });
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "METHOD_MISSING");
});

test("dynamic destinations fail closed without expression evaluation", () => {
  const result = classifyHttp({
    parameters: { method: "POST", url: "={{ $json.destination }}" },
  });
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "DESTINATION_DYNAMIC");
});

test("invalid destinations fail closed", () => {
  const result = classifyHttp({
    parameters: { method: "POST", url: "not-an-absolute-url" },
  });
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "DESTINATION_INVALID");
});

test("destinations with embedded credentials are blocked", () => {
  const result = classifyHttp({
    parameters: {
      method: "POST",
      url: "https://synthetic-user:synthetic-password@api.example.invalid/v1/items",
    },
  });
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "DESTINATION_CREDENTIALS_BLOCKED");
});

test("unknown active built-in nodes are blocked", () => {
  const result = classifyReleaseRehearsalNode(
    controlNode(1, { type: "n8n-nodes-base.unknownWidget" }),
  );
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "NODE_UNSUPPORTED");
});

test("community nodes are blocked", () => {
  const result = classifyReleaseRehearsalNode(
    controlNode(1, { type: "community-nodes.externalAction" }),
  );
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "COMMUNITY_OR_CUSTOM_NODE_BLOCKED");
});

test("Code nodes are blocked", () => {
  const result = classifyReleaseRehearsalNode(
    controlNode(1, { type: "n8n-nodes-base.code" }),
  );
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "CODE_NODE_BLOCKED");
});

test("Execute Command nodes are blocked", () => {
  const result = classifyReleaseRehearsalNode(
    controlNode(1, { type: "n8n-nodes-base.executeCommand" }),
  );
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "EXECUTE_COMMAND_NODE_BLOCKED");
});

test("unresolved sub-workflow calls are unsupported", () => {
  const result = classifyReleaseRehearsalNode(
    controlNode(1, {
      type: "n8n-nodes-base.executeWorkflow",
      parameters: { workflowId: "missing-workflow" },
    }),
  );
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "SUBWORKFLOW_UNSUPPORTED");
});

test("unsupported connection channels fail closed", () => {
  const input = workflow([controlNode(1), controlNode(2)]);
  input.connections = {
    "Synthetic Control 1": {
      ai_tool: [
        [
          {
            node: "Synthetic Control 2",
            type: "ai_tool",
            index: 0,
          },
        ],
      ],
    },
  };
  const result = preflightReleaseRehearsalWorkflow(input, { variant: "baseline" });
  assert.equal(result.status, "UNSUPPORTED");
  assert.ok(result.coverage.reasonCodes.includes("PATH_UNSUPPORTED"));
});

test("more than 20 active nodes blocks planning", () => {
  const nodes = Array.from(
    { length: RELEASE_REHEARSAL_MAX_ACTIVE_NODES + 1 },
    (_, index) => controlNode(index + 1),
  );
  const result = preflightReleaseRehearsalWorkflow(workflow(nodes), {
    variant: "baseline",
  });
  assert.equal(result.status, "UNSUPPORTED");
  assert.equal(result.counts.activeNodes, 21);
  assert.ok(result.coverage.reasonCodes.includes("ACTIVE_NODE_LIMIT_EXCEEDED"));
});

test("disabled ordinary built-in nodes are excluded from active coverage", () => {
  const result = preflightReleaseRehearsalWorkflow(
    workflow([controlNode(1, { type: "n8n-nodes-base.unknownWidget", disabled: true })]),
    { variant: "baseline" },
  );
  assert.equal(result.status, "PLANNABLE");
  assert.equal(result.counts.activeNodes, 0);
  assert.equal(result.nodes[0].classification, "DISABLED_EXCLUDED");
});

test("disabled Code nodes remain blocked", () => {
  const result = classifyReleaseRehearsalNode(
    controlNode(1, { type: "n8n-nodes-base.code", disabled: true }),
  );
  assert.equal(result.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(result.reasonCode, "CODE_NODE_BLOCKED");
});

test("credential-bound nodes are blocked without serializing credential identity", () => {
  const secretCredentialId = "synthetic-credential-id-private-123456";
  const input = workflow([
    httpNode({
      credentials: {
        httpHeaderAuth: {
          id: secretCredentialId,
          name: "Synthetic private credential",
        },
      },
    }),
  ]);
  const plan = planReleaseRehearsalTransformations(input, { variant: "baseline" });
  assert.equal(plan.status, "UNSUPPORTED");
  assert.equal(plan.nodes[0].reasonCode, "CREDENTIAL_REFERENCE_PRESENT");
  assert.doesNotMatch(serializeReleaseRehearsalPlan(plan), new RegExp(secretCredentialId));
});

test("preflight and planning never mutate workflow inputs", () => {
  const input = workflow([httpNode()]);
  const before = canonicalJson(input);
  preflightReleaseRehearsalWorkflow(input, { variant: "baseline" });
  planReleaseRehearsalTransformations(input, { variant: "baseline" });
  assert.equal(canonicalJson(input), before);
});

test("strict action schema rejects secret-bearing and unknown fields", () => {
  const valid = action();
  for (const field of [
    "headers",
    "authorization",
    "cookies",
    "payload",
    "credentials",
    "productionId",
  ]) {
    assert.throws(
      () => validateIntendedActionRecord({ ...valid, [field]: "not-allowed" }),
      /contains unknown fields/,
    );
  }
  assert.throws(
    () =>
      validateIntendedActionRecord({
        ...valid,
        intent: {
          ...valid.intent,
          destination: {
            ...valid.intent.destination,
            rawUrl: "https://api.example.invalid/?token=not-allowed",
          },
        },
      }),
    /contains unknown fields/,
  );
});

test("action evidence status distinguishes observed, planned, and unresolved", () => {
  assert.equal(action({ evidenceStatus: "observed" }).evidenceStatus, "observed");
  assert.equal(action({ evidenceStatus: "planned" }).evidenceStatus, "planned");
  const unresolved = action({ evidenceStatus: "unresolved" });
  assert.equal(unresolved.evidenceStatus, "unresolved");
  assert.equal(unresolved.intent, null);
  assert.equal(unresolved.resolutionCode, "DESTINATION_DYNAMIC");
});

test("destination normalization omits query values and default ports", () => {
  const destination = normalizeHttpDestination(
    "HTTPS://API.Example.Invalid:443/v1/items?token=private-value&mode=sync&mode=again",
  );
  assert.deepEqual(destination.queryNames, ["mode", "mode", "token"]);
  assert.equal(destination.scheme, "https");
  assert.equal(destination.host, "api.example.invalid");
  assert.equal(destination.port, null);
  assert.doesNotMatch(JSON.stringify(destination), /private-value/);
});

test("added actions are detected", () => {
  const result = diff([], [action({ variant: "candidate" })]);
  assert.equal(result.summary.new_action, 1);
  assert.ok(result.changes.some((change) => change.kind === "new_action"));
});

test("removed actions are detected", () => {
  const result = diff([action()], []);
  assert.equal(result.summary.removed_action, 1);
  assert.ok(result.changes.some((change) => change.kind === "removed_action"));
});

test("destination changes are detected by normalized destination hash", () => {
  const baseline = action();
  const candidate = action({
    variant: "candidate",
    url: "https://api.example.invalid/v2/items",
  });
  const result = diff([baseline], [candidate]);
  assert.equal(result.summary.destination_changed, 1);
});

test("HTTP method changes are detected", () => {
  const result = diff(
    [action({ method: "POST" })],
    [action({ variant: "candidate", method: "PATCH" })],
  );
  assert.equal(result.summary.method_changed, 1);
});

test("action-count increases are detected without deduplication", () => {
  const result = diff(
    [action()],
    [
      action({ variant: "candidate" }),
      action({ variant: "candidate", attempt: 2 }),
    ],
  );
  const change = result.changes.find((item) => item.kind === "action_count_changed");
  assert.equal(change.direction, "increased");
  assert.equal(change.beforeCount, 1);
  assert.equal(change.afterCount, 2);
});

test("action-count decreases are detected", () => {
  const result = diff(
    [action(), action({ attempt: 2 })],
    [action({ variant: "candidate" })],
  );
  const change = result.changes.find((item) => item.kind === "action_count_changed");
  assert.equal(change.direction, "decreased");
  assert.equal(change.beforeCount, 2);
  assert.equal(change.afterCount, 1);
});

test("unsupported coverage prevents a complete comparison", () => {
  const result = diff([], [], {
    candidateCoverage: {
      status: "UNSUPPORTED",
      reasonCodes: ["NODE_UNSUPPORTED"],
    },
  });
  assert.equal(result.status, "INCOMPLETE");
  assert.equal(result.comparisonReady, false);
  assert.equal(result.summary.unsupported_coverage, 1);
  assert.ok(result.changes.some((change) => change.kind === "unsupported_coverage"));
  assert.equal(Object.hasOwn(result, "pass"), false);
});

test("unresolved coverage is reported separately", () => {
  const result = diff([], [], {
    baselineCoverage: {
      status: "UNRESOLVED",
      reasonCodes: ["DESTINATION_DYNAMIC"],
    },
  });
  assert.equal(result.status, "INCOMPLETE");
  assert.equal(result.summary.unresolved_coverage, 1);
  assert.ok(result.changes.some((change) => change.kind === "unresolved_coverage"));
});

test("planning and diff JSON are byte-for-byte deterministic", () => {
  const input = workflow([httpNode()]);
  const firstPlan = serializeReleaseRehearsalPlan(
    planReleaseRehearsalTransformations(input, { variant: "baseline" }),
  );
  const secondPlan = serializeReleaseRehearsalPlan(
    planReleaseRehearsalTransformations(input, { variant: "baseline" }),
  );
  assert.equal(firstPlan, secondPlan);

  const firstDiff = serializeReleaseRehearsalDiff(
    diff([action()], [action({ variant: "candidate" })]),
  );
  const secondDiff = serializeReleaseRehearsalDiff(
    diff([action()], [action({ variant: "candidate" })]),
  );
  assert.equal(firstDiff, secondDiff);
});

test("serialized plans and diffs omit secret-bearing source fields", () => {
  const secret = "synthetic-private-value-123456789";
  const input = workflow([
    httpNode({
      parameters: {
        method: "POST",
        url: "https://api.example.invalid/v1/items?token=" + secret,
        sendHeaders: true,
        headerParameters: {
          parameters: [{ name: "Authorization", value: "Bearer " + secret }],
        },
        sendBody: true,
        jsonBody: { customerPayload: secret, cookie: secret },
      },
    }),
  ]);
  const planJson = serializeReleaseRehearsalPlan(
    planReleaseRehearsalTransformations(input, { variant: "baseline" }),
  );
  const diffJson = serializeReleaseRehearsalDiff(
    diff(
      [action({ url: "https://api.example.invalid/v1/items?token=" + secret })],
      [
        action({
          variant: "candidate",
          url: "https://api.example.invalid/v1/items?token=" + secret,
        }),
      ],
    ),
  );
  const serialized = planJson + diffJson;
  assert.doesNotMatch(serialized, new RegExp(secret));
  assert.doesNotMatch(serialized, /authorization/i);
  assert.doesNotMatch(serialized, /customerPayload/i);
  assert.doesNotMatch(serialized, /cookie/i);
  assert.doesNotMatch(serialized, /headerParameters/i);
});

test("only the exact current HTTP Request type version is supported", () => {
  const wrongVersion = classifyHttp({ typeVersion: 4.3 });
  assert.equal(wrongVersion.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(wrongVersion.reasonCode, "NODE_VERSION_UNSUPPORTED");

  const wrongType = classifyHttp({ type: "n8n-nodes-base.httpRequestTool" });
  assert.equal(wrongType.classification, "UNSUPPORTED_BLOCKED");
  assert.equal(wrongType.reasonCode, "NODE_UNSUPPORTED");
});

test("transformation plans preserve the original workflow fingerprint", () => {
  const input = workflow([httpNode()]);
  const expected = fingerprintJson(input);
  const plan = planReleaseRehearsalTransformations(input, { variant: "candidate" });
  assert.equal(plan.workflow.canonicalSha256, expected);
  assert.equal(plan.evidenceStatus, "planned");
  assert.equal(plan.replacements.length, 1);
  assert.equal(plan.replacements[0].classification, "SUPPORTED_CAPTURE");
  assert.match(plan.limitations[0], /not an observed action/);
});

test("the declared diff category set is complete and stable", () => {
  assert.deepEqual(RELEASE_REHEARSAL_DIFF_CATEGORIES, [
    "new_action",
    "removed_action",
    "destination_changed",
    "method_changed",
    "action_count_changed",
    "unsupported_coverage",
    "unresolved_coverage",
  ]);
});

for (const { name, callback } of tests) {
  try {
    callback();
  } catch (error) {
    error.message = name + ": " + error.message;
    throw error;
  }
}

process.stdout.write("release rehearsal deterministic core: " + tests.length + " tests passed\n");
