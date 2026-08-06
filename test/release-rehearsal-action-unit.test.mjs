import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import path from "node:path";

import { canonicalJson, fingerprintJson } from "../src/evidence-fingerprint.mjs";
import {
  createReleaseRehearsalActionCaptureConfig,
  diffReleaseRehearsalObservedPair,
  normalizeReleaseRehearsalObservedActions,
  prepareReleaseRehearsalActionPair,
  serializeReleaseRehearsalActionCore,
} from "../src/release-rehearsal-action.mjs";
import { RELEASE_REHEARSAL_CAPTURE_HEADERS } from "../src/release-rehearsal-capture.mjs";
import { buildReleaseRehearsalN8nCreateArgs } from "../src/release-rehearsal-n8n-docker.mjs";
import { RELEASE_REHEARSAL_N8N_IMAGE } from "../src/release-rehearsal-n8n.mjs";
import { preflightReleaseRehearsalActionWorkflow } from "../src/release-rehearsal-preflight.mjs";
import {
  transformReleaseRehearsalWorkflow,
} from "../src/release-rehearsal-transform.mjs";

const tests = [];

function test(name, callback) {
  tests.push({ name, callback });
}

function webhookNode(path = "phase6-unit") {
  return {
    id: "entry-webhook",
    name: "Synthetic Entry",
    type: "n8n-nodes-base.webhook",
    typeVersion: 2.1,
    webhookId: "11111111-1111-4111-8111-111111111111",
    position: [0, 0],
    parameters: {
      httpMethod: "POST",
      path,
      responseMode: "lastNode",
      options: {},
    },
  };
}

function httpNode(id = "action-a", overrides = {}) {
  return {
    id,
    name: `Synthetic ${id}`,
    type: "n8n-nodes-base.httpRequest",
    typeVersion: 4.2,
    position: [240, 0],
    parameters: {
      method: "POST",
      url: "https://api.example.invalid/v1/items",
      authentication: "none",
      sendBody: true,
      contentType: "json",
      specifyBody: "json",
      jsonBody: canonicalJson({ kind: "synthetic-action", node: id }),
      options: {
        redirect: { followRedirects: false },
        response: {
          response: { fullResponse: false, responseFormat: "json" },
        },
        timeout: 5_000,
      },
      ...(overrides.parameters ?? {}),
    },
    ...Object.fromEntries(
      Object.entries(overrides).filter(([key]) => key !== "parameters"),
    ),
  };
}

function workflow(nodes = [webhookNode(), httpNode()], connections) {
  return {
    id: "csint-action-rehearsal-v1",
    name: "Synthetic Phase 6 workflow",
    active: false,
    nodes,
    connections:
      connections ?? {
        "Synthetic Entry": {
          main: [[{ node: "Synthetic action-a", type: "main", index: 0 }]],
        },
      },
    settings: { executionOrder: "v1" },
    versionId: "22222222-2222-4222-8222-222222222222",
  };
}

function fixtureSet(nodeIds = ["action-a"], overrides = {}) {
  return {
    schemaVersion: 1,
    fixtures: [
      {
        schemaVersion: 1,
        id: overrides.id ?? "fixture-unit",
        correlationId: "fixture-unit-seed",
        webhook: {
          method: "POST",
          path: "/phase6-unit",
          headers: {},
          json: { kind: "synthetic-webhook" },
        },
        nodes: nodeIds.map((nodeId) => ({
          nodeId,
          minimumOccurrences: overrides.minimumOccurrences?.[nodeId] ?? 1,
          maximumOccurrences: overrides.maximumOccurrences?.[nodeId] ?? 1,
          responses:
            overrides.responses?.[nodeId] ?? [
              {
                status: 200,
                headers: { "content-type": "application/json; charset=utf-8" },
                json: { result: "accepted" },
              },
            ],
        })),
      },
    ],
  };
}

test("the Phase 6 compatibility profile accepts one literal webhook and HTTP action", () => {
  const input = workflow();
  const result = preflightReleaseRehearsalActionWorkflow(input, {
    variant: "baseline",
  });
  assert.equal(result.status, "PLANNABLE");
  assert.equal(result.actions.length, 1);
  assert.equal(result.actions[0].method, "POST");
  assert.equal(result.staticAudit.criticalFindingCount, 0);
});

test("dynamic actions, alternate triggers, headers, and retry modes fail closed", () => {
  const cases = [
    workflow([webhookNode(), httpNode("action-a", { parameters: { url: "={{$json.url}}" } })]),
    workflow([
      { ...webhookNode(), typeVersion: 1 },
      httpNode(),
    ]),
    workflow([
      webhookNode(),
      httpNode("action-a", {
        parameters: { sendHeaders: true, headerParameters: { parameters: [] } },
      }),
    ]),
    workflow([webhookNode(), httpNode("action-a", { retryOnFail: true })]),
  ];
  for (const input of cases) {
    assert.equal(
      preflightReleaseRehearsalActionWorkflow(input, { variant: "candidate" })
        .status,
      "UNSUPPORTED",
    );
  }
});

test("transformation is immutable, original-bound, local-only, and canonical", () => {
  const input = workflow();
  const before = canonicalJson(input);
  const transformed = transformReleaseRehearsalWorkflow(input, {
    variant: "baseline",
    runId: "run-unit",
    caseId: "case-unit",
    fixtureId: "fixture-unit",
    correlationId: "correlation-unit",
  });
  assert.equal(canonicalJson(input), before);
  assert.equal(
    transformed.manifest.workflow.originalCanonicalSha256,
    fingerprintJson(input),
  );
  assert.notEqual(
    transformed.manifest.workflow.originalCanonicalSha256,
    transformed.manifest.workflow.transformedCanonicalSha256,
  );
  const action = transformed.transformedWorkflow.nodes[1];
  assert.equal(
    action.parameters.url,
    "http://127.0.0.1:18080/v1/rehearsal/capture",
  );
  assert.doesNotMatch(canonicalJson(transformed.transformedWorkflow), /api\.example/u);
  const headers = new Map(
    action.parameters.headerParameters.parameters.map((header) => [
      header.name,
      header.value,
    ]),
  );
  assert.equal(
    headers.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.workflowSha256),
    fingerprintJson(input),
  );
  assert.equal(
    headers.get(RELEASE_REHEARSAL_CAPTURE_HEADERS.actionId),
    "fixture-unit:action-a",
  );
  assert.equal(headers.size, 8);
  const transformedBody = JSON.parse(action.parameters.jsonBody);
  assert.deepEqual(Object.keys(transformedBody).sort(), [
    "actionId",
    "kind",
    "originalBodyCanonicalSha256",
  ]);
  assert.equal(transformedBody.actionId, "fixture-unit:action-a");
  assert.match(
    transformedBody.originalBodyCanonicalSha256,
    /^[a-f0-9]{64}$/u,
  );
  assert.doesNotMatch(action.parameters.jsonBody, /synthetic-action/u);
  assert.ok(
    transformed.manifest.actions[0].changes.some(
      (change) =>
        change.pointer === "/nodes/1/parameters/jsonBody" &&
        /^[a-f0-9]{64}$/u.test(change.beforeCanonicalSha256) &&
        /^[a-f0-9]{64}$/u.test(change.afterCanonicalSha256),
    ),
  );
  assert.doesNotMatch(canonicalJson(transformed.manifest), /synthetic-action/u);
});

test("server-mode arguments stay headless, exact-image, and shared-loopback only", () => {
  const runDirectory = path.join(tmpdir(), "csint-n8n-action-unit");
  const common = {
    ownerId: "owner-unit",
    runId: "n8n-action-unit",
    imageId: RELEASE_REHEARSAL_N8N_IMAGE.localImageId,
    volumeName: "csint-n8n-aaaaaaaaaaaaaaaa",
    runDirectory,
    resolverPath: path.join(runDirectory, "resolv.conf"),
    encryptionKey: "b".repeat(64),
  };
  const server = buildReleaseRehearsalN8nCreateArgs({
    ...common,
    role: "n8n-server",
    name: "server-unit",
    captureContainerId: "c".repeat(64),
  });
  assert.ok(server.includes("N8N_DISABLE_UI=true"));
  assert.ok(server.includes("container:" + "c".repeat(64)));
  assert.equal(server.at(-1), "start");
  assert.equal(server.includes("--publish"), false);
  assert.equal(server.includes("/var/run/docker.sock"), false);

  const publish = buildReleaseRehearsalN8nCreateArgs({
    ...common,
    role: "n8n-publish",
    name: "publish-unit",
    workflowId: "MixedCase_Export-ID",
  });
  assert.deepEqual(publish.slice(-3), [
    RELEASE_REHEARSAL_N8N_IMAGE.localImageId,
    "publish:workflow",
    "--id=MixedCase_Export-ID",
  ]);
});

test("pair preparation supports union fixtures without weakening present-action minima", () => {
  const baseline = workflow();
  const candidate = workflow(
    [webhookNode(), httpNode(), httpNode("action-b")],
    {
      "Synthetic Entry": {
        main: [[{ node: "Synthetic action-a", type: "main", index: 0 }]],
      },
      "Synthetic action-a": {
        main: [[{ node: "Synthetic action-b", type: "main", index: 0 }]],
      },
    },
  );
  const prepared = prepareReleaseRehearsalActionPair({
    baselineWorkflow: baseline,
    candidateWorkflow: candidate,
    fixtureSet: fixtureSet(["action-a", "action-b"], {
      minimumOccurrences: { "action-b": 0 },
    }),
  });
  assert.equal(prepared.status, "READY");
  const baselineConfig = createReleaseRehearsalActionCaptureConfig({
    runId: "run-baseline",
    caseId: "case-baseline",
    correlationId: "correlation-baseline",
    variant: "baseline",
    fixture: prepared.fixtureSet.fixtures[0],
    preflight: prepared.preflight.baseline,
  });
  const candidateConfig = createReleaseRehearsalActionCaptureConfig({
    runId: "run-candidate",
    caseId: "case-candidate",
    correlationId: "correlation-candidate",
    variant: "candidate",
    fixture: prepared.fixtureSet.fixtures[0],
    preflight: prepared.preflight.candidate,
  });
  assert.deepEqual(baselineConfig.allowedNodeIds, ["action-a"]);
  assert.deepEqual(candidateConfig.allowedNodeIds, ["action-a", "action-b"]);
  assert.ok(candidateConfig.nodes.every((node) => node.minimumOccurrences >= 1));
  assert.notEqual(baselineConfig.correlationId, candidateConfig.correlationId);
});

test("only an extended, exact capture envelope becomes observed action evidence", () => {
  const prepared = prepareReleaseRehearsalActionPair({
    baselineWorkflow: workflow(),
    candidateWorkflow: workflow(),
    fixtureSet: fixtureSet(),
  });
  const fixture = prepared.fixtureSet.fixtures[0];
  const preflight = prepared.preflight.baseline;
  const config = createReleaseRehearsalActionCaptureConfig({
    runId: "run-observed",
    caseId: "case-observed",
    correlationId: "correlation-observed",
    variant: "baseline",
    fixture,
    preflight,
  });
  const planned = preflight.actions[0];
  const event = {
    schemaVersion: 1,
    runId: config.runId,
    caseId: config.caseId,
    variant: config.variant,
    fixtureId: config.fixtureId,
    correlationId: config.correlationId,
    workflowCanonicalSha256: config.workflowCanonicalSha256,
    nodeId: planned.nodeId,
    occurrence: 1,
    actionId: `${config.fixtureId}:${planned.nodeId}`,
    correlationProfile: "extended",
    method: planned.method,
    destination: planned.destination,
    responseStubIndex: 0,
    forwarded: false,
  };
  const summary = {
    status: "COMPLETE",
    runId: config.runId,
    caseId: config.caseId,
    variant: config.variant,
    fixtureId: config.fixtureId,
    fixtureCanonicalSha256: config.fixtureCanonicalSha256,
    correlationId: config.correlationId,
    workflowCanonicalSha256: config.workflowCanonicalSha256,
    eventCount: 1,
    forwarded: false,
    violationCodes: [],
    missing: [],
    exhaustedNodeIds: [],
  };
  const dnsSummary = {
    status: "COMPLETE",
    queryCount: 0,
    forwarded: false,
    violationCodes: [],
  };
  const normalized = normalizeReleaseRehearsalObservedActions({
    events: [event],
    summary,
    dnsSummary,
    config,
    preflight,
  });
  assert.equal(normalized.status, "OBSERVED");
  assert.equal(normalized.actions[0].evidenceStatus, "observed");
  assert.equal(normalized.actions[0].attempt, 1);
  assert.equal(normalized.rawValuesRetained, false);
  assert.throws(
    () =>
      normalizeReleaseRehearsalObservedActions({
        events: [{ ...event, correlationProfile: "base" }],
        summary,
        dnsSummary,
        config,
        preflight,
      }),
    /CAPTURE_CORRELATION_MISMATCH/,
  );
});

test("observed action diffs remain deterministic and omit raw action values", () => {
  const prepared = prepareReleaseRehearsalActionPair({
    baselineWorkflow: workflow(),
    candidateWorkflow: workflow([
      webhookNode(),
      httpNode("action-a", { parameters: { method: "PATCH" } }),
    ]),
    fixtureSet: fixtureSet(),
  });
  function plannedAction(preflight) {
    const action = preflight.actions[0];
    return {
      schemaVersion: 1,
      evidenceStatus: "observed",
      variant: preflight.variant,
      fixtureId: "fixture-unit",
      workflowCanonicalSha256: preflight.workflow.canonicalSha256,
      source: { nodeId: action.nodeId, nodeName: action.nodeName },
      sequence: action.sequence,
      attempt: 1,
      intent: {
        kind: "http",
        method: action.method,
        destination: action.destination,
      },
      resolutionCode: null,
    };
  }
  const input = {
    baselineActions: [plannedAction(prepared.preflight.baseline)],
    candidateActions: [plannedAction(prepared.preflight.candidate)],
  };
  const first = diffReleaseRehearsalObservedPair(input);
  const second = diffReleaseRehearsalObservedPair(input);
  assert.equal(first.summary.method_changed, 1);
  assert.equal(canonicalJson(first), canonicalJson(second));
  assert.doesNotMatch(serializeReleaseRehearsalActionCore(first), /synthetic-action/u);

  const unresolved = diffReleaseRehearsalObservedPair({
    ...input,
    candidateCoverage: {
      status: "UNRESOLVED",
      reasonCodes: ["CAPTURE_INCOMPLETE"],
    },
  });
  assert.equal(unresolved.status, "INCOMPLETE");
  assert.equal(unresolved.summary.unresolved_coverage, 1);
  assert.equal(unresolved.summary.removed_action, 0);
  assert.equal(unresolved.summary.action_count_changed, 0);
});

let failed = 0;
for (const entry of tests) {
  try {
    await entry.callback();
  } catch (error) {
    failed += 1;
    console.error(`not ok - ${entry.name}`);
    console.error(error);
  }
}

if (failed > 0) {
  process.exitCode = 1;
} else {
  console.log(`release rehearsal action unit core: ${tests.length} tests passed`);
}
