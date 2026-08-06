import { canonicalJson, fingerprintJson } from "./evidence-fingerprint.mjs";
import { RELEASE_REHEARSAL_CAPTURE_HEADERS } from "./release-rehearsal-capture.mjs";
import { RELEASE_REHEARSAL_N8N_CAPTURE_URL } from "./release-rehearsal-n8n.mjs";
import {
  preflightReleaseRehearsalActionWorkflow,
  preflightReleaseRehearsalWorkflow,
} from "./release-rehearsal-preflight.mjs";

export const RELEASE_REHEARSAL_PLAN_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_TRANSFORMATION_SCHEMA_VERSION = 1;

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertIdentifier(value, label, maxLength = 128) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength ||
    !IDENTIFIER_PATTERN.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded synthetic identifier.`);
  }
  return value;
}

function pointerChange(pointer, beforePresent, beforeValue, afterValue) {
  return {
    pointer,
    beforePresent,
    beforeCanonicalSha256: fingerprintJson(beforeValue),
    afterCanonicalSha256: fingerprintJson(afterValue),
  };
}

function publicNodeClassification(node) {
  return {
    sequence: node.sequence,
    nodeId: node.nodeId,
    nodeName: node.nodeName,
    nodeType: node.nodeType,
    typeVersion: node.typeVersion,
    active: node.active,
    classification: node.classification,
    reasonCode: node.reasonCode,
    reason: node.reason,
    requiredAdapterCapability: node.requiredAdapterCapability,
  };
}

export function planReleaseRehearsalTransformations(workflow, { variant } = {}) {
  const preflight = preflightReleaseRehearsalWorkflow(workflow, { variant });
  const nodes = preflight.nodes.map(publicNodeClassification);
  const replacements = preflight.nodes
    .filter((node) => node.classification === "SUPPORTED_CAPTURE")
    .map((node) => ({
      sequence: node.sequence,
      nodeId: node.nodeId,
      nodeName: node.nodeName,
      nodeType: node.nodeType,
      typeVersion: node.typeVersion,
      classification: node.classification,
      reasonCode: node.reasonCode,
      reason: node.reason,
      requiredAdapterCapability: node.requiredAdapterCapability,
      method: node.method,
    }));

  return {
    schemaVersion: RELEASE_REHEARSAL_PLAN_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-transformation-plan",
    evidenceStatus: "planned",
    variant: preflight.variant,
    workflow: { ...preflight.workflow },
    status: preflight.status,
    coverage: {
      status: preflight.coverage.status,
      reasonCodes: [...preflight.coverage.reasonCodes],
    },
    limits: { ...preflight.limits },
    counts: {
      ...preflight.counts,
      plannedReplacements: replacements.length,
    },
    nodes,
    replacements,
    limitations: [
      "This is a deterministic transformation plan, not an observed action.",
      "No workflow or node was executed, evaluated, replaced, or mutated.",
      "Runtime node semantics, expression evaluation, capture, and containment remain unimplemented.",
    ],
  };
}

export function serializeReleaseRehearsalPlan(plan) {
  return canonicalJson(plan) + "\n";
}

export function transformReleaseRehearsalWorkflow(
  workflow,
  {
    variant,
    runId,
    caseId,
    fixtureId,
    correlationId,
    captureUrl = RELEASE_REHEARSAL_N8N_CAPTURE_URL,
  } = {},
) {
  const metadata = {
    runId: assertIdentifier(runId, "runId"),
    caseId: assertIdentifier(caseId, "caseId"),
    fixtureId: assertIdentifier(fixtureId, "fixtureId"),
    correlationId: assertIdentifier(correlationId, "correlationId"),
  };
  if (!new Set(["baseline", "candidate"]).has(variant)) {
    throw new TypeError("variant must be baseline or candidate.");
  }
  if (captureUrl !== RELEASE_REHEARSAL_N8N_CAPTURE_URL) {
    throw new TypeError("The Phase 6 capture URL is fixed to the contained loopback route.");
  }

  const originalCanonicalSha256 = fingerprintJson(workflow);
  const preflight = preflightReleaseRehearsalActionWorkflow(workflow, { variant });
  if (preflight.status !== "PLANNABLE") {
    const error = new Error("TRANSFORM_PREFLIGHT_UNSUPPORTED");
    error.code = "TRANSFORM_PREFLIGHT_UNSUPPORTED";
    throw error;
  }

  const transformedWorkflow = structuredClone(workflow);
  const actions = [];
  for (const planned of preflight.actions) {
    const nodeIndex = planned.sequence - 1;
    const node = transformedWorkflow.nodes[nodeIndex];
    if (node?.id !== planned.nodeId || node?.name !== planned.nodeName) {
      throw new Error("TRANSFORM_NODE_BINDING_INVALID");
    }
    const actionId = `${metadata.fixtureId}:${planned.nodeId}`;
    assertIdentifier(actionId, "actionId", 768);
    const syntheticBody = canonicalJson({
      actionId,
      kind: "csint-release-rehearsal-action",
      originalBodyCanonicalSha256: fingerprintJson(
        JSON.parse(node.parameters.jsonBody),
      ),
    });
    const headers = [
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.runId, metadata.runId],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.caseId, metadata.caseId],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.variant, variant],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.fixtureId, metadata.fixtureId],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.correlationId, metadata.correlationId],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.nodeId, planned.nodeId],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.workflowSha256, originalCanonicalSha256],
      [RELEASE_REHEARSAL_CAPTURE_HEADERS.actionId, actionId],
    ].map(([name, value]) => ({ name, value }));
    const changes = [
      pointerChange(
        `/nodes/${nodeIndex}/parameters/url`,
        Object.hasOwn(node.parameters, "url"),
        node.parameters.url,
        captureUrl,
      ),
      pointerChange(
        `/nodes/${nodeIndex}/parameters/sendHeaders`,
        Object.hasOwn(node.parameters, "sendHeaders"),
        node.parameters.sendHeaders,
        true,
      ),
      pointerChange(
        `/nodes/${nodeIndex}/parameters/headerParameters`,
        Object.hasOwn(node.parameters, "headerParameters"),
        node.parameters.headerParameters,
        { parameters: headers },
      ),
      pointerChange(
        `/nodes/${nodeIndex}/parameters/jsonBody`,
        Object.hasOwn(node.parameters, "jsonBody"),
        node.parameters.jsonBody,
        syntheticBody,
      ),
    ];
    node.parameters.url = captureUrl;
    node.parameters.sendHeaders = true;
    node.parameters.headerParameters = { parameters: headers };
    node.parameters.jsonBody = syntheticBody;
    actions.push({
      actionId,
      sequence: planned.sequence,
      nodeId: planned.nodeId,
      nodeName: planned.nodeName,
      method: planned.method,
      destination: planned.destination,
      changes,
    });
  }

  if (fingerprintJson(workflow) !== originalCanonicalSha256) {
    throw new Error("ORIGINAL_WORKFLOW_MUTATED");
  }
  const transformedBasePreflight = preflightReleaseRehearsalWorkflow(
    transformedWorkflow,
    { variant },
  );
  if (transformedBasePreflight.status !== "PLANNABLE") {
    throw new Error("TRANSFORMED_WORKFLOW_INVALID");
  }
  const transformedCanonicalSha256 = fingerprintJson(transformedWorkflow);
  if (transformedCanonicalSha256 === originalCanonicalSha256) {
    throw new Error("TRANSFORMED_WORKFLOW_UNCHANGED");
  }

  const manifestBase = {
    schemaVersion: RELEASE_REHEARSAL_TRANSFORMATION_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-transformation-manifest",
    evidenceStatus: "planned",
    variant,
    fixtureId: metadata.fixtureId,
    correlation: {
      runId: metadata.runId,
      caseId: metadata.caseId,
      correlationId: metadata.correlationId,
    },
    workflow: {
      id: workflow.id,
      originalCanonicalSha256,
      transformedCanonicalSha256,
    },
    capture: {
      routeCanonicalSha256: fingerprintJson({ url: captureUrl }),
      loopbackOnly: true,
      forwardingConfigured: false,
    },
    actions,
    limitations: [
      "Planned metadata comes from the validated original export.",
      "Observed evidence requires an accepted local capture event.",
      "The transformed workflow is not the original exported workflow.",
      "No node-level execution trace is produced.",
    ],
  };
  const manifest = {
    ...manifestBase,
    manifestCanonicalSha256: fingerprintJson(manifestBase),
  };
  return deepFreeze({
    transformedWorkflow,
    manifest,
    preflight,
  });
}

export function serializeReleaseRehearsalTransformationManifest(manifest) {
  return canonicalJson(manifest) + "\n";
}
