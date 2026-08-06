import { canonicalJson, fingerprintJson } from "./evidence-fingerprint.mjs";
import { diffReleaseRehearsalActions } from "./release-rehearsal-diff.mjs";
import {
  RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION,
  validateReleaseRehearsalCaptureConfig,
  validateReleaseRehearsalFixtureSet,
} from "./release-rehearsal-fixture.mjs";
import { preflightReleaseRehearsalActionWorkflow } from "./release-rehearsal-preflight.mjs";
import {
  RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION,
  validateIntendedActionRecord,
} from "./release-rehearsal-schema.mjs";

export const RELEASE_REHEARSAL_ACTION_CORE_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_ACTION_OUTCOMES = Object.freeze([
  "PASS_ACTION_REHEARSAL_CORE",
  "PARTIAL_ACTION_REHEARSAL",
  "BLOCKED_TRANSFORMATION_FIDELITY",
  "FAIL_CONTAINMENT",
]);

const MAX_OBSERVED_ACTIONS = 100;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableUnique(values) {
  return [...new Set(values)].sort(stableCompare);
}

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

function assertSha256(value, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 value.`);
  }
  return value;
}

function workflowEntryMaterial(workflow) {
  const trigger = workflow.nodes.find(
    (node) => node.disabled !== true && node.type === "n8n-nodes-base.webhook",
  );
  return trigger
    ? {
        method: trigger.parameters.httpMethod,
        path: `/${trigger.parameters.path}`,
      }
    : null;
}

function coverage(preflight) {
  return {
    status: preflight.coverage.status,
    reasonCodes: [...preflight.coverage.reasonCodes],
  };
}

function unsupportedPreparation(baselinePreflight, candidatePreflight) {
  const baselineCoverage = coverage(baselinePreflight);
  const candidateCoverage = coverage(candidatePreflight);
  return deepFreeze({
    schemaVersion: RELEASE_REHEARSAL_ACTION_CORE_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-action-pair-preparation",
    status: "UNSUPPORTED",
    executionAuthorized: false,
    baselinePreflight,
    candidatePreflight,
    fixtureSet: null,
    diff: diffReleaseRehearsalActions({
      baselineActions: [],
      candidateActions: [],
      baselineCoverage,
      candidateCoverage,
    }),
    reasonCodes: stableUnique([
      ...baselineCoverage.reasonCodes,
      ...candidateCoverage.reasonCodes,
    ]),
  });
}

export function prepareReleaseRehearsalActionPair({
  baselineWorkflow,
  candidateWorkflow,
  fixtureSet,
}) {
  const baselinePreflight = preflightReleaseRehearsalActionWorkflow(
    baselineWorkflow,
    { variant: "baseline" },
  );
  const candidatePreflight = preflightReleaseRehearsalActionWorkflow(
    candidateWorkflow,
    { variant: "candidate" },
  );
  if (
    baselinePreflight.status !== "PLANNABLE" ||
    candidatePreflight.status !== "PLANNABLE"
  ) {
    return unsupportedPreparation(baselinePreflight, candidatePreflight);
  }

  const validatedFixtureSet = validateReleaseRehearsalFixtureSet(fixtureSet);
  const baselineEntry = workflowEntryMaterial(baselineWorkflow);
  const candidateEntry = workflowEntryMaterial(candidateWorkflow);
  if (
    canonicalJson(baselineEntry) !== canonicalJson(candidateEntry) ||
    validatedFixtureSet.fixtures.some(
      (fixture) =>
        fixture.webhook.method !== baselineEntry.method ||
        fixture.webhook.path !== baselineEntry.path,
    )
  ) {
    throw new Error("FIXTURE_ENTRY_MISMATCH");
  }

  const baselineIds = new Set(
    baselinePreflight.actions.map((action) => action.nodeId),
  );
  const candidateIds = new Set(
    candidatePreflight.actions.map((action) => action.nodeId),
  );
  const unionIds = stableUnique([...baselineIds, ...candidateIds]);
  for (const fixture of validatedFixtureSet.fixtures) {
    const fixtureIds = fixture.nodes.map((node) => node.nodeId).sort(stableCompare);
    if (canonicalJson(fixtureIds) !== canonicalJson(unionIds)) {
      throw new Error("FIXTURE_ACTION_SET_MISMATCH");
    }
    for (const node of fixture.nodes) {
      if (
        (!baselineIds.has(node.nodeId) || !candidateIds.has(node.nodeId)) &&
        node.minimumOccurrences !== 0
      ) {
        throw new Error("OPTIONAL_FIXTURE_ACTION_REQUIRES_ZERO_MINIMUM");
      }
    }
  }

  return deepFreeze({
    schemaVersion: RELEASE_REHEARSAL_ACTION_CORE_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-action-pair-preparation",
    status: "READY",
    executionAuthorized: true,
    workflows: {
      baseline: structuredClone(baselineWorkflow),
      candidate: structuredClone(candidateWorkflow),
    },
    preflight: {
      baseline: baselinePreflight,
      candidate: candidatePreflight,
    },
    fixtureSet: validatedFixtureSet,
    fixtureSetCanonicalSha256: fingerprintJson({
      schemaVersion: validatedFixtureSet.schemaVersion,
      fixtures: validatedFixtureSet.fixtures.map(
        ({ canonicalSha256: _canonicalSha256, ...fixture }) => fixture,
      ),
    }),
    entry: baselineEntry,
    actionNodeIds: unionIds,
    reasonCodes: [],
  });
}

export function createReleaseRehearsalActionCaptureConfig({
  runId,
  caseId,
  correlationId,
  variant,
  fixture,
  preflight,
}) {
  assertIdentifier(runId, "runId");
  assertIdentifier(caseId, "caseId");
  assertIdentifier(correlationId, "correlationId");
  if (!new Set(["baseline", "candidate"]).has(variant)) {
    throw new TypeError("variant must be baseline or candidate.");
  }
  if (preflight?.status !== "PLANNABLE" || preflight.variant !== variant) {
    throw new Error("ACTION_PREFLIGHT_NOT_PLANNABLE");
  }
  assertSha256(fixture?.canonicalSha256, "fixture canonical fingerprint");
  const fixtureById = new Map(fixture.nodes.map((node) => [node.nodeId, node]));
  const nodes = preflight.actions
    .map((action) => {
      const fixtureNode = fixtureById.get(action.nodeId);
      if (!fixtureNode) throw new Error("FIXTURE_ACTION_MISSING");
      return {
        nodeId: action.nodeId,
        method: action.method,
        destination: action.destination,
        minimumOccurrences: Math.max(1, fixtureNode.minimumOccurrences),
        maximumOccurrences: fixtureNode.maximumOccurrences,
        responseStubs: fixtureNode.responses,
      };
    })
    .sort((left, right) => stableCompare(left.nodeId, right.nodeId));
  const allowedNodeIds = nodes.map((node) => node.nodeId);
  return validateReleaseRehearsalCaptureConfig({
    schemaVersion: RELEASE_REHEARSAL_CAPTURE_CONFIG_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-capture-config",
    runId,
    caseId,
    variant,
    fixtureId: fixture.id,
    fixtureCanonicalSha256: fixture.canonicalSha256,
    correlationId,
    workflowCanonicalSha256: preflight.workflow.canonicalSha256,
    allowedNodeIds,
    nodes,
  });
}

function assertCaptureEnvelope(summary, dnsSummary, config, events) {
  if (
    !summary ||
    summary.status !== "COMPLETE" ||
    summary.runId !== config.runId ||
    summary.caseId !== config.caseId ||
    summary.variant !== config.variant ||
    summary.fixtureId !== config.fixtureId ||
    summary.fixtureCanonicalSha256 !== config.fixtureCanonicalSha256 ||
    summary.correlationId !== config.correlationId ||
    summary.workflowCanonicalSha256 !== config.workflowCanonicalSha256 ||
    summary.eventCount !== events.length ||
    summary.forwarded !== false ||
    !Array.isArray(summary.violationCodes) ||
    summary.violationCodes.length !== 0 ||
    !Array.isArray(summary.missing) ||
    summary.missing.length !== 0 ||
    !Array.isArray(summary.exhaustedNodeIds) ||
    summary.exhaustedNodeIds.length !== 0
  ) {
    throw new Error("CAPTURE_SUMMARY_INVALID");
  }
  if (
    !dnsSummary ||
    dnsSummary.status !== "COMPLETE" ||
    dnsSummary.queryCount !== 0 ||
    dnsSummary.forwarded !== false ||
    !Array.isArray(dnsSummary.violationCodes) ||
    dnsSummary.violationCodes.length !== 0
  ) {
    throw new Error("DNS_CONTAINMENT_VIOLATION");
  }
}

export function normalizeReleaseRehearsalObservedActions({
  events,
  summary,
  dnsSummary,
  config,
  preflight,
}) {
  if (!Array.isArray(events) || events.length > MAX_OBSERVED_ACTIONS) {
    throw new Error("CAPTURE_EVENT_LIMIT_EXCEEDED");
  }
  assertCaptureEnvelope(summary, dnsSummary, config, events);
  const plannedById = new Map(preflight.actions.map((action) => [action.nodeId, action]));
  const nextOccurrence = new Map();
  const actions = events.map((event) => {
    const planned = plannedById.get(event?.nodeId);
    const expectedOccurrence = (nextOccurrence.get(event?.nodeId) ?? 0) + 1;
    if (
      !planned ||
      event.schemaVersion !== 1 ||
      event.runId !== config.runId ||
      event.caseId !== config.caseId ||
      event.variant !== config.variant ||
      event.fixtureId !== config.fixtureId ||
      event.correlationId !== config.correlationId ||
      event.workflowCanonicalSha256 !== config.workflowCanonicalSha256 ||
      event.actionId !== `${config.fixtureId}:${event.nodeId}` ||
      event.correlationProfile !== "extended" ||
      event.occurrence !== expectedOccurrence ||
      event.method !== planned.method ||
      canonicalJson(event.destination) !== canonicalJson(planned.destination) ||
      event.forwarded !== false ||
      event.responseStubIndex !== event.occurrence - 1
    ) {
      throw new Error("CAPTURE_CORRELATION_MISMATCH");
    }
    nextOccurrence.set(event.nodeId, expectedOccurrence);
    return validateIntendedActionRecord({
      schemaVersion: RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION,
      evidenceStatus: "observed",
      variant: config.variant,
      fixtureId: config.fixtureId,
      workflowCanonicalSha256: config.workflowCanonicalSha256,
      source: {
        nodeId: planned.nodeId,
        nodeName: planned.nodeName,
      },
      sequence: planned.sequence,
      attempt: event.occurrence,
      intent: {
        kind: "http",
        method: planned.method,
        destination: planned.destination,
      },
      resolutionCode: null,
    });
  });

  for (const node of config.nodes) {
    const count = nextOccurrence.get(node.nodeId) ?? 0;
    if (count < node.minimumOccurrences || count > node.maximumOccurrences) {
      throw new Error("CAPTURE_INCOMPLETE");
    }
  }
  return deepFreeze({
    status: "OBSERVED",
    actions,
    actionCount: actions.length,
    forwarded: false,
    rawValuesRetained: false,
  });
}

export function createReleaseRehearsalUnresolvedActions(preflight, fixtureId, code) {
  assertIdentifier(fixtureId, "fixtureId");
  assertIdentifier(code, "resolution code");
  return preflight.actions.map((planned) =>
    validateIntendedActionRecord({
      schemaVersion: RELEASE_REHEARSAL_ACTION_SCHEMA_VERSION,
      evidenceStatus: "unresolved",
      variant: preflight.variant,
      fixtureId,
      workflowCanonicalSha256: preflight.workflow.canonicalSha256,
      source: { nodeId: planned.nodeId, nodeName: planned.nodeName },
      sequence: planned.sequence,
      attempt: 1,
      intent: null,
      resolutionCode: code,
    }),
  );
}

export function diffReleaseRehearsalObservedPair({
  baselineActions,
  candidateActions,
  baselineCoverage = { status: "COMPLETE", reasonCodes: [] },
  candidateCoverage = { status: "COMPLETE", reasonCodes: [] },
}) {
  const comparisonReady =
    baselineCoverage.status === "COMPLETE" &&
    candidateCoverage.status === "COMPLETE";
  return diffReleaseRehearsalActions({
    baselineActions: comparisonReady ? baselineActions : [],
    candidateActions: comparisonReady ? candidateActions : [],
    baselineCoverage,
    candidateCoverage,
  });
}

export function serializeReleaseRehearsalActionCore(value) {
  const serialized = canonicalJson(value);
  if (
    /"(?:authorization|cookie|password|private[_-]?key|api[_-]?key|jsonBody|rawStdout|rawStderr)"\s*:/iu.test(
      serialized,
    ) ||
    /(?:bearer\s|-----BEGIN [^-]{0,64}PRIVATE KEY-----)/iu.test(serialized)
  ) {
    throw new Error("ACTION_RESULT_REDACTION_VIOLATION");
  }
  return serialized + "\n";
}
