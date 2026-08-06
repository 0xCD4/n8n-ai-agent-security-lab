import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";

import {
  canonicalJson,
  EVIDENCE_FINGERPRINT_ALGORITHM,
  fingerprintJson,
} from "./evidence-fingerprint.mjs";
import {
  diffReleaseRehearsalActions,
  RELEASE_REHEARSAL_DIFF_CATEGORIES,
} from "./release-rehearsal-diff.mjs";
import { RELEASE_REHEARSAL_N8N_IMAGE } from "./release-rehearsal-n8n.mjs";
import {
  RELEASE_REHEARSAL_HTTP_NODE_TYPE,
  RELEASE_REHEARSAL_HTTP_TYPE_VERSIONS,
  RELEASE_REHEARSAL_MAX_ACTIVE_NODES,
  RELEASE_REHEARSAL_MAX_TOTAL_NODES,
} from "./release-rehearsal-preflight.mjs";

export const RELEASE_REHEARSAL_SUMMARY_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_EVIDENCE_MANIFEST_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_NORMALIZED_CAPTURE_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_SYNTHETIC_EXAMPLE_LABEL =
  "Generated from synthetic fixtures. Not customer or production evidence.";

export const RELEASE_REHEARSAL_RESULTS = Object.freeze([
  "REHEARSAL_COMPLETE",
  "REVIEW_REQUIRED",
  "BLOCKED_UNSUPPORTED",
  "INCOMPLETE_EVIDENCE",
  "CONTAINMENT_FAILURE",
]);

export const RELEASE_REHEARSAL_RESULT_EXIT_CODES = Object.freeze({
  REHEARSAL_COMPLETE: 0,
  REVIEW_REQUIRED: 2,
  BLOCKED_UNSUPPORTED: 3,
  INCOMPLETE_EVIDENCE: 4,
  CONTAINMENT_FAILURE: 5,
});

export const RELEASE_REHEARSAL_UNSUPPORTED_CLAIMS = Object.freeze([
  "Node-level execution order or item linking",
  "Approval-node execution",
  "Retry or loop behavior",
  "Structural-node or downstream completion",
  "Delivery to an original destination",
  "Production readiness",
  "A penetration-test outcome",
  "Complete workflow equivalence",
  "Deployment identity",
  "A human release decision",
]);

const SUMMARY_FILE = "summary.json";
const REPORT_FILE = "report.md";
const MANIFEST_FILE = "evidence-manifest.json";
const OUTPUT_FILES = Object.freeze([MANIFEST_FILE, REPORT_FILE, SUMMARY_FILE]);
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;
const RESULT_SET = new Set(RELEASE_REHEARSAL_RESULTS);
const CHANGE_KIND_SET = new Set(RELEASE_REHEARSAL_DIFF_CATEGORIES);
const MEANINGFUL_CHANGE_KINDS = Object.freeze([
  "new_action",
  "removed_action",
  "destination_changed",
  "method_changed",
  "action_count_changed",
]);
const REPORT_BANNED_LANGUAGE =
  /\bsecure\b|\bapproved\b|security guarantee|penetration test passed|production safe/iu;
const HIGH_CONFIDENCE_SECRET_PATTERNS = Object.freeze([
  /-----BEGIN [^-\r\n]{0,64}PRIVATE KEY-----/giu,
  /\bBearer\s+[A-Za-z0-9+/=_-]{8,}/gu,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu,
  /\b(?:ghp|github_pat|sk|xox[baprs])[_-][A-Za-z0-9_-]{8,}\b/gu,
]);
const SAFE_ERROR_CODE = /^[A-Z][A-Z0-9_]{0,127}$/u;
const MAX_BUNDLE_FILE_BYTES = 1024 * 1024;
const MAX_BUNDLE_TOTAL_BYTES = 2 * 1024 * 1024;

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertObject(value, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} must be an object.`);
}

function assertKnownKeys(value, keys, label) {
  assertObject(value, label);
  if (Object.keys(value).some((key) => !keys.has(key))) {
    throw new TypeError(`${label} contains unknown fields.`);
  }
}

function assertSha256(value, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 value.`);
  }
  return value;
}

function assertIdentifier(value, label, maxLength = 512) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength ||
    !IDENTIFIER_PATTERN.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded identifier.`);
  }
  return value;
}

function assertCount(value, label) {
  if (!Number.isInteger(value) || value < 0 || value > 100_000) {
    throw new TypeError(`${label} must be a bounded non-negative integer.`);
  }
  return value;
}

function assertBooleanOrNull(value, label) {
  if (value !== null && typeof value !== "boolean") {
    throw new TypeError(`${label} must be boolean or null.`);
  }
  return value;
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableUnique(values) {
  return [...new Set(values)].sort(stableCompare);
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function fileEvidence(filePath, content) {
  return {
    path: filePath,
    bytes: Buffer.byteLength(content, "utf8"),
    sha256: sha256Bytes(Buffer.from(content, "utf8")),
  };
}

export function normalizeReleaseRehearsalGeneratedAt(value) {
  if (value === null || value === undefined || value === "") return null;
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
  ) {
    throw new TypeError(
      "generatedAt must be a canonical UTC timestamp such as 2026-08-06T12:00:00.000Z.",
    );
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new TypeError("generatedAt must be a valid canonical UTC timestamp.");
  }
  return value;
}

export function releaseRehearsalFixtureSetMaterial(fixtureSet) {
  assertObject(fixtureSet, "fixtureSet");
  if (fixtureSet.schemaVersion !== 1 || !Array.isArray(fixtureSet.fixtures)) {
    throw new TypeError("fixtureSet must be a validated release rehearsal fixture set.");
  }
  return {
    schemaVersion: fixtureSet.schemaVersion,
    fixtures: fixtureSet.fixtures.map((fixture) => {
      const material = structuredClone(fixture);
      delete material.canonicalSha256;
      return material;
    }),
  };
}

function normalizeReasonCodes(value, label) {
  if (!Array.isArray(value) || value.length > 200) {
    throw new TypeError(`${label} must be a bounded array.`);
  }
  for (const code of value) {
    if (typeof code !== "string" || !SAFE_ERROR_CODE.test(code)) {
      throw new TypeError(`${label} contains an invalid code.`);
    }
  }
  return stableUnique(value);
}

function normalizeCoverage(value, label) {
  assertKnownKeys(value, new Set(["status", "reasonCodes"]), label);
  if (!new Set(["COMPLETE", "UNSUPPORTED", "UNRESOLVED"]).has(value.status)) {
    throw new TypeError(`${label}.status is unsupported.`);
  }
  const reasonCodes = normalizeReasonCodes(value.reasonCodes, `${label}.reasonCodes`);
  if ((value.status === "COMPLETE") !== (reasonCodes.length === 0)) {
    throw new TypeError(`${label} has inconsistent coverage reasons.`);
  }
  return { status: value.status, reasonCodes };
}

function normalizeActionSide(value, label) {
  if (value === null) return null;
  assertObject(value, label);
  const known = new Set(["destinationCanonicalSha256", "method"]);
  if (Object.keys(value).some((key) => !known.has(key))) {
    throw new TypeError(`${label} contains unknown fields.`);
  }
  const normalized = {};
  if (value.method !== undefined) {
    if (!new Set(["POST", "PUT", "PATCH"]).has(value.method)) {
      throw new TypeError(`${label}.method is unsupported.`);
    }
    normalized.method = value.method;
  }
  if (value.destinationCanonicalSha256 !== undefined) {
    normalized.destinationCanonicalSha256 = assertSha256(
      value.destinationCanonicalSha256,
      `${label}.destinationCanonicalSha256`,
    );
  }
  if (Object.keys(normalized).length === 0) {
    throw new TypeError(`${label} must contain normalized action metadata.`);
  }
  return normalized;
}

function normalizeDiffChange(change, index) {
  assertObject(change, `actionDiff.changes[${index}]`);
  if (!CHANGE_KIND_SET.has(change.kind)) {
    throw new TypeError(`actionDiff.changes[${index}].kind is unsupported.`);
  }
  const label = `actionDiff.changes[${index}]`;
  if (new Set(["unsupported_coverage", "unresolved_coverage"]).has(change.kind)) {
    assertKnownKeys(change, new Set(["kind", "variant", "reasonCodes"]), label);
    if (!new Set(["baseline", "candidate"]).has(change.variant)) {
      throw new TypeError(`${label}.variant is unsupported.`);
    }
    return {
      kind: change.kind,
      variant: change.variant,
      reasonCodes: normalizeReasonCodes(change.reasonCodes, `${label}.reasonCodes`),
    };
  }
  if (change.kind === "action_count_changed") {
    assertKnownKeys(
      change,
      new Set([
        "kind",
        "fixtureId",
        "nodeId",
        "direction",
        "beforeCount",
        "afterCount",
      ]),
      label,
    );
    if (!new Set(["increased", "decreased"]).has(change.direction)) {
      throw new TypeError(`${label}.direction is unsupported.`);
    }
    return {
      kind: change.kind,
      fixtureId: assertIdentifier(change.fixtureId, `${label}.fixtureId`, 128),
      nodeId: assertIdentifier(change.nodeId, `${label}.nodeId`),
      direction: change.direction,
      beforeCount: assertCount(change.beforeCount, `${label}.beforeCount`),
      afterCount: assertCount(change.afterCount, `${label}.afterCount`),
    };
  }
  assertKnownKeys(
    change,
    new Set([
      "kind",
      "fixtureId",
      "nodeId",
      "sequence",
      "attempt",
      "before",
      "after",
    ]),
    label,
  );
  return {
    kind: change.kind,
    fixtureId: assertIdentifier(change.fixtureId, `${label}.fixtureId`, 128),
    nodeId: assertIdentifier(change.nodeId, `${label}.nodeId`),
    sequence: assertCount(change.sequence, `${label}.sequence`),
    attempt: assertCount(change.attempt, `${label}.attempt`),
    before: normalizeActionSide(change.before, `${label}.before`),
    after: normalizeActionSide(change.after, `${label}.after`),
  };
}

function normalizeDiff(diff) {
  assertKnownKeys(
    diff,
    new Set([
      "schemaVersion",
      "kind",
      "status",
      "comparisonReady",
      "coverage",
      "summary",
      "changes",
    ]),
    "actionDiff",
  );
  if (
    diff.schemaVersion !== 1 ||
    diff.kind !== "csint-release-rehearsal-behavioral-diff" ||
    !new Set(["COMPLETE", "INCOMPLETE"]).has(diff.status) ||
    typeof diff.comparisonReady !== "boolean"
  ) {
    throw new TypeError("actionDiff identity is invalid.");
  }
  assertKnownKeys(diff.coverage, new Set(["baseline", "candidate"]), "actionDiff.coverage");
  const coverage = {
    baseline: normalizeCoverage(diff.coverage.baseline, "actionDiff.coverage.baseline"),
    candidate: normalizeCoverage(
      diff.coverage.candidate,
      "actionDiff.coverage.candidate",
    ),
  };
  const summaryKeys = new Set([
    "baselineActions",
    "candidateActions",
    ...RELEASE_REHEARSAL_DIFF_CATEGORIES,
    "totalChanges",
  ]);
  assertKnownKeys(diff.summary, summaryKeys, "actionDiff.summary");
  const summary = Object.fromEntries(
    [...summaryKeys].map((key) => [key, assertCount(diff.summary[key], `actionDiff.summary.${key}`)]),
  );
  if (!Array.isArray(diff.changes) || diff.changes.length > 500) {
    throw new TypeError("actionDiff.changes must be a bounded array.");
  }
  const changes = diff.changes.map(normalizeDiffChange);
  if (summary.totalChanges !== changes.length) {
    throw new TypeError("actionDiff change count is inconsistent.");
  }
  for (const kind of RELEASE_REHEARSAL_DIFF_CATEGORIES) {
    if (summary[kind] !== changes.filter((change) => change.kind === kind).length) {
      throw new TypeError(`actionDiff ${kind} count is inconsistent.`);
    }
  }
  const comparisonReady =
    coverage.baseline.status === "COMPLETE" &&
    coverage.candidate.status === "COMPLETE";
  if (
    comparisonReady !== diff.comparisonReady ||
    (comparisonReady ? "COMPLETE" : "INCOMPLETE") !== diff.status
  ) {
    throw new TypeError("actionDiff coverage status is inconsistent.");
  }
  return {
    schemaVersion: 1,
    kind: diff.kind,
    status: diff.status,
    comparisonReady,
    coverage,
    summary,
    changes,
  };
}

function unresolvedDiff(preflight) {
  return diffReleaseRehearsalActions({
    baselineActions: [],
    candidateActions: [],
    baselineCoverage: {
      status: "UNRESOLVED",
      reasonCodes: preflight.baseline.coverage.reasonCodes.length
        ? preflight.baseline.coverage.reasonCodes
        : ["RUNTIME_EVIDENCE_UNAVAILABLE"],
    },
    candidateCoverage: {
      status: "UNRESOLVED",
      reasonCodes: preflight.candidate.coverage.reasonCodes.length
        ? preflight.candidate.coverage.reasonCodes
        : ["RUNTIME_EVIDENCE_UNAVAILABLE"],
    },
  });
}

function hasContainmentFailure(coreResult) {
  return (
    coreResult.outcome === "FAIL_CONTAINMENT" ||
    coreResult.cleanup?.status === "FAILED" ||
    coreResult.imageCleanup?.status === "FAILED" ||
    coreResult.inventory?.unchanged === false ||
    (coreResult.cases ?? []).some(
      (item) =>
        item.cleanup?.status === "FAILED" ||
        item.containment?.unexpectedActionDetected === true ||
        item.evidence?.captureForwarded === true ||
        (Number.isInteger(item.evidence?.dnsQueryCount) &&
          item.evidence.dnsQueryCount > 0),
    )
  );
}

export function mapReleaseRehearsalCoreResult(coreResult, diff = coreResult?.diff) {
  assertObject(coreResult, "coreResult");
  if (hasContainmentFailure(coreResult)) return "CONTAINMENT_FAILURE";
  if (coreResult.outcome === "BLOCKED_TRANSFORMATION_FIDELITY") {
    return "BLOCKED_UNSUPPORTED";
  }
  if (
    coreResult.outcome !== "PASS_ACTION_REHEARSAL_CORE" ||
    !diff ||
    diff.status !== "COMPLETE" ||
    coreResult.cleanup?.status !== "COMPLETE"
  ) {
    return "INCOMPLETE_EVIDENCE";
  }
  const meaningfulChanges = MEANINGFUL_CHANGE_KINDS.reduce(
    (sum, kind) => sum + (diff.summary?.[kind] ?? 0),
    0,
  );
  return meaningfulChanges > 0 ? "REVIEW_REQUIRED" : "REHEARSAL_COMPLETE";
}

function normalizeScope(preflight) {
  return {
    status: preflight.status,
    totalNodes: assertCount(preflight.counts.totalNodes, "scope.totalNodes"),
    activeNodes: assertCount(preflight.counts.activeNodes, "scope.activeNodes"),
    plannedActionNodes:
      preflight.status === "PLANNABLE" ? preflight.actions.length : 0,
    reasonCodes: normalizeReasonCodes(
      preflight.coverage.reasonCodes,
      "scope.reasonCodes",
    ),
  };
}

function observedCounts(cases) {
  const byVariant = { baseline: 0, candidate: 0 };
  for (const item of cases) {
    if (new Set(["baseline", "candidate"]).has(item.variant)) {
      byVariant[item.variant] += Array.isArray(item.observedActions)
        ? item.observedActions.length
        : 0;
    }
  }
  return { ...byVariant, total: byVariant.baseline + byVariant.candidate };
}

function unresolvedCounts(coreResult, preflight, fixtureCount) {
  if (coreResult.outcome === "BLOCKED_TRANSFORMATION_FIDELITY") {
    return { baseline: 0, candidate: 0, total: 0 };
  }
  const cases = Array.isArray(coreResult.cases) ? coreResult.cases : [];
  const byVariant = { baseline: 0, candidate: 0 };
  for (const variant of ["baseline", "candidate"]) {
    const variantCases = cases.filter((item) => item.variant === variant);
    if (variantCases.length === 0) {
      byVariant[variant] = preflight[variant].actions.length * fixtureCount;
    } else {
      byVariant[variant] =
        variantCases.filter((item) => item.status !== "COMPLETE").length *
        preflight[variant].actions.length;
    }
  }
  return { ...byVariant, total: byVariant.baseline + byVariant.candidate };
}

function normalizeContainment(coreResult) {
  const cases = Array.isArray(coreResult.cases) ? coreResult.cases : [];
  if (coreResult.outcome === "BLOCKED_TRANSFORMATION_FIDELITY") {
    return {
      status: "NOT_RUN",
      casesEvaluated: 0,
      localCaptureRouteOnly: null,
      forwardingObserved: null,
      dnsQueryCount: 0,
      unexpectedActionCount: 0,
      inventoryUnchanged: null,
    };
  }
  const forwardingValues = cases
    .map((item) => item.evidence?.captureForwarded)
    .filter((value) => typeof value === "boolean");
  const localCaptureRouteOnly =
    cases.length > 0
      ? cases.every(
          (item) =>
            item.containment?.captureNetworkMode === "none" &&
            item.containment?.setupNetworkMode === "none" &&
            item.containment?.publishNetworkMode === "none" &&
            item.containment?.serverNetworkMode ===
              "container:<capture-container-id>" &&
            item.containment?.noPublishedPorts === true,
        )
      : null;
  const forwardingObserved =
    forwardingValues.length > 0 ? forwardingValues.some(Boolean) : null;
  const dnsQueryCount = cases.reduce(
    (sum, item) =>
      sum + (Number.isInteger(item.evidence?.dnsQueryCount) ? item.evidence.dnsQueryCount : 0),
    0,
  );
  const unexpectedActionCount = cases.filter(
    (item) => item.containment?.unexpectedActionDetected === true,
  ).length;
  return {
    status: hasContainmentFailure(coreResult)
      ? "FAILED"
      : coreResult.outcome === "PASS_ACTION_REHEARSAL_CORE"
        ? "COMPLETE"
        : "INCOMPLETE",
    casesEvaluated: cases.length,
    localCaptureRouteOnly,
    forwardingObserved,
    dnsQueryCount,
    unexpectedActionCount,
    inventoryUnchanged:
      typeof coreResult.inventory?.unchanged === "boolean"
        ? coreResult.inventory.unchanged
        : null,
  };
}

function normalizeCleanup(coreResult) {
  return {
    status: coreResult.cleanup?.status === "COMPLETE" ? "COMPLETE" : "FAILED",
    remainingResourceCount: Number.isInteger(coreResult.cleanup?.remainingResourceCount)
      ? coreResult.cleanup.remainingResourceCount
      : 0,
    captureImageCleanupStatus: coreResult.imageCleanup?.status ??
      (coreResult.outcome === "BLOCKED_TRANSFORMATION_FIDELITY"
        ? "NOT_CREATED"
        : "UNKNOWN"),
    inventoryUnchanged:
      typeof coreResult.inventory?.unchanged === "boolean"
        ? coreResult.inventory.unchanged
        : null,
  };
}

function normalizedCaptureEvidence(item) {
  const evidence = item.evidence ?? {};
  const processEvidence = item.process ?? {};
  const containment = item.containment ?? {};
  return {
    schemaVersion: RELEASE_REHEARSAL_NORMALIZED_CAPTURE_SCHEMA_VERSION,
    caseId: item.caseId,
    variant: item.variant,
    fixtureId: item.fixtureId,
    fixtureCanonicalSha256: item.fixtureCanonicalSha256,
    status: item.status,
    workflow: item.subjects
      ? {
          originalCanonicalSha256:
            item.subjects.originalWorkflowCanonicalSha256,
          transformedCanonicalSha256:
            item.subjects.transformedWorkflowCanonicalSha256,
        }
      : null,
    observedActions: Array.isArray(item.observedActions)
      ? structuredClone(item.observedActions)
      : [],
    capture: {
      status: evidence.captureStatus ?? null,
      eventCount: evidence.captureEventCount ?? null,
      forwarded: evidence.captureForwarded ?? null,
      violationCodes: stableUnique(evidence.captureViolationCodes ?? []),
      responseStatuses: [...(evidence.responseStatuses ?? [])],
      dnsStatus: evidence.dnsStatus ?? null,
      dnsQueryCount: evidence.dnsQueryCount ?? null,
      rawValuesRetained: false,
    },
    process: {
      importExitCode: processEvidence.importExitCode ?? null,
      publishExitCode: processEvidence.publishExitCode ?? null,
      injectorExitCode: processEvidence.injectorExitCode ?? null,
      n8nProcessExitCode: processEvidence.n8nProcessExitCode ?? null,
      startupCompletionMarkerObserved:
        processEvidence.startupCompletionMarkerObserved ?? false,
      healthReadinessObserved: processEvidence.healthReadinessObserved ?? false,
      n8nProcessExitCodeIsNodeTrace: false,
      n8nProcessExitCodeIsWorkflowStatus: false,
    },
    containment: {
      captureNetworkMode: containment.captureNetworkMode ?? null,
      setupNetworkMode: containment.setupNetworkMode ?? null,
      publishNetworkMode: containment.publishNetworkMode ?? null,
      serverNetworkMode: containment.serverNetworkMode ?? null,
      noPublishedPorts: containment.noPublishedPorts ?? false,
      noProxyEnvironment: containment.noProxyEnvironment ?? false,
      unexpectedActionDetected: containment.unexpectedActionDetected ?? false,
    },
    cleanup: {
      status: item.cleanup?.status ?? "FAILED",
      remainingResourceCount: item.cleanup?.remainingResourceCount ?? 0,
    },
    errorCodes: normalizeReasonCodes(item.errorCodes ?? [], "case.errorCodes"),
  };
}

function normalizeExecutionCases(coreResult) {
  const cases = Array.isArray(coreResult.cases) ? coreResult.cases : [];
  const normalizedCases = cases
    .map((item) => {
      assertIdentifier(item.caseId, "case.caseId", 256);
      assertIdentifier(item.fixtureId, "case.fixtureId", 128);
      assertSha256(item.fixtureCanonicalSha256, "case.fixtureCanonicalSha256");
      const normalized = normalizedCaptureEvidence(item);
      return {
        caseId: item.caseId,
        variant: item.variant,
        fixtureId: item.fixtureId,
        fixtureCanonicalSha256: item.fixtureCanonicalSha256,
        originalWorkflowCanonicalSha256:
          item.subjects?.originalWorkflowCanonicalSha256 ?? null,
        transformedWorkflowCanonicalSha256:
          item.subjects?.transformedWorkflowCanonicalSha256 ?? null,
        transformationManifestCanonicalSha256:
          item.subjects?.transformationManifestCanonicalSha256 ?? null,
        normalizedCaptureEvidenceCanonicalSha256: fingerprintJson(normalized),
        normalized,
      };
    })
    .sort((left, right) =>
      stableCompare(
        `${left.fixtureId}:${left.variant}:${left.caseId}`,
        `${right.fixtureId}:${right.variant}:${right.caseId}`,
      ),
    );
  if (
    new Set(normalizedCases.map((item) => item.caseId)).size !==
    normalizedCases.length
  ) {
    throw new Error("EXECUTION_CASE_ID_AMBIGUOUS");
  }
  return normalizedCases;
}

function evidenceCount(unit, baseline, candidate) {
  return {
    unit,
    baseline,
    candidate,
    total: baseline + candidate,
  };
}

function buildSummary({
  baselineWorkflow,
  candidateWorkflow,
  fixtureSet,
  preflight,
  coreResult,
  diff,
  overallResult,
  evidenceLabel,
}) {
  const fixtureCount = fixtureSet.fixtures.length;
  const baselineScope = normalizeScope(preflight.baseline);
  const candidateScope = normalizeScope(preflight.candidate);
  const planned = evidenceCount(
    "action_node_case",
    baselineScope.plannedActionNodes * fixtureCount,
    candidateScope.plannedActionNodes * fixtureCount,
  );
  const observed = observedCounts(coreResult.cases ?? []);
  const unresolved = unresolvedCounts(coreResult, preflight, fixtureCount);
  return {
    schemaVersion: RELEASE_REHEARSAL_SUMMARY_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-summary",
    evidenceLabel,
    overallResult,
    humanReleaseDecisionRequired: true,
    subjects: {
      baseline: {
        fingerprintAlgorithm: EVIDENCE_FINGERPRINT_ALGORITHM,
        canonicalSha256: fingerprintJson(baselineWorkflow),
      },
      candidate: {
        fingerprintAlgorithm: EVIDENCE_FINGERPRINT_ALGORITHM,
        canonicalSha256: fingerprintJson(candidateWorkflow),
      },
      fixtureSet: {
        fingerprintAlgorithm: EVIDENCE_FINGERPRINT_ALGORITHM,
        canonicalSha256: fingerprintJson(
          releaseRehearsalFixtureSetMaterial(fixtureSet),
        ),
      },
    },
    environment: {
      n8n: {
        requestedTag: RELEASE_REHEARSAL_N8N_IMAGE.requestedTag,
        repositoryDigest: RELEASE_REHEARSAL_N8N_IMAGE.repositoryDigest,
        platform: RELEASE_REHEARSAL_N8N_IMAGE.platform,
      },
    },
    supportedScope: {
      maximumActiveNodes: RELEASE_REHEARSAL_MAX_ACTIVE_NODES,
      maximumParsedNodes: RELEASE_REHEARSAL_MAX_TOTAL_NODES,
      fixtureCount,
      httpAction: {
        nodeType: RELEASE_REHEARSAL_HTTP_NODE_TYPE,
        typeVersions: [...RELEASE_REHEARSAL_HTTP_TYPE_VERSIONS],
        methods: ["POST", "PUT", "PATCH"],
      },
      baseline: baselineScope,
      candidate: candidateScope,
    },
    evidenceCounts: {
      planned,
      observed: evidenceCount(
        "capture_occurrence",
        observed.baseline,
        observed.candidate,
      ),
      unresolved: evidenceCount(
        "action_node_case",
        unresolved.baseline,
        unresolved.candidate,
      ),
    },
    actionDiff: diff,
    containment: normalizeContainment(coreResult),
    cleanup: normalizeCleanup(coreResult),
    redaction: {
      highConfidenceSecretPatternsAbsent: true,
      forbiddenPayloadValuesAbsent: true,
      rawWorkflowContentRetained: false,
      rawCaptureStreamRetained: false,
    },
    unsupportedClaims: [...RELEASE_REHEARSAL_UNSUPPORTED_CLAIMS],
  };
}

function markdownEscape(value) {
  return String(value).replace(/[\\`*_[\]{}()#+\-.!|>]/gu, "\\$&");
}

function describeDiff(change) {
  const fixture = markdownEscape(change.fixtureId ?? "unknown-fixture");
  const node = markdownEscape(change.nodeId ?? "unknown-node");
  if (change.kind === "new_action") {
    return `new_action: fixture ${fixture}, node ${node}, ${change.after.method}, destination fingerprint ${change.after.destinationCanonicalSha256}.`;
  }
  if (change.kind === "removed_action") {
    return `removed_action: fixture ${fixture}, node ${node}, ${change.before.method}, destination fingerprint ${change.before.destinationCanonicalSha256}.`;
  }
  if (change.kind === "destination_changed") {
    return `destination_changed: fixture ${fixture}, node ${node}, ${change.before.destinationCanonicalSha256} to ${change.after.destinationCanonicalSha256}.`;
  }
  if (change.kind === "method_changed") {
    return `method_changed: fixture ${fixture}, node ${node}, ${change.before.method} to ${change.after.method}.`;
  }
  if (change.kind === "action_count_changed") {
    return `action_count_changed: fixture ${fixture}, node ${node}, ${change.beforeCount} to ${change.afterCount}.`;
  }
  return `${change.kind}: ${change.variant} coverage, ${change.reasonCodes.join(", ")}.`;
}

function executiveSummary(result) {
  return {
    REHEARSAL_COMPLETE:
      "Every supported case completed, and the expected local captures were observed. No observed-action difference was found for these fixtures.",
    REVIEW_REQUIRED:
      "Every supported case completed, and meaningful observed-action differences were found. A person must decide whether the candidate should proceed.",
    BLOCKED_UNSUPPORTED:
      "Execution did not start because one or both workflows are outside the supported subset.",
    INCOMPLETE_EVIDENCE:
      "Expected capture evidence is missing or unresolved. No equivalence conclusion is reported.",
    CONTAINMENT_FAILURE:
      "A containment or cleanup check failed. This is not a completed rehearsal result.",
  }[result];
}

export function renderReleaseRehearsalReport(summary, { generatedAt = null } = {}) {
  validateReleaseRehearsalSummary(summary);
  const timestamp = normalizeReleaseRehearsalGeneratedAt(generatedAt);
  const lines = [
    "# Release Rehearsal Evidence",
    "",
  ];
  if (summary.evidenceLabel) lines.push(summary.evidenceLabel, "");
  const fixtureCaseLabel =
    summary.supportedScope.fixtureCount === 1 ? "fixture case" : "fixture cases";
  lines.push(
    "## Executive summary",
    "",
    `Result: ${summary.overallResult}`,
    "",
    executiveSummary(summary.overallResult),
    "",
    "The human makes the release decision.",
    "",
    "## What was checked",
    "",
    `- ${summary.supportedScope.fixtureCount} sanitized ${fixtureCaseLabel} against separate transformed baseline and candidate runs.`,
    `- Literal POST, PUT, and PATCH actions using ${summary.supportedScope.httpAction.nodeType} type version ${summary.supportedScope.httpAction.typeVersions.join(", ")}.`,
    `- ${summary.evidenceCounts.observed.total} accepted local capture occurrence(s), with forwarding observed: ${String(summary.containment.forwardingObserved)}.`,
    `- Containment: ${summary.containment.status}. Cleanup: ${summary.cleanup.status}.`,
    "",
    "## Observed action changes",
    "",
  );
  if (summary.actionDiff.changes.length === 0) {
    lines.push("- No observed-action change is reported for the supported cases.");
  } else {
    for (const change of summary.actionDiff.changes) {
      lines.push(`- ${describeDiff(change)}`);
    }
  }
  lines.push(
    "",
    "## Coverage limits",
    "",
    "Observed means only that the contained local capture service accepted the transformed synthetic request. Planned data comes from the source-bound transformation. Unresolved means runtime capture evidence was unavailable.",
    "",
    ...summary.unsupportedClaims.map((claim) => `- Not established: ${claim}.`),
    "",
    "## Items requiring human review",
    "",
  );
  if (summary.overallResult === "REVIEW_REQUIRED") {
    lines.push("- Review every observed-action change listed above.");
  } else if (summary.overallResult === "BLOCKED_UNSUPPORTED") {
    lines.push("- Review the unsupported reason codes before preparing another export.");
  } else if (summary.overallResult === "INCOMPLETE_EVIDENCE") {
    lines.push("- Review missing or unresolved capture evidence before drawing a comparison.");
  } else if (summary.overallResult === "CONTAINMENT_FAILURE") {
    lines.push("- Review the containment and cleanup failure before running another rehearsal.");
  } else {
    lines.push("- Review whether these fixtures cover the release decision that matters.");
  }
  lines.push(
    "- Decide whether additional fixtures or manual review are required.",
    "",
    "## Input and evidence fingerprints",
    "",
    `- Baseline workflow: ${summary.subjects.baseline.canonicalSha256}`,
    `- Candidate workflow: ${summary.subjects.candidate.canonicalSha256}`,
    `- Fixture set: ${summary.subjects.fixtureSet.canonicalSha256}`,
    `- n8n image: ${summary.environment.n8n.repositoryDigest}`,
  );
  if (timestamp) lines.push(`- Caller-supplied generation timestamp: ${timestamp}`);
  lines.push("");
  const report = lines.join("\n");
  if (REPORT_BANNED_LANGUAGE.test(report)) {
    throw new Error("REPORT_LANGUAGE_BOUNDARY_VIOLATION");
  }
  return report;
}

export function scanReleaseRehearsalEvidenceText(
  texts,
  { forbiddenValues = [] } = {},
) {
  if (!Array.isArray(texts) || texts.some((value) => typeof value !== "string")) {
    throw new TypeError("Evidence scan input must be an array of strings.");
  }
  const joined = texts.join("\n");
  let secretPatternMatches = 0;
  for (const pattern of HIGH_CONFIDENCE_SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    secretPatternMatches += [...joined.matchAll(pattern)].length;
  }
  const uniqueForbidden = stableUnique(
    forbiddenValues.filter(
      (value) => typeof value === "string" && value.length >= 8 && value.length <= 4096,
    ),
  );
  const forbiddenValueMatches = uniqueForbidden.filter((value) =>
    joined.includes(value),
  ).length;
  return {
    passed: secretPatternMatches === 0 && forbiddenValueMatches === 0,
    secretPatternMatches,
    forbiddenValueMatches,
    scannedTextCount: texts.length,
  };
}

function createManifest({
  summary,
  report,
  executionCases,
  generatedAt,
  evidenceLabel,
}) {
  const summaryText = canonicalJson(summary) + "\n";
  const outputs = [
    fileEvidence(SUMMARY_FILE, summaryText),
    fileEvidence(REPORT_FILE, report),
  ].sort((left, right) => stableCompare(left.path, right.path));
  const cases = executionCases.map(({ normalized: _normalized, ...item }) => item);
  const manifestBase = {
    schemaVersion: RELEASE_REHEARSAL_EVIDENCE_MANIFEST_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-evidence-manifest",
    evidenceLabel,
    generation: {
      generatedAt,
      timestampSource: generatedAt ? "caller" : "omitted",
    },
    hashAlgorithms: {
      bytes: "sha256",
      canonicalJson: EVIDENCE_FINGERPRINT_ALGORITHM,
    },
    originalInputs: {
      baselineWorkflowCanonicalSha256:
        summary.subjects.baseline.canonicalSha256,
      candidateWorkflowCanonicalSha256:
        summary.subjects.candidate.canonicalSha256,
      fixtureSetCanonicalSha256: summary.subjects.fixtureSet.canonicalSha256,
    },
    transformedWorkflows: cases.map((item) => ({
      caseId: item.caseId,
      variant: item.variant,
      fixtureId: item.fixtureId,
      originalWorkflowCanonicalSha256:
        item.originalWorkflowCanonicalSha256,
      transformedWorkflowCanonicalSha256:
        item.transformedWorkflowCanonicalSha256,
      transformationManifestCanonicalSha256:
        item.transformationManifestCanonicalSha256,
    })),
    normalizedCaptureEvidence: {
      aggregateCanonicalSha256: fingerprintJson(
        executionCases.map((item) => item.normalized),
      ),
      cases: cases.map((item) => ({
        caseId: item.caseId,
        variant: item.variant,
        fixtureId: item.fixtureId,
        canonicalSha256: item.normalizedCaptureEvidenceCanonicalSha256,
      })),
    },
    executionCases: cases.map((item) => ({
      caseId: item.caseId,
      variant: item.variant,
      fixtureId: item.fixtureId,
      fixtureCanonicalSha256: item.fixtureCanonicalSha256,
    })),
    runtime: {
      n8nImageTag: RELEASE_REHEARSAL_N8N_IMAGE.requestedTag,
      n8nImageDigest: RELEASE_REHEARSAL_N8N_IMAGE.repositoryDigest,
      platform: RELEASE_REHEARSAL_N8N_IMAGE.platform,
    },
    outputs,
    redaction: {
      rawWorkflowContentRetained: false,
      rawCaptureStreamRetained: false,
      rawHeaderQueryOrPayloadValuesRetained: false,
    },
  };
  return {
    ...manifestBase,
    manifestCanonicalSha256: fingerprintJson(manifestBase),
  };
}

export function buildReleaseRehearsalEvidenceBundle({
  baselineWorkflow,
  candidateWorkflow,
  fixtureSet,
  preflight,
  coreResult,
  generatedAt = null,
  syntheticExample = false,
  forbiddenValues = [],
}) {
  const normalizedTimestamp = normalizeReleaseRehearsalGeneratedAt(generatedAt);
  assertKnownKeys(preflight, new Set(["baseline", "candidate"]), "preflight");
  const rawDiff = coreResult.diff ?? unresolvedDiff(preflight);
  const diff = normalizeDiff(rawDiff);
  const overallResult = mapReleaseRehearsalCoreResult(coreResult, diff);
  const evidenceLabel = syntheticExample
    ? RELEASE_REHEARSAL_SYNTHETIC_EXAMPLE_LABEL
    : null;
  const summary = buildSummary({
    baselineWorkflow,
    candidateWorkflow,
    fixtureSet,
    preflight,
    coreResult,
    diff,
    overallResult,
    evidenceLabel,
  });
  validateReleaseRehearsalSummary(summary);
  const report = renderReleaseRehearsalReport(summary, {
    generatedAt: normalizedTimestamp,
  });
  const executionCases = normalizeExecutionCases(coreResult);
  const manifest = createManifest({
    summary,
    report,
    executionCases,
    generatedAt: normalizedTimestamp,
    evidenceLabel,
  });
  validateReleaseRehearsalEvidenceManifest(manifest);
  const files = {
    [SUMMARY_FILE]: canonicalJson(summary) + "\n",
    [REPORT_FILE]: report,
    [MANIFEST_FILE]: canonicalJson(manifest) + "\n",
  };
  const scan = scanReleaseRehearsalEvidenceText(Object.values(files), {
    forbiddenValues,
  });
  if (!scan.passed) throw new Error("EVIDENCE_REDACTION_SCAN_FAILED");
  return {
    overallResult,
    exitCode: RELEASE_REHEARSAL_RESULT_EXIT_CODES[overallResult],
    summary,
    report,
    manifest,
    files,
    redactionScan: scan,
  };
}

function validateEvidenceCount(value, label) {
  assertKnownKeys(value, new Set(["unit", "baseline", "candidate", "total"]), label);
  if (!new Set(["action_node_case", "capture_occurrence"]).has(value.unit)) {
    throw new TypeError(`${label}.unit is unsupported.`);
  }
  const baseline = assertCount(value.baseline, `${label}.baseline`);
  const candidate = assertCount(value.candidate, `${label}.candidate`);
  if (value.total !== baseline + candidate) {
    throw new TypeError(`${label}.total is inconsistent.`);
  }
}

function validateScopeSummary(value, label) {
  assertKnownKeys(
    value,
    new Set([
      "status",
      "totalNodes",
      "activeNodes",
      "plannedActionNodes",
      "reasonCodes",
    ]),
    label,
  );
  if (!new Set(["PLANNABLE", "UNSUPPORTED"]).has(value.status)) {
    throw new TypeError(`${label}.status is unsupported.`);
  }
  const totalNodes = assertCount(value.totalNodes, `${label}.totalNodes`);
  const activeNodes = assertCount(value.activeNodes, `${label}.activeNodes`);
  const plannedActionNodes = assertCount(
    value.plannedActionNodes,
    `${label}.plannedActionNodes`,
  );
  const reasonCodes = normalizeReasonCodes(value.reasonCodes, `${label}.reasonCodes`);
  if (
    totalNodes > RELEASE_REHEARSAL_MAX_TOTAL_NODES ||
    activeNodes > totalNodes ||
    plannedActionNodes > activeNodes ||
    (value.status === "PLANNABLE") !== (reasonCodes.length === 0) ||
    (value.status === "UNSUPPORTED" && plannedActionNodes !== 0)
  ) {
    throw new TypeError(`${label} is inconsistent with the supported scope.`);
  }
}

export function validateReleaseRehearsalSummary(summary) {
  assertKnownKeys(
    summary,
    new Set([
      "schemaVersion",
      "kind",
      "evidenceLabel",
      "overallResult",
      "humanReleaseDecisionRequired",
      "subjects",
      "environment",
      "supportedScope",
      "evidenceCounts",
      "actionDiff",
      "containment",
      "cleanup",
      "redaction",
      "unsupportedClaims",
    ]),
    "summary",
  );
  if (
    summary.schemaVersion !== RELEASE_REHEARSAL_SUMMARY_SCHEMA_VERSION ||
    summary.kind !== "csint-release-rehearsal-summary" ||
    !RESULT_SET.has(summary.overallResult) ||
    summary.humanReleaseDecisionRequired !== true ||
    (summary.evidenceLabel !== null &&
      summary.evidenceLabel !== RELEASE_REHEARSAL_SYNTHETIC_EXAMPLE_LABEL)
  ) {
    throw new TypeError("summary identity is invalid.");
  }
  assertKnownKeys(
    summary.subjects,
    new Set(["baseline", "candidate", "fixtureSet"]),
    "summary.subjects",
  );
  for (const name of ["baseline", "candidate", "fixtureSet"]) {
    assertKnownKeys(
      summary.subjects[name],
      new Set(["fingerprintAlgorithm", "canonicalSha256"]),
      `summary.subjects.${name}`,
    );
    if (summary.subjects[name].fingerprintAlgorithm !== EVIDENCE_FINGERPRINT_ALGORITHM) {
      throw new TypeError(`summary.subjects.${name} uses an unknown algorithm.`);
    }
    assertSha256(
      summary.subjects[name].canonicalSha256,
      `summary.subjects.${name}.canonicalSha256`,
    );
  }
  assertKnownKeys(summary.environment, new Set(["n8n"]), "summary.environment");
  assertKnownKeys(
    summary.environment.n8n,
    new Set(["requestedTag", "repositoryDigest", "platform"]),
    "summary.environment.n8n",
  );
  if (
    summary.environment.n8n.requestedTag !== RELEASE_REHEARSAL_N8N_IMAGE.requestedTag ||
    summary.environment.n8n.repositoryDigest !==
      RELEASE_REHEARSAL_N8N_IMAGE.repositoryDigest ||
    summary.environment.n8n.platform !== RELEASE_REHEARSAL_N8N_IMAGE.platform
  ) {
    throw new TypeError("summary.environment.n8n is not the exact pinned image identity.");
  }
  assertKnownKeys(
    summary.supportedScope,
    new Set([
      "maximumActiveNodes",
      "maximumParsedNodes",
      "fixtureCount",
      "httpAction",
      "baseline",
      "candidate",
    ]),
    "summary.supportedScope",
  );
  if (
    summary.supportedScope.maximumActiveNodes !== RELEASE_REHEARSAL_MAX_ACTIVE_NODES ||
    summary.supportedScope.maximumParsedNodes !== RELEASE_REHEARSAL_MAX_TOTAL_NODES ||
    !Number.isInteger(summary.supportedScope.fixtureCount) ||
    summary.supportedScope.fixtureCount < 1 ||
    summary.supportedScope.fixtureCount > 3
  ) {
    throw new TypeError("summary.supportedScope limits are invalid.");
  }
  assertKnownKeys(
    summary.supportedScope.httpAction,
    new Set(["nodeType", "typeVersions", "methods"]),
    "summary.supportedScope.httpAction",
  );
  if (
    summary.supportedScope.httpAction.nodeType !== RELEASE_REHEARSAL_HTTP_NODE_TYPE ||
    canonicalJson(summary.supportedScope.httpAction.typeVersions) !==
      canonicalJson(RELEASE_REHEARSAL_HTTP_TYPE_VERSIONS) ||
    canonicalJson(summary.supportedScope.httpAction.methods) !==
      canonicalJson(["POST", "PUT", "PATCH"])
  ) {
    throw new TypeError("summary.supportedScope.httpAction is invalid.");
  }
  validateScopeSummary(summary.supportedScope.baseline, "summary.supportedScope.baseline");
  validateScopeSummary(summary.supportedScope.candidate, "summary.supportedScope.candidate");
  assertKnownKeys(summary.evidenceCounts, new Set(["planned", "observed", "unresolved"]), "summary.evidenceCounts");
  validateEvidenceCount(summary.evidenceCounts.planned, "summary.evidenceCounts.planned");
  validateEvidenceCount(summary.evidenceCounts.observed, "summary.evidenceCounts.observed");
  validateEvidenceCount(summary.evidenceCounts.unresolved, "summary.evidenceCounts.unresolved");
  normalizeDiff(summary.actionDiff);
  assertKnownKeys(
    summary.containment,
    new Set([
      "status",
      "casesEvaluated",
      "localCaptureRouteOnly",
      "forwardingObserved",
      "dnsQueryCount",
      "unexpectedActionCount",
      "inventoryUnchanged",
    ]),
    "summary.containment",
  );
  if (!new Set(["COMPLETE", "INCOMPLETE", "FAILED", "NOT_RUN"]).has(summary.containment.status)) {
    throw new TypeError("summary.containment.status is unsupported.");
  }
  assertCount(summary.containment.casesEvaluated, "summary.containment.casesEvaluated");
  assertBooleanOrNull(summary.containment.localCaptureRouteOnly, "summary.containment.localCaptureRouteOnly");
  assertBooleanOrNull(summary.containment.forwardingObserved, "summary.containment.forwardingObserved");
  assertCount(summary.containment.dnsQueryCount, "summary.containment.dnsQueryCount");
  assertCount(summary.containment.unexpectedActionCount, "summary.containment.unexpectedActionCount");
  assertBooleanOrNull(summary.containment.inventoryUnchanged, "summary.containment.inventoryUnchanged");
  assertKnownKeys(
    summary.cleanup,
    new Set([
      "status",
      "remainingResourceCount",
      "captureImageCleanupStatus",
      "inventoryUnchanged",
    ]),
    "summary.cleanup",
  );
  if (
    !new Set(["COMPLETE", "FAILED"]).has(summary.cleanup.status) ||
    !new Set(["COMPLETE", "FAILED", "NOT_CREATED", "UNKNOWN"]).has(
      summary.cleanup.captureImageCleanupStatus,
    )
  ) {
    throw new TypeError("summary.cleanup status is unsupported.");
  }
  assertCount(
    summary.cleanup.remainingResourceCount,
    "summary.cleanup.remainingResourceCount",
  );
  assertBooleanOrNull(summary.cleanup.inventoryUnchanged, "summary.cleanup.inventoryUnchanged");
  assertKnownKeys(
    summary.redaction,
    new Set([
      "highConfidenceSecretPatternsAbsent",
      "forbiddenPayloadValuesAbsent",
      "rawWorkflowContentRetained",
      "rawCaptureStreamRetained",
    ]),
    "summary.redaction",
  );
  if (
    summary.redaction.highConfidenceSecretPatternsAbsent !== true ||
    summary.redaction.forbiddenPayloadValuesAbsent !== true ||
    summary.redaction.rawWorkflowContentRetained !== false ||
    summary.redaction.rawCaptureStreamRetained !== false
  ) {
    throw new TypeError("summary.redaction is inconsistent.");
  }
  if (
    !Array.isArray(summary.unsupportedClaims) ||
    canonicalJson(summary.unsupportedClaims) !==
      canonicalJson(RELEASE_REHEARSAL_UNSUPPORTED_CLAIMS)
  ) {
    throw new TypeError("summary.unsupportedClaims is not the exact boundary list.");
  }
  const meaningfulChanges = MEANINGFUL_CHANGE_KINDS.reduce(
    (sum, kind) => sum + summary.actionDiff.summary[kind],
    0,
  );
  if (
    new Set(["REHEARSAL_COMPLETE", "REVIEW_REQUIRED"]).has(
      summary.overallResult,
    ) &&
    (summary.actionDiff.status !== "COMPLETE" ||
      summary.containment.status !== "COMPLETE" ||
      summary.cleanup.status !== "COMPLETE" ||
      summary.evidenceCounts.unresolved.total !== 0 ||
      (summary.overallResult === "REHEARSAL_COMPLETE"
        ? meaningfulChanges !== 0
        : meaningfulChanges === 0))
  ) {
    throw new TypeError("summary completed result is inconsistent with its evidence.");
  }
  if (
    summary.overallResult === "BLOCKED_UNSUPPORTED" &&
    (summary.containment.status !== "NOT_RUN" ||
      summary.containment.casesEvaluated !== 0 ||
      summary.evidenceCounts.observed.total !== 0 ||
      summary.actionDiff.summary.unsupported_coverage === 0)
  ) {
    throw new TypeError("summary blocked result is inconsistent with its evidence.");
  }
  if (
    summary.overallResult === "INCOMPLETE_EVIDENCE" &&
    summary.actionDiff.status === "COMPLETE" &&
    summary.evidenceCounts.unresolved.total === 0
  ) {
    throw new TypeError("summary incomplete result lacks unresolved evidence.");
  }
  if (
    summary.overallResult === "CONTAINMENT_FAILURE" &&
    summary.containment.status !== "FAILED" &&
    summary.cleanup.status !== "FAILED"
  ) {
    throw new TypeError("summary containment result lacks a failed boundary.");
  }
  return summary;
}

export function validateReleaseRehearsalEvidenceManifest(manifest) {
  assertKnownKeys(
    manifest,
    new Set([
      "schemaVersion",
      "kind",
      "evidenceLabel",
      "generation",
      "hashAlgorithms",
      "originalInputs",
      "transformedWorkflows",
      "normalizedCaptureEvidence",
      "executionCases",
      "runtime",
      "outputs",
      "redaction",
      "manifestCanonicalSha256",
    ]),
    "manifest",
  );
  if (
    manifest.schemaVersion !== RELEASE_REHEARSAL_EVIDENCE_MANIFEST_SCHEMA_VERSION ||
    manifest.kind !== "csint-release-rehearsal-evidence-manifest" ||
    (manifest.evidenceLabel !== null &&
      manifest.evidenceLabel !== RELEASE_REHEARSAL_SYNTHETIC_EXAMPLE_LABEL)
  ) {
    throw new TypeError("manifest identity is invalid.");
  }
  assertKnownKeys(
    manifest.generation,
    new Set(["generatedAt", "timestampSource"]),
    "manifest.generation",
  );
  const generatedAt = normalizeReleaseRehearsalGeneratedAt(
    manifest.generation.generatedAt,
  );
  if (
    manifest.generation.timestampSource !== (generatedAt ? "caller" : "omitted")
  ) {
    throw new TypeError("manifest.generation timestamp source is inconsistent.");
  }
  assertKnownKeys(
    manifest.hashAlgorithms,
    new Set(["bytes", "canonicalJson"]),
    "manifest.hashAlgorithms",
  );
  if (
    manifest.hashAlgorithms.bytes !== "sha256" ||
    manifest.hashAlgorithms.canonicalJson !== EVIDENCE_FINGERPRINT_ALGORITHM
  ) {
    throw new TypeError("manifest.hashAlgorithms is unsupported.");
  }
  assertKnownKeys(
    manifest.originalInputs,
    new Set([
      "baselineWorkflowCanonicalSha256",
      "candidateWorkflowCanonicalSha256",
      "fixtureSetCanonicalSha256",
    ]),
    "manifest.originalInputs",
  );
  assertSha256(
    manifest.originalInputs.baselineWorkflowCanonicalSha256,
    "manifest original baseline fingerprint",
  );
  assertSha256(
    manifest.originalInputs.candidateWorkflowCanonicalSha256,
    "manifest original candidate fingerprint",
  );
  assertSha256(
    manifest.originalInputs.fixtureSetCanonicalSha256,
    "manifest fixture-set fingerprint",
  );
  if (!Array.isArray(manifest.transformedWorkflows) || manifest.transformedWorkflows.length > 6) {
    throw new TypeError("manifest.transformedWorkflows is outside the case bound.");
  }
  for (const item of manifest.transformedWorkflows) {
    assertKnownKeys(
      item,
      new Set([
        "caseId",
        "variant",
        "fixtureId",
        "originalWorkflowCanonicalSha256",
        "transformedWorkflowCanonicalSha256",
        "transformationManifestCanonicalSha256",
      ]),
      "manifest.transformedWorkflows[]",
    );
    assertIdentifier(item.caseId, "manifest transformed case ID", 256);
    assertIdentifier(item.fixtureId, "manifest transformed fixture ID", 128);
    if (!new Set(["baseline", "candidate"]).has(item.variant)) {
      throw new TypeError("manifest transformed variant is invalid.");
    }
    for (const key of [
      "originalWorkflowCanonicalSha256",
      "transformedWorkflowCanonicalSha256",
      "transformationManifestCanonicalSha256",
    ]) {
      if (item[key] !== null) assertSha256(item[key], `manifest transformed ${key}`);
    }
    const expectedOriginal =
      item.variant === "baseline"
        ? manifest.originalInputs.baselineWorkflowCanonicalSha256
        : manifest.originalInputs.candidateWorkflowCanonicalSha256;
    if (
      item.originalWorkflowCanonicalSha256 !== null &&
      item.originalWorkflowCanonicalSha256 !== expectedOriginal
    ) {
      throw new TypeError("manifest transformed workflow has the wrong original binding.");
    }
  }
  assertKnownKeys(
    manifest.normalizedCaptureEvidence,
    new Set(["aggregateCanonicalSha256", "cases"]),
    "manifest.normalizedCaptureEvidence",
  );
  assertSha256(
    manifest.normalizedCaptureEvidence.aggregateCanonicalSha256,
    "manifest normalized capture aggregate fingerprint",
  );
  if (
    !Array.isArray(manifest.normalizedCaptureEvidence.cases) ||
    manifest.normalizedCaptureEvidence.cases.length !==
      manifest.transformedWorkflows.length
  ) {
    throw new TypeError("manifest normalized capture cases are inconsistent.");
  }
  for (const item of manifest.normalizedCaptureEvidence.cases) {
    assertKnownKeys(
      item,
      new Set(["caseId", "variant", "fixtureId", "canonicalSha256"]),
      "manifest.normalizedCaptureEvidence.cases[]",
    );
    assertIdentifier(item.caseId, "manifest capture case ID", 256);
    assertIdentifier(item.fixtureId, "manifest capture fixture ID", 128);
    if (!new Set(["baseline", "candidate"]).has(item.variant)) {
      throw new TypeError("manifest capture variant is invalid.");
    }
    assertSha256(item.canonicalSha256, "manifest normalized capture fingerprint");
  }
  if (
    !Array.isArray(manifest.executionCases) ||
    manifest.executionCases.length !== manifest.transformedWorkflows.length
  ) {
    throw new TypeError("manifest.executionCases is inconsistent.");
  }
  for (const item of manifest.executionCases) {
    assertKnownKeys(
      item,
      new Set(["caseId", "variant", "fixtureId", "fixtureCanonicalSha256"]),
      "manifest.executionCases[]",
    );
    assertIdentifier(item.caseId, "manifest execution case ID", 256);
    assertIdentifier(item.fixtureId, "manifest execution fixture ID", 128);
    if (!new Set(["baseline", "candidate"]).has(item.variant)) {
      throw new TypeError("manifest execution variant is invalid.");
    }
    assertSha256(item.fixtureCanonicalSha256, "manifest fixture fingerprint");
  }
  const identity = (item) => `${item.fixtureId}:${item.variant}:${item.caseId}`;
  const transformedIdentities = manifest.transformedWorkflows.map(identity);
  if (
    canonicalJson(transformedIdentities) !==
      canonicalJson([...transformedIdentities].sort(stableCompare)) ||
    canonicalJson(transformedIdentities) !==
      canonicalJson(manifest.normalizedCaptureEvidence.cases.map(identity)) ||
    canonicalJson(transformedIdentities) !==
      canonicalJson(manifest.executionCases.map(identity))
  ) {
    throw new TypeError("manifest execution-case bindings are inconsistent.");
  }
  assertKnownKeys(
    manifest.runtime,
    new Set(["n8nImageTag", "n8nImageDigest", "platform"]),
    "manifest.runtime",
  );
  if (
    manifest.runtime.n8nImageTag !== RELEASE_REHEARSAL_N8N_IMAGE.requestedTag ||
    manifest.runtime.n8nImageDigest !== RELEASE_REHEARSAL_N8N_IMAGE.repositoryDigest ||
    manifest.runtime.platform !== RELEASE_REHEARSAL_N8N_IMAGE.platform
  ) {
    throw new TypeError("manifest.runtime is not the exact pinned image identity.");
  }
  if (!Array.isArray(manifest.outputs) || manifest.outputs.length !== 2) {
    throw new TypeError("manifest.outputs must cover summary.json and report.md.");
  }
  const outputNames = manifest.outputs.map((item) => item.path).sort(stableCompare);
  if (canonicalJson(outputNames) !== canonicalJson([REPORT_FILE, SUMMARY_FILE])) {
    throw new TypeError("manifest.outputs contains an unexpected file.");
  }
  for (const item of manifest.outputs) {
    assertKnownKeys(item, new Set(["path", "bytes", "sha256"]), "manifest.outputs[]");
    if (!Number.isInteger(item.bytes) || item.bytes < 1 || item.bytes > MAX_BUNDLE_FILE_BYTES) {
      throw new TypeError("manifest output byte count is invalid.");
    }
    assertSha256(item.sha256, "manifest output fingerprint");
  }
  assertKnownKeys(
    manifest.redaction,
    new Set([
      "rawWorkflowContentRetained",
      "rawCaptureStreamRetained",
      "rawHeaderQueryOrPayloadValuesRetained",
    ]),
    "manifest.redaction",
  );
  if (
    manifest.redaction.rawWorkflowContentRetained !== false ||
    manifest.redaction.rawCaptureStreamRetained !== false ||
    manifest.redaction.rawHeaderQueryOrPayloadValuesRetained !== false
  ) {
    throw new TypeError("manifest.redaction is inconsistent.");
  }
  const { manifestCanonicalSha256, ...base } = manifest;
  assertSha256(manifestCanonicalSha256, "manifest canonical fingerprint");
  if (fingerprintJson(base) !== manifestCanonicalSha256) {
    throw new TypeError("manifest canonical fingerprint does not match its content.");
  }
  return manifest;
}

async function readBoundedBundleFile(directory, name) {
  const filePath = path.join(directory, name);
  const entry = await lstat(filePath);
  if (entry.isSymbolicLink() || !entry.isFile()) {
    throw new Error(`Evidence bundle ${name} must be a regular file.`);
  }
  if (entry.size > MAX_BUNDLE_FILE_BYTES) {
    throw new Error(`Evidence bundle ${name} exceeds its size limit.`);
  }
  return readFile(filePath);
}

export async function verifyReleaseRehearsalEvidenceBundle(directory) {
  const absolute = path.resolve(directory);
  const entries = await readdir(absolute, { withFileTypes: true });
  const names = entries.map((entry) => entry.name).sort(stableCompare);
  if (
    entries.some((entry) => !entry.isFile() || entry.isSymbolicLink()) ||
    canonicalJson(names) !== canonicalJson(OUTPUT_FILES)
  ) {
    throw new Error("Evidence bundle must contain exactly three regular files.");
  }
  const buffers = Object.fromEntries(
    await Promise.all(
      OUTPUT_FILES.map(async (name) => [name, await readBoundedBundleFile(absolute, name)]),
    ),
  );
  const totalBytes = Object.values(buffers).reduce((sum, buffer) => sum + buffer.length, 0);
  if (totalBytes > MAX_BUNDLE_TOTAL_BYTES) {
    throw new Error("Evidence bundle exceeds its total size limit.");
  }
  let summary;
  let manifest;
  let report;
  try {
    const decoder = () => new TextDecoder("utf-8", { fatal: true });
    summary = JSON.parse(decoder().decode(buffers[SUMMARY_FILE]));
    manifest = JSON.parse(decoder().decode(buffers[MANIFEST_FILE]));
    report = decoder().decode(buffers[REPORT_FILE]);
  } catch {
    throw new Error("Evidence bundle content is malformed or not UTF-8.");
  }
  validateReleaseRehearsalSummary(summary);
  validateReleaseRehearsalEvidenceManifest(manifest);
  if (canonicalJson(summary) + "\n" !== buffers[SUMMARY_FILE].toString("utf8")) {
    throw new Error("summary.json is not canonical JSON.");
  }
  if (canonicalJson(manifest) + "\n" !== buffers[MANIFEST_FILE].toString("utf8")) {
    throw new Error("evidence-manifest.json is not canonical JSON.");
  }
  if (
    !report.endsWith("\n") ||
    !report.includes(`Result: ${summary.overallResult}`) ||
    (summary.evidenceLabel !== null) !== report.includes(
      RELEASE_REHEARSAL_SYNTHETIC_EXAMPLE_LABEL,
    ) ||
    REPORT_BANNED_LANGUAGE.test(report)
  ) {
    throw new Error("report.md does not match the summary evidence boundary.");
  }
  for (const output of manifest.outputs) {
    const buffer = buffers[output.path];
    if (buffer.length !== output.bytes || sha256Bytes(buffer) !== output.sha256) {
      throw new Error(`Evidence bundle hash mismatch for ${output.path}.`);
    }
  }
  if (
    manifest.originalInputs.baselineWorkflowCanonicalSha256 !==
      summary.subjects.baseline.canonicalSha256 ||
    manifest.originalInputs.candidateWorkflowCanonicalSha256 !==
      summary.subjects.candidate.canonicalSha256 ||
    manifest.originalInputs.fixtureSetCanonicalSha256 !==
      summary.subjects.fixtureSet.canonicalSha256 ||
    manifest.runtime.n8nImageDigest !== summary.environment.n8n.repositoryDigest
  ) {
    throw new Error("Evidence bundle subject binding is inconsistent.");
  }
  const scan = scanReleaseRehearsalEvidenceText(
    Object.values(buffers).map((buffer) => buffer.toString("utf8")),
  );
  if (!scan.passed) throw new Error("Evidence bundle secret scan failed.");
  return {
    status: "VERIFIED",
    fileCount: OUTPUT_FILES.length,
    totalBytes,
    overallResult: summary.overallResult,
    manifestCanonicalSha256: manifest.manifestCanonicalSha256,
    highConfidenceSecretPatternsAbsent: true,
  };
}
