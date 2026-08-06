import { canonicalJson } from "./evidence-fingerprint.mjs";
import { validateIntendedActionRecord } from "./release-rehearsal-schema.mjs";

export const RELEASE_REHEARSAL_DIFF_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_MAX_ACTION_RECORDS = 100;
export const RELEASE_REHEARSAL_DIFF_CATEGORIES = Object.freeze([
  "new_action",
  "removed_action",
  "destination_changed",
  "method_changed",
  "action_count_changed",
  "unsupported_coverage",
  "unresolved_coverage",
]);

const INPUT_KEYS = new Set([
  "baselineActions",
  "candidateActions",
  "baselineCoverage",
  "candidateCoverage",
]);
const COVERAGE_KEYS = new Set(["status", "reasonCodes"]);
const COVERAGE_STATUSES = new Set(["COMPLETE", "UNSUPPORTED", "UNRESOLVED"]);
const REASON_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/u;
const CHANGE_ORDER = new Map(
  RELEASE_REHEARSAL_DIFF_CATEGORIES.map((kind, index) => [kind, index]),
);

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertKnownKeys(value, known, label) {
  if (!isPlainObject(value)) throw new TypeError(label + " must be an object.");
  if (Object.keys(value).some((key) => !known.has(key))) {
    throw new TypeError(label + " contains unknown fields.");
  }
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableUnique(values) {
  return [...new Set(values)].sort(stableCompare);
}

function normalizeCoverage(value, label) {
  const coverage =
    value === undefined ? { status: "COMPLETE", reasonCodes: [] } : value;
  assertKnownKeys(coverage, COVERAGE_KEYS, label);
  if (!COVERAGE_STATUSES.has(coverage.status)) {
    throw new TypeError(label + ".status is unsupported.");
  }
  if (!Array.isArray(coverage.reasonCodes) || coverage.reasonCodes.length > 100) {
    throw new TypeError(label + ".reasonCodes must be a bounded array.");
  }
  for (const code of coverage.reasonCodes) {
    if (typeof code !== "string" || !REASON_CODE_PATTERN.test(code)) {
      throw new TypeError(label + ".reasonCodes contains an invalid code.");
    }
  }
  const reasonCodes = stableUnique(coverage.reasonCodes);
  if (coverage.status === "COMPLETE" && reasonCodes.length > 0) {
    throw new TypeError(label + " cannot be COMPLETE with reason codes.");
  }
  if (coverage.status !== "COMPLETE" && reasonCodes.length === 0) {
    throw new TypeError(label + " requires a reason code when coverage is incomplete.");
  }
  return { status: coverage.status, reasonCodes };
}

function normalizeActions(actions, expectedVariant, label) {
  if (!Array.isArray(actions) || actions.length > RELEASE_REHEARSAL_MAX_ACTION_RECORDS) {
    throw new TypeError(
      label +
        " must be an array with at most " +
        RELEASE_REHEARSAL_MAX_ACTION_RECORDS +
        " records.",
    );
  }
  const normalized = actions.map(validateIntendedActionRecord);
  for (const action of normalized) {
    if (action.variant !== expectedVariant) {
      throw new TypeError(label + " contains an action for the wrong workflow variant.");
    }
  }
  const fingerprints = new Set(normalized.map((action) => action.workflowCanonicalSha256));
  if (fingerprints.size > 1) {
    throw new TypeError(label + " contains actions bound to multiple workflow fingerprints.");
  }
  return normalized;
}

function actionKey(action) {
  return canonicalJson([
    action.fixtureId,
    action.source.nodeId,
    action.sequence,
    action.attempt,
  ]);
}

function countKey(action) {
  return canonicalJson([action.fixtureId, action.source.nodeId]);
}

function indexActions(actions, label) {
  const indexed = new Map();
  for (const action of actions) {
    const key = actionKey(action);
    if (indexed.has(key)) {
      throw new TypeError(label + " contains a duplicate action identity.");
    }
    indexed.set(key, action);
  }
  return indexed;
}

function actionSummary(action) {
  return {
    method: action.intent.method,
    destinationCanonicalSha256: action.intent.destination.canonicalSha256,
  };
}

function actionLocation(action) {
  return {
    fixtureId: action.fixtureId,
    nodeId: action.source.nodeId,
    sequence: action.sequence,
    attempt: action.attempt,
  };
}

function countActions(actions) {
  const counts = new Map();
  const locations = new Map();
  for (const action of actions) {
    const key = countKey(action);
    counts.set(key, (counts.get(key) ?? 0) + 1);
    locations.set(key, {
      fixtureId: action.fixtureId,
      nodeId: action.source.nodeId,
    });
  }
  return { counts, locations };
}

function mergeUnresolvedCoverage(coverage, actions) {
  const unresolvedCodes = actions
    .filter((action) => action.evidenceStatus === "unresolved")
    .map((action) => action.resolutionCode);
  if (unresolvedCodes.length === 0) return coverage;
  return {
    status: coverage.status === "UNSUPPORTED" ? "UNSUPPORTED" : "UNRESOLVED",
    reasonCodes: stableUnique([...coverage.reasonCodes, ...unresolvedCodes]),
  };
}

function compareChanges(left, right) {
  const order = (CHANGE_ORDER.get(left.kind) ?? 999) - (CHANGE_ORDER.get(right.kind) ?? 999);
  if (order !== 0) return order;
  return stableCompare(canonicalJson(left), canonicalJson(right));
}

export function diffReleaseRehearsalActions(input) {
  assertKnownKeys(input, INPUT_KEYS, "diff input");
  const baselineActions = normalizeActions(
    input.baselineActions,
    "baseline",
    "baselineActions",
  );
  const candidateActions = normalizeActions(
    input.candidateActions,
    "candidate",
    "candidateActions",
  );
  const baselineCoverage = mergeUnresolvedCoverage(
    normalizeCoverage(input.baselineCoverage, "baselineCoverage"),
    baselineActions,
  );
  const candidateCoverage = mergeUnresolvedCoverage(
    normalizeCoverage(input.candidateCoverage, "candidateCoverage"),
    candidateActions,
  );

  const comparableBaseline = baselineActions.filter(
    (action) => action.evidenceStatus !== "unresolved",
  );
  const comparableCandidate = candidateActions.filter(
    (action) => action.evidenceStatus !== "unresolved",
  );
  const baselineByKey = indexActions(comparableBaseline, "baselineActions");
  const candidateByKey = indexActions(comparableCandidate, "candidateActions");
  const changes = [];

  for (const [key, baseline] of baselineByKey) {
    const candidate = candidateByKey.get(key);
    if (!candidate) {
      changes.push({
        kind: "removed_action",
        ...actionLocation(baseline),
        before: actionSummary(baseline),
        after: null,
      });
      continue;
    }
    if (
      baseline.intent.destination.canonicalSha256 !==
      candidate.intent.destination.canonicalSha256
    ) {
      changes.push({
        kind: "destination_changed",
        ...actionLocation(candidate),
        before: {
          destinationCanonicalSha256:
            baseline.intent.destination.canonicalSha256,
        },
        after: {
          destinationCanonicalSha256:
            candidate.intent.destination.canonicalSha256,
        },
      });
    }
    if (baseline.intent.method !== candidate.intent.method) {
      changes.push({
        kind: "method_changed",
        ...actionLocation(candidate),
        before: { method: baseline.intent.method },
        after: { method: candidate.intent.method },
      });
    }
  }

  for (const [key, candidate] of candidateByKey) {
    if (baselineByKey.has(key)) continue;
    changes.push({
      kind: "new_action",
      ...actionLocation(candidate),
      before: null,
      after: actionSummary(candidate),
    });
  }

  const baselineCounts = countActions(comparableBaseline);
  const candidateCounts = countActions(comparableCandidate);
  const countKeys = stableUnique([
    ...baselineCounts.counts.keys(),
    ...candidateCounts.counts.keys(),
  ]);
  for (const key of countKeys) {
    const beforeCount = baselineCounts.counts.get(key) ?? 0;
    const afterCount = candidateCounts.counts.get(key) ?? 0;
    if (beforeCount === afterCount) continue;
    const location =
      candidateCounts.locations.get(key) ?? baselineCounts.locations.get(key);
    changes.push({
      kind: "action_count_changed",
      ...location,
      direction: afterCount > beforeCount ? "increased" : "decreased",
      beforeCount,
      afterCount,
    });
  }

  for (const [variant, coverage] of [
    ["baseline", baselineCoverage],
    ["candidate", candidateCoverage],
  ]) {
    if (coverage.status === "UNSUPPORTED") {
      changes.push({
        kind: "unsupported_coverage",
        variant,
        reasonCodes: [...coverage.reasonCodes],
      });
    } else if (coverage.status === "UNRESOLVED") {
      changes.push({
        kind: "unresolved_coverage",
        variant,
        reasonCodes: [...coverage.reasonCodes],
      });
    }
  }

  changes.sort(compareChanges);
  const summary = Object.fromEntries(
    RELEASE_REHEARSAL_DIFF_CATEGORIES.map((kind) => [
      kind,
      changes.filter((change) => change.kind === kind).length,
    ]),
  );
  const comparisonReady =
    baselineCoverage.status === "COMPLETE" &&
    candidateCoverage.status === "COMPLETE";

  return {
    schemaVersion: RELEASE_REHEARSAL_DIFF_SCHEMA_VERSION,
    kind: "csint-release-rehearsal-behavioral-diff",
    status: comparisonReady ? "COMPLETE" : "INCOMPLETE",
    comparisonReady,
    coverage: {
      baseline: baselineCoverage,
      candidate: candidateCoverage,
    },
    summary: {
      baselineActions: comparableBaseline.length,
      candidateActions: comparableCandidate.length,
      ...summary,
      totalChanges: changes.length,
    },
    changes,
  };
}

export function serializeReleaseRehearsalDiff(diff) {
  return canonicalJson(diff) + "\n";
}
