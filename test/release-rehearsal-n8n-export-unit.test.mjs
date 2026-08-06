import assert from "node:assert/strict";

import {
  normalizeReleaseRehearsalN8nEntityArchive,
  RELEASE_REHEARSAL_N8N_EXPORT_LIMITS,
} from "../src/release-rehearsal-n8n-export.mjs";
import {
  RELEASE_REHEARSAL_N8N_NODE_BINDINGS,
  RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
} from "../src/release-rehearsal-n8n.mjs";

const tests = [];

function test(name, callback) {
  tests.push({ name, callback });
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) === 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value = CRC32_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function zip(entries) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const data = Buffer.isBuffer(entry.data)
      ? entry.data
      : Buffer.from(entry.data ?? "", "utf8");
    const checksum = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    localParts.push(local, name, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(((entry.host ?? 0) << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(entry.externalAttributes ?? 0, 38);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, name);
    localOffset += local.length + name.length + data.length;
  }
  const locals = Buffer.concat(localParts);
  const central = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(locals.length, 16);
  return Buffer.concat([locals, central, eocd]);
}

function opaqueEnvelope(seed = 0x41) {
  return Buffer.concat([
    Buffer.from("Salted__", "ascii"),
    Buffer.alloc(8, seed),
    Buffer.alloc(16, seed ^ 0xff),
  ]).toString("base64") + "\n";
}

function expectedNodes() {
  return RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map(
    ({ id, name, type, typeVersion }) => ({ id, name, type, typeVersion }),
  );
}

function executionData({ omitLinkFor = null } = {}) {
  const runData = Object.fromEntries(
    RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map((node, executionIndex) => {
      const item = { json: { hidden: "Bearer fake-never-retain" } };
      if (node.role !== "trigger" && node.id !== omitLinkFor) {
        item.pairedItem = { item: 0 };
      }
      return [
        node.name,
        [{ executionIndex, data: { main: [[item]] } }],
      ];
    }),
  );
  return { resultData: { runData } };
}

function plainArchive(options = {}) {
  const workflow = {
    id: RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
    name: "CSINT Release Rehearsal n8n CLI Trace Probe",
    nodes: expectedNodes(),
  };
  const execution = {
    id: "synthetic-execution-1",
    workflowId: options.executionWorkflowId ?? RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
    status: "success",
    mode: "cli",
    finished: true,
    stoppedAt: "2026-08-06T00:00:00.000Z",
  };
  const data = {
    executionId: execution.id,
    workflowData: {
      id: RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
      nodes: expectedNodes(),
    },
    data: executionData(options),
  };
  const workflowRows = options.duplicateWorkflow
    ? `${JSON.stringify(workflow)}\n${JSON.stringify(workflow)}\n`
    : `${JSON.stringify(workflow)}\n`;
  return zip([
    { name: "entities.zip", data: "" },
    { name: "workflowentity.jsonl", data: workflowRows },
    { name: "executionentity.jsonl", data: `${JSON.stringify(execution)}\n` },
    { name: "executiondata.jsonl", data: `${JSON.stringify(data)}\n` },
    { name: "settings.jsonl", data: "unparsed unrelated bytes" },
  ]);
}

test("opaque target envelopes stop at the documented export boundary", () => {
  const archive = zip([
    { name: "entities.zip", data: "" },
    { name: "workflowentity.jsonl", data: opaqueEnvelope(1) },
    { name: "executionentity.jsonl", data: opaqueEnvelope(2) },
    { name: "executiondata.jsonl", data: opaqueEnvelope(3) },
    { name: "settings.jsonl", data: "must-not-be-parsed" },
  ]);
  const result = normalizeReleaseRehearsalN8nEntityArchive(archive);
  assert.equal(result.status, "TRACE_EXPORT_UNAVAILABLE");
  assert.equal(result.archive.encryptedTargetFileCount, 3);
  assert.equal(result.archive.unrelatedEntityFileCount, 1);
  assert.equal(result.archive.rawRetained, false);
  assert.equal(result.correlation, null);
  assert.equal(result.trace, null);
  assert.ok(result.limitationCodes.includes("DOCUMENTED_EXPORT_TARGETS_ENCRYPTED"));
});

test("a complete plain bounded export can prove all required trace fields", () => {
  const result = normalizeReleaseRehearsalN8nEntityArchive(plainArchive());
  assert.equal(result.status, "PASS_TRACE_EXPORT");
  assert.deepEqual(result.requiredEvidence, {
    terminalStatus: true,
    executedNodeIdentities: true,
    nodeOrder: true,
    runAndOutputIndexes: true,
    itemLinkInformation: true,
    downstreamFinalNodeExecution: true,
  });
  assert.deepEqual(
    result.trace.nodeOrder.map(({ executionIndex, nodeId, runIndex }) => ({
      executionIndex,
      nodeId,
      runIndex,
    })),
    RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map((node, executionIndex) => ({
      executionIndex,
      nodeId: node.id,
      runIndex: 0,
    })),
  );
  assert.doesNotMatch(JSON.stringify(result), /Bearer|fake-never-retain/iu);
});

test("missing item linkage produces a strict partial result", () => {
  const result = normalizeReleaseRehearsalN8nEntityArchive(
    plainArchive({ omitLinkFor: "csint-capture-http" }),
  );
  assert.equal(result.status, "TRACE_EXPORT_PARTIAL");
  assert.equal(result.requiredEvidence.itemLinkInformation, false);
  assert.ok(
    result.limitationCodes.includes("TRACE_FIELD_ITEM_LINK_INFORMATION_UNAVAILABLE"),
  );
});

test("missing execution-history members produce unavailable evidence", () => {
  const result = normalizeReleaseRehearsalN8nEntityArchive(
    zip([
      { name: "entities.zip", data: "" },
      { name: "workflowentity.jsonl", data: opaqueEnvelope() },
    ]),
  );
  assert.equal(result.status, "TRACE_EXPORT_UNAVAILABLE");
  assert.ok(
    result.limitationCodes.includes("EXECUTION_HISTORY_TARGET_FILES_MISSING"),
  );
});

test("duplicate workflow matches and mismatched executions fail closed", () => {
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(plainArchive({ duplicateWorkflow: true })),
    (error) => error.code === "EXPORT_WORKFLOW_MATCH_AMBIGUOUS",
  );
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(
      plainArchive({ executionWorkflowId: "different-workflow" }),
    ),
    (error) => error.code === "EXPORT_EXECUTION_CORRELATION_INVALID",
  );
});

test("ZIP symlinks, unknown formats, and duplicate members are rejected", () => {
  const symlinkMode = ((0xa000 | 0o777) << 16) >>> 0;
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(zip([
      { name: "entities.zip", data: "", host: 3, externalAttributes: symlinkMode },
    ])),
    (error) => error.code === "EXPORT_ZIP_NON_REGULAR_MEMBER",
  );
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(zip([
      { name: "entities.zip", data: "" },
      { name: "unexpected.txt", data: "value" },
    ])),
    (error) => error.code === "EXPORT_ZIP_MEMBER_NAME_UNEXPECTED",
  );
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(zip([
      { name: "entities.zip", data: "" },
      { name: "entities.zip", data: "" },
    ])),
    (error) => error.code === "EXPORT_ZIP_DUPLICATE_MEMBER",
  );
});

test("archive, entry, and total-size bounds are enforced before parsing", () => {
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(plainArchive(), {
      limits: { maxArchiveBytes: 32 },
    }),
    (error) => error.code === "EXPORT_ARCHIVE_SIZE_LIMIT_EXCEEDED",
  );
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(plainArchive(), {
      limits: { maxEntryBytes: 32 },
    }),
    (error) => error.code === "EXPORT_ZIP_MEMBER_INVALID",
  );
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(plainArchive(), {
      limits: { maxTotalEntryBytes: 64 },
    }),
    (error) => error.code === "EXPORT_ZIP_TOTAL_SIZE_LIMIT_EXCEEDED",
  );
});

test("JSON depth, array, string, and execution-count bounds stay fixed", () => {
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(plainArchive(), {
      limits: { maxJsonDepth: 2 },
    }),
    (error) => /DEPTH_LIMIT_EXCEEDED$/u.test(error.code),
  );
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(plainArchive(), {
      limits: { maxArrayLength: 2 },
    }),
    (error) => /ARRAY_LIMIT_EXCEEDED$/u.test(error.code),
  );
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(plainArchive(), {
      limits: { maxStringBytes: 8 },
    }),
    (error) => /STRING_LIMIT_EXCEEDED$/u.test(error.code),
  );
  assert.throws(
    () => normalizeReleaseRehearsalN8nEntityArchive(plainArchive(), {
      limits: { maxExecutions: 2 },
    }),
    /maxExecutions must remain exactly one/u,
  );
  assert.equal(RELEASE_REHEARSAL_N8N_EXPORT_LIMITS.maxExecutions, 1);
});

for (const { name, callback } of tests) {
  try {
    await callback();
  } catch (error) {
    error.message = `${name}: ${error.message}`;
    throw error;
  }
}

process.stdout.write(
  `release rehearsal n8n entity-export unit core: ${tests.length} tests passed\n`,
);
