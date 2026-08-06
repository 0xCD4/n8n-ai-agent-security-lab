import { createHash } from "node:crypto";
import { lstat, open, readdir, unlink } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";
import { inflateRawSync } from "node:zlib";

import { canonicalJson, fingerprintJson } from "./evidence-fingerprint.mjs";
import {
  parseReleaseRehearsalN8nRawOutput,
  RELEASE_REHEARSAL_N8N_NODE_BINDINGS,
  RELEASE_REHEARSAL_N8N_WORKFLOW_ID,
} from "./release-rehearsal-n8n.mjs";

export const RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_N8N_EXPORT_COMMAND =
  "n8n export:entities --outputDir=<empty-dir> --includeExecutionHistoryDataTables=true";
export const RELEASE_REHEARSAL_N8N_EXPORT_LIMITS = Object.freeze({
  maxArchiveBytes: 4 * 1024 * 1024,
  maxEntries: 128,
  maxEntryBytes: 2 * 1024 * 1024,
  maxTotalEntryBytes: 8 * 1024 * 1024,
  maxJsonDepth: 48,
  maxJsonValues: 60_000,
  maxArrayLength: 512,
  maxObjectKeys: 512,
  maxStringBytes: 2 * 1024 * 1024,
  maxLineBytes: 2 * 1024 * 1024,
  maxLinesPerTarget: 2,
  maxExecutions: 1,
});

const ARCHIVE_NAME = "entities.zip";
const TARGET_MEMBERS = Object.freeze({
  workflow: "workflowentity.jsonl",
  execution: "executionentity.jsonl",
  executionData: "executiondata.jsonl",
});
const TARGET_MEMBER_SET = new Set(Object.values(TARGET_MEMBERS));
const JSONL_NAME_PATTERN = /^[a-z][a-z0-9_]{0,95}\.jsonl$/u;
const EXECUTION_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const ZIP_EOCD_SIGNATURE = 0x06054b50;
const ZIP_CENTRAL_SIGNATURE = 0x02014b50;
const ZIP_LOCAL_SIGNATURE = 0x04034b50;
const ZIP64_EXTRA_ID = 0x0001;
const ZIP_ALLOWED_FLAGS = 0x080c;
const ZIP_UTF8_FLAG = 0x0800;
const ZIP_METHOD_STORE = 0;
const ZIP_METHOD_DEFLATE = 8;
const ZIP_UNIX_HOST = 3;
const ZIP_DOS_HOST = 0;
const ZIP_DOS_DIRECTORY_ATTRIBUTE = 0x10;
const ZIP_UNIX_FILE_TYPE_MASK = 0xf000;
const ZIP_UNIX_REGULAR_FILE = 0x8000;
const REQUIRED_TRACE_FIELDS = Object.freeze([
  "terminalStatus",
  "executedNodeIdentities",
  "nodeOrder",
  "runAndOutputIndexes",
  "itemLinkInformation",
  "downstreamFinalNodeExecution",
]);

export class ReleaseRehearsalN8nExportError extends Error {
  constructor(code, outcome = "TRACE_EXPORT_UNAVAILABLE") {
    super(code);
    this.code = code;
    this.outcome = outcome;
  }
}

function fail(code, outcome) {
  throw new ReleaseRehearsalN8nExportError(code, outcome);
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(stableCompare);
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertPositiveInteger(value, label) {
  if (!Number.isInteger(value) || value < 1) {
    throw new TypeError(`${label} must be a positive integer.`);
  }
}

function normalizeLimits(overrides = {}) {
  const limits = Object.freeze({
    ...RELEASE_REHEARSAL_N8N_EXPORT_LIMITS,
    ...overrides,
  });
  for (const [name, value] of Object.entries(limits)) {
    assertPositiveInteger(value, name);
  }
  if (limits.maxExecutions !== 1) {
    throw new TypeError("maxExecutions must remain exactly one.");
  }
  return limits;
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) === 1
        ? 0xedb88320 ^ (value >>> 1)
        : value >>> 1;
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

function decodeUtf8(buffer, code) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    fail(code);
  }
}

function assertNoDuplicateJsonKeys(text) {
  let index = 0;

  function invalid() {
    const error = new Error("invalid JSON scan");
    error.invalidJsonScan = true;
    throw error;
  }

  function skipWhitespace() {
    while (index < text.length && /[\u0009\u000A\u000D\u0020]/u.test(text[index])) {
      index += 1;
    }
  }

  function scanString() {
    if (text[index] !== '"') invalid();
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === '"') {
        index += 1;
        try {
          return JSON.parse(text.slice(start, index));
        } catch {
          invalid();
        }
      }
      if (character === "\\") {
        index += 1;
        if (index >= text.length) invalid();
        if (text[index] === "u") {
          if (!/^[a-f0-9]{4}$/iu.test(text.slice(index + 1, index + 5))) invalid();
          index += 5;
        } else {
          if (!/["\\/bfnrt]/u.test(text[index])) invalid();
          index += 1;
        }
        continue;
      }
      if (character.codePointAt(0) <= 0x1f) invalid();
      index += 1;
    }
    invalid();
  }

  function scanObject() {
    index += 1;
    skipWhitespace();
    const keys = new Set();
    if (text[index] === "}") {
      index += 1;
      return;
    }
    while (index < text.length) {
      const key = scanString();
      if (keys.has(key)) fail("EXPORT_JSON_DUPLICATE_KEY");
      keys.add(key);
      skipWhitespace();
      if (text[index] !== ":") invalid();
      index += 1;
      scanValue();
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      if (text[index] !== ",") invalid();
      index += 1;
      skipWhitespace();
    }
    invalid();
  }

  function scanArray() {
    index += 1;
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return;
    }
    while (index < text.length) {
      scanValue();
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      if (text[index] !== ",") invalid();
      index += 1;
      skipWhitespace();
    }
    invalid();
  }

  function scanValue() {
    skipWhitespace();
    const character = text[index];
    if (character === "{") return scanObject();
    if (character === "[") return scanArray();
    if (character === '"') {
      scanString();
      return;
    }
    for (const literal of ["true", "false", "null"]) {
      if (text.startsWith(literal, index)) {
        index += literal.length;
        return;
      }
    }
    const number = text.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u)?.[0];
    if (!number) invalid();
    index += number.length;
  }

  try {
    scanValue();
    skipWhitespace();
    if (index !== text.length) invalid();
  } catch (error) {
    if (error instanceof ReleaseRehearsalN8nExportError) throw error;
    if (error?.invalidJsonScan) fail("EXPORT_JSON_TOKEN_SCAN_INVALID");
    throw error;
  }
}

function inspectJsonShape(value, limits) {
  const stack = [{ value, depth: 0 }];
  let values = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    values += 1;
    if (values > limits.maxJsonValues) fail("EXPORT_JSON_VALUE_LIMIT_EXCEEDED");
    if (current.depth > limits.maxJsonDepth) fail("EXPORT_JSON_DEPTH_LIMIT_EXCEEDED");
    if (typeof current.value === "string") {
      if (Buffer.byteLength(current.value, "utf8") > limits.maxStringBytes) {
        fail("EXPORT_JSON_STRING_LIMIT_EXCEEDED");
      }
      continue;
    }
    if (Array.isArray(current.value)) {
      if (current.value.length > limits.maxArrayLength) {
        fail("EXPORT_JSON_ARRAY_LIMIT_EXCEEDED");
      }
      for (const child of current.value) {
        stack.push({ value: child, depth: current.depth + 1 });
      }
      continue;
    }
    if (!current.value || typeof current.value !== "object") continue;
    const entries = Object.entries(current.value);
    if (entries.length > limits.maxObjectKeys) {
      fail("EXPORT_JSON_OBJECT_LIMIT_EXCEEDED");
    }
    for (const [key, child] of entries) {
      if (Buffer.byteLength(key, "utf8") > 256) fail("EXPORT_JSON_KEY_LIMIT_EXCEEDED");
      stack.push({ value: child, depth: current.depth + 1 });
    }
  }
}

function parseStrictJson(text, limits) {
  if (Buffer.byteLength(text, "utf8") > limits.maxLineBytes) {
    fail("EXPORT_JSON_LINE_LIMIT_EXCEEDED");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail("EXPORT_JSON_MALFORMED");
  }
  assertNoDuplicateJsonKeys(text);
  inspectJsonShape(value, limits);
  return value;
}

function parseJsonLines(buffer, limits, label) {
  if (buffer.length > limits.maxEntryBytes) fail("EXPORT_TARGET_FILE_TOO_LARGE");
  const text = decodeUtf8(buffer, "EXPORT_JSON_UTF8_INVALID");
  if (text.startsWith("\uFEFF")) fail("EXPORT_JSON_BOM_FORBIDDEN");
  const completeText = text.endsWith("\r\n")
    ? text.slice(0, -2)
    : text.endsWith("\n")
      ? text.slice(0, -1)
      : text;
  if (completeText.length > 0) {
    try {
      const complete = parseStrictJson(completeText, limits);
      const rows = Array.isArray(complete) ? complete : [complete];
      if (rows.length > limits.maxLinesPerTarget) fail(`${label}_COUNT_LIMIT_EXCEEDED`);
      if (rows.every(isPlainObject)) return rows;
      fail(`${label}_ROW_INVALID`);
    } catch (error) {
      if (
        error instanceof ReleaseRehearsalN8nExportError &&
        !new Set(["EXPORT_JSON_MALFORMED", "EXPORT_JSON_TOKEN_SCAN_INVALID"]).has(error.code)
      ) {
        throw error;
      }
    }
  }
  const rawLines = text.split("\n");
  if (rawLines.at(-1) === "") rawLines.pop();
  const lines = rawLines.map((line) => line.endsWith("\r") ? line.slice(0, -1) : line);
  if (lines.some((line) => line.length === 0)) fail("EXPORT_JSONL_BLANK_LINE");
  if (lines.length > limits.maxLinesPerTarget) fail(`${label}_COUNT_LIMIT_EXCEEDED`);
  return lines.map((line) => {
    let parsed;
    try {
      parsed = parseStrictJson(line, limits);
    } catch (error) {
      if (error instanceof ReleaseRehearsalN8nExportError) {
        fail(`${label}_${error.code.replace(/^EXPORT_JSON_/u, "")}`);
      }
      throw error;
    }
    if (!isPlainObject(parsed)) fail(`${label}_ROW_INVALID`);
    return parsed;
  });
}

function parseZipExtra(extra) {
  let offset = 0;
  while (offset < extra.length) {
    if (offset + 4 > extra.length) fail("EXPORT_ZIP_EXTRA_MALFORMED");
    const id = extra.readUInt16LE(offset);
    const size = extra.readUInt16LE(offset + 2);
    offset += 4;
    if (offset + size > extra.length) fail("EXPORT_ZIP_EXTRA_MALFORMED");
    if (id === ZIP64_EXTRA_ID) fail("EXPORT_ZIP64_UNSUPPORTED");
    offset += size;
  }
}

function locateEndOfCentralDirectory(buffer) {
  const minimumOffset = Math.max(0, buffer.length - 65_557);
  for (let offset = buffer.length - 22; offset >= minimumOffset; offset -= 1) {
    if (buffer.readUInt32LE(offset) === ZIP_EOCD_SIGNATURE) return offset;
  }
  fail("EXPORT_ZIP_EOCD_MISSING");
}

function assertSafeMemberName(name) {
  if (
    name === ARCHIVE_NAME ||
    JSONL_NAME_PATTERN.test(name)
  ) {
    return name;
  }
  fail("EXPORT_ZIP_MEMBER_NAME_UNEXPECTED");
}

function inventoryZip(buffer, limits) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError("Export archive must be a Buffer.");
  if (buffer.length < 22) fail("EXPORT_ZIP_TOO_SMALL");
  if (buffer.length > limits.maxArchiveBytes) fail("EXPORT_ARCHIVE_SIZE_LIMIT_EXCEEDED");
  const eocdOffset = locateEndOfCentralDirectory(buffer);
  const disk = buffer.readUInt16LE(eocdOffset + 4);
  const centralDisk = buffer.readUInt16LE(eocdOffset + 6);
  const diskEntries = buffer.readUInt16LE(eocdOffset + 8);
  const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
  const centralSize = buffer.readUInt32LE(eocdOffset + 12);
  const centralOffset = buffer.readUInt32LE(eocdOffset + 16);
  const commentLength = buffer.readUInt16LE(eocdOffset + 20);
  if (
    disk !== 0 ||
    centralDisk !== 0 ||
    diskEntries !== totalEntries ||
    totalEntries < 1 ||
    totalEntries > limits.maxEntries ||
    commentLength !== 0 ||
    eocdOffset + 22 !== buffer.length ||
    centralOffset + centralSize !== eocdOffset
  ) {
    fail("EXPORT_ZIP_LAYOUT_INVALID");
  }

  const entries = [];
  const names = new Set();
  let offset = centralOffset;
  let totalUncompressedBytes = 0;
  for (let index = 0; index < totalEntries; index += 1) {
    if (offset + 46 > eocdOffset || buffer.readUInt32LE(offset) !== ZIP_CENTRAL_SIGNATURE) {
      fail("EXPORT_ZIP_CENTRAL_DIRECTORY_INVALID");
    }
    const versionMadeBy = buffer.readUInt16LE(offset + 4);
    const host = versionMadeBy >>> 8;
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const expectedCrc32 = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const memberCommentLength = buffer.readUInt16LE(offset + 32);
    const memberDisk = buffer.readUInt16LE(offset + 34);
    const externalAttributes = buffer.readUInt32LE(offset + 38);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const end = offset + 46 + nameLength + extraLength + memberCommentLength;
    if (end > eocdOffset || nameLength < 1 || nameLength > 128) {
      fail("EXPORT_ZIP_CENTRAL_DIRECTORY_INVALID");
    }
    const unixRegular =
      host === ZIP_UNIX_HOST &&
      ((externalAttributes >>> 16) & ZIP_UNIX_FILE_TYPE_MASK) === ZIP_UNIX_REGULAR_FILE;
    const dosRegular =
      host === ZIP_DOS_HOST &&
      (externalAttributes & ZIP_DOS_DIRECTORY_ATTRIBUTE) === 0;
    if (!unixRegular && !dosRegular) {
      fail("EXPORT_ZIP_NON_REGULAR_MEMBER");
    }
    if (
      (flags & ~ZIP_ALLOWED_FLAGS) !== 0 ||
      ![ZIP_METHOD_STORE, ZIP_METHOD_DEFLATE].includes(method) ||
      memberCommentLength !== 0 ||
      memberDisk !== 0 ||
      compressedSize > limits.maxArchiveBytes ||
      uncompressedSize > limits.maxEntryBytes
    ) {
      fail("EXPORT_ZIP_MEMBER_INVALID");
    }
    const nameBytes = buffer.subarray(offset + 46, offset + 46 + nameLength);
    if ((flags & ZIP_UTF8_FLAG) === 0 && nameBytes.some((byte) => byte > 0x7f)) {
      fail("EXPORT_ZIP_MEMBER_NAME_ENCODING_INVALID");
    }
    const name = assertSafeMemberName(
      decodeUtf8(nameBytes, "EXPORT_ZIP_MEMBER_NAME_ENCODING_INVALID"),
    );
    if (names.has(name)) fail("EXPORT_ZIP_DUPLICATE_MEMBER");
    names.add(name);
    const extra = buffer.subarray(
      offset + 46 + nameLength,
      offset + 46 + nameLength + extraLength,
    );
    parseZipExtra(extra);
    totalUncompressedBytes += uncompressedSize;
    if (totalUncompressedBytes > limits.maxTotalEntryBytes) {
      fail("EXPORT_ZIP_TOTAL_SIZE_LIMIT_EXCEEDED");
    }
    entries.push(Object.freeze({
      name,
      flags,
      method,
      crc32: expectedCrc32,
      compressedSize,
      uncompressedSize,
      localOffset,
    }));
    offset = end;
  }
  if (offset !== eocdOffset) fail("EXPORT_ZIP_CENTRAL_DIRECTORY_INVALID");
  const placeholder = entries.find((entry) => entry.name === ARCHIVE_NAME);
  if (!placeholder || placeholder.uncompressedSize !== 0) {
    fail("EXPORT_ZIP_PLACEHOLDER_INVALID");
  }

  const ranges = [];
  for (const entry of entries) {
    if (
      entry.localOffset + 30 > centralOffset ||
      buffer.readUInt32LE(entry.localOffset) !== ZIP_LOCAL_SIGNATURE
    ) {
      fail("EXPORT_ZIP_LOCAL_HEADER_INVALID");
    }
    const flags = buffer.readUInt16LE(entry.localOffset + 6);
    const method = buffer.readUInt16LE(entry.localOffset + 8);
    const localNameLength = buffer.readUInt16LE(entry.localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(entry.localOffset + 28);
    const dataOffset = entry.localOffset + 30 + localNameLength + localExtraLength;
    const dataEnd = dataOffset + entry.compressedSize;
    if (flags !== entry.flags || method !== entry.method || dataEnd > centralOffset) {
      fail("EXPORT_ZIP_LOCAL_HEADER_INVALID");
    }
    const localName = decodeUtf8(
      buffer.subarray(entry.localOffset + 30, entry.localOffset + 30 + localNameLength),
      "EXPORT_ZIP_MEMBER_NAME_ENCODING_INVALID",
    );
    if (localName !== entry.name) fail("EXPORT_ZIP_LOCAL_HEADER_INVALID");
    parseZipExtra(
      buffer.subarray(
        entry.localOffset + 30 + localNameLength,
        entry.localOffset + 30 + localNameLength + localExtraLength,
      ),
    );
    ranges.push({ start: entry.localOffset, end: dataEnd, name: entry.name, dataOffset });
  }
  ranges.sort((left, right) => left.start - right.start);
  for (let index = 1; index < ranges.length; index += 1) {
    if (ranges[index].start < ranges[index - 1].end) fail("EXPORT_ZIP_MEMBER_OVERLAP");
  }
  const dataOffsets = new Map(ranges.map((range) => [range.name, range.dataOffset]));
  return Object.freeze({
    archiveBytes: buffer.length,
    archiveSha256: sha256(buffer),
    entryCount: entries.length,
    totalUncompressedBytes,
    entries,
    dataOffsets,
  });
}

function extractTarget(buffer, inventory, memberName, limits) {
  const entry = inventory.entries.find((candidate) => candidate.name === memberName);
  if (!entry) return null;
  const dataOffset = inventory.dataOffsets.get(memberName);
  const compressed = buffer.subarray(dataOffset, dataOffset + entry.compressedSize);
  let output;
  try {
    output = entry.method === ZIP_METHOD_STORE
      ? Buffer.from(compressed)
      : inflateRawSync(compressed, { maxOutputLength: limits.maxEntryBytes });
  } catch {
    fail("EXPORT_ZIP_TARGET_DECOMPRESSION_FAILED");
  }
  if (output.length !== entry.uncompressedSize || crc32(output) !== entry.crc32) {
    output.fill(0);
    fail("EXPORT_ZIP_TARGET_INTEGRITY_INVALID");
  }
  return output;
}

function isOpaqueSaltedBase64Envelope(buffer) {
  const text = decodeUtf8(buffer, "EXPORT_TARGET_UTF8_INVALID");
  const value = text.endsWith("\n")
    ? text.slice(0, -1)
    : text;
  if (
    value.length < 44 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    return false;
  }
  const decoded = Buffer.from(value, "base64");
  try {
    return (
      decoded.toString("base64") === value &&
      decoded.length >= 32 &&
      decoded.subarray(0, 8).equals(Buffer.from("Salted__", "ascii")) &&
      (decoded.length - 16) % 16 === 0
    );
  } finally {
    decoded.fill(0);
  }
}

function parseNestedJson(value, limits, label) {
  if (typeof value === "string") {
    try {
      return parseStrictJson(value, limits);
    } catch (error) {
      if (error instanceof ReleaseRehearsalN8nExportError) {
        fail(`${label}_${error.code.replace(/^EXPORT_JSON_/u, "")}`);
      }
      throw error;
    }
  }
  if (Array.isArray(value) || isPlainObject(value)) {
    inspectJsonShape(value, limits);
    return value;
  }
  fail(`${label}_INVALID`);
}

function validateNodeSet(nodes, label) {
  if (!Array.isArray(nodes) || nodes.length !== RELEASE_REHEARSAL_N8N_NODE_BINDINGS.length) {
    fail(`${label}_NODE_SET_INVALID`);
  }
  const normalized = nodes.map((node) => {
    if (!isPlainObject(node)) fail(`${label}_NODE_SET_INVALID`);
    return {
      id: node.id,
      name: node.name,
      type: node.type,
      typeVersion: node.typeVersion,
    };
  });
  const expected = RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map(
    ({ id, name, type, typeVersion }) => ({ id, name, type, typeVersion }),
  );
  if (canonicalJson(normalized) !== canonicalJson(expected)) {
    fail(`${label}_NODE_SET_INVALID`);
  }
  return normalized;
}

function normalizeItemLink(pairedItem, isOrigin) {
  if (pairedItem === undefined) {
    return { state: isOrigin ? "ORIGIN" : "ABSENT", links: [] };
  }
  const values = Array.isArray(pairedItem) ? pairedItem : [pairedItem];
  if (values.length < 1 || values.length > 16) fail("EXPORT_ITEM_LINK_INVALID");
  const links = values.map((link) => {
    if (!isPlainObject(link)) fail("EXPORT_ITEM_LINK_INVALID");
    const keys = Object.keys(link).sort(stableCompare);
    if (keys.some((key) => !["input", "item"].includes(key))) {
      fail("EXPORT_ITEM_LINK_FIELD_UNEXPECTED");
    }
    if (!Number.isInteger(link.item) || link.item < 0) fail("EXPORT_ITEM_LINK_INVALID");
    if (link.input !== undefined && (!Number.isInteger(link.input) || link.input < 0)) {
      fail("EXPORT_ITEM_LINK_INVALID");
    }
    return { inputIndex: link.input ?? 0, itemIndex: link.item };
  });
  return { state: "LINKED", links };
}

function normalizeItemLinks(executionData) {
  const runData = executionData?.resultData?.runData;
  if (!isPlainObject(runData)) fail("EXPORT_RUN_DATA_MISSING");
  const bindingByName = new Map(
    RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map((binding) => [binding.name, binding]),
  );
  const links = [];
  for (const [name, runs] of Object.entries(runData)) {
    const binding = bindingByName.get(name);
    if (!binding || !Array.isArray(runs)) fail("EXPORT_EXECUTED_NODE_INVALID");
    for (let runIndex = 0; runIndex < runs.length; runIndex += 1) {
      const outputs = runs[runIndex]?.data?.main;
      if (!Array.isArray(outputs)) fail("EXPORT_RUN_OUTPUT_INVALID");
      for (let outputIndex = 0; outputIndex < outputs.length; outputIndex += 1) {
        const items = outputs[outputIndex] ?? [];
        if (!Array.isArray(items)) fail("EXPORT_RUN_OUTPUT_INVALID");
        for (let itemIndex = 0; itemIndex < items.length; itemIndex += 1) {
          const item = items[itemIndex];
          if (!isPlainObject(item)) fail("EXPORT_RUN_ITEM_INVALID");
          links.push({
            nodeId: binding.id,
            runIndex,
            outputIndex,
            itemIndex,
            ...normalizeItemLink(item.pairedItem, binding.role === "trigger"),
          });
        }
      }
    }
  }
  return links;
}

function requiredEvidence(trace, executionRow, itemLinks) {
  const expectedOrder = RELEASE_REHEARSAL_N8N_NODE_BINDINGS.map((node) => node.id);
  const actualOrder = trace.executionOrder?.map((entry) => entry.nodeId) ?? null;
  const terminalStatus =
    trace.terminalStatus === "SUCCESS" &&
    executionRow.finished === true &&
    typeof executionRow.stoppedAt === "string";
  const executedNodeIdentities =
    trace.traceStatus === "TRACE_AVAILABLE" &&
    canonicalJson(trace.actualNodeIds) ===
      canonicalJson([...expectedOrder].sort(stableCompare));
  const nodeOrder = actualOrder !== null && canonicalJson(actualOrder) === canonicalJson(expectedOrder);
  const runAndOutputIndexes = trace.nodeExecutions.length === expectedOrder.length &&
    trace.nodeExecutions.every((node) =>
      node.runs.length === 1 &&
      node.runs[0].runIndex === 0 &&
      node.runs[0].outputBranches.length === 1 &&
      node.runs[0].outputBranches[0].branchIndex === 0,
    );
  const linksByNode = new Map(
    expectedOrder.map((nodeId) => [
      nodeId,
      itemLinks.filter((item) => item.nodeId === nodeId),
    ]),
  );
  const itemLinkInformation = expectedOrder.every((nodeId, index) => {
    const items = linksByNode.get(nodeId);
    if (items.length !== 1) return false;
    if (index === 0) return items[0].state === "ORIGIN" && items[0].links.length === 0;
    return (
      items[0].state === "LINKED" &&
      items[0].links.length === 1 &&
      items[0].links[0].inputIndex === 0 &&
      items[0].links[0].itemIndex === 0
    );
  });
  const downstreamId = RELEASE_REHEARSAL_N8N_NODE_BINDINGS.find(
    (node) => node.role === "downstream",
  ).id;
  const downstreamFinalNodeExecution =
    trace.downstreamNodeExecuted === true && actualOrder?.at(-1) === downstreamId;
  return Object.freeze({
    terminalStatus,
    executedNodeIdentities,
    nodeOrder,
    runAndOutputIndexes,
    itemLinkInformation,
    downstreamFinalNodeExecution,
  });
}

function targetFileEvidence(inventory) {
  return Object.entries(TARGET_MEMBERS).flatMap(([kind, name]) => {
    const entry = inventory.entries.find((candidate) => candidate.name === name);
    return entry
      ? [{ kind, bytes: entry.uncompressedSize, compressedBytes: entry.compressedSize }]
      : [];
  });
}

export function normalizeReleaseRehearsalN8nEntityArchive(archiveBuffer, options = {}) {
  const limits = normalizeLimits(options.limits);
  const expectedWorkflowId = options.workflowId ?? RELEASE_REHEARSAL_N8N_WORKFLOW_ID;
  if (expectedWorkflowId !== RELEASE_REHEARSAL_N8N_WORKFLOW_ID) {
    throw new TypeError("Only the fixed synthetic workflow ID is supported.");
  }
  const inventory = inventoryZip(archiveBuffer, limits);
  const missingTargets = Object.values(TARGET_MEMBERS).filter(
    (name) => !inventory.entries.some((entry) => entry.name === name),
  );
  const archiveEvidence = Object.freeze({
    format: "ZIP_JSONL",
    archiveBytes: inventory.archiveBytes,
    archiveSha256: inventory.archiveSha256,
    fileCount: inventory.entryCount,
    totalUncompressedBytes: inventory.totalUncompressedBytes,
    targetFiles: targetFileEvidence(inventory),
    unrelatedEntityFileCount:
      inventory.entryCount - targetFileEvidence(inventory).length - 1,
    rawRetained: false,
  });
  if (missingTargets.length > 0) {
    return Object.freeze({
      schemaVersion: RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION,
      status: "TRACE_EXPORT_UNAVAILABLE",
      command: RELEASE_REHEARSAL_N8N_EXPORT_COMMAND,
      archive: archiveEvidence,
      correlation: null,
      trace: null,
      requiredEvidence: Object.fromEntries(REQUIRED_TRACE_FIELDS.map((field) => [field, false])),
      limitationCodes: ["EXECUTION_HISTORY_TARGET_FILES_MISSING"],
      errorCodes: [],
    });
  }

  const extracted = new Map();
  try {
    for (const name of Object.values(TARGET_MEMBERS)) {
      extracted.set(name, extractTarget(archiveBuffer, inventory, name, limits));
    }
    const encryptedTargets = [...extracted.values()].filter(
      isOpaqueSaltedBase64Envelope,
    ).length;
    if (encryptedTargets > 0) {
      if (encryptedTargets !== TARGET_MEMBER_SET.size) {
        fail("EXPORT_TARGET_ENCRYPTION_SET_INCONSISTENT");
      }
      return Object.freeze({
        schemaVersion: RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION,
        status: "TRACE_EXPORT_UNAVAILABLE",
        command: RELEASE_REHEARSAL_N8N_EXPORT_COMMAND,
        archive: Object.freeze({
          ...archiveEvidence,
          targetPayloadEncoding: "OPAQUE_SALTED_BASE64_ENVELOPE",
          encryptedTargetFileCount: encryptedTargets,
        }),
        correlation: null,
        trace: null,
        requiredEvidence: Object.fromEntries(
          REQUIRED_TRACE_FIELDS.map((field) => [field, false]),
        ),
        limitationCodes: [
          "DOCUMENTED_EXPORT_TARGETS_ENCRYPTED",
          "EXACT_WORKFLOW_EXECUTION_CORRELATION_UNAVAILABLE",
          "NO_DOCUMENTED_STANDALONE_DECRYPT_OUTPUT_SURFACE",
        ],
        errorCodes: [],
      });
    }
    const workflows = parseJsonLines(
      extracted.get(TARGET_MEMBERS.workflow),
      limits,
      "EXPORT_WORKFLOW",
    );
    const executions = parseJsonLines(
      extracted.get(TARGET_MEMBERS.execution),
      limits,
      "EXPORT_EXECUTION",
    );
    const executionDataRows = parseJsonLines(
      extracted.get(TARGET_MEMBERS.executionData),
      limits,
      "EXPORT_EXECUTION_DATA",
    );
    if (workflows.length !== 1) fail("EXPORT_WORKFLOW_MATCH_AMBIGUOUS");
    if (executions.length !== limits.maxExecutions) fail("EXPORT_EXECUTION_MATCH_AMBIGUOUS");
    if (executionDataRows.length !== limits.maxExecutions) {
      fail("EXPORT_EXECUTION_DATA_MATCH_AMBIGUOUS");
    }
    const workflow = workflows[0];
    const execution = executions[0];
    const executionDataRow = executionDataRows[0];
    if (
      workflow.id !== expectedWorkflowId ||
      workflow.name !== "CSINT Release Rehearsal n8n CLI Trace Probe"
    ) {
      fail("EXPORT_WORKFLOW_MATCH_INVALID");
    }
    const workflowNodes = parseNestedJson(workflow.nodes, limits, "EXPORT_WORKFLOW_NODES");
    const workflowNodeProjection = validateNodeSet(workflowNodes, "EXPORT_WORKFLOW");
    if (
      !EXECUTION_ID_PATTERN.test(String(execution.id ?? "")) ||
      execution.workflowId !== expectedWorkflowId ||
      executionDataRow.executionId !== execution.id
    ) {
      fail("EXPORT_EXECUTION_CORRELATION_INVALID");
    }
    const storedWorkflow = parseNestedJson(
      executionDataRow.workflowData,
      limits,
      "EXPORT_EXECUTION_WORKFLOW_DATA",
    );
    if (storedWorkflow.id !== expectedWorkflowId) {
      fail("EXPORT_EXECUTION_WORKFLOW_CORRELATION_INVALID");
    }
    const storedWorkflowNodes = parseNestedJson(
      storedWorkflow.nodes,
      limits,
      "EXPORT_EXECUTION_WORKFLOW_NODES",
    );
    validateNodeSet(storedWorkflowNodes, "EXPORT_EXECUTION_WORKFLOW");
    const executionData = parseNestedJson(
      executionDataRow.data,
      limits,
      "EXPORT_EXECUTION_DATA",
    );
    const trace = parseReleaseRehearsalN8nRawOutput(
      Buffer.from(canonicalJson({
        status: execution.status,
        mode: execution.mode,
        data: executionData,
      }), "utf8"),
    );
    const itemLinks = normalizeItemLinks(executionData);
    const evidence = requiredEvidence(trace, execution, itemLinks);
    const missingFields = REQUIRED_TRACE_FIELDS.filter((field) => evidence[field] !== true);
    const status = missingFields.length === 0
      ? "PASS_TRACE_EXPORT"
      : "TRACE_EXPORT_PARTIAL";
    return Object.freeze({
      schemaVersion: RELEASE_REHEARSAL_N8N_EXPORT_SCHEMA_VERSION,
      status,
      command: RELEASE_REHEARSAL_N8N_EXPORT_COMMAND,
      archive: archiveEvidence,
      correlation: Object.freeze({
        workflowCount: workflows.length,
        executionCount: executions.length,
        executionDataCount: executionDataRows.length,
        workflowId: expectedWorkflowId,
        workflowNodeProjectionSha256: fingerprintJson(workflowNodeProjection),
        executionIdSha256: sha256(String(execution.id)),
      }),
      trace: Object.freeze({
        terminalStatus: trace.terminalStatus,
        executionMode: trace.executionMode,
        executedNodeIds: trace.actualNodeIds,
        nodeOrder: trace.executionOrder,
        runOutputs: trace.nodeExecutions,
        itemLinks,
        downstreamNodeExecuted: trace.downstreamNodeExecuted,
      }),
      requiredEvidence: evidence,
      limitationCodes: missingFields.map(
        (field) => `TRACE_FIELD_${field.replace(/([a-z])([A-Z])/gu, "$1_$2").toUpperCase()}_UNAVAILABLE`,
      ),
      errorCodes: [],
    });
  } finally {
    for (const buffer of extracted.values()) buffer?.fill(0);
  }
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameSnapshot(left, right) {
  return left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

export async function readReleaseRehearsalN8nEntityExport(exportDirectory, options = {}) {
  const limits = normalizeLimits(options.limits);
  const absoluteDirectory = path.resolve(exportDirectory);
  const directoryEntry = await lstat(absoluteDirectory, { bigint: true });
  if (directoryEntry.isSymbolicLink() || !directoryEntry.isDirectory()) {
    fail("EXPORT_DIRECTORY_NOT_REGULAR");
  }
  const entries = await readdir(absoluteDirectory, { withFileTypes: true });
  if (
    entries.length !== 1 ||
    entries[0].name !== ARCHIVE_NAME ||
    entries[0].isSymbolicLink() ||
    !entries[0].isFile()
  ) {
    fail("EXPORT_DIRECTORY_INVENTORY_INVALID");
  }
  const archivePath = path.join(absoluteDirectory, ARCHIVE_NAME);
  const before = await lstat(archivePath, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile()) fail("EXPORT_ARCHIVE_NOT_REGULAR");
  if (before.size > BigInt(limits.maxArchiveBytes)) fail("EXPORT_ARCHIVE_SIZE_LIMIT_EXCEEDED");
  const handle = await open(archivePath, "r");
  let buffer;
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameFile(before, opened) || !sameSnapshot(before, opened)) {
      fail("EXPORT_ARCHIVE_CHANGED");
    }
    buffer = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== buffer.length) fail("EXPORT_ARCHIVE_SHORT_READ");
    const after = await handle.stat({ bigint: true });
    if (!sameFile(opened, after) || !sameSnapshot(opened, after)) {
      fail("EXPORT_ARCHIVE_CHANGED");
    }
    return normalizeReleaseRehearsalN8nEntityArchive(buffer, { ...options, limits });
  } finally {
    buffer?.fill(0);
    await handle.close();
  }
}

export async function deleteReleaseRehearsalN8nRawExport(exportDirectory) {
  const absoluteDirectory = path.resolve(exportDirectory);
  const entries = await readdir(absoluteDirectory, { withFileTypes: true });
  if (
    entries.length !== 1 ||
    entries[0].name !== ARCHIVE_NAME ||
    entries[0].isSymbolicLink() ||
    !entries[0].isFile()
  ) {
    fail("EXPORT_RAW_DELETE_TARGET_INVALID", "BLOCKED");
  }
  await unlink(path.join(absoluteDirectory, ARCHIVE_NAME));
  const remaining = await readdir(absoluteDirectory);
  if (remaining.length !== 0) fail("EXPORT_RAW_DELETE_INCOMPLETE", "BLOCKED");
  return Object.freeze({ rawArchiveDeleted: true, exportDirectoryEmpty: true });
}
