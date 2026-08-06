import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { createSocket } from "node:dgram";

import { canonicalJson } from "./evidence-fingerprint.mjs";

export const RELEASE_REHEARSAL_DNS_EVENT_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_DNS_SUMMARY_SCHEMA_VERSION = 1;
export const RELEASE_REHEARSAL_DNS_MAX_PACKET_BYTES = 512;
export const RELEASE_REHEARSAL_DNS_DEFAULT_EVENT_LIMIT = 100;
export const RELEASE_REHEARSAL_DNS_DEFAULT_VIOLATION_LIMIT = 100;

const DNS_HEADER_BYTES = 12;
const DNS_CLASS_IN = 1;
const DNS_FLAG_QUERY_RESPONSE = 0x8000;
const DNS_FLAG_RECURSION_DESIRED = 0x0100;
const DNS_RCODE_FORMAT_ERROR = 1;
const DNS_RCODE_NAME_ERROR = 3;
const DNS_LABEL_PATTERN = /^[A-Za-z0-9-]+$/u;

class DnsSinkError extends Error {
  constructor(code) {
    super("DNS request rejected.");
    this.code = code;
  }
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  if (Buffer.isBuffer(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertPositiveInteger(value, label) {
  if (!Number.isInteger(value) || value < 1 || value > 10_000) {
    throw new TypeError(`${label} must be an integer from 1 through 10000.`);
  }
}

function queryNameSha256(queryName) {
  return createHash("sha256").update(queryName.toLowerCase(), "ascii").digest("hex");
}

export function parseReleaseRehearsalDnsQuery(packet) {
  if (!Buffer.isBuffer(packet)) {
    throw new TypeError("DNS packet must be a Buffer.");
  }
  if (packet.length > RELEASE_REHEARSAL_DNS_MAX_PACKET_BYTES) {
    throw new DnsSinkError("DNS_PACKET_OVERSIZED");
  }
  if (packet.length < DNS_HEADER_BYTES) {
    throw new DnsSinkError("DNS_PACKET_MALFORMED");
  }

  const flags = packet.readUInt16BE(2);
  const questionCount = packet.readUInt16BE(4);
  const answerCount = packet.readUInt16BE(6);
  const authorityCount = packet.readUInt16BE(8);
  const additionalCount = packet.readUInt16BE(10);
  if (
    (flags & DNS_FLAG_QUERY_RESPONSE) !== 0 ||
    (flags & 0x7800) !== 0 ||
    questionCount !== 1 ||
    answerCount !== 0 ||
    authorityCount !== 0 ||
    additionalCount !== 0
  ) {
    throw new DnsSinkError("DNS_PACKET_UNSUPPORTED");
  }

  let offset = DNS_HEADER_BYTES;
  let wireNameBytes = 1;
  const labels = [];
  while (true) {
    if (offset >= packet.length) {
      throw new DnsSinkError("DNS_PACKET_MALFORMED");
    }
    const length = packet[offset];
    offset += 1;
    if (length === 0) break;
    if ((length & 0xc0) !== 0 || length > 63 || offset + length > packet.length) {
      throw new DnsSinkError("DNS_PACKET_MALFORMED");
    }
    wireNameBytes += length + 1;
    if (wireNameBytes > 255) {
      throw new DnsSinkError("DNS_NAME_OVERSIZED");
    }
    const labelBytes = packet.subarray(offset, offset + length);
    if (labelBytes.some((byte) => byte > 0x7f)) {
      throw new DnsSinkError("DNS_NAME_INVALID");
    }
    const label = labelBytes.toString("ascii");
    if (
      !DNS_LABEL_PATTERN.test(label) ||
      label.startsWith("-") ||
      label.endsWith("-")
    ) {
      throw new DnsSinkError("DNS_NAME_INVALID");
    }
    labels.push(label);
    offset += length;
  }
  if (labels.length === 0 || offset + 4 !== packet.length) {
    throw new DnsSinkError("DNS_PACKET_MALFORMED");
  }
  const queryType = packet.readUInt16BE(offset);
  const queryClass = packet.readUInt16BE(offset + 2);
  if (queryType < 1 || queryClass !== DNS_CLASS_IN) {
    throw new DnsSinkError("DNS_QUESTION_UNSUPPORTED");
  }

  const queryName = labels.join(".").toLowerCase();
  return deepFreeze({
    id: packet.readUInt16BE(0),
    recursionDesired: (flags & DNS_FLAG_RECURSION_DESIRED) !== 0,
    queryType,
    queryNameSha256: queryNameSha256(queryName),
    question: Buffer.from(packet.subarray(DNS_HEADER_BYTES)),
  });
}

export function createReleaseRehearsalDnsResponse(query, rcode = DNS_RCODE_NAME_ERROR) {
  if (!query || !Buffer.isBuffer(query.question)) {
    throw new TypeError("A parsed DNS query is required.");
  }
  const response = Buffer.alloc(DNS_HEADER_BYTES + query.question.length);
  response.writeUInt16BE(query.id, 0);
  response.writeUInt16BE(
    DNS_FLAG_QUERY_RESPONSE |
      (query.recursionDesired ? DNS_FLAG_RECURSION_DESIRED : 0) |
      rcode,
    2,
  );
  response.writeUInt16BE(1, 4);
  response.writeUInt16BE(0, 6);
  response.writeUInt16BE(0, 8);
  response.writeUInt16BE(0, 10);
  query.question.copy(response, DNS_HEADER_BYTES);
  return response;
}

function createFormatErrorResponse(packet) {
  if (!Buffer.isBuffer(packet) || packet.length < 2) return null;
  const response = Buffer.alloc(DNS_HEADER_BYTES);
  packet.copy(response, 0, 0, 2);
  response.writeUInt16BE(DNS_FLAG_QUERY_RESPONSE | DNS_RCODE_FORMAT_ERROR, 2);
  return response;
}

export function createReleaseRehearsalDnsSink(options = {}) {
  const maxEvents =
    options.maxEvents ?? RELEASE_REHEARSAL_DNS_DEFAULT_EVENT_LIMIT;
  const maxViolations =
    options.maxViolations ?? RELEASE_REHEARSAL_DNS_DEFAULT_VIOLATION_LIMIT;
  assertPositiveInteger(maxEvents, "maxEvents");
  assertPositiveInteger(maxViolations, "maxViolations");

  const events = [];
  const violationCodes = [];
  let eventOverflow = false;
  let violationOverflow = false;
  let finalized = false;

  function recordViolation(code) {
    if (violationCodes.length < maxViolations) {
      violationCodes.push(code);
    } else {
      violationOverflow = true;
    }
  }

  const socket = createSocket("udp4");
  socket.on("message", (packet, remote) => {
    if (finalized) {
      recordViolation("DNS_QUERY_AFTER_FINALIZATION");
      return;
    }
    if (remote.address !== "127.0.0.1") {
      recordViolation("DNS_REMOTE_NOT_LOOPBACK");
      return;
    }

    let query;
    try {
      query = parseReleaseRehearsalDnsQuery(packet);
    } catch (error) {
      recordViolation(error instanceof DnsSinkError ? error.code : "DNS_PACKET_MALFORMED");
      const response = createFormatErrorResponse(packet);
      if (response) socket.send(response, remote.port, remote.address);
      return;
    }

    if (events.length < maxEvents) {
      events.push(
        deepFreeze({
          schemaVersion: RELEASE_REHEARSAL_DNS_EVENT_SCHEMA_VERSION,
          queryType: query.queryType,
          queryNameSha256: query.queryNameSha256,
          occurrence: events.length + 1,
        }),
      );
    } else {
      eventOverflow = true;
      recordViolation("DNS_EVENT_LIMIT_EXCEEDED");
    }
    socket.send(
      createReleaseRehearsalDnsResponse(query),
      remote.port,
      remote.address,
    );
  });
  socket.on("error", () => recordViolation("DNS_SOCKET_ERROR"));

  function getEvents() {
    return Object.freeze([...events]);
  }

  function serializeEvents() {
    return canonicalJson(events) + "\n";
  }

  function finalize() {
    finalized = true;
    const counts = new Map();
    for (const event of events) {
      counts.set(event.queryType, (counts.get(event.queryType) ?? 0) + 1);
    }
    const uniqueViolations = [...new Set([
      ...violationCodes,
      ...(eventOverflow ? ["DNS_EVENT_LIMIT_EXCEEDED"] : []),
      ...(violationOverflow ? ["DNS_VIOLATION_LIMIT_EXCEEDED"] : []),
    ])].sort(stableCompare);
    return deepFreeze({
      schemaVersion: RELEASE_REHEARSAL_DNS_SUMMARY_SCHEMA_VERSION,
      status: uniqueViolations.length === 0 ? "COMPLETE" : "FAILED",
      queryCount: events.length,
      queryTypeCounts: [...counts.entries()]
        .sort((left, right) => left[0] - right[0])
        .map(([queryType, count]) => ({ queryType, count })),
      violationCodes: uniqueViolations,
      forwarded: false,
    });
  }

  function serializeSummary() {
    return canonicalJson(finalize()) + "\n";
  }

  return Object.freeze({
    socket,
    getEvents,
    serializeEvents,
    finalize,
    serializeSummary,
  });
}
