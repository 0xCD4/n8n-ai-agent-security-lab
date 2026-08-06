import { readFile, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { networkInterfaces } from "node:os";
import { createConnection } from "node:net";
import { lookup, resolve4 } from "node:dns/promises";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../../src/evidence-fingerprint.mjs";
import {
  RELEASE_REHEARSAL_CAPTURE_HEADERS,
  RELEASE_REHEARSAL_CAPTURE_ROUTE,
} from "../../src/release-rehearsal-capture.mjs";
import { validateReleaseRehearsalCaptureConfig } from "../../src/release-rehearsal-fixture.mjs";
import { readBoundedJsonFile } from "../../src/safe-json.mjs";
import {
  CAPTURE_CONFIG_PATH,
  CAPTURE_HTTP_ADDRESS,
  CAPTURE_HTTP_PORT,
  CAPTURE_OUTPUT_DIRECTORY,
} from "./server.mjs";

const PROBE_RESULT_PATH = `${CAPTURE_OUTPUT_DIRECTORY}/probe-result.json`;
const RESOLVER_PATH = "/etc/resolv.conf";
const EXPECTED_RESOLVER =
  "nameserver 127.0.0.1\noptions timeout:1 attempts:1 ndots:1\n";
const TCP_TIMEOUT_MS = 750;
const HTTP_TIMEOUT_MS = 2_000;
const DNS_TIMEOUT_MS = 2_000;
const ROUTE_BLOCKED_CODES = new Set([
  "EACCES",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "EPERM",
]);

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function parseMode(argv) {
  if (argv.length === 0) return "normal";
  if (argv.length !== 2 || argv[0] !== "--mode") {
    throw new Error("PROBE_ARGUMENT_INVALID");
  }
  if (!["normal", "synthetic-failure", "timeout"].includes(argv[1])) {
    throw new Error("PROBE_ARGUMENT_INVALID");
  }
  return argv[1];
}

function withTimeout(promise, timeoutMs, code) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(code)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function inspectInterfaces() {
  const procText = await readFile("/proc/net/dev", "utf8");
  const procNames = procText
    .split("\n")
    .slice(2)
    .map((line) => line.split(":", 1)[0].trim())
    .filter(Boolean)
    .sort(stableCompare);
  const apiNames = Object.keys(networkInterfaces()).sort(stableCompare);
  return {
    names: apiNames,
    procAgreement: canonicalJson(apiNames) === canonicalJson(procNames),
    onlyLoopback:
      apiNames.length === 1 && apiNames[0] === "lo" && procNames.length === 1,
  };
}

async function inspectRoutes() {
  const [ipv4Text, ipv6Text] = await Promise.all([
    readFile("/proc/net/route", "utf8"),
    readFile("/proc/net/ipv6_route", "utf8"),
  ]);
  const ipv4Default = ipv4Text
    .split("\n")
    .slice(1)
    .map((line) => line.trim().split(/\s+/u))
    .some((fields) => fields.length >= 8 && fields[1] === "00000000" && fields[7] === "00000000");
  const ipv6Default = ipv6Text
    .split("\n")
    .map((line) => line.trim().split(/\s+/u))
    .some((fields) => {
      if (fields.length < 10 || fields[0] !== "0".repeat(32) || fields[1] !== "00") {
        return false;
      }
      const flags = Number.parseInt(fields[8], 16);
      const isUp = (flags & 0x1) !== 0;
      const isReject = (flags & 0x200) !== 0;
      return isUp && !isReject;
    });
  return { ipv4Default, ipv6Default };
}

function attemptTcp(host, port, label) {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    let settled = false;
    function finish(errorCode, blocked) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ label, blocked, errorCode });
    }
    const timer = setTimeout(() => finish("TIMEOUT_UNPROVEN", false), TCP_TIMEOUT_MS);
    socket.once("connect", () => finish("CONNECTED", false));
    socket.once("error", (error) => {
      const code = typeof error.code === "string" ? error.code : "NETWORK_ERROR";
      finish(code, ROUTE_BLOCKED_CODES.has(code));
    });
  });
}

function sendCaptureRequest(config) {
  const node = config.nodes[0];
  const body = Buffer.from(canonicalJson({ value: "synthetic-value" }), "utf8");
  const headers = {
    "content-type": "application/json",
    "content-length": String(body.length),
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.runId]: config.runId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.caseId]: config.caseId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.variant]: config.variant,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.fixtureId]: config.fixtureId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.correlationId]: config.correlationId,
    [RELEASE_REHEARSAL_CAPTURE_HEADERS.nodeId]: node.nodeId,
    "x-synthetic-note": "bounded-probe",
  };

  return new Promise((resolve) => {
    const outgoing = request(
      {
        host: CAPTURE_HTTP_ADDRESS,
        port: CAPTURE_HTTP_PORT,
        path: RELEASE_REHEARSAL_CAPTURE_ROUTE,
        method: node.method,
        headers,
      },
      (response) => {
        let bytes = 0;
        response.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > 4_096) outgoing.destroy(new Error("HTTP_RESPONSE_OVERSIZED"));
        });
        response.on("end", () => {
          resolve({
            succeeded: response.statusCode === node.responseStubs[0].status,
            statusCode: response.statusCode ?? 0,
            errorCode:
              response.statusCode === node.responseStubs[0].status
                ? null
                : "HTTP_STATUS_UNEXPECTED",
          });
        });
      },
    );
    outgoing.setTimeout(HTTP_TIMEOUT_MS, () => {
      outgoing.destroy(new Error("HTTP_TIMEOUT"));
    });
    outgoing.once("error", (error) => {
      resolve({
        succeeded: false,
        statusCode: 0,
        errorCode: error.message === "HTTP_TIMEOUT" ? "HTTP_TIMEOUT" : "HTTP_FAILED",
      });
    });
    outgoing.end(body);
  });
}

async function expectNxdomain(name, label) {
  try {
    await withTimeout(resolve4(name), DNS_TIMEOUT_MS, "DNS_TIMEOUT");
    return { label, nxdomain: false, errorCode: "DNS_RESOLVED" };
  } catch (error) {
    const code = error.message === "DNS_TIMEOUT" ? "DNS_TIMEOUT" : error.code;
    return {
      label,
      nxdomain: code === "ENOTFOUND",
      errorCode: typeof code === "string" ? code : "DNS_FAILED",
    };
  }
}

async function checkHostDockerInternal() {
  try {
    const resolved = await withTimeout(
      lookup("host.docker.internal", { family: 4 }),
      DNS_TIMEOUT_MS,
      "HOST_ALIAS_LOOKUP_TIMEOUT",
    );
    const connection = await attemptTcp(
      resolved.address,
      80,
      "host-docker-internal",
    );
    return {
      label: connection.label,
      blocked: connection.blocked,
      resolution: "RESOLVED",
      errorCode: connection.errorCode,
    };
  } catch (error) {
    const code =
      error.message === "HOST_ALIAS_LOOKUP_TIMEOUT"
        ? "HOST_ALIAS_LOOKUP_TIMEOUT"
        : error.code;
    return {
      label: "host-docker-internal",
      blocked: code === "ENOTFOUND",
      resolution: code === "ENOTFOUND" ? "NOT_FOUND" : "UNPROVEN",
      errorCode: typeof code === "string" ? code : "HOST_ALIAS_LOOKUP_FAILED",
    };
  }
}

async function writeProbeResult(result) {
  await writeFile(PROBE_RESULT_PATH, canonicalJson(result) + "\n", {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

export async function runReleaseRehearsalProbe(argv = process.argv.slice(2)) {
  const mode = parseMode(argv);
  if (mode === "timeout") {
    await new Promise(() => {
      setInterval(() => {}, 1_000);
    });
    return;
  }
  if (mode === "synthetic-failure") {
    await writeProbeResult({
      schemaVersion: 1,
      status: "FAILED",
      errorCodes: ["SYNTHETIC_PROBE_FAILURE"],
    });
    throw new Error("SYNTHETIC_PROBE_FAILURE");
  }

  const [parsedConfig, resolverText, interfaces, routes] = await Promise.all([
    readBoundedJsonFile(CAPTURE_CONFIG_PATH, {
      label: "capture configuration",
      maxBytes: 256 * 1024,
      maxDepth: 32,
      maxValues: 10_000,
    }),
    readFile(RESOLVER_PATH, "utf8"),
    inspectInterfaces(),
    inspectRoutes(),
  ]);
  const config = validateReleaseRehearsalCaptureConfig(parsedConfig);
  const resolverIsLocalOnly = resolverText === EXPECTED_RESOLVER;
  const [http, ordinaryDns, hostAccess, ...blockedDestinations] =
    await Promise.all([
      sendCaptureRequest(config),
      expectNxdomain("probe-target.example.invalid", "ordinary-invalid"),
      checkHostDockerInternal(),
      attemptTcp("192.0.2.1", 80, "public-test-ip"),
      attemptTcp("169.254.169.254", 80, "cloud-metadata"),
      attemptTcp("192.168.1.1", 80, "private-lan"),
      attemptTcp("172.17.0.1", 80, "docker-gateway"),
    ]);

  const errorCodes = [];
  if (!resolverIsLocalOnly) errorCodes.push("RESOLVER_NOT_LOCAL_ONLY");
  if (!interfaces.onlyLoopback || !interfaces.procAgreement) {
    errorCodes.push("NON_LOOPBACK_INTERFACE_PRESENT");
  }
  if (routes.ipv4Default) errorCodes.push("IPV4_DEFAULT_ROUTE_PRESENT");
  if (routes.ipv6Default) errorCodes.push("IPV6_DEFAULT_ROUTE_PRESENT");
  if (!http.succeeded) errorCodes.push(http.errorCode ?? "HTTP_FAILED");
  if (!ordinaryDns.nxdomain) errorCodes.push(ordinaryDns.errorCode);
  if (!hostAccess.blocked) {
    errorCodes.push("HOST_DOCKER_INTERNAL_USABLE");
  }
  for (const destination of blockedDestinations) {
    if (!destination.blocked) {
      errorCodes.push(`DESTINATION_${destination.label.toUpperCase().replaceAll("-", "_")}_${destination.errorCode}`);
    }
  }

  const result = {
    schemaVersion: 1,
    status: errorCodes.length === 0 ? "PASS" : "FAILED",
    interfaces,
    routes,
    http,
    dns: {
      resolverIsLocalOnly,
      ordinaryQuery: ordinaryDns,
    },
    hostAccess,
    blockedDestinations,
    errorCodes: [...new Set(errorCodes)].sort(stableCompare),
  };
  await writeProbeResult(result);
  return result;
}

const invokedDirectly =
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  runReleaseRehearsalProbe().catch(() => {
    process.stderr.write(
      canonicalJson({ code: "PROBE_FAILED", schemaVersion: 1 }) + "\n",
    );
    process.exitCode = 1;
  });
}
