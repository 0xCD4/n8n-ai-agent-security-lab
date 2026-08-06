import { lstat, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../../src/evidence-fingerprint.mjs";
import { createReleaseRehearsalCaptureService } from "../../src/release-rehearsal-capture.mjs";
import { createReleaseRehearsalDnsSink } from "../../src/release-rehearsal-dns-sink.mjs";
import { validateReleaseRehearsalCaptureConfig } from "../../src/release-rehearsal-fixture.mjs";
import { readBoundedJsonFile } from "../../src/safe-json.mjs";

export const CAPTURE_CONFIG_PATH = "/run/rehearsal/config/config.json";
export const CAPTURE_OUTPUT_DIRECTORY = "/run/rehearsal/output";
export const CAPTURE_HTTP_ADDRESS = "127.0.0.1";
export const CAPTURE_HTTP_PORT = 18_080;
export const CAPTURE_DNS_ADDRESS = "127.0.0.1";
export const CAPTURE_DNS_PORT = 53;

const CONFIG_LIMITS = Object.freeze({
  maxBytes: 256 * 1024,
  maxDepth: 32,
  maxValues: 10_000,
});
const SHUTDOWN_TIMEOUT_MS = 3_000;

function fixedMessage(code) {
  return canonicalJson({ code, schemaVersion: 1 }) + "\n";
}

async function assertPrivateOutputDirectory(directory) {
  const entry = await lstat(directory);
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    throw new Error("CAPTURE_OUTPUT_INVALID");
  }
}

function listenHttp(server, address, port) {
  return new Promise((resolve, reject) => {
    const onError = () => {
      server.off("listening", onListening);
      reject(new Error("HTTP_BIND_FAILED"));
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ host: address, port, exclusive: true });
  });
}

function listenDns(socket, address, port) {
  return new Promise((resolve, reject) => {
    const onError = () => {
      socket.off("listening", onListening);
      reject(new Error("DNS_BIND_FAILED"));
    };
    const onListening = () => {
      socket.off("error", onError);
      resolve();
    };
    socket.once("error", onError);
    socket.once("listening", onListening);
    socket.bind({ address, port, exclusive: true });
  });
}

function closeHttp(server) {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      server.closeAllConnections?.();
      resolve();
    }, SHUTDOWN_TIMEOUT_MS);
    timer.unref();
    server.close(() => {
      clearTimeout(timer);
      resolve();
    });
  });
}

function closeDns(socket) {
  return new Promise((resolve) => {
    try {
      socket.close(resolve);
    } catch {
      resolve();
    }
  });
}

async function writeEvidence(outputDirectory, capture, dns) {
  await Promise.all([
    writeFile(
      `${outputDirectory}/capture-events.json`,
      capture.serializeEvents(),
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    ),
    writeFile(
      `${outputDirectory}/capture-summary.json`,
      capture.serializeSummary(),
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    ),
    writeFile(
      `${outputDirectory}/dns-events.json`,
      dns.serializeEvents(),
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    ),
    writeFile(
      `${outputDirectory}/dns-summary.json`,
      dns.serializeSummary(),
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    ),
  ]);
}

export async function startReleaseRehearsalCaptureRole(options = {}) {
  const configPath = options.configPath ?? CAPTURE_CONFIG_PATH;
  const outputDirectory = options.outputDirectory ?? CAPTURE_OUTPUT_DIRECTORY;
  const httpAddress = options.httpAddress ?? CAPTURE_HTTP_ADDRESS;
  const httpPort = options.httpPort ?? CAPTURE_HTTP_PORT;
  const dnsAddress = options.dnsAddress ?? CAPTURE_DNS_ADDRESS;
  const dnsPort = options.dnsPort ?? CAPTURE_DNS_PORT;

  await assertPrivateOutputDirectory(outputDirectory);
  const parsed = await readBoundedJsonFile(configPath, {
    ...CONFIG_LIMITS,
    label: "capture configuration",
  });
  const config = validateReleaseRehearsalCaptureConfig(parsed);
  const capture = createReleaseRehearsalCaptureService(config);
  const dns = createReleaseRehearsalDnsSink();

  try {
    await listenDns(dns.socket, dnsAddress, dnsPort);
    await listenHttp(capture.server, httpAddress, httpPort);
  } catch (error) {
    await Promise.all([closeHttp(capture.server), closeDns(dns.socket)]);
    throw error;
  }

  let stopped = false;
  async function stop() {
    if (stopped) return;
    stopped = true;
    await closeHttp(capture.server);
    await closeDns(dns.socket);
    await writeEvidence(outputDirectory, capture, dns);
  }

  return Object.freeze({ capture, dns, stop });
}

export async function runReleaseRehearsalCaptureRole() {
  const role = await startReleaseRehearsalCaptureRole();
  process.stdout.write(fixedMessage("CAPTURE_READY"));
  await new Promise((resolve, reject) => {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      const hardStop = setTimeout(() => reject(new Error("CAPTURE_STOP_TIMEOUT")), 5_000);
      hardStop.unref();
      role.stop().then(
        () => {
          clearTimeout(hardStop);
          process.stdout.write(fixedMessage("CAPTURE_STOPPED"));
          resolve();
        },
        reject,
      );
    };
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
  });
}

const invokedDirectly =
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  runReleaseRehearsalCaptureRole().catch((error) => {
    const code = ["DNS_BIND_FAILED", "HTTP_BIND_FAILED"].includes(error?.message)
      ? error.message
      : "CAPTURE_START_FAILED";
    process.stderr.write(fixedMessage(code));
    process.exitCode = 1;
  });
}
