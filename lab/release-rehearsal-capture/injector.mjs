import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { request } from "node:http";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../../src/evidence-fingerprint.mjs";
import { validateReleaseRehearsalFixtureSet } from "../../src/release-rehearsal-fixture.mjs";
import { readBoundedJsonFile } from "../../src/safe-json.mjs";

export const ACTION_FIXTURE_PATH = "/run/rehearsal/fixture/fixture-set.json";
export const ACTION_INJECTOR_RESULT_PATH =
  "/run/rehearsal/output/injector-result.json";
export const ACTION_N8N_ADDRESS = "127.0.0.1";
export const ACTION_N8N_PORT = 5_678;

const READY_TIMEOUT_MS = 30_000;
const REQUEST_TIMEOUT_MS = 15_000;
const RESPONSE_LIMIT_BYTES = 64 * 1024;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function readinessOnce() {
  return new Promise((resolve) => {
    let responseBytes = 0;
    let oversized = false;
    const outgoing = request(
      {
        host: ACTION_N8N_ADDRESS,
        port: ACTION_N8N_PORT,
        path: "/healthz/readiness",
        method: "GET",
      },
      (response) => {
        response.on("data", (chunk) => {
          responseBytes += chunk.length;
          if (responseBytes > 1_024) oversized = true;
        });
        response.on("end", () => {
          resolve(oversized ? 0 : (response.statusCode ?? 0));
        });
      },
    );
    outgoing.setTimeout(500, () => outgoing.destroy());
    outgoing.once("error", () => resolve(0));
    outgoing.end();
  });
}

export async function waitForReleaseRehearsalN8nReady() {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  let lastStatusCode = 0;
  while (Date.now() < deadline) {
    lastStatusCode = await readinessOnce();
    if (lastStatusCode === 200) return;
    await delay(250);
  }
  const error = new Error("N8N_READY_TIMEOUT");
  error.code = lastStatusCode > 0
    ? `N8N_READY_TIMEOUT_HTTP_${lastStatusCode}`
    : "N8N_READY_TIMEOUT_TRANSPORT";
  throw error;
}

function sendFixture(fixture) {
  const body = Buffer.from(canonicalJson(fixture.webhook.json), "utf8");
  const headers = {
    ...fixture.webhook.headers,
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.length),
  };
  return new Promise((resolve) => {
    const chunks = [];
    let responseBytes = 0;
    let oversized = false;
    const outgoing = request(
      {
        host: ACTION_N8N_ADDRESS,
        port: ACTION_N8N_PORT,
        path: `/webhook${fixture.webhook.path}`,
        method: fixture.webhook.method,
        headers,
      },
      (response) => {
        response.on("data", (chunk) => {
          responseBytes += chunk.length;
          if (responseBytes > RESPONSE_LIMIT_BYTES) {
            oversized = true;
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          if (oversized) {
            resolve({ status: "FAILED", errorCode: "RESPONSE_LIMIT_EXCEEDED" });
            return;
          }
          const responseBody = Buffer.concat(chunks, responseBytes);
          resolve({
            status: "COMPLETED",
            errorCode: null,
            responseStatusCode: response.statusCode ?? 0,
            responseBytes,
            responseSha256: sha256(responseBody),
          });
        });
      },
    );
    outgoing.setTimeout(REQUEST_TIMEOUT_MS, () => {
      outgoing.destroy(new Error("REQUEST_TIMEOUT"));
    });
    outgoing.once("error", (error) => {
      resolve({
        status: "FAILED",
        errorCode:
          error.message === "REQUEST_TIMEOUT" ? "REQUEST_TIMEOUT" : "REQUEST_FAILED",
      });
    });
    outgoing.end(body);
  });
}

export async function runReleaseRehearsalActionInjector() {
  const parsed = await readBoundedJsonFile(ACTION_FIXTURE_PATH, {
    label: "action rehearsal fixture set",
    maxBytes: 256 * 1024,
    maxDepth: 20,
    maxValues: 10_000,
  });
  const fixtureSet = validateReleaseRehearsalFixtureSet(parsed);
  if (fixtureSet.fixtures.length !== 1) {
    throw new Error("FIXTURE_COUNT_INVALID");
  }
  const fixture = fixtureSet.fixtures[0];
  const requestResult = await sendFixture(fixture);
  const result = {
    schemaVersion: 1,
    status: requestResult.status,
    fixtureId: fixture.id,
    fixtureCanonicalSha256: fixture.canonicalSha256,
    requestMethod: fixture.webhook.method,
    requestPathCanonicalSha256: sha256(Buffer.from(fixture.webhook.path, "utf8")),
    requestBodyBytes: Buffer.byteLength(canonicalJson(fixture.webhook.json), "utf8"),
    requestBodySha256: sha256(Buffer.from(canonicalJson(fixture.webhook.json), "utf8")),
    responseStatusCode: requestResult.responseStatusCode ?? null,
    responseBytes: requestResult.responseBytes ?? 0,
    responseSha256: requestResult.responseSha256 ?? null,
    errorCode: requestResult.errorCode,
    rawValuesRetained: false,
  };
  await writeFile(ACTION_INJECTOR_RESULT_PATH, canonicalJson(result) + "\n", {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  if (result.status !== "COMPLETED") throw new Error(result.errorCode);
  return result;
}

function parseMode(argv) {
  if (argv.length !== 2 || argv[0] !== "--mode") {
    throw new Error("INJECTOR_ARGUMENT_INVALID");
  }
  if (!new Set(["ready", "trigger"]).has(argv[1])) {
    throw new Error("INJECTOR_ARGUMENT_INVALID");
  }
  return argv[1];
}

const invokedDirectly =
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  const mode = parseMode(process.argv.slice(2));
  const operation =
    mode === "ready"
      ? waitForReleaseRehearsalN8nReady()
      : runReleaseRehearsalActionInjector();
  operation.catch((error) => {
    const code =
      typeof error?.code === "string" &&
      /^N8N_READY_TIMEOUT_(?:HTTP_[1-5][0-9]{2}|TRANSPORT)$/u.test(
        error.code,
      )
        ? error.code
        : "ACTION_INJECTOR_FAILED";
    process.stderr.write(canonicalJson({ code }) + "\n");
    process.exitCode = 1;
  });
}
