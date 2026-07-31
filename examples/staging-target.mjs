#!/usr/bin/env node

import http from "node:http";
import { fileURLToPath } from "node:url";

export const DEMO_SIGNATURE = "demo-staging-signature";
const DEMO_APPROVAL_TOKEN = "demo-approval-token";
const MAX_BODY_BYTES = 64 * 1024;

function sendJson(response, status, body) {
  const serialized = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(serialized),
    "cache-control": "no-store",
  });
  response.end(serialized);
}

async function readJson(request) {
  const chunks = [];
  let size = 0;

  for await (const chunk of request) {
    size += chunk.byteLength;
    if (size > MAX_BODY_BYTES) {
      const error = new Error("Request body is too large.");
      error.code = "BODY_TOO_LARGE";
      throw error;
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    const error = new Error("Request body must be valid JSON.");
    error.code = "INVALID_JSON";
    throw error;
  }
}

function validateSupportRequest(body) {
  const allowedKeys = new Set([
    "request_id",
    "message",
    "customer_email",
    "customer_url",
  ]);
  const unexpected = Object.keys(body).filter((key) => !allowedKeys.has(key));
  if (unexpected.length > 0) {
    return `Unexpected fields: ${unexpected.join(", ")}`;
  }

  const requestId = String(body.request_id ?? "").trim();
  const message = String(body.message ?? "").trim();
  const email = String(body.customer_email ?? "").trim().toLowerCase();
  const rawUrl = String(body.customer_url ?? "").trim();

  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$/.test(requestId)) {
    return "request_id must be a short stable identifier.";
  }
  if (!message || message.length > 2_000) {
    return "message must contain 1 to 2000 characters.";
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return "customer_email is invalid.";
  }

  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:" || url.hostname !== "support.example.org") {
      return "customer_url is outside the staging allowlist.";
    }
  } catch {
    return "customer_url is invalid.";
  }

  return "";
}

function isPromptInjectionMarker(message) {
  return /ignore\s+(all\s+)?previous|system\s+prompt|bypass\s+approval/i.test(message);
}

export async function startDemoStagingServer({
  host = "127.0.0.1",
  port = 0,
  schemaDrift = false,
} = {}) {
  const state = {
    actionsExecuted: 0,
    requests: new Map(),
  };

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", `http://${host}`);

    if (request.method === "GET" && url.pathname === "/__gate/state") {
      sendJson(response, 200, {
        actions_executed: state.actionsExecuted,
        accepted_requests: state.requests.size,
      });
      return;
    }

    const supportPath = "/webhook-test/support-agent-demo";
    const approvalPath = `${supportPath}/approve`;
    if (![supportPath, approvalPath].includes(url.pathname)) {
      sendJson(response, 404, { accepted: false, code: "not_found" });
      return;
    }

    if (request.method !== "POST") {
      sendJson(response, 405, { accepted: false, code: "method_not_allowed" });
      return;
    }

    if (request.headers["x-staging-signature"] !== DEMO_SIGNATURE) {
      sendJson(response, 401, { accepted: false, code: "authentication_failed" });
      return;
    }

    let body;
    try {
      body = await readJson(request);
    } catch (error) {
      const status = error.code === "BODY_TOO_LARGE" ? 413 : 400;
      sendJson(response, status, {
        accepted: false,
        code: error.code === "BODY_TOO_LARGE" ? "payload_too_large" : "invalid_json",
      });
      return;
    }

    if (url.pathname === approvalPath) {
      if (body.approval_token !== DEMO_APPROVAL_TOKEN) {
        sendJson(response, 403, {
          accepted: false,
          code: "approval_required",
          actions_executed: state.actionsExecuted,
        });
        return;
      }

      const requestRecord = state.requests.get(String(body.request_id ?? ""));
      if (!requestRecord) {
        sendJson(response, 404, {
          accepted: false,
          code: "request_not_found",
          actions_executed: state.actionsExecuted,
        });
        return;
      }

      state.actionsExecuted += 1;
      sendJson(response, 200, {
        accepted: true,
        status: "simulated_action_recorded",
        actions_executed: state.actionsExecuted,
      });
      return;
    }

    const validationError = validateSupportRequest(body);
    if (validationError) {
      sendJson(response, 400, {
        accepted: false,
        code: "invalid_request",
        detail: validationError,
      });
      return;
    }

    const requestId = String(body.request_id);
    if (state.requests.has(requestId)) {
      const existing = state.requests.get(requestId);
      sendJson(response, 200, {
        ...existing,
        duplicate: true,
        ...(schemaDrift ? { debug_state: "unexpected-field" } : {}),
      });
      return;
    }

    const record = {
      accepted: true,
      status: "pending_approval",
      actions_executed: state.actionsExecuted,
      request_id: requestId,
      duplicate: false,
      risk_flags: isPromptInjectionMarker(body.message)
        ? ["instruction_override_attempt"]
        : [],
    };
    state.requests.set(requestId, record);
    sendJson(response, 202, {
      ...record,
      ...(schemaDrift ? { debug_state: "unexpected-field" } : {}),
    });
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    await new Promise((resolve) => server.close(resolve));
    throw new Error("Unable to resolve the demo staging server address.");
  }

  return {
    baseUrl: `http://${host}:${address.port}`,
    state,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    }),
  };
}

async function runFromCommandLine() {
  const port = Number(process.env.PORT ?? 47111);
  const instance = await startDemoStagingServer({ port });
  process.stdout.write(`Safe demo staging target: ${instance.baseUrl}\n`);
  process.stdout.write("Press Ctrl+C to stop.\n");

  const close = async () => {
    await instance.close();
    process.exit(0);
  };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runFromCommandLine().catch((error) => {
    process.stderr.write(`Demo staging target failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
