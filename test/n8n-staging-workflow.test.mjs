import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateSecurityContract } from "../src/runtime-gate.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = JSON.parse(
  await readFile(
    path.join(root, "workflows", "security-regression-staging-target.json"),
    "utf8",
  ),
);
const contract = JSON.parse(
  await readFile(path.join(root, "contracts", "n8n-staging.contract.json"), "utf8"),
);

validateSecurityContract(contract);

assert.equal(workflow.active, false, "The staging fixture must be inactive on import");
assert.equal(workflow.id, "CsintGateStgV1a2");
assert.equal(
  workflow.name,
  "CSINT - Security Regression Staging Target",
);

const allowedNodeTypes = new Set([
  "n8n-nodes-base.webhook",
  "n8n-nodes-base.code",
  "n8n-nodes-base.respondToWebhook",
]);
for (const node of workflow.nodes) {
  assert.equal(
    allowedNodeTypes.has(node.type),
    true,
    `Unexpected node type in isolated staging fixture: ${node.type}`,
  );
  assert.equal(
    Object.hasOwn(node, "credentials"),
    false,
    `Staging fixture must not embed a credential reference: ${node.name}`,
  );
}

const webhookRoutes = workflow.nodes
  .filter((node) => node.type === "n8n-nodes-base.webhook")
  .map((node) => ({
    method: node.parameters.httpMethod ?? "GET",
    path: node.parameters.path,
    responseMode: node.parameters.responseMode,
  }))
  .sort((left, right) =>
    `${left.method}:${left.path}`.localeCompare(`${right.method}:${right.path}`),
  );

assert.deepEqual(webhookRoutes, [
  {
    method: "GET",
    path: "security-regression-support-agent",
    responseMode: "responseNode",
  },
  {
    method: "GET",
    path: "security-regression-support-agent/state",
    responseMode: "responseNode",
  },
  {
    method: "POST",
    path: "security-regression-support-agent",
    responseMode: "responseNode",
  },
  {
    method: "POST",
    path: "security-regression-support-agent/approve",
    responseMode: "responseNode",
  },
]);

assert.equal(contract.tests.length, 8);
assert.equal(
  contract.target.allowedPathPrefixes[0],
  "/webhook/security-regression-support-agent",
);
assert.equal(
  JSON.stringify(contract).includes("${N8N_STAGING_SIGNATURE}"),
  true,
  "The real n8n contract must read its staging signature from the environment",
);

console.log("n8n staging workflow: structure and contract checks passed");
