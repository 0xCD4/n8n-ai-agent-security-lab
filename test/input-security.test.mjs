import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { readBoundedJsonFile } from "../src/safe-json.mjs";
import { readWorkflowFile, validateWorkflowExport } from "../src/workflow-input.mjs";

function syntheticWorkflow(overrides = {}) {
  return {
    name: "Synthetic parser fixture",
    nodes: [
      {
        name: "Manual Trigger",
        type: "n8n-nodes-base.manualTrigger",
        parameters: {},
      },
    ],
    connections: {},
    ...overrides,
  };
}

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "n8n-ai-sec-parser-"));
try {
  const workflowPath = path.join(temporaryRoot, "workflow.json");
  const workflowJson = JSON.stringify(syntheticWorkflow());
  await writeFile(workflowPath, workflowJson, "utf8");

  assert.equal((await readWorkflowFile(workflowPath)).name, "Synthetic parser fixture");
  assert.deepEqual(
    await readBoundedJsonFile(workflowPath, { maxBytes: Buffer.byteLength(workflowJson) }),
    syntheticWorkflow(),
  );
  await assert.rejects(
    readBoundedJsonFile(workflowPath, { maxBytes: Buffer.byteLength(workflowJson) - 1 }),
    /exceeds the file size limit/,
  );

  const invalidUtf8Path = path.join(temporaryRoot, "invalid-utf8.json");
  await writeFile(invalidUtf8Path, Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d]));
  await assert.rejects(readBoundedJsonFile(invalidUtf8Path), /is not valid UTF-8/);

  const nestedPath = path.join(temporaryRoot, "nested.json");
  await writeFile(nestedPath, JSON.stringify({ outer: { inner: true } }), "utf8");
  await assert.rejects(
    readBoundedJsonFile(nestedPath, { maxDepth: 1 }),
    /exceeds the JSON nesting limit/,
  );
  await assert.rejects(
    readBoundedJsonFile(nestedPath, { maxValues: 2 }),
    /exceeds the JSON value limit/,
  );

  const duplicateMarker = "private-customer-node-name";
  assert.throws(
    () =>
      validateWorkflowExport(
        syntheticWorkflow({
          nodes: [
            { name: duplicateMarker, type: "n8n-nodes-base.noOp", parameters: {} },
            { name: duplicateMarker, type: "n8n-nodes-base.noOp", parameters: {} },
          ],
        }),
      ),
    (error) => {
      assert.match(error.message, /duplicate node names at indexes 0 and 1/);
      assert.doesNotMatch(error.message, new RegExp(duplicateMarker));
      return true;
    },
  );

  assert.throws(
    () => validateWorkflowExport(syntheticWorkflow({ name: "Spoofed\u202Ename" })),
    /without control or bidirectional formatting characters/,
  );
  assert.throws(
    () =>
      validateWorkflowExport(
        syntheticWorkflow({
          nodes: [
            {
              name: "Injected\nreport heading",
              type: "n8n-nodes-base.noOp",
              parameters: {},
            },
          ],
        }),
      ),
    /without control or bidirectional formatting characters/,
  );
  assert.throws(
    () => validateWorkflowExport(syntheticWorkflow(), { maxNodes: 0 }),
    /maxNodes must be a positive integer/,
  );
  assert.throws(
    () =>
      validateWorkflowExport(
        syntheticWorkflow({
          connections: {
            "Missing source": { main: [[{ node: "Manual Trigger", type: "main", index: 0 }]] },
          },
        }),
      ),
    /unknown source node/,
  );
  assert.throws(
    () =>
      validateWorkflowExport(
        syntheticWorkflow({
          connections: {
            "Manual Trigger": { main: [[{ node: "Missing target", type: "main", index: 0 }]] },
          },
        }),
      ),
    /unknown target node/,
  );
  assert.doesNotThrow(() =>
    validateWorkflowExport(
      syntheticWorkflow({
        connections: {
          "Manual Trigger": { main: [null, []], ai_tool: null },
        },
      }),
    ),
  );

  const symlinkPath = path.join(temporaryRoot, "workflow-link.json");
  try {
    await symlink(workflowPath, symlinkPath, "file");
    await assert.rejects(readWorkflowFile(symlinkPath), /must not be a symbolic link/);
  } catch (error) {
    if (!["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) throw error;
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

console.log("untrusted workflow input: all checks passed");
