import { readBoundedJsonFile } from "./safe-json.mjs";

const UNSAFE_IDENTIFIER_CHARACTERS =
  /[\u0000-\u001F\u007F-\u009F\u200B\u200E\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/u;
const UNSAFE_DISPLAY_CHARACTERS =
  /[\u0000-\u001F\u007F-\u009F\u200B\u200E\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/gu;

export const DEFAULT_WORKFLOW_LIMITS = Object.freeze({
  maxNodesPerWorkflow: 5_000,
  maxWorkflows: 500,
});

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertPositiveInteger(value, label) {
  if (!Number.isInteger(value) || value < 1) {
    throw new TypeError(`${label} must be a positive integer.`);
  }
}

function validIdentifier(value) {
  return (
    typeof value === "string" &&
    Boolean(value.trim()) &&
    value.length <= 512 &&
    !UNSAFE_IDENTIFIER_CHARACTERS.test(value)
  );
}

function safeLabel(value) {
  const label = String(value ?? "")
    .replace(UNSAFE_DISPLAY_CHARACTERS, "?")
    .slice(0, 1024);
  return label || "Workflow export";
}

function validateConnections(connections, names, label) {
  if (connections === undefined) return;
  for (const [sourceName, outputs] of Object.entries(connections)) {
    if (!names.has(sourceName)) {
      throw new Error(`${label}.connections contains an unknown source node.`);
    }
    if (!isPlainObject(outputs)) {
      throw new Error(`${label}.connections contains malformed outputs.`);
    }
    for (const channel of Object.values(outputs)) {
      if (channel === null) continue;
      if (!Array.isArray(channel)) {
        throw new Error(`${label}.connections contains a malformed channel.`);
      }
      for (const branch of channel) {
        if (branch === null) continue;
        if (!Array.isArray(branch)) {
          throw new Error(`${label}.connections contains a malformed branch.`);
        }
        for (const edge of branch) {
          if (!isPlainObject(edge) || !validIdentifier(edge.node)) {
            throw new Error(`${label}.connections contains a malformed target.`);
          }
          if (!names.has(edge.node)) {
            throw new Error(`${label}.connections contains an unknown target node.`);
          }
        }
      }
    }
  }
}

export function validateWorkflowExport(workflow, options = {}) {
  const label = safeLabel(options.label || "Workflow export");
  const maxNodes = options.maxNodes ?? DEFAULT_WORKFLOW_LIMITS.maxNodesPerWorkflow;
  assertPositiveInteger(maxNodes, "maxNodes");
  if (!isPlainObject(workflow) || !Array.isArray(workflow.nodes)) {
    throw new Error(`${label} must be an n8n workflow object with a nodes array.`);
  }
  if (workflow.nodes.length > maxNodes) {
    throw new Error(`${label} exceeds the node limit (${maxNodes}).`);
  }
  if (workflow.connections !== undefined && !isPlainObject(workflow.connections)) {
    throw new Error(`${label}.connections must be an object.`);
  }
  if (workflow.name !== undefined && !validIdentifier(workflow.name)) {
    throw new Error(
      `${label}.name must be a non-empty string up to 512 characters without control or bidirectional formatting characters.`,
    );
  }

  const names = new Map();
  for (const [index, node] of workflow.nodes.entries()) {
    if (!isPlainObject(node)) throw new Error(`${label}.nodes[${index}] must be an object.`);
    if (!validIdentifier(node.name)) {
      throw new Error(
        `${label}.nodes[${index}].name must be a non-empty string up to 512 characters without control or bidirectional formatting characters.`,
      );
    }
    if (!validIdentifier(node.type)) {
      throw new Error(
        `${label}.nodes[${index}].type must be a non-empty string up to 512 characters without control or bidirectional formatting characters.`,
      );
    }
    if (names.has(node.name)) {
      throw new Error(
        `${label} contains duplicate node names at indexes ${names.get(node.name)} and ${index}.`,
      );
    }
    names.set(node.name, index);
  }
  validateConnections(workflow.connections, names, label);
  return workflow;
}

export async function readWorkflowFile(filePath, options = {}) {
  const workflow = await readBoundedJsonFile(filePath, options);
  return validateWorkflowExport(workflow, {
    label: options.label,
    maxNodes: options.maxNodes,
  });
}
