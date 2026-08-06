import { lstat, open } from "node:fs/promises";
import path from "node:path";

const UNSAFE_DISPLAY_CHARACTERS =
  /[\u0000-\u001F\u007F-\u009F\u200B\u200E\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/gu;

export const DEFAULT_JSON_LIMITS = Object.freeze({
  maxBytes: 10 * 1024 * 1024,
  maxDepth: 100,
  maxValues: 250_000,
});

function describe(filePath) {
  return path.basename(filePath) || "JSON input";
}

function safeLabel(value) {
  const label = String(value ?? "")
    .replace(UNSAFE_DISPLAY_CHARACTERS, "?")
    .slice(0, 1024);
  return label || "JSON input";
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameSnapshot(left, right) {
  return (
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function assertPositiveInteger(value, label) {
  if (!Number.isInteger(value) || value < 1) {
    throw new TypeError(`${label} must be a positive integer.`);
  }
}

function inspectJsonShape(value, { maxDepth, maxValues }, label) {
  const stack = [{ value, depth: 0 }];
  let values = 0;

  while (stack.length > 0) {
    const current = stack.pop();
    values += 1;
    if (values > maxValues) {
      throw new Error(`${label} exceeds the JSON value limit (${maxValues}).`);
    }
    if (current.depth > maxDepth) {
      throw new Error(`${label} exceeds the JSON nesting limit (${maxDepth}).`);
    }
    if (!current.value || typeof current.value !== "object") continue;

    for (const child of Object.values(current.value)) {
      stack.push({ value: child, depth: current.depth + 1 });
    }
  }
}

export async function readBoundedJsonFile(filePath, options = {}) {
  const absolutePath = path.resolve(filePath);
  const label = safeLabel(options.label || describe(absolutePath));
  const limits = {
    maxBytes: options.maxBytes ?? DEFAULT_JSON_LIMITS.maxBytes,
    maxDepth: options.maxDepth ?? DEFAULT_JSON_LIMITS.maxDepth,
    maxValues: options.maxValues ?? DEFAULT_JSON_LIMITS.maxValues,
  };
  assertPositiveInteger(limits.maxBytes, "maxBytes");
  assertPositiveInteger(limits.maxDepth, "maxDepth");
  assertPositiveInteger(limits.maxValues, "maxValues");

  const entry = await lstat(absolutePath, { bigint: true });
  if (entry.isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link.`);
  }
  if (!entry.isFile()) {
    throw new Error(`${label} must be a regular file.`);
  }
  if (entry.size > BigInt(limits.maxBytes)) {
    throw new Error(`${label} exceeds the file size limit (${limits.maxBytes} bytes).`);
  }

  const handle = await open(absolutePath, "r");
  try {
    const openedEntry = await handle.stat({ bigint: true });
    if (!openedEntry.isFile()) {
      throw new Error(`${label} must be a regular file.`);
    }
    if (!sameFile(entry, openedEntry)) {
      throw new Error(`${label} changed while it was being opened.`);
    }
    if (!sameSnapshot(entry, openedEntry)) {
      throw new Error(`${label} changed before it could be read.`);
    }

    const buffer = Buffer.allocUnsafe(limits.maxBytes + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        offset,
        buffer.length - offset,
        offset,
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > limits.maxBytes) {
      throw new Error(`${label} exceeds the file size limit (${limits.maxBytes} bytes).`);
    }
    const finalEntry = await handle.stat({ bigint: true });
    if (!sameFile(openedEntry, finalEntry) || !sameSnapshot(openedEntry, finalEntry)) {
      throw new Error(`${label} changed while it was being read.`);
    }

    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true })
        .decode(buffer.subarray(0, offset))
        .replace(/^\uFEFF/, "");
    } catch {
      throw new Error(`${label} is not valid UTF-8.`);
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error(`${label} is not valid JSON.`);
    }
    inspectJsonShape(parsed, limits, label);
    return parsed;
  } finally {
    await handle.close();
  }
}
