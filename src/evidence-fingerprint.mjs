import { createHash } from "node:crypto";

export const EVIDENCE_FINGERPRINT_ALGORITHM = "sha256-canonical-json-v1";

export function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .filter((key) => value[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return "null";
}

export function fingerprintJson(value) {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

export function buildEvidenceSubject(label, sourcePath, value) {
  if (!label || !sourcePath) throw new TypeError("Evidence subjects need a label and source path.");
  return {
    label,
    sourcePath,
    fingerprintAlgorithm: EVIDENCE_FINGERPRINT_ALGORITHM,
    canonicalSha256: fingerprintJson(value),
  };
}
