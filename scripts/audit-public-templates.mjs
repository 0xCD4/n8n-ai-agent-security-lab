#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { auditN8nWorkflow } from "../src/rules.mjs";
import {
  buildAggregateSummary,
  buildStudyManifest,
  hashWorkflow,
  isStudyManualReviewFinding,
  renderAggregateMarkdown,
  selectStudyCandidates,
} from "../src/template-study.mjs";

const SEARCH_API = "https://api.n8n.io/api/templates/search";
const WORKFLOW_API_PREFIX = "https://api.n8n.io/workflows/templates/";
const SOURCE_PREFIX = "https://n8n.io/workflows/";
const USER_AGENT =
  "CSINT-n8n-template-study/1.0 (+https://github.com/0xCD4/n8n-ai-agent-security-lab)";
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_SAMPLE_SIZE = 100;

function printUsage() {
  process.stdout.write(
    [
      "Public n8n AI Agent template static scan",
      "",
      "Usage:",
      "  node scripts/audit-public-templates.mjs [--count 20] [--out <directory>]",
      "",
      "Safety:",
      "  Fetches public JSON only from api.n8n.io.",
      "  Does not import, activate or execute community workflows.",
      "  Does not save raw workflow exports.",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = {
    count: 20,
    out: "research/template-study/feasibility-20",
    help: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--help" || value === "-h") {
      options.help = true;
      continue;
    }
    const [flag, inlineValue] = value.split("=", 2);
    if (!["--count", "--out"].includes(flag)) {
      throw new Error(`Unknown argument: ${value}`);
    }
    const nextValue = inlineValue ?? argv[index + 1];
    if (!nextValue || nextValue.startsWith("--")) {
      throw new Error(`${flag} requires a value.`);
    }
    if (flag === "--count") options.count = Number(nextValue);
    if (flag === "--out") options.out = nextValue;
    if (inlineValue === undefined) index += 1;
  }

  if (!Number.isInteger(options.count) || options.count < 1 || options.count > MAX_SAMPLE_SIZE) {
    throw new Error(`--count must be an integer between 1 and ${MAX_SAMPLE_SIZE}.`);
  }
  if (!String(options.out).trim()) throw new Error("--out cannot be empty.");
  return options;
}

function assertOfficialApiUrl(value) {
  const url = new URL(value);
  const validPath =
    url.pathname === "/api/templates/search" ||
    /^\/workflows\/templates\/\d+$/.test(url.pathname);
  if (url.protocol !== "https:" || url.hostname !== "api.n8n.io" || !validPath) {
    throw new Error(`Refusing non-official template API URL: ${url.origin}${url.pathname}`);
  }
  return url;
}

async function fetchJson(value) {
  const url = assertOfficialApiUrl(value);
  let lastError = null;

  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      const response = await fetch(url, {
        headers: {
          accept: "application/json",
          "user-agent": USER_AGENT,
        },
        redirect: "error",
        signal: controller.signal,
      });
      const declaredLength = Number(response.headers.get("content-length") ?? 0);
      if (declaredLength > MAX_RESPONSE_BYTES) {
        throw new Error(`Response exceeded ${MAX_RESPONSE_BYTES} bytes.`);
      }
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.byteLength > MAX_RESPONSE_BYTES) {
        throw new Error(`Response exceeded ${MAX_RESPONSE_BYTES} bytes.`);
      }
      if (!response.ok) {
        const retryable = response.status === 429 || response.status >= 500;
        const error = new Error(`Official API returned HTTP ${response.status}.`);
        if (!retryable || attempt === 2) throw error;
        lastError = error;
        await delay(500 * attempt);
        continue;
      }
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch (error) {
      lastError = error;
      if (attempt === 2 || error.name === "SyntaxError") throw error;
      await delay(500 * attempt);
    } finally {
      clearTimeout(timeout);
    }
  }

  throw lastError ?? new Error("Official template API request failed.");
}

function buildSearchUrl(count) {
  const url = new URL(SEARCH_API);
  url.searchParams.set("rows", String(Math.min(250, Math.max(count * 3, count + 20))));
  url.searchParams.set("page", "1");
  url.searchParams.set("category", "AI");
  url.searchParams.set("apps", "AI Agent");
  url.searchParams.set("sort", "views:desc");
  return url;
}

function publicSourceUrl(templateId, title) {
  const slug = String(title ?? "template")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 100);
  return `${SOURCE_PREFIX}${templateId}-${slug || "template"}/`;
}

async function run(options) {
  const retrievedAt = new Date().toISOString();
  const searchUrl = buildSearchUrl(options.count);
  const searchResponse = await fetchJson(searchUrl);
  if (!Array.isArray(searchResponse.workflows)) {
    throw new Error("Official template search response did not contain a workflows array.");
  }

  const candidates = selectStudyCandidates(searchResponse.workflows);
  if (candidates.length < options.count) {
    throw new Error(
      `Only ${candidates.length} free AI Agent candidates were returned; ${options.count} required.`,
    );
  }

  const records = [];
  const failures = [];
  for (const listing of candidates) {
    if (records.length >= options.count) break;
    const templateId = Number(listing.id);
    const apiUrl = `${WORKFLOW_API_PREFIX}${templateId}`;
    try {
      const detail = await fetchJson(apiUrl);
      if (!detail?.workflow || !Array.isArray(detail.workflow.nodes)) {
        throw new Error("Template response did not contain an exported workflow nodes array.");
      }
      const title = String(detail.name || listing.name || `Template ${templateId}`);
      const workflow = { ...detail.workflow, name: title };
      records.push({
        templateId,
        title,
        sourceUrl: publicSourceUrl(templateId, title),
        apiUrl,
        totalViews: Number(listing.totalViews ?? 0),
        sha256: hashWorkflow(detail.workflow),
        audit: auditN8nWorkflow(workflow),
      });
      process.stdout.write(`Scanned ${records.length}/${options.count}: template ${templateId}\n`);
    } catch (error) {
      failures.push({ templateId, apiUrl, error: String(error.message ?? error) });
      process.stderr.write(`Skipped template ${templateId}: ${error.message}\n`);
    }
  }

  if (records.length < options.count) {
    throw new Error(
      `Only ${records.length} public workflows could be scanned; ${options.count} required.`,
    );
  }

  const collection = {
    retrievedAt,
    requestedCount: options.count,
    scannedCount: records.length,
    failedDownloads: failures.length,
    searchUrl: searchUrl.toString(),
    searchTotalWorkflows: Number(searchResponse.totalWorkflows ?? 0),
    selection:
      "Most-viewed free templates in the AI category containing the AI Agent node; deterministic ties by template ID.",
    rawWorkflowStorage: false,
  };
  const manifest = buildStudyManifest(records, collection);
  const summary = buildAggregateSummary(records, collection);
  const privateReviewQueue = {
    schemaVersion: 1,
    collection,
    warning:
      "Private validation queue. Do not publish template-level findings before manual review.",
    failures,
    templates: records.map((record) => ({
      templateId: record.templateId,
      title: record.title,
      sourceUrl: record.sourceUrl,
      sha256: record.sha256,
      score: record.audit.score,
      grade: record.audit.grade,
      workflow: record.audit.workflow,
      studyPriorityFindings: record.audit.findings.filter(isStudyManualReviewFinding),
      findings: record.audit.findings,
    })),
  };

  const outputDirectory = path.resolve(options.out);
  await mkdir(outputDirectory, { recursive: true });
  await Promise.all([
    writeFile(
      path.join(outputDirectory, "manifest.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
      "utf8",
    ),
    writeFile(
      path.join(outputDirectory, "summary.json"),
      `${JSON.stringify(summary, null, 2)}\n`,
      "utf8",
    ),
    writeFile(path.join(outputDirectory, "summary.md"), renderAggregateMarkdown(summary), "utf8"),
    writeFile(
      path.join(outputDirectory, "review-queue.private.json"),
      `${JSON.stringify(privateReviewQueue, null, 2)}\n`,
      "utf8",
    ),
  ]);

  process.stdout.write(
    [
      "",
      `Public template scan complete: ${records.length} templates.`,
      `Anonymous summary: ${path.join(outputDirectory, "summary.md")}`,
      `Source manifest: ${path.join(outputDirectory, "manifest.json")}`,
      `Private review queue: ${path.join(outputDirectory, "review-queue.private.json")}`,
      "",
    ].join("\n"),
  );
}

try {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    printUsage();
  } else {
    await run(options);
  }
} catch (error) {
  process.stderr.write(`Template feasibility scan failed: ${error.message}\n`);
  process.exitCode = 1;
}
