import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const reportPath = path.join(root, "reports", "public-multi-workflow-snapshot.json");
const manifestPath = path.join(
  root,
  "research",
  "multi-workflow-study",
  "public-repo-snapshot",
  "source-manifest.json",
);
const outputDirectory = path.join(root, "media", "launch");

function escapeXml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function text(x, y, size, value, options = {}) {
  const attrs = [
    `x="${x}"`,
    `y="${y}"`,
    `font-size="${size}"`,
    `fill="${options.fill ?? "#171b1f"}"`,
    `font-family="${options.family ?? "Segoe UI, Arial, sans-serif"}"`,
  ];
  if (options.weight) attrs.push(`font-weight="${options.weight}"`);
  if (options.anchor) attrs.push(`text-anchor="${options.anchor}"`);
  if (options.spacing) attrs.push(`letter-spacing="${options.spacing}"`);
  return `<text ${attrs.join(" ")}>${escapeXml(value)}</text>`;
}

function card(x, y, width, height, label, value, accent = false) {
  return [
    `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="8" fill="#ffffff" stroke="${accent ? "#8d1f1f" : "#c8c4ba"}" stroke-width="${accent ? 2 : 1}"/>`,
    text(x + 28, y + 43, 18, label.toUpperCase(), { fill: "#696d70", weight: 700, spacing: 1.6 }),
    text(x + 28, y + 112, 58, value, { fill: accent ? "#8d1f1f" : "#181d22", weight: 750 }),
  ].join("\n");
}

function linkedInSvg(report, commit) {
  const summary = report.summary;
  const reuse = report.findings.filter((finding) => finding.id.startsWith("MW-003")).length;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="1500" viewBox="0 0 1200 1500" role="img" aria-labelledby="title desc">
<title id="title">n8n multi-workflow trust boundary map launch</title>
<desc id="desc">Measured static analysis of ${summary.workflows} public workflow exports and ${summary.nodes} nodes.</desc>
<defs><filter id="shadow" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="14" stdDeviation="20" flood-color="#1f2933" flood-opacity="0.14"/></filter></defs>
<rect width="1200" height="1500" fill="#d9d5cc"/>
<rect x="58" y="42" width="1084" height="1416" fill="#fbfaf6" filter="url(#shadow)"/>
<g font-family="Segoe UI, Arial, sans-serif">
${text(108, 105, 17, "CSINT RESEARCH / BUILD NOTE", { weight: 700, spacing: 3 })}
${text(1092, 105, 17, "03.08.2026", { fill: "#6f7376", anchor: "end" })}
<line x1="108" y1="132" x2="1092" y2="132" stroke="#30353a" stroke-width="1.5"/>
${text(108, 222, 57, "n8n workflows are not", { family: "Georgia, Times New Roman, serif", weight: 700 })}
${text(108, 291, 57, "isolated JSON files.", { family: "Georgia, Times New Roman, serif", weight: 700 })}
${text(108, 348, 27, "I added a trust-boundary map for workflow sets.", { family: "Georgia, Times New Roman, serif", fill: "#484f55" })}
${text(108, 424, 17, "REAL PUBLIC REPOSITORY SNAPSHOT", { fill: "#8d1f1f", weight: 800, spacing: 2.4 })}
${card(108, 458, 468, 145, "Workflow exports", summary.workflows)}
${card(624, 458, 468, 145, "Nodes parsed", summary.nodes)}
${text(108, 664, 17, "THE CROSS-WORKFLOW ROUTE", { fill: "#8d1f1f", weight: 800, spacing: 2.4 })}
<rect x="108" y="697" width="984" height="156" rx="8" fill="#20262b"/>
${text(150, 748, 17, "PUBLIC TRIGGER", { fill: "#f5f2ea", weight: 700 })}
${text(380, 748, 17, "PARENT AGENT", { fill: "#f5f2ea", weight: 700 })}
${text(620, 748, 17, "SUB-WORKFLOW", { fill: "#f5f2ea", weight: 700 })}
${text(872, 748, 17, "CREDENTIALED ACTION", { fill: "#f5f2ea", weight: 700 })}
<path d="M 151 791 L 1010 791" fill="none" stroke="#d4cfc4" stroke-width="2"/>
<circle cx="210" cy="791" r="8" fill="#d4cfc4"/><circle cx="445" cy="791" r="8" fill="#d4cfc4"/><circle cx="685" cy="791" r="8" fill="#d4cfc4"/><circle cx="967" cy="791" r="10" fill="#b33a32"/>
${text(108, 916, 17, "WHAT THE EXPORTS SHOWED", { fill: "#8d1f1f", weight: 800, spacing: 2.4 })}
${card(108, 950, 300, 145, "Workflow calls", summary.workflowCalls)}
${card(450, 950, 300, 145, "Resolved", summary.resolvedCalls)}
${card(792, 950, 300, 145, "Need review", summary.unresolvedCalls)}
${card(108, 1132, 468, 145, "Credential reuse signals", reuse)}
${card(624, 1132, 468, 145, "High review paths", summary.highFindings, true)}
${text(108, 1333, 19, "Credential names and IDs stay out of the report.", { weight: 700 })}
${text(108, 1367, 17, "Static export analysis only. Nothing was imported, activated or executed.", { fill: "#555b60" })}
<line x1="108" y1="1403" x2="1092" y2="1403" stroke="#b8b6b0"/>
${text(108, 1433, 14, `SOURCE  dvasquez08/n8n-workflows @ ${commit.slice(0, 7)}`, { fill: "#6f7376", family: "Consolas, Courier New, monospace" })}
${text(1092, 1433, 14, "STATIC SIGNALS, NOT EXPLOITABILITY CLAIMS", { fill: "#6f7376", anchor: "end", weight: 700 })}
</g></svg>\n`;
}

function xSvg(report, commit) {
  const summary = report.summary;
  const reuse = report.findings.filter((finding) => finding.id.startsWith("MW-003")).length;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" viewBox="0 0 1600 900" role="img" aria-labelledby="title desc">
<title id="title">n8n multi-workflow trust boundary map launch</title>
<desc id="desc">Measured static analysis of ${summary.workflows} public workflow exports and ${summary.nodes} nodes.</desc>
<rect width="1600" height="900" fill="#20262b"/>
<rect x="46" y="42" width="1508" height="816" rx="10" fill="#fbfaf6"/>
<g font-family="Segoe UI, Arial, sans-serif">
${text(96, 98, 15, "CSINT RESEARCH / BUILD NOTE", { weight: 700, spacing: 2.8 })}
${text(1504, 98, 15, `03.08.2026  /  ${commit.slice(0, 7)}`, { fill: "#6f7376", anchor: "end" })}
<line x1="96" y1="122" x2="1504" y2="122" stroke="#30353a"/>
${text(96, 211, 55, "n8n workflows are not isolated files.", { family: "Georgia, Times New Roman, serif", weight: 700 })}
${text(96, 260, 24, "A local trust-boundary map for exported workflow sets.", { fill: "#4e555a" })}
${card(96, 314, 230, 137, "Workflows", summary.workflows)}
${card(350, 314, 230, 137, "Nodes", summary.nodes)}
${card(604, 314, 230, 137, "Calls", summary.workflowCalls)}
${card(858, 314, 230, 137, "Resolved", summary.resolvedCalls)}
${card(1112, 314, 230, 137, "Need review", summary.unresolvedCalls)}
<rect x="96" y="500" width="1408" height="131" rx="8" fill="#20262b"/>
${text(138, 553, 17, "PUBLIC TRIGGER", { fill: "#f5f2ea", weight: 700 })}
${text(454, 553, 17, "PARENT AGENT", { fill: "#f5f2ea", weight: 700 })}
${text(756, 553, 17, "SUB-WORKFLOW", { fill: "#f5f2ea", weight: 700 })}
${text(1111, 553, 17, "CREDENTIALED ACTION", { fill: "#f5f2ea", weight: 700 })}
<path d="M 139 587 L 1457 587" fill="none" stroke="#d4cfc4" stroke-width="2"/>
<circle cx="210" cy="587" r="8" fill="#d4cfc4"/><circle cx="520" cy="587" r="8" fill="#d4cfc4"/><circle cx="825" cy="587" r="8" fill="#d4cfc4"/><circle cx="1245" cy="587" r="10" fill="#b33a32"/>
${text(96, 693, 17, "MEASURED REVIEW SIGNALS", { fill: "#8d1f1f", weight: 800, spacing: 2.2 })}
${text(96, 751, 42, String(reuse), { weight: 750 })}${text(150, 751, 20, "credential-reference reuse signals", { fill: "#4e555a" })}
${text(813, 751, 42, String(summary.highFindings), { fill: "#8d1f1f", weight: 750 })}${text(862, 751, 20, "cross-workflow high review paths", { fill: "#4e555a" })}
<line x1="96" y1="795" x2="1504" y2="795" stroke="#b8b6b0"/>
${text(96, 827, 14, "Public GitHub snapshot. Static parsing only; nothing imported or executed.", { fill: "#6f7376" })}
${text(1504, 827, 14, "RAW CREDENTIAL NAMES AND IDs OMITTED", { fill: "#6f7376", anchor: "end", weight: 700 })}
</g></svg>\n`;
}

const report = JSON.parse(await readFile(reportPath, "utf8"));
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
await mkdir(outputDirectory, { recursive: true });
await Promise.all([
  writeFile(
    path.join(outputDirectory, "multi-workflow-map-linkedin.svg"),
    linkedInSvg(report, manifest.source.commit),
    "utf8",
  ),
  writeFile(
    path.join(outputDirectory, "multi-workflow-map-x.svg"),
    xSvg(report, manifest.source.commit),
    "utf8",
  ),
]);
process.stdout.write(`Launch SVGs written to ${outputDirectory}\n`);
