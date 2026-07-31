function xmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function failureText(test) {
  const failedChecks = [
    ...test.checks.filter((item) => !item.passed).map((item) => item.name),
    ...(test.observation?.checks ?? [])
      .filter((item) => !item.passed)
      .map((item) => `Observation: ${item.name}`),
  ];
  if (test.error) failedChecks.push(test.error);
  return failedChecks.join("; ") || "Runtime contract failed.";
}

export function renderGateMarkdown(result) {
  const lines = [
    "# n8n AI Security Regression Gate",
    "",
    `Decision: ${result.decision.toUpperCase()}`,
    `Workflow: ${result.workflow.name}`,
    result.workflow.sourcePath ? `Source: ${result.workflow.sourcePath}` : null,
    `Contract: ${result.contract.name}`,
    `Target: ${result.target}`,
    "",
    "## Gate summary",
    "",
    `- Static audit: ${result.static.score}/100 (${result.static.grade})`,
    `- Blocking static findings: ${result.static.blockers.length}`,
    `- Runtime tests: ${result.runtime.passed}/${result.runtime.total} passed`,
    "",
    "## Runtime contract",
    "",
    "| Test | Request | Result | Status |",
    "| --- | --- | --- | ---: |",
    ...result.runtime.tests.map(
      (test) =>
        `| ${test.name} | ${test.request.method} ${test.request.path} | ${
          test.passed ? "PASS" : "FAIL"
        } | ${test.status ?? "n/a"} |`,
    ),
    "",
  ].filter((line) => line !== null);

  const failedTests = result.runtime.tests.filter((test) => !test.passed);
  if (failedTests.length > 0) {
    lines.push("## Failed runtime checks", "");
    for (const test of failedTests) {
      lines.push(`### ${test.id}`, "", failureText(test), "");
    }
  }

  if (result.static.blockers.length > 0) {
    lines.push("## Blocking static findings", "");
    for (const finding of result.static.findings.filter((item) =>
      result.static.blockers.includes(item.id),
    )) {
      lines.push(
        `### ${finding.id} | ${finding.severity.toUpperCase()} | ${finding.title}`,
        "",
        finding.evidence,
        "",
      );
    }
  }

  lines.push(
    "## Review limits",
    "",
    ...result.limitations.map((item) => `- ${item}`),
    "",
  );

  return `${lines.join("\n").replace(/\n+$/, "")}\n`;
}

export function renderGateJUnit(result) {
  const staticFailed = result.static.blockers.length > 0;
  const failures =
    result.runtime.tests.filter((test) => !test.passed).length + (staticFailed ? 1 : 0);
  const staticCase = staticFailed
    ? [
        '    <testcase classname="n8n.security.static" name="static-audit" time="0.000">',
        `      <failure message="Blocking static findings">${xmlEscape(
          result.static.blockers.join(", "),
        )}</failure>`,
        "    </testcase>",
      ].join("\n")
    : '    <testcase classname="n8n.security.static" name="static-audit" time="0.000" />';
  const runtimeCases = result.runtime.tests
    .map((test) => {
      const durationSeconds = ((test.durationMs ?? 0) / 1000).toFixed(3);
      if (test.passed) {
        return `    <testcase classname="n8n.security.runtime" name="${xmlEscape(
          test.id,
        )}" time="${durationSeconds}" />`;
      }
      return [
        `    <testcase classname="n8n.security.runtime" name="${xmlEscape(
          test.id,
        )}" time="${durationSeconds}">`,
        `      <failure message="Runtime security contract failed">${xmlEscape(
          failureText(test),
        )}</failure>`,
        "    </testcase>",
      ].join("\n");
    })
    .join("\n");

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuite name="n8n AI Security Regression Gate" tests="${
      result.runtime.total + 1
    }" failures="${failures}">`,
    staticCase,
    runtimeCases,
    "</testsuite>",
    "",
  ].join("\n");
}

function sarifLevel(severity) {
  if (["critical", "high"].includes(severity)) return "error";
  if (severity === "medium") return "warning";
  return "note";
}

export function renderGateSarif(result) {
  const staticResults = result.static.findings.map((finding) => ({
    ruleId: finding.id,
    level: sarifLevel(finding.severity),
    message: {
      text: `${finding.title}. ${finding.evidence}`,
    },
    locations: result.workflow.sourcePath
      ? [
          {
            physicalLocation: {
              artifactLocation: {
                uri: result.workflow.sourcePath,
              },
            },
          },
        ]
      : undefined,
  }));

  const runtimeResults = result.runtime.tests
    .filter((test) => !test.passed)
    .map((test) => ({
      ruleId: `RT-${test.id}`,
      level: "error",
      message: {
        text: `${test.name}: ${failureText(test)}`,
      },
    }));

  return `${JSON.stringify(
    {
      version: "2.1.0",
      $schema:
        "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "n8n AI Security Regression Gate",
              informationUri:
                "https://github.com/0xCD4/n8n-ai-agent-security-lab",
              rules: [],
            },
          },
          results: [...staticResults, ...runtimeResults],
        },
      ],
    },
    null,
    2,
  )}\n`;
}
