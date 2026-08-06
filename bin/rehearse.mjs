#!/usr/bin/env node

import process from "node:process";

import { executeReleaseRehearsalCommand } from "../src/release-rehearsal-cli.mjs";

const controller = new AbortController();
const interrupt = () => controller.abort();
process.on("SIGINT", interrupt);
process.on("SIGTERM", interrupt);

try {
  const result = await executeReleaseRehearsalCommand(process.argv.slice(2), {
    signal: controller.signal,
  });
  if (result.status === "HELP") {
    process.stdout.write(result.usage);
  } else if (result.status === "COMPLETED") {
    process.stdout.write(
      [
        `Result: ${result.overallResult}`,
        `Evidence bundle: ${result.outputPath}`,
        `Exit code: ${result.exitCode}`,
        "",
      ].join("\n"),
    );
  } else {
    process.stderr.write(
      `Release rehearsal stopped: ${result.errorCode ?? "UNKNOWN_ERROR"}\n`,
    );
  }
  process.exitCode = result.exitCode;
} finally {
  process.removeListener("SIGINT", interrupt);
  process.removeListener("SIGTERM", interrupt);
}
