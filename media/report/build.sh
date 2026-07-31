#!/usr/bin/env bash
# Build the sample review PDF from the HTML source.
#
# Requirements: a Chromium or Chrome binary (set CHROME, default: chromium).
# Output: reports/sample-security-review.pdf
#
# The document content is fixed, including the stated generation date, so the
# build is deterministic apart from PDF metadata written by the browser.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
chrome="${CHROME:-chromium}"
out="$root/reports/sample-security-review.pdf"

"$chrome" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
  --no-pdf-header-footer --print-to-pdf="$out" \
  "file://$here/sample-security-review.html" >/dev/null 2>&1

echo "wrote $out"
