const SEVERITY_RANK = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
});

const SEVERITY_COLOR = Object.freeze({
  critical: "#f87171",
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#94a3b8",
});

// Print-safe severity inks for the SVG report figure (readable on paper and screens).
const SEVERITY_INK = Object.freeze({
  critical: "#7f1d1d",
  high: "#b91c1c",
  medium: "#b45309",
  low: "#526172",
});

const SVG_FONT = "ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif";

const SVG_COLORS = Object.freeze({
  canvas: "#f6f8fa",
  frame: "#cfd8e0",
  card: "#ffffff",
  cardBorder: "#bcc8d4",
  ink: "#1b2733",
  muted: "#5b6b7c",
  faint: "#8494a5",
  rule: "#dde3e9",
  separator: "#e7ecf1",
});

function xmlEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function mermaidEscape(value) {
  return String(value ?? "")
    .replace(/[\r\n]+/g, " ")
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

const EDGE_KEY_SEPARATOR = String.fromCharCode(0);

function strongestSeverity(left, right) {
  return SEVERITY_RANK[left] >= SEVERITY_RANK[right] ? left : right;
}

function severityInk(severity) {
  return SEVERITY_INK[severity] ?? SEVERITY_INK.low;
}

function severityMarker(severity) {
  return SEVERITY_INK[severity] ? severity : "low";
}

function fmt(value) {
  return String(Math.round(value * 100) / 100);
}

function wrapText(value, maxChars, maxLines) {
  const text = String(value ?? "").trim().replace(/\s+/g, " ");
  if (!text) return [];

  const chunks = [];
  for (const word of text.split(" ")) {
    if (word.length <= maxChars) {
      chunks.push(word);
    } else {
      for (let index = 0; index < word.length; index += maxChars) {
        chunks.push(word.slice(index, index + maxChars));
      }
    }
  }

  const lines = [];
  let current = "";
  let truncated = false;
  for (const chunk of chunks) {
    const candidate = current ? `${current} ${chunk}` : chunk;
    if (candidate.length <= maxChars) {
      current = candidate;
      continue;
    }
    if (lines.length === maxLines - 1) {
      truncated = true;
      break;
    }
    lines.push(current);
    current = chunk;
  }
  if (current && lines.length < maxLines) lines.push(current);
  if (truncated) {
    const last = lines[lines.length - 1];
    lines[lines.length - 1] = `${last.slice(0, Math.max(1, maxChars - 1))}…`;
  }
  return lines;
}

function truncate(value, maxLength) {
  const text = String(value ?? "");
  return text.length > maxLength ? `${text.slice(0, maxLength - 3)}...` : text;
}

function svgText(x, y, size, fill, content, options = {}) {
  const attrs = [
    `x="${fmt(x)}"`,
    `y="${fmt(y)}"`,
    `fill="${fill}"`,
    `font-family="${SVG_FONT}"`,
    `font-size="${size}"`,
  ];
  if (options.weight) attrs.push(`font-weight="${options.weight}"`);
  if (options.anchor) attrs.push(`text-anchor="${options.anchor}"`);
  if (options.spacing) attrs.push(`letter-spacing="${options.spacing}"`);
  return `<text ${attrs.join(" ")}>${xmlEscape(content)}</text>`;
}

export function buildExposureGraph(workflowName, findings) {
  const paths = findings
    .filter((item) => Array.isArray(item.path) && item.path.length >= 2)
    .map((item) => ({
      findingId: item.id,
      severity: item.severity,
      title: item.title,
      nodes: [...item.path],
    }));

  const nodes = new Map();
  const edges = new Map();

  for (const path of paths) {
    for (const label of path.nodes) {
      const existing = nodes.get(label);
      nodes.set(label, {
        id: existing?.id ?? `node-${nodes.size + 1}`,
        label,
        severity: existing
          ? strongestSeverity(existing.severity, path.severity)
          : path.severity,
        findingIds: [...new Set([...(existing?.findingIds ?? []), path.findingId])].sort(),
      });
    }

    for (let index = 0; index < path.nodes.length - 1; index += 1) {
      const source = path.nodes[index];
      const target = path.nodes[index + 1];
      const key = `${source}${EDGE_KEY_SEPARATOR}${target}`;
      const existing = edges.get(key);
      edges.set(key, {
        source,
        target,
        severity: existing
          ? strongestSeverity(existing.severity, path.severity)
          : path.severity,
        findingIds: [...new Set([...(existing?.findingIds ?? []), path.findingId])].sort(),
      });
    }
  }

  return {
    schemaVersion: 1,
    workflow: workflowName,
    paths,
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    note: "Only structured risky paths found by the static scanner are included.",
  };
}

export function renderExposureGraphMermaid(graph) {
  const lines = [
    "flowchart LR",
    `%% ${mermaidEscape(graph.workflow)} exposure graph`,
  ];

  if (graph.paths.length === 0) {
    lines.push('empty["No structured risky paths detected"]');
    return `${lines.join("\n")}\n`;
  }

  graph.paths.forEach((path, pathIndex) => {
    const color = SEVERITY_COLOR[path.severity] ?? SEVERITY_COLOR.low;
    lines.push(`subgraph path_${pathIndex}["${path.findingId} | ${path.severity.toUpperCase()}"]`);
    path.nodes.forEach((label, nodeIndex) => {
      const id = `p${pathIndex}_n${nodeIndex}`;
      lines.push(`  ${id}["${mermaidEscape(label)}"]`);
      if (nodeIndex > 0) lines.push(`  p${pathIndex}_n${nodeIndex - 1} --> ${id}`);
    });
    lines.push("end");
    lines.push(
      `style path_${pathIndex} fill:#0b0f14,stroke:${color},color:#e5e7eb`,
    );
    path.nodes.forEach((_, nodeIndex) => {
      lines.push(
        `style p${pathIndex}_n${nodeIndex} fill:#141b24,stroke:${color},color:#f8fafc`,
      );
    });
  });

  return `${lines.join("\n")}\n`;
}

export function renderExposureGraphSvg(graph) {
  const pad = 44;
  const nodeW = 190;
  const gap = 104;
  const lineH = 19;
  const labelChars = 18;

  const paths = Array.isArray(graph.paths) ? graph.paths : [];

  // Merge every finding path into one deduplicated left-to-right flow so
  // shared nodes are drawn once instead of repeating a card per finding.
  const nodes = new Map();
  for (const path of paths) {
    path.nodes.forEach((label, index) => {
      const existing = nodes.get(label);
      if (existing) {
        existing.col = Math.max(existing.col, index);
        existing.severity = strongestSeverity(existing.severity, path.severity);
      } else {
        nodes.set(label, { label, col: index, severity: path.severity });
      }
    });
  }

  const edges = new Map();
  for (const path of paths) {
    for (let index = 0; index < path.nodes.length - 1; index += 1) {
      const key = `${path.nodes[index]}${EDGE_KEY_SEPARATOR}${path.nodes[index + 1]}`;
      const existing = edges.get(key);
      if (existing) {
        existing.severity = strongestSeverity(existing.severity, path.severity);
        if (!existing.findingIds.includes(path.findingId)) {
          existing.findingIds.push(path.findingId);
        }
      } else {
        edges.set(key, {
          source: path.nodes[index],
          target: path.nodes[index + 1],
          severity: path.severity,
          findingIds: [path.findingId],
        });
      }
    }
  }
  for (const edge of edges.values()) edge.findingIds.sort();

  const rowsPerCol = new Map();
  for (const node of nodes.values()) {
    node.row = rowsPerCol.get(node.col) ?? 0;
    rowsPerCol.set(node.col, node.row + 1);
    node.lines = wrapText(node.label, labelChars, 3);
  }
  const cols = nodes.size
    ? Math.max(...[...nodes.values()].map((node) => node.col)) + 1
    : 0;
  const maxRows = nodes.size ? Math.max(...rowsPerCol.values()) : 0;
  const maxLines = Math.max(1, ...[...nodes.values()].map((node) => node.lines.length));
  const cardH = Math.max(54, maxLines * lineH + 28);
  const slotH = cardH + 30;

  const diagramW = cols > 0 ? cols * nodeW + (cols - 1) * gap : 0;
  const width = Math.max(940, pad * 2 + diagramW);

  const body = [];

  const assemble = (height) => {
    const head = [
      `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${fmt(height)}" viewBox="0 0 ${width} ${fmt(height)}" role="img" aria-labelledby="title description">`,
      '<title id="title">AI agent exposure graph</title>',
      `<desc id="description">${xmlEscape(graph.note)}</desc>`,
      "<defs>",
      ...Object.keys(SEVERITY_INK).map(
        (severity) =>
          `<marker id="arrow-${severity}" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="10" markerHeight="10" markerUnits="userSpaceOnUse" orient="auto"><path d="M 0 0.8 L 9.5 5 L 0 9.2 z" fill="${severityInk(severity)}"/></marker>`,
      ),
      "</defs>",
      `<rect width="${width}" height="${fmt(height)}" fill="${SVG_COLORS.canvas}"/>`,
      `<rect x="0.5" y="0.5" width="${fmt(width - 1)}" height="${fmt(height - 1)}" fill="none" stroke="${SVG_COLORS.frame}"/>`,
    ];
    return `${[...head, ...body, "</svg>"].join("\n")}\n`;
  };

  const pushFooter = (topY) => {
    body.push(
      `<line x1="${pad}" y1="${fmt(topY)}" x2="${fmt(width - pad)}" y2="${fmt(topY)}" stroke="${SVG_COLORS.rule}" stroke-width="1"/>`,
    );
    body.push(svgText(pad, topY + 21, 11, SVG_COLORS.faint, truncate(graph.note, 120)));
    body.push(
      svgText(width - pad, topY + 21, 10, SVG_COLORS.faint, "CSINT RESEARCH", {
        weight: 700,
        anchor: "end",
        spacing: "1.6",
      }),
    );
    return topY + 34;
  };

  // Header: title, workflow, severity summary, hairline rule.
  body.push(svgText(pad, 46, 20, SVG_COLORS.ink, "Agent Exposure Graph", { weight: 700 }));
  body.push(svgText(pad, 69, 13, SVG_COLORS.muted, truncate(graph.workflow, 96)));

  if (paths.length > 0) {
    const counts = new Map();
    for (const path of paths) {
      counts.set(path.severity, (counts.get(path.severity) ?? 0) + 1);
    }
    let cursor = width - pad;
    for (const severity of ["low", "medium", "high", "critical"]) {
      if (!counts.has(severity)) continue;
      const label = `${counts.get(severity)} ${severity.toUpperCase()}`;
      cursor -= label.length * 7.4;
      body.push(
        svgText(cursor, 46, 12.5, severityInk(severity), label, { weight: 700, spacing: "0.4" }),
      );
      cursor -= 14;
      body.push(
        `<rect x="${fmt(cursor)}" y="37" width="9" height="9" rx="2" fill="${severityInk(severity)}"/>`,
      );
      cursor -= 24;
    }
  }

  body.push(
    `<line x1="${pad}" y1="92" x2="${fmt(width - pad)}" y2="92" stroke="${SVG_COLORS.rule}" stroke-width="1"/>`,
  );
  body.push(svgText(pad, 118, 11, SVG_COLORS.faint, "RISKY DATA FLOW", { weight: 700, spacing: "1.6" }));

  if (paths.length === 0) {
    const cardY = 130;
    const emptyH = 92;
    body.push(
      `<rect x="${pad}" y="${cardY}" width="${fmt(width - pad * 2)}" height="${emptyH}" rx="4" fill="${SVG_COLORS.card}" stroke="${SVG_COLORS.cardBorder}" stroke-dasharray="5 4"/>`,
    );
    body.push(
      svgText(width / 2, cardY + 41, 14.5, SVG_COLORS.ink, "No structured risky paths were detected.", {
        weight: 600,
        anchor: "middle",
      }),
    );
    body.push(
      svgText(width / 2, cardY + 64, 12.5, SVG_COLORS.muted, "Manual review is still required.", {
        anchor: "middle",
      }),
    );
    return assemble(pushFooter(cardY + emptyH + 28));
  }

  const offsetX = pad + Math.max(0, (width - pad * 2 - diagramW) / 2);
  const nodeX = (col) => offsetX + col * (nodeW + gap);
  const hasIncoming = new Set([...edges.values()].map((edge) => edge.target));
  const hasEntry = [...nodes.values()].some((node) => !hasIncoming.has(node.label));
  const diagramTop = hasEntry ? 152 : 138;
  const nodeY = (row) => diagramTop + row * slotH;
  let contentBottom = diagramTop + (maxRows - 1) * slotH + cardH;

  // Edges first so node cards paint over the line ends.
  for (const edge of edges.values()) {
    const source = nodes.get(edge.source);
    const target = nodes.get(edge.target);
    if (!source || !target) continue;
    const color = severityInk(edge.severity);
    const marker = severityMarker(edge.severity);
    const sx = nodeX(source.col) + nodeW;
    const sy = nodeY(source.row) + cardH / 2;
    const tx = nodeX(target.col);
    const ty = nodeY(target.row) + cardH / 2;
    // Stack IDs vertically so labels never overflow the corridor between cards.
    const ids = edge.findingIds;
    const idLines = ids.length <= 2 ? [...ids] : [ids[0], `+${ids.length - 1}`];
    const pushIdLines = (cx, bottomY) => {
      idLines.forEach((line, index) => {
        body.push(
          svgText(cx, bottomY - (idLines.length - 1 - index) * 13, 11, color, line, {
            weight: 700,
            anchor: "middle",
            spacing: "0.3",
          }),
        );
      });
    };

    if (target.col === source.col + 1) {
      if (source.row === target.row) {
        body.push(
          `<line x1="${fmt(sx + 3)}" y1="${fmt(sy)}" x2="${fmt(tx - 3)}" y2="${fmt(ty)}" stroke="${color}" stroke-width="2" marker-end="url(#arrow-${marker})"/>`,
        );
      } else {
        body.push(
          `<path d="M ${fmt(sx + 3)} ${fmt(sy)} C ${fmt(sx + gap * 0.45)} ${fmt(sy)}, ${fmt(tx - gap * 0.45)} ${fmt(ty)}, ${fmt(tx - 3)} ${fmt(ty)}" fill="none" stroke="${color}" stroke-width="2" marker-end="url(#arrow-${marker})"/>`,
        );
      }
      pushIdLines((sx + tx) / 2, (sy + ty) / 2 - 10);
    } else {
      // Long or backward hop: route below the rows it crosses.
      const lo = Math.min(source.col, target.col);
      const hi = Math.max(source.col, target.col);
      let clearY = Math.max(sy, ty) + cardH / 2;
      for (const other of nodes.values()) {
        const inSpan = target.col > source.col
          ? other.col > lo && other.col < hi
          : other.col >= lo && other.col <= hi;
        if (inSpan) clearY = Math.max(clearY, nodeY(other.row) + cardH);
      }
      const dipY = clearY + 36;
      body.push(
        `<path d="M ${fmt(sx + 3)} ${fmt(sy)} C ${fmt(sx + 52)} ${fmt(sy)}, ${fmt(sx + 52)} ${fmt(dipY)}, ${fmt(sx + 104)} ${fmt(dipY)} L ${fmt(tx - 104)} ${fmt(dipY)} C ${fmt(tx - 52)} ${fmt(dipY)}, ${fmt(tx - 52)} ${fmt(ty)}, ${fmt(tx - 3)} ${fmt(ty)}" fill="none" stroke="${color}" stroke-width="2" marker-end="url(#arrow-${marker})"/>`,
      );
      pushIdLines((sx + tx) / 2, dipY - 8);
      contentBottom = Math.max(contentBottom, dipY + 8);
    }
  }

  for (const node of nodes.values()) {
    const x = nodeX(node.col);
    const y = nodeY(node.row);
    if (!hasIncoming.has(node.label)) {
      body.push(
        svgText(x + 1, y - 10, 10, SVG_COLORS.faint, "ENTRY POINT", { weight: 700, spacing: "1.4" }),
      );
    }
    body.push(
      `<rect x="${fmt(x)}" y="${fmt(y)}" width="${nodeW}" height="${fmt(cardH)}" rx="4" fill="${SVG_COLORS.card}" stroke="${SVG_COLORS.cardBorder}" stroke-width="1"/>`,
    );
    body.push(
      `<rect x="${fmt(x + 1)}" y="${fmt(y + 4)}" width="3.5" height="${fmt(cardH - 8)}" rx="1.75" fill="${severityInk(node.severity)}"/>`,
    );
    const firstY = y + cardH / 2 - ((node.lines.length - 1) * lineH) / 2 + 5;
    node.lines.forEach((line, index) => {
      body.push(
        svgText(x + nodeW / 2, firstY + index * lineH, 14, SVG_COLORS.ink, line, {
          weight: 600,
          anchor: "middle",
        }),
      );
    });
  }

  // Findings ledger: chip, ID, title, and the path each finding proved.
  const ledgerRuleY = contentBottom + 32;
  body.push(
    `<line x1="${pad}" y1="${fmt(ledgerRuleY)}" x2="${fmt(width - pad)}" y2="${fmt(ledgerRuleY)}" stroke="${SVG_COLORS.rule}" stroke-width="1"/>`,
  );
  body.push(
    svgText(pad, ledgerRuleY + 26, 11, SVG_COLORS.faint, "FINDINGS", { weight: 700, spacing: "1.6" }),
  );

  let rowY = ledgerRuleY + 44;
  const chipW = Math.round(
    Math.max(...paths.map((path) => String(path.severity).length)) * 7.4 + 16,
  );
  const chipH = 19;
  const idW = Math.max(...paths.map((path) => String(path.findingId).length)) * 7.8;
  const titleX = pad + chipW + 14 + idW + 18;
  const bodyW = width - pad - titleX;
  const titleChars = Math.max(24, Math.floor(bodyW / 7));
  const crumbChars = Math.max(24, Math.floor(bodyW / 6.4));

  paths.forEach((path, index) => {
    if (index > 0) {
      body.push(
        `<line x1="${pad}" y1="${fmt(rowY - 11)}" x2="${fmt(width - pad)}" y2="${fmt(rowY - 11)}" stroke="${SVG_COLORS.separator}" stroke-width="1"/>`,
      );
    }
    const color = severityInk(path.severity);
    const baseline = rowY + 14;
    body.push(`<rect x="${pad}" y="${fmt(rowY)}" width="${chipW}" height="${chipH}" rx="3" fill="${color}"/>`);
    body.push(
      svgText(pad + chipW / 2, rowY + 13.5, 10.5, "#ffffff", String(path.severity).toUpperCase(), {
        weight: 700,
        anchor: "middle",
        spacing: "0.8",
      }),
    );
    body.push(svgText(pad + chipW + 14, baseline, 13, SVG_COLORS.ink, path.findingId, { weight: 700 }));
    const titleLines = wrapText(path.title, titleChars, 2);
    titleLines.forEach((line, lineIndex) => {
      body.push(svgText(titleX, baseline + lineIndex * 18, 13, SVG_COLORS.ink, line));
    });
    const crumb = path.nodes.map((label) => truncate(label, 30)).join(" → ");
    const crumbLines = wrapText(crumb, crumbChars, 2);
    const crumbBase = baseline + Math.max(1, titleLines.length) * 18 + 3;
    crumbLines.forEach((line, lineIndex) => {
      body.push(svgText(titleX, crumbBase + lineIndex * 17, 12, SVG_COLORS.muted, line));
    });
    rowY += 14 + Math.max(1, titleLines.length) * 18 + 3 + crumbLines.length * 17 + 14;
  });

  return assemble(pushFooter(rowY + 2));
}
