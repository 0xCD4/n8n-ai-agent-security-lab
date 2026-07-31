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

function strongestSeverity(left, right) {
  return SEVERITY_RANK[left] >= SEVERITY_RANK[right] ? left : right;
}

function wrapLabel(value, maxLength = 25) {
  const words = String(value ?? "").trim().split(/\s+/).filter(Boolean);
  const lines = [];
  let current = "";

  for (const word of words) {
    if (!current) {
      current = word;
      continue;
    }
    if (`${current} ${word}`.length <= maxLength) {
      current = `${current} ${word}`;
      continue;
    }
    lines.push(current);
    current = word;
  }
  if (current) lines.push(current);

  return lines.slice(0, 2).map((line, index, all) => {
    if (index === all.length - 1 && words.join(" ").length > all.join(" ").length) {
      return `${line.slice(0, Math.max(1, maxLength - 3))}...`;
    }
    return line;
  });
}

function truncate(value, maxLength) {
  const text = String(value ?? "");
  return text.length > maxLength ? `${text.slice(0, maxLength - 3)}...` : text;
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
      const key = `${source}\u0000${target}`;
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
  const padding = 48;
  const nodeWidth = 190;
  const nodeHeight = 68;
  const nodeGap = 70;
  const rowHeight = 156;
  const headingHeight = 112;
  const maxNodes = Math.max(1, ...graph.paths.map((path) => path.nodes.length));
  const width = Math.max(920, padding * 2 + maxNodes * nodeWidth + (maxNodes - 1) * nodeGap);
  const height =
    graph.paths.length === 0
      ? 260
      : headingHeight + graph.paths.length * rowHeight + padding;
  const parts = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="title description">`,
    '<title id="title">AI agent exposure graph</title>',
    `<desc id="description">${xmlEscape(graph.note)}</desc>`,
    "<defs>",
    '<pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">',
    '<path d="M 24 0 L 0 0 0 24" fill="none" stroke="#1f2937" stroke-width="1" opacity="0.45"/>',
    "</pattern>",
    ...Object.entries(SEVERITY_COLOR).map(
      ([severity, color]) =>
        `<marker id="arrow-${severity}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="${color}"/></marker>`,
    ),
    "</defs>",
    `<rect width="${width}" height="${height}" fill="#0b0f14"/>`,
    `<rect width="${width}" height="${height}" fill="url(#grid)"/>`,
    `<text x="${padding}" y="46" fill="#f8fafc" font-family="Inter, ui-sans-serif, system-ui, sans-serif" font-size="24" font-weight="700">Agent Exposure Graph</text>`,
    `<text x="${padding}" y="76" fill="#94a3b8" font-family="Inter, ui-sans-serif, system-ui, sans-serif" font-size="15">${xmlEscape(truncate(graph.workflow, 90))}</text>`,
    `<text x="${width - padding}" y="46" fill="#94a3b8" font-family="Inter, ui-sans-serif, system-ui, sans-serif" font-size="13" text-anchor="end" letter-spacing="1.5">CSINT RESEARCH</text>`,
  ];

  if (graph.paths.length === 0) {
    parts.push(
      `<rect x="${padding}" y="118" width="${width - padding * 2}" height="86" rx="8" fill="#141b24" stroke="#334155"/>`,
      `<text x="${padding + 24}" y="168" fill="#cbd5e1" font-family="Inter, ui-sans-serif, system-ui, sans-serif" font-size="16">No structured risky paths were detected. Manual review is still required.</text>`,
    );
  }

  graph.paths.forEach((path, pathIndex) => {
    const color = SEVERITY_COLOR[path.severity] ?? SEVERITY_COLOR.low;
    const rowTop = headingHeight + pathIndex * rowHeight;
    const nodeY = rowTop + 52;
    const label = `${path.findingId}  ${path.severity.toUpperCase()}`;
    parts.push(
      `<text x="${padding}" y="${rowTop + 18}" fill="${color}" font-family="Inter, ui-sans-serif, system-ui, sans-serif" font-size="13" font-weight="700" letter-spacing="1">${xmlEscape(label)}</text>`,
      `<text x="${padding + 118}" y="${rowTop + 18}" fill="#cbd5e1" font-family="Inter, ui-sans-serif, system-ui, sans-serif" font-size="14">${xmlEscape(truncate(path.title, 92))}</text>`,
    );

    path.nodes.forEach((nodeLabel, nodeIndex) => {
      const x = padding + nodeIndex * (nodeWidth + nodeGap);
      if (nodeIndex < path.nodes.length - 1) {
        const lineStart = x + nodeWidth;
        const lineEnd = x + nodeWidth + nodeGap - 12;
        parts.push(
          `<line x1="${lineStart}" y1="${nodeY + nodeHeight / 2}" x2="${lineEnd}" y2="${nodeY + nodeHeight / 2}" stroke="${color}" stroke-width="2.5" marker-end="url(#arrow-${path.severity})"/>`,
        );
      }

      parts.push(
        `<rect x="${x}" y="${nodeY}" width="${nodeWidth}" height="${nodeHeight}" rx="8" fill="#141b24" stroke="${color}" stroke-width="1.5"/>`,
      );
      const lines = wrapLabel(nodeLabel);
      const firstLineY = nodeY + (lines.length === 1 ? 40 : 31);
      lines.forEach((line, lineIndex) => {
        parts.push(
          `<text x="${x + 16}" y="${firstLineY + lineIndex * 21}" fill="#f8fafc" font-family="Inter, ui-sans-serif, system-ui, sans-serif" font-size="15" font-weight="600">${xmlEscape(line)}</text>`,
        );
      });
    });
  });

  parts.push("</svg>");
  return `${parts.join("\n")}\n`;
}
