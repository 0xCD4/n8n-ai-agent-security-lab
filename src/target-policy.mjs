import net from "node:net";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function normalizeHostname(hostname) {
  return String(hostname ?? "")
    .trim()
    .toLowerCase()
    .replace(/^\[(.*)\]$/, "$1");
}

export function isLoopbackHostname(hostname) {
  const normalized = normalizeHostname(hostname);
  return LOOPBACK_HOSTS.has(normalized) || normalized.startsWith("127.");
}

export function sanitizeTargetUrl(value) {
  const url = value instanceof URL ? value : new URL(value);
  return `${url.origin}${url.pathname}`;
}

export function assertTargetAllowed(
  value,
  {
    allowedHosts = [],
    allowedPathPrefixes = ["/webhook-test/"],
    allowRemote = false,
    requireAllowedPath = true,
  } = {},
) {
  const url = value instanceof URL ? value : new URL(value);
  const hostname = normalizeHostname(url.hostname);

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS staging targets are supported.");
  }
  if (url.username || url.password) {
    throw new Error("Credentials must not be embedded in a staging target URL.");
  }

  if (isLoopbackHostname(hostname)) {
    return url;
  }

  if (!allowRemote) {
    throw new Error(
      "Remote targets are blocked by default. Use --allow-remote with an exact contract allowlist.",
    );
  }

  if (net.isIP(hostname)) {
    throw new Error("Remote staging targets must use an allowlisted DNS hostname, not a raw IP.");
  }

  const normalizedAllowedHosts = new Set(allowedHosts.map(normalizeHostname));
  if (!normalizedAllowedHosts.has(hostname)) {
    throw new Error(`Remote host is not allowlisted by the security contract: ${hostname}`);
  }

  if (
    requireAllowedPath &&
    !allowedPathPrefixes.some(
      (prefix) => typeof prefix === "string" && url.pathname.startsWith(prefix),
    )
  ) {
    throw new Error("Remote runtime request path is not allowlisted by the security contract.");
  }

  return url;
}

export function resolveTestUrl(baseUrl, requestPath, policy) {
  if (typeof requestPath !== "string" || !requestPath.startsWith("/")) {
    throw new Error("Every runtime request path must start with '/'.");
  }

  const base = new URL(baseUrl);
  const target = new URL(requestPath, base);
  if (target.origin !== base.origin) {
    throw new Error("Runtime request paths must stay on the configured staging origin.");
  }

  return assertTargetAllowed(target, policy);
}
