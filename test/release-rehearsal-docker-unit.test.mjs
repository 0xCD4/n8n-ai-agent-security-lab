import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createSocket } from "node:dgram";
import { once } from "node:events";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  createReleaseRehearsalDnsResponse,
  createReleaseRehearsalDnsSink,
  parseReleaseRehearsalDnsQuery,
  RELEASE_REHEARSAL_DNS_MAX_PACKET_BYTES,
} from "../src/release-rehearsal-dns-sink.mjs";
import {
  assertReleaseRehearsalDockerIdentifier,
  assertReleaseRehearsalPrivatePath,
  buildReleaseRehearsalCaptureCreateArgs,
  buildReleaseRehearsalCleanupTarget,
  buildReleaseRehearsalProbeCreateArgs,
  inspectReleaseRehearsalContainer,
  RELEASE_REHEARSAL_DOCKER_LABELS,
  RELEASE_REHEARSAL_NODE_IMAGE_TAG,
  serializeReleaseRehearsalLogicalResult,
  validateReleaseRehearsalImageIdentity,
  verifyReleaseRehearsalOwnership,
} from "../src/release-rehearsal-docker.mjs";

const tests = [];
const IMAGE_ID = `sha256:${"a".repeat(64)}`;
const CAPTURE_ID = "b".repeat(64);
const OWNER_ID = "owner-0123456789abcdef";
const RUN_ID = "run-0123456789abcdef";
const PRIVATE_ROOT = path.join(tmpdir(), "csint-release-rehearsal-unit-run");
const CONFIG_PATH = path.join(PRIVATE_ROOT, "config", "config.json");
const RESOLVER_PATH = path.join(PRIVATE_ROOT, "resolv.conf");
const OUTPUT_PATH = path.join(PRIVATE_ROOT, "output");

function test(name, callback) {
  tests.push({ name, callback });
}

function labels(role) {
  return {
    [RELEASE_REHEARSAL_DOCKER_LABELS.managed]: "true",
    [RELEASE_REHEARSAL_DOCKER_LABELS.owner]: OWNER_ID,
    [RELEASE_REHEARSAL_DOCKER_LABELS.run]: RUN_ID,
    [RELEASE_REHEARSAL_DOCKER_LABELS.role]: role,
  };
}

function expectedMounts(role) {
  const mounts = [
    {
      source: CONFIG_PATH,
      destination: "/run/rehearsal/config/config.json",
      readWrite: false,
    },
    {
      source: OUTPUT_PATH,
      destination: "/run/rehearsal/output",
      readWrite: true,
    },
  ];
  if (role === "probe") {
    mounts.push({
      source: RESOLVER_PATH,
      destination: "/etc/resolv.conf",
      readWrite: false,
    });
  }
  return mounts;
}

function containerInspect(role = "capture") {
  const networkMode = role === "capture" ? "none" : `container:${CAPTURE_ID}`;
  return {
    Id: role === "capture" ? CAPTURE_ID : "c".repeat(64),
    Config: {
      Image: IMAGE_ID,
      User: "1000:1000",
      Labels: labels(role),
      Env: [
        "PATH=/usr/local/bin",
        "NODE_VERSION=24.19.0",
        "YARN_VERSION=1.22.22",
        "NODE_ENV=production",
      ],
      ExposedPorts: null,
    },
    HostConfig: {
      Privileged: false,
      ReadonlyRootfs: true,
      CapDrop: ["ALL"],
      CapAdd: null,
      SecurityOpt: ["no-new-privileges=true"],
      Memory: 134_217_728,
      MemorySwap: 134_217_728,
      NanoCpus: 500_000_000,
      PidsLimit: 64,
      PortBindings: {},
      ExtraHosts: null,
      Dns: null,
      Devices: null,
      NetworkMode: networkMode,
    },
    Mounts: expectedMounts(role).map((mount) => ({
      Type: "bind",
      Source: mount.source,
      Destination: mount.destination,
      RW: mount.readWrite,
    })),
    NetworkSettings: {
      Ports: {},
      Networks: role === "capture" ? { none: {} } : {},
    },
  };
}

function inspectExpected(role) {
  return {
    ownerId: OWNER_ID,
    runId: RUN_ID,
    role,
    imageId: IMAGE_ID,
    networkMode: role === "capture" ? "none" : `container:${CAPTURE_ID}`,
    logicalNetworkMode:
      role === "capture" ? "none" : "container:<capture-container-id>",
    mounts: expectedMounts(role),
  };
}

function dnsQuery(name, queryType = 1, id = 0x1234) {
  const labels = name.split(".");
  const nameBytes = Buffer.concat(
    labels.flatMap((label) => {
      const value = Buffer.from(label, "ascii");
      return [Buffer.from([value.length]), value];
    }),
  );
  const packet = Buffer.alloc(12 + nameBytes.length + 1 + 4);
  packet.writeUInt16BE(id, 0);
  packet.writeUInt16BE(0x0100, 2);
  packet.writeUInt16BE(1, 4);
  nameBytes.copy(packet, 12);
  const offset = 12 + nameBytes.length;
  packet[offset] = 0;
  packet.writeUInt16BE(queryType, offset + 1);
  packet.writeUInt16BE(1, offset + 3);
  return packet;
}

test("capture arguments enforce the fixed isolated security profile", () => {
  const args = buildReleaseRehearsalCaptureCreateArgs({
    name: "capture-run-unit",
    ownerId: OWNER_ID,
    runId: RUN_ID,
    imageId: IMAGE_ID,
    runDirectory: PRIVATE_ROOT,
    configPath: CONFIG_PATH,
    outputPath: OUTPUT_PATH,
  });
  assert.deepEqual(args.slice(0, 2), ["container", "create"]);
  assert.equal(args[args.indexOf("--network") + 1], "none");
  assert.equal(args[args.indexOf("--cap-drop") + 1], "ALL");
  assert.ok(args.includes("no-new-privileges=true"));
  assert.ok(args.includes("--read-only"));
  assert.ok(args.includes("1000:1000"));
  assert.equal(args.at(-1), IMAGE_ID);
  assert.equal(args.some((value) => /privileged|publish|docker\.sock/iu.test(value)), false);
});

test("probe arguments use the exact capture namespace and read-only resolver", () => {
  const args = buildReleaseRehearsalProbeCreateArgs({
    name: "probe-run-unit",
    ownerId: OWNER_ID,
    runId: RUN_ID,
    imageId: IMAGE_ID,
    captureContainerId: CAPTURE_ID,
    runDirectory: PRIVATE_ROOT,
    configPath: CONFIG_PATH,
    resolverPath: RESOLVER_PATH,
    outputPath: OUTPUT_PATH,
    mode: "normal",
  });
  assert.equal(args[args.indexOf("--network") + 1], `container:${CAPTURE_ID}`);
  assert.equal(args.includes("--dns"), false);
  assert.ok(
    args.some(
      (value) =>
        value.includes("target=/etc/resolv.conf") && value.endsWith(",readonly"),
    ),
  );
  assert.deepEqual(args.slice(-3), [
    "/app/lab/release-rehearsal-capture/probe.mjs",
    "--mode",
    "normal",
  ]);
});

test("unsafe identifiers and paths are rejected before Docker invocation", () => {
  for (const value of ["../escape", "UPPERCASE", "name with space", "", "a".repeat(64)]) {
    assert.throws(() => assertReleaseRehearsalDockerIdentifier(value), /unsafe/u);
  }
  assert.throws(
    () => assertReleaseRehearsalPrivatePath(PRIVATE_ROOT, path.dirname(PRIVATE_ROOT)),
    /escapes/u,
  );
  assert.throws(
    () => assertReleaseRehearsalPrivatePath(PRIVATE_ROOT, `${PRIVATE_ROOT},extra`),
    /commas/u,
  );
});

test("ownership labels are exact and cleanup targets only verified IDs", () => {
  const inspect = containerInspect("capture");
  assert.equal(
    verifyReleaseRehearsalOwnership(inspect, {
      ownerId: OWNER_ID,
      runId: RUN_ID,
      role: "capture",
    }),
    true,
  );
  assert.equal(
    buildReleaseRehearsalCleanupTarget(inspect, {
      ownerId: OWNER_ID,
      runId: RUN_ID,
      role: "capture",
    }),
    CAPTURE_ID,
  );
  const wrong = structuredClone(inspect);
  wrong.Config.Labels[RELEASE_REHEARSAL_DOCKER_LABELS.owner] = "owner-wrong";
  assert.throws(
    () =>
      buildReleaseRehearsalCleanupTarget(wrong, {
        ownerId: OWNER_ID,
        runId: RUN_ID,
        role: "capture",
      }),
    /OWNERSHIP_LABEL_MISMATCH/u,
  );
});

test("Docker inspect parsing accepts only the intended capture and probe modes", () => {
  const capture = inspectReleaseRehearsalContainer(
    containerInspect("capture"),
    inspectExpected("capture"),
  );
  const probe = inspectReleaseRehearsalContainer(
    containerInspect("probe"),
    inspectExpected("probe"),
  );
  assert.equal(capture.networkMode, "none");
  assert.equal(probe.networkMode, "container:<capture-container-id>");
  assert.equal(capture.publishedPorts, false);
  assert.equal(probe.dockerSocketMounted, false);
});

test("forbidden Docker security settings fail closed", () => {
  const mutations = [
    (value) => {
      value.HostConfig.Privileged = true;
    },
    (value) => {
      value.HostConfig.CapAdd = ["NET_ADMIN"];
    },
    (value) => {
      value.HostConfig.CapAdd = ["NET_RAW"];
    },
    (value) => {
      value.HostConfig.SecurityOpt.push("seccomp=unconfined");
    },
    (value) => {
      value.HostConfig.NetworkMode = "host";
    },
    (value) => {
      value.HostConfig.PortBindings = { "18080/tcp": [{ HostPort: "18080" }] };
    },
    (value) => {
      value.Mounts[0] = {
        Type: "bind",
        Source: "/var/run/docker.sock",
        Destination: "/var/run/docker.sock",
        RW: true,
      };
    },
  ];
  for (const mutate of mutations) {
    const inspect = containerInspect("capture");
    mutate(inspect);
    assert.throws(
      () => inspectReleaseRehearsalContainer(inspect, inspectExpected("capture")),
      /(?:SECURITY_PROFILE|NETWORK_MODE|MOUNT_SET|DOCKER_SOCKET)/u,
    );
  }
});

test("official image identity requires an exact Linux Node digest and image ID", () => {
  const identity = validateReleaseRehearsalImageIdentity(
    {
      Id: IMAGE_ID,
      RepoDigests: [`node@sha256:${"d".repeat(64)}`],
      Os: "linux",
      Architecture: "amd64",
    },
    RELEASE_REHEARSAL_NODE_IMAGE_TAG,
  );
  assert.equal(identity.platform, "linux/amd64");
  assert.match(identity.repositoryDigest, /^node@sha256:[a-f0-9]{64}$/u);
  assert.throws(
    () =>
      validateReleaseRehearsalImageIdentity(
        {
          Id: IMAGE_ID,
          RepoDigests: ["node:latest"],
          Os: "linux",
          Architecture: "amd64",
        },
        RELEASE_REHEARSAL_NODE_IMAGE_TAG,
      ),
    /IMAGE_IDENTITY_INVALID/u,
  );
});

test("logical serialization is deterministic and excludes operational IDs", () => {
  const base = {
    schemaVersion: 1,
    status: "PASS",
    image: {
      repositoryDigest: `node@sha256:${"d".repeat(64)}`,
      localImageId: IMAGE_ID,
    },
    errorCodes: [],
    operational: {
      comparisonExcluded: true,
      captureContainerId: CAPTURE_ID,
      privatePath: "C:\\private\\run",
    },
  };
  const first = serializeReleaseRehearsalLogicalResult(base);
  const second = serializeReleaseRehearsalLogicalResult({
    ...base,
    operational: {
      comparisonExcluded: true,
      captureContainerId: "e".repeat(64),
      privatePath: "C:\\another\\run",
    },
  });
  assert.equal(first, second);
  assert.doesNotMatch(first, /private|captureContainerId/u);
  assert.throws(
    () =>
      serializeReleaseRehearsalLogicalResult({
        ...base,
        dns: { raw: "probe-target.example.invalid" },
      }),
    /RESULT_REDACTION_VIOLATION/u,
  );
  assert.throws(
    () => serializeReleaseRehearsalLogicalResult({ ...base, requestBody: "value" }),
    /RESULT_REDACTION_VIOLATION/u,
  );
});

test("DNS parsing hashes the query name and creates non-recursive NXDOMAIN", () => {
  const packet = dnsQuery("probe-target.example.invalid");
  const parsed = parseReleaseRehearsalDnsQuery(packet);
  assert.equal(parsed.queryType, 1);
  assert.equal(
    parsed.queryNameSha256,
    createHash("sha256")
      .update("probe-target.example.invalid", "ascii")
      .digest("hex"),
  );
  const response = createReleaseRehearsalDnsResponse(parsed);
  assert.equal(response.readUInt16BE(0), 0x1234);
  assert.equal(response.readUInt16BE(2) & 0x000f, 3);
  assert.equal(response.readUInt16BE(2) & 0x0080, 0);
  assert.equal(response.readUInt16BE(4), 1);
  assert.throws(
    () => parseReleaseRehearsalDnsQuery(Buffer.alloc(RELEASE_REHEARSAL_DNS_MAX_PACKET_BYTES + 1)),
    /DNS request rejected/u,
  );
});

test("the DNS sink emits bounded hashed events without forwarding raw names", async () => {
  const sink = createReleaseRehearsalDnsSink({ maxEvents: 1, maxViolations: 2 });
  const client = createSocket("udp4");
  try {
    sink.socket.bind({ address: "127.0.0.1", port: 0, exclusive: true });
    await once(sink.socket, "listening");
    const address = sink.socket.address();
    const responsePromise = once(client, "message");
    client.send(dnsQuery("unit-probe.example.invalid"), address.port, "127.0.0.1");
    const [response] = await responsePromise;
    assert.equal(response.readUInt16BE(2) & 0x000f, 3);
    const events = sink.getEvents();
    assert.equal(events.length, 1);
    assert.match(events[0].queryNameSha256, /^[a-f0-9]{64}$/u);
    assert.doesNotMatch(sink.serializeEvents(), /unit-probe|\.invalid/u);
    const summary = sink.finalize();
    assert.equal(summary.status, "COMPLETE");
    assert.equal(summary.forwarded, false);
  } finally {
    client.close();
    sink.socket.close();
  }
});

for (const { name, callback } of tests) {
  try {
    await callback();
  } catch (error) {
    error.message = `${name}: ${error.message}`;
    throw error;
  }
}

process.stdout.write(
  `release rehearsal Docker unit core: ${tests.length} tests passed\n`,
);
