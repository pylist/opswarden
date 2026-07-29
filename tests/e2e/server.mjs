import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync, mkdirSync, openSync, writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const runtime = resolve(process.env.OPSWARDEN_E2E_RUNTIME_DIR ?? "");
const artifacts = resolve(process.env.OPSWARDEN_E2E_ARTIFACT_DIR ?? "");
const appPort = Number(process.env.OPSWARDEN_E2E_APP_PORT);
const baseURL = process.env.OPSWARDEN_E2E_BASE_URL ?? "";
const baseProject = process.env.OPSWARDEN_E2E_PROJECT ?? "";
const project = `${baseProject}-release`;
const imageVersion = process.env.OPSWARDEN_E2E_IMAGE_VERSION ?? "";
const backendSubnet = process.env.OPSWARDEN_E2E_BACKEND_SUBNET ?? "";
const appIP = process.env.OPSWARDEN_E2E_APP_IP ?? "";
const caddyIP = process.env.OPSWARDEN_E2E_CADDY_IP ?? "";
const revision = imageVersion.slice(4);
const stateRoot = resolve(runtime, "state-root");
const caddySourceImage =
  "caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d";
const expectedRuntimeParent = resolve(root, ".tmp");
const expectedArtifactParent = resolve(root, ".artifacts");
if (
  dirname(runtime) !== expectedRuntimeParent ||
  dirname(artifacts) !== expectedArtifactParent ||
  !/^opswarden-e2e\.[A-Za-z0-9]{8}$/u.test(runtime.split("/").at(-1) ?? "") ||
  !/^opswarden-e2e\.[A-Za-z0-9]{8}$/u.test(artifacts.split("/").at(-1) ?? "") ||
  !Number.isInteger(appPort) ||
  appPort < 1024 ||
  appPort > 65535 ||
  baseURL !== `https://localhost:${appPort}` ||
  !/^opswarden-e2e-[a-z0-9]{8}$/u.test(baseProject) ||
  !/^e2e-[0-9a-f]{40}$/u.test(imageVersion) ||
  !/^172\.2[0-7]\.\d{1,3}\.0\/29$/u.test(backendSubnet) ||
  appIP.replace(/\.2$/u, ".0/29") !== backendSubnet ||
  caddyIP.replace(/\.3$/u, ".0/29") !== backendSubnet
) {
  throw new Error("refusing unvalidated E2E runtime scope");
}

for (const directory of [
  runtime,
  artifacts,
  stateRoot,
  resolve(stateRoot, "data"),
  resolve(stateRoot, "backups"),
  resolve(runtime, "caddy-data"),
  resolve(runtime, "caddy-config"),
]) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
}
for (const directory of ["backups", "logs", "audit", "browser", "errors", "playwright"]) {
  mkdirSync(resolve(artifacts, directory), { recursive: true, mode: 0o700 });
}

const keyPath = resolve(runtime, "master.key");
const envPath = resolve(runtime, "compose.env");
const caddyfilePath = resolve(runtime, "Caddyfile");
const overridePath = resolve(runtime, "release.override.yaml");
writeFileSync(keyPath, randomBytes(32).toString("base64") + "\n", { mode: 0o600 });
chmodSync(keyPath, 0o600);
writeFileSync(caddyfilePath, `{
\tadmin off
\tauto_https disable_redirects
\tservers {
\t\tprotocols h1 h2
\t}
}

localhost {
\ttls internal
\theader {
\t\t-Server
\t\t-Via
\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains"
\t\tX-Content-Type-Options "nosniff"
\t\tReferrer-Policy "no-referrer"
\t\tPermissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
\t\tX-Frame-Options "DENY"
\t\tContent-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; manifest-src 'self'; worker-src 'none'; upgrade-insecure-requests"
\t}
\treverse_proxy opswarden:8080 {
\t\theader_up X-Forwarded-For 127.0.0.1
\t\theader_up X-Forwarded-Proto https
\t\theader_up X-Forwarded-Host {host}
\t\tflush_interval -1
\t}
}
`, { mode: 0o444 });
writeFileSync(envPath, [
  `OPSWARDEN_VERSION=${imageVersion}`,
  `OPSWARDEN_REVISION=${revision}`,
  "SOURCE_DATE_EPOCH=0",
  `OPSWARDEN_STATE_PATH=${stateRoot}`,
  `OPSWARDEN_MASTER_KEY_PATH=${keyPath}`,
  `CADDY_DATA_PATH=${resolve(runtime, "caddy-data")}`,
  `CADDY_CONFIG_PATH=${resolve(runtime, "caddy-config")}`,
  "OPSWARDEN_HOSTNAME=localhost",
  "OPSWARDEN_TLS_EMAIL=e2e@example.invalid",
  `OPSWARDEN_BACKEND_SUBNET=${backendSubnet}`,
  `OPSWARDEN_APP_IP=${appIP}`,
  `OPSWARDEN_CADDY_IP=${caddyIP}`,
  "OPSWARDEN_INTERNAL_CIDRS=127.0.0.1/32",
].join("\n") + "\n", { mode: 0o600 });
writeFileSync(overridePath, [
  "services:",
  "  caddy:",
  "    ports: !override",
  `      - "127.0.0.1:${appPort}:443/tcp"`,
  "    volumes: !override",
  "      - type: bind",
  `        source: ${caddyfilePath}`,
  "        target: /etc/caddy/Caddyfile",
  "        read_only: true",
  "      - type: bind",
  `        source: ${resolve(runtime, "caddy-data")}`,
  "        target: /data",
  "      - type: bind",
  `        source: ${resolve(runtime, "caddy-config")}`,
  "        target: /config",
].join("\n") + "\n", { mode: 0o600 });

const compose = [
  "compose", "-p", project,
  "--env-file", envPath,
  "-f", resolve(root, "deploy/compose.yaml"),
  "-f", overridePath,
];
function runDocker(args, timeout = 120_000) {
  const result = spawnSync("docker", args, {
    cwd: root,
    encoding: "utf8",
    timeout,
    maxBuffer: 4 << 20,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
  });
  if (result.status !== 0 || result.error) {
    process.stderr.write(result.stderr ?? "");
    throw result.error ?? new Error(`docker ${args.join(" ")} failed with ${result.status}`);
  }
  return (result.stdout ?? "").trim();
}

function inspectContainer(id) {
  const raw = runDocker(["inspect", id], 30_000);
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed) || parsed.length !== 1) {
    throw new Error("Docker returned an invalid container inspection");
  }
  return parsed[0];
}

let logFollower;
let stopping = false;
let keyDelegated = false;
let runtimeDelegated = false;
function setKeyIdentity(uid, gid, mode) {
  if (
    !Number.isInteger(uid) || uid < 0 ||
    !Number.isInteger(gid) || gid < 0 ||
    !/^(?:0400|0600)$/u.test(mode)
  ) {
    throw new Error("invalid bounded E2E key identity");
  }
  runDocker([
    "run", "--rm", "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
    "--security-opt", "no-new-privileges:true",
    "--mount", `type=bind,src=${runtime},dst=/work`,
    "--entrypoint", "/bin/sh",
    caddySourceImage,
    "-c", 'chown "$1:$2" /work/master.key && chmod "$3" /work/master.key',
    "opswarden-e2e-key", String(uid), String(gid), mode,
  ], 60_000);
}
function setRuntimeIdentity(uid, gid, edgeUID, edgeGID) {
  if (
    !Number.isInteger(uid) || uid < 0 ||
    !Number.isInteger(gid) || gid < 0 ||
    !Number.isInteger(edgeUID) || edgeUID < 0 ||
    !Number.isInteger(edgeGID) || edgeGID < 0
  ) {
    throw new Error("invalid bounded E2E runtime identity");
  }
  runDocker([
    "run", "--rm", "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
    "--security-opt", "no-new-privileges:true",
    "--mount", `type=bind,src=${runtime},dst=/work`,
    "--entrypoint", "/bin/sh",
    caddySourceImage,
    "-c",
    'chown -R "$1:$2" /work/state-root && chmod 0700 /work/state-root /work/state-root/data /work/state-root/backups && chown -R "$3:$4" /work/caddy-data /work/caddy-config && chmod 0700 /work/caddy-data /work/caddy-config',
    "opswarden-e2e-runtime",
    String(uid), String(gid), String(edgeUID), String(edgeGID),
  ], 60_000);
}
function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  if (keyDelegated) {
    try {
      setKeyIdentity(process.getuid(), process.getgid(), "0600");
      keyDelegated = false;
    } catch (error) {
      process.stderr.write(`${error}\n`);
      exitCode ||= 1;
    }
  }
  if (logFollower && !logFollower.killed) logFollower.kill("SIGTERM");
  try {
    runDocker([...compose, "down", "--volumes", "--remove-orphans"], 60_000);
  } catch (error) {
    process.stderr.write(`${error}\n`);
    exitCode ||= 1;
  }
  if (runtimeDelegated) {
    try {
      setRuntimeIdentity(
        process.getuid(), process.getgid(), process.getuid(), process.getgid(),
      );
      runtimeDelegated = false;
    } catch (error) {
      process.stderr.write(`${error}\n`);
      exitCode ||= 1;
    }
  }
  process.exit(exitCode);
}

try {
  const image = JSON.parse(runDocker(["image", "inspect", `opswarden:${imageVersion}`], 30_000));
  if (
    !Array.isArray(image) ||
    image.length !== 1 ||
    image[0]?.Config?.Labels?.["org.opencontainers.image.revision"] !== revision
  ) {
    throw new Error("exact revision OpsWarden image label is missing");
  }
  runDocker([...compose, "build", "caddy"], 300_000);
  // Compose implements a local file secret as a bind mount and cannot honor
  // uid/gid. A pinned, network-isolated helper supplies the same 10001:0400
  // identity declared by production Compose, then restores host ownership.
  setKeyIdentity(10001, 10001, "0400");
  keyDelegated = true;
  setRuntimeIdentity(10001, 10001, 10002, 10002);
  runtimeDelegated = true;
  runDocker([...compose, "up", "-d", "--no-build", "opswarden", "caddy"], 180_000);
  setKeyIdentity(process.getuid(), process.getgid(), "0600");
  keyDelegated = false;

  const opswardenID = runDocker([...compose, "ps", "-q", "opswarden"], 30_000);
  const caddyID = runDocker([...compose, "ps", "-q", "caddy"], 30_000);
  if (!/^[0-9a-f]{12,64}$/u.test(opswardenID) || !/^[0-9a-f]{12,64}$/u.test(caddyID)) {
    throw new Error("full Compose topology did not start exactly two services");
  }
  const opswarden = inspectContainer(opswardenID);
  const caddy = inspectContainer(caddyID);
  if (
    opswarden.Config?.Image !== `opswarden:${imageVersion}` ||
    opswarden.Config?.Labels?.["org.opencontainers.image.revision"] !== revision
  ) {
    throw new Error("running OpsWarden container is not the exact revision image");
  }
  const appPorts = opswarden.NetworkSettings.Ports ?? {};
  const edgePorts = caddy.NetworkSettings.Ports ?? {};
  const appPublished = Object.values(appPorts).some((bindings) => Array.isArray(bindings));
  const edgeKeys = Object.keys(edgePorts);
  const edgeBinding = edgePorts["443/tcp"];
  if (
    appPublished ||
    edgeKeys.some((key) => key !== "443/tcp") ||
    !Array.isArray(edgeBinding) ||
    edgeBinding.length !== 1 ||
    edgeBinding[0]?.HostIp !== "127.0.0.1" ||
    edgeBinding[0]?.HostPort !== String(appPort)
  ) {
    throw new Error("E2E topology must publish only Caddy container port 443 on loopback");
  }
  writeFileSync(
    resolve(artifacts, "deployment.json"),
    JSON.stringify({
      baseURL,
      image: opswarden.Config.Image,
      revision: opswarden.Config.Labels["org.opencontainers.image.revision"],
      publishedPorts: { opswarden: appPorts, caddy: edgePorts },
    }),
    { mode: 0o600 },
  );
  const log = openSync(resolve(artifacts, "logs/application.log"), "a", 0o600);
  logFollower = spawn("docker", [...compose, "logs", "--no-color", "--follow"], {
    cwd: root,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
    stdio: ["ignore", log, log],
  });
  logFollower.on("error", (error) => {
    process.stderr.write(`${error}\n`);
    stop(1);
  });
} catch (error) {
  try {
    const startupLogs = runDocker([...compose, "logs", "--no-color"], 30_000);
    writeFileSync(resolve(artifacts, "logs/application.log"), startupLogs, { mode: 0o600 });
    process.stderr.write(startupLogs);
  } catch {
    // The original bounded startup failure remains authoritative.
  }
  process.stderr.write(`${error}\n`);
  stop(1);
}

process.on("SIGTERM", () => stop());
process.on("SIGINT", () => stop(130));
setInterval(() => undefined, 60_000);
