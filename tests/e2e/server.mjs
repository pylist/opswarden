import { spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, openSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const runtime = resolve(process.env.OPSWARDEN_E2E_RUNTIME_DIR ?? "");
const artifacts = resolve(process.env.OPSWARDEN_E2E_ARTIFACT_DIR ?? "");
const appPort = Number(process.env.OPSWARDEN_E2E_APP_PORT);
const expectedRuntimeParent = resolve(root, ".tmp");
const expectedArtifactParent = resolve(root, ".artifacts");
if (
  dirname(runtime) !== expectedRuntimeParent ||
  dirname(artifacts) !== expectedArtifactParent ||
  !/^opswarden-e2e\.[A-Za-z0-9]{8}$/u.test(runtime.split("/").at(-1) ?? "") ||
  !/^opswarden-e2e\.[A-Za-z0-9]{8}$/u.test(artifacts.split("/").at(-1) ?? "") ||
  !Number.isInteger(appPort) ||
  appPort < 1024 ||
  appPort > 65535
) {
  throw new Error("refusing unvalidated E2E runtime scope");
}
for (const directory of [runtime, artifacts, resolve(runtime, "data"), resolve(runtime, "backups")]) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
}
for (const directory of ["backups", "logs", "audit", "browser", "errors", "playwright"]) {
  mkdirSync(resolve(artifacts, directory), { recursive: true, mode: 0o700 });
}

const keyPath = resolve(runtime, "master.key");
writeFileSync(keyPath, randomBytes(32).toString("base64") + "\n", { mode: 0o600 });
chmodSync(keyPath, 0o600);
const build = spawnSync("go", ["build", "-trimpath", "-o", resolve(runtime, "opswarden"), "./cmd/opswarden"], {
  cwd: root,
  encoding: "utf8",
});
if (build.status !== 0) {
  process.stderr.write(build.stderr);
  process.exit(build.status ?? 1);
}

const log = openSync(resolve(artifacts, "logs/application.log"), "a", 0o600);
const child = spawn(resolve(runtime, "opswarden"), [], {
  cwd: root,
  env: {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    OPSWARDEN_LISTEN_ADDR: `127.0.0.1:${appPort}`,
    OPSWARDEN_DATA_DIR: resolve(runtime, "data"),
    OPSWARDEN_MASTER_KEY_FILE: keyPath,
    OPSWARDEN_BACKUP_DIR: resolve(runtime, "backups"),
    OPSWARDEN_DISABLE_AUDIT_RETENTION: "false",
  },
  stdio: ["ignore", log, log],
});

function stop(signal = "SIGTERM") {
  if (!child.killed) {
    child.kill(signal);
    setTimeout(() => {
      if (child.exitCode === null) child.kill("SIGKILL");
    }, 5000).unref();
  }
}
process.on("SIGTERM", () => stop());
process.on("SIGINT", () => stop("SIGINT"));
child.on("exit", (code) => process.exit(code ?? 0));
