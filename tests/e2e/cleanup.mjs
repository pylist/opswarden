import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const runtime = resolve(process.env.OPSWARDEN_E2E_RUNTIME_DIR ?? "");
const project = process.env.OPSWARDEN_E2E_PROJECT ?? "";
if (
  dirname(runtime) !== resolve(root, ".tmp") ||
  !/^opswarden-e2e\.[A-Za-z0-9]{8}$/u.test(runtime.split("/").at(-1) ?? "") ||
  !/^opswarden-e2e-[a-z0-9]{8}$/u.test(project)
) {
  throw new Error("refusing unvalidated E2E cleanup scope");
}

let failed = false;
function docker(args, timeout = 60_000) {
  const result = spawnSync("docker", args, {
    cwd: root,
    encoding: "utf8",
    timeout,
    maxBuffer: 4 << 20,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
  });
  if (result.status !== 0 || result.error) {
    process.stderr.write(result.stderr ?? "");
    failed = true;
  }
}

function down(name, envPath, overridePath) {
  if (!existsSync(envPath)) return;
  const args = [
    "compose", "-p", name,
    "--env-file", envPath,
    "-f", resolve(root, "deploy/compose.yaml"),
  ];
  if (overridePath && existsSync(overridePath)) args.push("-f", overridePath);
  docker([...args, "down", "--volumes", "--remove-orphans"]);
}

down(
  `${project}-release`,
  resolve(runtime, "compose.env"),
  resolve(runtime, "release.override.yaml"),
);
down(project, resolve(runtime, "restore/restore.env"), resolve(runtime, "restore/restore.override.yaml"));
down(
  `${project}-wrong`,
  resolve(runtime, "restore-wrong/restore.env"),
  resolve(runtime, "restore-wrong/restore.override.yaml"),
);

const caddySourceImage =
  "caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d";
docker([
  "run", "--rm", "--network", "none", "--read-only",
  "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
  "--security-opt", "no-new-privileges:true",
  "--mount", `type=bind,src=${runtime},dst=/work`,
  "--entrypoint", "/bin/sh",
  caddySourceImage,
  "-c",
  'for path in /work/state-root /work/caddy-data /work/caddy-config /work/restore /work/restore-wrong; do if [ -e "$path" ]; then chown -R "$1:$2" "$path"; chmod 0700 "$path"; fi; done; for key in /work/master.key /work/restore/master.key /work/restore-wrong/master.key; do if [ -f "$key" ]; then chown "$1:$2" "$key"; chmod 0600 "$key"; fi; done',
  "opswarden-e2e-cleanup",
  String(process.getuid()),
  String(process.getgid()),
]);

process.exit(failed ? 1 : 0);
