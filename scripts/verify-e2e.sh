#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
image_version="${OPSWARDEN_E2E_IMAGE_VERSION:?set the image version built by make}"
[[ "${image_version}" =~ ^e2e-[0-9a-f]{40}$ ]] || {
  echo "E2E image version is not bound to an exact revision" >&2
  exit 2
}

mkdir -p -- "${repo_root}/.tmp" "${repo_root}/.artifacts"
runtime_dir="$(mktemp -d "${repo_root}/.tmp/opswarden-e2e.XXXXXXXX")"
artifact_dir="$(mktemp -d "${repo_root}/.artifacts/opswarden-e2e.XXXXXXXX")"
chmod 0700 "${runtime_dir}" "${artifact_dir}"
run_suffix="${runtime_dir##*.}"
[[ "${run_suffix}" =~ ^[A-Za-z0-9]{8}$ ]] || exit 2
run_suffix_lower="$(printf '%s' "${run_suffix}" | tr '[:upper:]' '[:lower:]')"
project="opswarden-e2e-${run_suffix_lower}"

read -r app_port restore_port < <(
  node -e '
    const net = require("node:net");
    const allocate = () => new Promise((resolve, reject) => {
      const server = net.createServer();
      server.unref();
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const port = server.address().port;
        server.close((error) => error ? reject(error) : resolve(port));
      });
    });
    Promise.all([allocate(), allocate()]).then(([one, two]) => {
      if (one === two) process.exit(2);
      process.stdout.write(`${one} ${two}\n`);
    }).catch(() => process.exit(2));
  '
)
[[ "${app_port}" =~ ^[0-9]{4,5}$ && "${restore_port}" =~ ^[0-9]{4,5}$ ]] || exit 2
[[ "${app_port}" != "${restore_port}" ]] || exit 2
subnet_checksum="$(printf '%s' "${run_suffix}" | cksum | awk '{print $1}')"
subnet_second="$((20 + subnet_checksum % 8))"
subnet_third="$(((subnet_checksum / 8) % 256))"

export OPSWARDEN_E2E_RUNTIME_DIR="${runtime_dir}"
export OPSWARDEN_E2E_ARTIFACT_DIR="${artifact_dir}"
export OPSWARDEN_E2E_SECRET_FILE="${runtime_dir}/sensitive-patterns"
export OPSWARDEN_E2E_APP_PORT="${app_port}"
export OPSWARDEN_E2E_RESTORE_PORT="${restore_port}"
export OPSWARDEN_E2E_PROJECT="${project}"
export OPSWARDEN_E2E_BACKEND_SUBNET="172.${subnet_second}.${subnet_third}.0/29"
export OPSWARDEN_E2E_APP_IP="172.${subnet_second}.${subnet_third}.2"
export OPSWARDEN_E2E_CADDY_IP="172.${subnet_second}.${subnet_third}.3"
export OPSWARDEN_E2E_IMAGE_VERSION="${image_version}"

playwright_status=0
scan_status=0
finish() {
  trap - EXIT INT TERM
  set +e
  "${repo_root}/scripts/scan-sensitive-fixtures.sh"
  scan_status=$?
  node -e '
    const fs = require("node:fs");
    for (const candidate of process.argv.slice(1)) {
      try {
        const metadata = fs.lstatSync(candidate);
        if (metadata.isFile() && !metadata.isSymbolicLink()) fs.unlinkSync(candidate);
      } catch {}
    }
  ' \
    "${runtime_dir}/sensitive-patterns" \
    "${runtime_dir}/control.json" \
    "${runtime_dir}/master.key" \
    "${runtime_dir}/restore/master.key" \
    "${runtime_dir}/restore-wrong/master.key"
  if [[ "${playwright_status}" -ne 0 ]]; then
    exit "${playwright_status}"
  fi
  exit "${scan_status}"
}
trap finish EXIT INT TERM

cd "${repo_root}/tests/e2e"
npm ci --ignore-scripts --no-audit --no-fund
node check-browser.mjs
npx --no-install playwright test || playwright_status=$?
exit "${playwright_status}"
