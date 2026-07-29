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
subnet_index="$((subnet_checksum % 2048))"
docker_bin="$(command -v docker)"
[[ "${docker_bin}" = /* ]] || {
  echo "E2E release gate refused: docker executable is not absolute" >&2
  exit 2
}
network_output="$(
  /usr/bin/python3 -I "${repo_root}/scripts/bounded_command.py" \
    15 "${docker_bin}" network ls -q
)"
network_args=()
while IFS= read -r network_id; do
  [[ -z "${network_id}" ]] && continue
  [[ "${network_id}" =~ ^[0-9a-f]{12,64}$ ]] || {
    echo "E2E release gate refused: Docker returned an unsafe network ID" >&2
    exit 2
  }
  network_args+=("${network_id}")
  ((${#network_args[@]} <= 4096)) || {
    echo "E2E release gate refused: Docker network count exceeds bound" >&2
    exit 2
  }
done <<<"${network_output}"
used_subnets=""
if ((${#network_args[@]} > 0)); then
  used_subnets="$(
    /usr/bin/python3 -I "${repo_root}/scripts/bounded_command.py" \
      15 "${docker_bin}" network inspect "${network_args[@]}" \
      --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}'
  )"
fi
subnet=""
for ((attempt = 0; attempt < 2048; attempt++)); do
  candidate="$(((subnet_index + attempt) % 2048))"
  subnet_second="$((20 + candidate / 256))"
  subnet_third="$((candidate % 256))"
  candidate_subnet="172.${subnet_second}.${subnet_third}.0/29"
  if ! grep -Fqx -- "${candidate_subnet}" <<<"${used_subnets}"; then
    subnet="${candidate_subnet}"
    break
  fi
done
[[ -n "${subnet}" ]] || {
  echo "E2E release gate refused: no isolated backend subnet is available" >&2
  exit 75
}

export OPSWARDEN_E2E_RUNTIME_DIR="${runtime_dir}"
export OPSWARDEN_E2E_ARTIFACT_DIR="${artifact_dir}"
export OPSWARDEN_E2E_SECRET_FILE="${runtime_dir}/sensitive-patterns"
export OPSWARDEN_E2E_APP_PORT="${app_port}"
export OPSWARDEN_E2E_RESTORE_PORT="${restore_port}"
export OPSWARDEN_E2E_PROJECT="${project}"
export OPSWARDEN_E2E_BACKEND_SUBNET="${subnet}"
export OPSWARDEN_E2E_APP_IP="172.${subnet_second}.${subnet_third}.2"
export OPSWARDEN_E2E_CADDY_IP="172.${subnet_second}.${subnet_third}.3"
export OPSWARDEN_E2E_IMAGE_VERSION="${image_version}"

playwright_status=0
scan_status=0
signal_status=0
finish() {
  trap - EXIT INT TERM
  set +e
  "${repo_root}/scripts/scan-sensitive-fixtures.sh"
  scan_status=$?
  cleanup_status=0
  for relative in \
    sensitive-patterns control.json master.key \
    restore/master.key restore-wrong/master.key; do
    /usr/bin/env -i \
      HOME="/nonexistent" PATH="/usr/bin:/bin" LC_ALL=C \
      /usr/bin/python3 -I "${repo_root}/scripts/cleanup_e2e_secrets.py" \
      "${runtime_dir}" "${relative}" || cleanup_status=$?
  done
  if [[ "${signal_status}" -ne 0 ]]; then
    exit "${signal_status}"
  fi
  if [[ "${playwright_status}" -ne 0 ]]; then
    exit "${playwright_status}"
  fi
  if [[ "${cleanup_status}" -ne 0 ]]; then
    exit "${cleanup_status}"
  fi
  exit "${scan_status}"
}
on_signal() {
  signal_status="$1"
  exit "${signal_status}"
}
trap finish EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

printf 'E2E runtime=%s artifact=%s project=%s app_port=%s restore_port=%s subnet=%s\n' \
  "${runtime_dir}" "${artifact_dir}" "${project}" "${app_port}" "${restore_port}" "${subnet}"

cd "${repo_root}/tests/e2e"
npm ci --ignore-scripts --no-audit --no-fund
node check-browser.mjs
npx --no-install playwright test || playwright_status=$?
exit "${playwright_status}"
