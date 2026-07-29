#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
artifact_dir="${OPSWARDEN_E2E_ARTIFACT_DIR:-${repo_root}/.artifacts/e2e}"
runtime_dir="${OPSWARDEN_E2E_RUNTIME_DIR:-${repo_root}/.tmp/e2e}"
secret_file="${OPSWARDEN_E2E_SECRET_FILE:-${artifact_dir}/.sensitive-values}"

if [[ ! -f "${secret_file}" || -L "${secret_file}" || ! -s "${secret_file}" ]]; then
  echo "sensitive fixture scan refused: protected value file is missing or unsafe" >&2
  exit 2
fi

targets=(
  "${runtime_dir}/data/opswarden.db"
  "${artifact_dir}/online-backup.sqlite3"
  "${artifact_dir}/application.log"
  "${artifact_dir}/audit-export.json"
  "${artifact_dir}/browser-storage.json"
  "${artifact_dir}/captured-errors.json"
  "${artifact_dir}/restore-compose.log"
)
for target in "${targets[@]}"; do
  if [[ ! -f "${target}" || -L "${target}" ]]; then
    echo "sensitive fixture scan refused: required artifact is missing or unsafe: ${target}" >&2
    exit 2
  fi
done

# -q prevents a detected value from ever being echoed into CI output. The value
# file is passed by path, so raw fixtures never enter argv or process listings.
if LC_ALL=C grep -a -q -F -f "${secret_file}" -- "${targets[@]}"; then
  echo "sensitive fixture scan failed: a protected value escaped an encrypted boundary" >&2
  exit 1
fi

if git -C "${repo_root}" grep -a -q -F -f "${secret_file}" --; then
  echo "sensitive fixture scan failed: a protected value is present in a tracked file" >&2
  exit 1
fi

echo "sensitive fixture scan: clean (${#targets[@]} required artifact classes)"
