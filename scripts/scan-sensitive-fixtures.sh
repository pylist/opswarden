#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
artifact_dir="${OPSWARDEN_E2E_ARTIFACT_DIR:-${repo_root}/.artifacts/e2e}"
runtime_dir="${OPSWARDEN_E2E_RUNTIME_DIR:-${repo_root}/.tmp/e2e}"
secret_file="${OPSWARDEN_E2E_SECRET_FILE:-${runtime_dir}/sensitive-patterns}"
exec /usr/bin/env -i \
  HOME="${HOME:-/nonexistent}" \
  PATH="/usr/bin:/bin" \
  LC_ALL=C \
  OPSWARDEN_E2E_REPO_ROOT="${repo_root}" \
  OPSWARDEN_E2E_ARTIFACT_DIR="${artifact_dir}" \
  OPSWARDEN_E2E_RUNTIME_DIR="${runtime_dir}" \
  OPSWARDEN_E2E_SECRET_FILE="${secret_file}" \
  /usr/bin/python3 -I "${repo_root}/scripts/scan_sensitive_fixtures.py"
