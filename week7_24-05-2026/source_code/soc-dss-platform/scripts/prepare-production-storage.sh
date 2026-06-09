#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENV_FILE="${ROOT_DIR}/deploy/production/.env"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

resolve_path() {
  local path=$1
  if [[ "${path}" = /* ]]; then
    echo "${path}"
  elif [[ "${path}" == ./* ]]; then
    echo "${ROOT_DIR}/deploy/production/${path#./}"
  else
    echo "${ROOT_DIR}/${path}"
  fi
}

mkdir -p \
  "$(resolve_path "${POSTGRES_DATA_DIR:-./runtime/postgres/data}")" \
  "$(resolve_path "${POSTGRES_BACKUP_DIR:-./runtime/postgres/backups}")" \
  "$(resolve_path "${BACKEND_LOG_DIR:-./runtime/backend/logs}")" \
  "$(resolve_path "${FRONTEND_LOG_DIR:-./runtime/frontend/logs}")" \
  "$(resolve_path "${REPORT_OUTPUT_DIR:-./runtime/reports}")"

echo "Prepared production storage directories under deploy/production/runtime."
