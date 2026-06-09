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

POSTGRES_DB=${POSTGRES_DB:-socdss}
POSTGRES_USER=${POSTGRES_USER:-socdss}

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

BACKUP_DIR="$(resolve_path "${POSTGRES_BACKUP_DIR:-./runtime/postgres/backups}")"
BACKUP_FILE="${BACKUP_DIR}/socdss-$(date +%Y%m%d-%H%M%S).sql.gz"

mkdir -p "${BACKUP_DIR}"
docker compose -f "${ROOT_DIR}/deploy/production/docker-compose.yml" exec -T postgres \
  pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" | gzip > "${BACKUP_FILE}"

echo "Saved database backup to ${BACKUP_FILE}"
