#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <backup.sql.gz>" >&2
  exit 1
fi

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENV_FILE="${ROOT_DIR}/deploy/production/.env"
BACKUP_FILE=$1

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

POSTGRES_DB=${POSTGRES_DB:-socdss}
POSTGRES_USER=${POSTGRES_USER:-socdss}

gzip -dc "${BACKUP_FILE}" | docker compose -f "${ROOT_DIR}/deploy/production/docker-compose.yml" exec -T postgres \
  psql -U "${POSTGRES_USER}" "${POSTGRES_DB}"

echo "Restored database backup from ${BACKUP_FILE}"
