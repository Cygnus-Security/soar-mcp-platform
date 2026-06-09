#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENV_FILE="${ROOT_DIR}/deploy/wazuh-lab/.env"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

WAZUH_LAB_ROOT=${WAZUH_LAB_ROOT:-deploy/wazuh-lab/runtime}

if [[ "${WAZUH_LAB_ROOT}" != /* ]]; then
  WAZUH_LAB_ROOT="${ROOT_DIR}/${WAZUH_LAB_ROOT}"
fi

COMPOSE_DIR="${WAZUH_LAB_ROOT}/wazuh-docker/single-node"

if [[ ! -d "${COMPOSE_DIR}" ]]; then
  echo "Wazuh lab runtime was not found at ${COMPOSE_DIR}"
  exit 0
fi

cd "${COMPOSE_DIR}"
docker compose down
