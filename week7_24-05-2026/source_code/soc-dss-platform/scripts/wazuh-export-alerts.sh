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
WAZUH_ALERTS_OUTPUT=${1:-${WAZUH_ALERTS_OUTPUT:-data/results/wazuh-alerts.json}}

if [[ "${WAZUH_LAB_ROOT}" != /* ]]; then
  WAZUH_LAB_ROOT="${ROOT_DIR}/${WAZUH_LAB_ROOT}"
fi

if [[ "${WAZUH_ALERTS_OUTPUT}" != /* ]]; then
  WAZUH_ALERTS_OUTPUT="${ROOT_DIR}/${WAZUH_ALERTS_OUTPUT}"
fi

COMPOSE_DIR="${WAZUH_LAB_ROOT}/wazuh-docker/single-node"

if [[ ! -d "${COMPOSE_DIR}" ]]; then
  echo "Wazuh lab runtime was not found. Run: make wazuh-lab-up" >&2
  exit 1
fi

mkdir -p "$(dirname "${WAZUH_ALERTS_OUTPUT}")"

cd "${COMPOSE_DIR}"

if [[ -z "$(docker compose ps -q wazuh.manager)" ]]; then
  echo "Wazuh manager is not running. Run: make wazuh-lab-up" >&2
  exit 1
fi

docker compose exec -T wazuh.manager sh -c 'cat /var/ossec/logs/alerts/alerts.json' > "${WAZUH_ALERTS_OUTPUT}"

echo "Exported Wazuh alerts to ${WAZUH_ALERTS_OUTPUT}"
