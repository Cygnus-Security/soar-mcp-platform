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

API_BASE=${API_BASE:-http://localhost:8080/api/v1}
WAZUH_ALERTS_OUTPUT=${WAZUH_ALERTS_OUTPUT:-data/results/wazuh-alerts.json}

"${ROOT_DIR}/scripts/wazuh-export-alerts.sh" "${WAZUH_ALERTS_OUTPUT}"

if [[ "${WAZUH_ALERTS_OUTPUT}" != /* ]]; then
  WAZUH_ALERTS_OUTPUT="${ROOT_DIR}/${WAZUH_ALERTS_OUTPUT}"
fi

IMPORT_RESPONSE=$(curl -s -F "file=@${WAZUH_ALERTS_OUTPUT}" "${API_BASE}/import/wazuh-alerts")
CORRELATE_RESPONSE=$(curl -s -X POST "${API_BASE}/incidents/correlate")

if command -v jq >/dev/null 2>&1; then
  echo "${IMPORT_RESPONSE}" | jq .
  echo "${CORRELATE_RESPONSE}" | jq .
else
  echo "${IMPORT_RESPONSE}"
  echo "${CORRELATE_RESPONSE}"
fi
