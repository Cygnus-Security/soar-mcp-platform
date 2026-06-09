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

WAZUH_VERSION=${WAZUH_VERSION:-v4.14.5}
WAZUH_LAB_ROOT=${WAZUH_LAB_ROOT:-deploy/wazuh-lab/runtime}

if [[ "${WAZUH_LAB_ROOT}" != /* ]]; then
  WAZUH_LAB_ROOT="${ROOT_DIR}/${WAZUH_LAB_ROOT}"
fi

REPO_DIR="${WAZUH_LAB_ROOT}/wazuh-docker"
COMPOSE_DIR="${REPO_DIR}/single-node"
CERT_DIR="${COMPOSE_DIR}/config/wazuh_indexer_ssl_certs"

if [[ "$(uname -s)" == "Linux" ]]; then
  MAX_MAP_COUNT=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
  if [[ "${MAX_MAP_COUNT}" -lt 262144 ]]; then
    echo "vm.max_map_count is ${MAX_MAP_COUNT}; Wazuh Indexer requires at least 262144."
    echo "Run: sudo sysctl -w vm.max_map_count=262144"
  fi
fi

mkdir -p "${WAZUH_LAB_ROOT}"

if [[ ! -d "${REPO_DIR}/.git" ]]; then
  git clone --depth 1 --branch "${WAZUH_VERSION}" https://github.com/wazuh/wazuh-docker.git "${REPO_DIR}"
else
  echo "Using existing Wazuh Docker checkout: ${REPO_DIR}"
fi

cd "${COMPOSE_DIR}"

if [[ ! -f "${CERT_DIR}/admin.pem" ]]; then
  docker compose -f generate-indexer-certs.yml run --rm generator
fi

docker compose up -d

echo "Wazuh lab is starting."
echo "Dashboard: https://localhost"
echo "Credentials: admin / SecretPassword"
