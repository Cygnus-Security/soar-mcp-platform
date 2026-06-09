#!/usr/bin/env bash
set -euo pipefail

API_BASE=${API_BASE:-http://localhost:8080/api/v1}
FILE=${1:-data/sample/wazuh-alerts-sample.json}

curl -s -F "file=@${FILE}" "${API_BASE}/import/wazuh-alerts" | jq .
curl -s -X POST "${API_BASE}/incidents/correlate" | jq .
