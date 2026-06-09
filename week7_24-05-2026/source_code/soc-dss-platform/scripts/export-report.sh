#!/usr/bin/env bash
set -euo pipefail

API_BASE=${API_BASE:-http://localhost:8080/api/v1}
mkdir -p data/results
curl -s "${API_BASE}/reports/incidents.csv" -o data/results/incidents.csv
echo "Saved data/results/incidents.csv"
