# Wazuh Validation Experiment

This folder is optional and is used only for experimental validation. The main product is implemented in `backend/`, `frontend/`, `deploy/`, and `integrations/`.

## Purpose

Use Wazuh to generate realistic security alerts, then import them into SOC DSS Platform for evaluation.

Use `deploy/wazuh-lab/` to install and run the optional Wazuh single-node Docker lab.

Recommended scenarios:

1. SSH brute force
2. File Integrity Monitoring change
3. Vulnerability alert
4. Web attack / network scan

## Research Metrics

- Raw alert count
- Correlated incident count
- Alert reduction rate
- Risk score distribution
- Response recommendation suitability

## Minimal Validation Flow

```text
Wazuh Manager + Wazuh Agent
        ↓
Generate alerts
        ↓
Export alerts.json
        ↓
Import to SOC DSS Platform
        ↓
Correlate + assess risk + recommend response
        ↓
Export CSV result for report
```

## Lab Commands

```bash
cp deploy/wazuh-lab/.env.example deploy/wazuh-lab/.env
make wazuh-lab-up
make wazuh-lab-export
make wazuh-lab-import
```
