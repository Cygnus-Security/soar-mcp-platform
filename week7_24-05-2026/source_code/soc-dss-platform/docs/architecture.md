# Architecture

## Product Architecture

```text
Security Monitoring Source
(Wazuh / SIEM / alerts.json)
        ↓
Wazuh Integration Layer
        ↓
Alert Normalization
        ↓
Alert Correlation Engine
        ↓
Risk Assessment Engine
        ↓
Response Recommendation Engine
        ↓
PostgreSQL
        ↓
Spring Boot REST API
        ↓
React SOC Dashboard
```

## Core Product Modules

### 1. Alert Normalization

Transforms Wazuh alerts into a common security alert model.

### 2. Alert Correlation

Groups related alerts into incidents based on:

- Target asset
- Source IP
- Incident type
- Time/context similarity

### 3. Risk Assessment

Calculates incident risk score using a weighted formula:

```text
Risk Score =
0.30 × Wazuh Severity
+ 0.20 × Asset Criticality
+ 0.15 × Alert Frequency
+ 0.15 × MITRE Technique Weight
+ 0.10 × Exposure Level
+ 0.10 × Vulnerability Context
```

### 4. Response Recommendation

Generates recommended response actions for the SOC analyst.

## Product vs Experiment

- Product: `backend/`, `frontend/`, `deploy/`, `integrations/`
- Experiment: `experiments/wazuh-validation/`

The experiment environment is not the product. It only validates the product with realistic Wazuh alerts.
