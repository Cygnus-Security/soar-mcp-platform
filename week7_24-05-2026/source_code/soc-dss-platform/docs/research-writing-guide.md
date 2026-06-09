# Research Writing Guide

Suggested paper/report title:

**A Decision Support System for Security Alert Correlation, Risk Assessment, and Incident Response Support in SOC Environments**

## Chapter 1: Introduction

- SOC alert overload
- Need for decision support
- Research objectives
- Scope and contributions

## Chapter 2: Background and Related Work

- SOC and SIEM/XDR
- Decision Support Systems
- Security alert correlation
- Risk assessment
- Incident response
- Wazuh as an alert source
- MITRE ATT&CK / D3FEND as future enhancement

## Chapter 3: Proposed Model

Use the product architecture in `docs/architecture.md`.

Key models:

1. Alert normalization model
2. Alert correlation model
3. Risk assessment model
4. Response recommendation model

## Chapter 4: System Implementation

Map to repository folders:

| Section | Repository |
|---|---|
| Backend API | `backend/` |
| DSS core engine | `backend/src/main/java/com/socdss/` |
| Dashboard | `frontend/` |
| Database | `backend/src/main/resources/db/migration/` |
| Deployment | `deploy/production/` |
| Wazuh integration | `integrations/wazuh/` |

## Chapter 5: Experiment and Evaluation

Use `experiments/wazuh-validation/` to generate real alerts.

Recommended evaluation tables:

### Alert Correlation Result

| Scenario | Raw Alerts | Correlated Incidents | Reduction |
|---|---:|---:|---:|
| SSH brute force | 50 | 1 | 98% |
| FIM file change | 8 | 1 | 87.5% |

### Risk Assessment Result

| Incident | Alert Count | Max Rule Level | Risk Score | Risk Level |
|---|---:|---:|---:|---|
| SSH Brute Force | 50 | 10 | 86 | Critical |

### Recommendation Result

| Incident | Recommendation | Explanation |
|---|---|---|
| SSH Brute Force | Block source IP and escalate | High frequency and authentication attack |

## Chapter 6: Conclusion

- Summary of product and model
- Experiment result discussion
- Limitations
- Future work
