# Risk Scoring Model

The DSS assigns an incident risk score from 0 to 100.

## Formula

```text
Risk Score =
0.30 × Wazuh Severity
+ 0.20 × Asset Criticality
+ 0.15 × Alert Frequency
+ 0.15 × MITRE Technique Weight
+ 0.10 × Exposure Level
+ 0.10 × Vulnerability Context
```

## Factors

| Factor | Meaning |
|---|---|
| Wazuh Severity | Maximum Wazuh rule level among related alerts, normalized to 0–100 |
| Asset Criticality | Importance of the affected asset |
| Alert Frequency | Number of related alerts in the incident |
| MITRE Technique Weight | Weight based on the attack tactic/technique |
| Exposure Level | Public-facing assets receive higher weight |
| Vulnerability Context | Extra risk if CVE/vulnerability context is present |

## Risk Levels

| Score | Level |
|---:|---|
| 0–39 | Low |
| 40–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |
