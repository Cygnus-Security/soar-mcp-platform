# SOC DSS Platform

**SOC DSS Platform** is a product-oriented Decision Support System for Security Operations Center (SOC) environments. It helps SOC analysts correlate security alerts, assess incident risk, and receive incident response recommendations from security monitoring data such as Wazuh alerts.

> Research title: **A Decision Support System for Security Alert Correlation, Risk Assessment, and Incident Response Support in SOC Environments**

## Product Scope

This repository is designed as a product-first MVP, not just a lab script. The main system includes:

- Spring Boot backend API
- React TypeScript SOC dashboard
- PostgreSQL database
- Docker Compose production-style deployment
- Wazuh alert import integration
- Alert correlation engine
- Risk assessment engine
- Incident response recommendation engine
- CSV export for research results

The Wazuh validation environment is kept under `experiments/` and is used only to generate realistic alerts for evaluation.

## Architecture

```text
Wazuh / SIEM Alerts
        ↓
Wazuh Integration Layer
        ↓
Spring Boot Backend API
        ↓
DSS Core Engine
 ├── Alert Normalization
 ├── Alert Correlation
 ├── Risk Assessment
 └── Response Recommendation
        ↓
PostgreSQL
        ↓
React SOC Dashboard
```

## Repository Structure

```text
soc-dss-platform-enterprise/
├── backend/                  # Spring Boot backend and DSS core engine
├── frontend/                 # React TypeScript dashboard
├── deploy/production/        # Docker Compose and production deployment files
├── deploy/wazuh-lab/         # Optional Wazuh single-node lab for alert generation
├── integrations/wazuh/       # Wazuh integration guide and sample alert format
├── experiments/              # Optional validation environment using Wazuh
├── docs/                     # Architecture, API and research documentation
├── data/sample/              # Sample Wazuh alerts and asset inventory
├── data/results/             # Exported experiment results
├── scripts/                  # Helper scripts
├── Makefile
└── README.md
```

## Quick Start with Docker Compose

```bash
cd soc-dss-platform-enterprise
cp deploy/production/.env.example deploy/production/.env
docker compose -f deploy/production/docker-compose.yml up --build -d
```

Open the dashboard:

```text
http://localhost:8080
```

Open backend API directly:

```text
http://localhost:8080/api/v1/health
```

## Run Product Locally for Development

### Backend

```bash
cd backend
mvn spring-boot:run
```

Backend API:

```text
http://localhost:8081/api/v1
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:5173
```

## Demo Flow

1. Open the dashboard.
2. Go to **Import Alerts**.
3. Upload `data/sample/wazuh-alerts-sample.json`.
4. Click **Correlate Alerts**.
5. Review generated incidents, risk scores and recommendations.
6. Export incident CSV from the Reports section or API.

## Optional Wazuh Lab

For validation with real Wazuh alerts, start the Wazuh single-node lab:

```bash
cp deploy/wazuh-lab/.env.example deploy/wazuh-lab/.env
make wazuh-lab-up
```

Export alerts from Wazuh and import them into SOC DSS:

```bash
make wazuh-lab-import
```

See `deploy/wazuh-lab/README.md` for details.

## Main API Endpoints

```text
POST   /api/v1/import/wazuh-alerts
GET    /api/v1/alerts
GET    /api/v1/incidents
GET    /api/v1/incidents/{id}
POST   /api/v1/incidents/correlate
GET    /api/v1/dashboard/summary
GET    /api/v1/reports/incidents.csv
GET    /api/v1/health
```

## Research Contribution

The product implements three DSS components that can be discussed in the research paper:

1. **Alert Correlation Model**
   - Groups multiple low-level security alerts into higher-level incidents.
   - Uses target asset, source IP, incident type and correlation window.

2. **Risk Assessment Model**
   - Calculates a risk score from severity, asset criticality, frequency, MITRE context, exposure and vulnerability context.

3. **Incident Response Recommendation Model**
   - Recommends actions such as monitoring, escalation, IP blocking, evidence collection, isolation or patch prioritization.

## Risk Scoring Model

```text
Risk Score =
0.30 × Wazuh Severity
+ 0.20 × Asset Criticality
+ 0.15 × Alert Frequency
+ 0.15 × MITRE Technique Weight
+ 0.10 × Exposure Level
+ 0.10 × Vulnerability Context
```

Risk levels:

```text
0–39    Low
40–59   Medium
60–79   High
80–100  Critical
```

## GitHub Topics

Recommended topics:

```text
soc cybersecurity decision-support-system wazuh siem incident-response alert-correlation risk-assessment spring-boot react postgresql docker
```

## License

This project is released for academic and research purposes.
