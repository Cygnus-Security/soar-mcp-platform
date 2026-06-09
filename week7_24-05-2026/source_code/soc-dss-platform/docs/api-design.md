# API Design

Base path:

```text
/api/v1
```

## Health

```http
GET /api/v1/health
```

## Import Wazuh Alerts

```http
POST /api/v1/import/wazuh-alerts
Content-Type: multipart/form-data
```

Field:

```text
file=<alerts.json>
```

## Alerts

```http
GET /api/v1/alerts
```

## Incidents

```http
GET /api/v1/incidents
GET /api/v1/incidents/{id}
POST /api/v1/incidents/correlate
```

## Dashboard

```http
GET /api/v1/dashboard/summary
```

## Reports

```http
GET /api/v1/reports/incidents.csv
```
