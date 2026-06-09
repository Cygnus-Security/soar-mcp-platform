# Production Deployment

## Start Services

```bash
cp deploy/production/.env.example deploy/production/.env
./scripts/prepare-production-storage.sh
docker compose -f deploy/production/docker-compose.yml up --build -d
```

## Access

```text
Dashboard: http://localhost:8080
API:       http://localhost:8080/api/v1
```

## Services

- `postgres`: PostgreSQL database
- `backend`: Spring Boot API and DSS engine
- `frontend`: React static frontend served by Nginx

## Persistent Data

Production data is bind-mounted under `deploy/production/runtime/` by default:

- `runtime/postgres/data`: PostgreSQL database files
- `runtime/postgres/backups`: database backups
- `runtime/backend/logs`: backend log directory
- `runtime/frontend/logs`: Nginx access/error logs
- `runtime/reports`: report export workspace

Before changing storage paths, edit `deploy/production/.env`.

## Backup and Restore

Create a compressed PostgreSQL backup:

```bash
./scripts/backup-production-db.sh
```

Restore a backup:

```bash
./scripts/restore-production-db.sh deploy/production/runtime/postgres/backups/socdss-YYYYMMDD-HHMMSS.sql.gz
```

## Stop Services

```bash
docker compose -f deploy/production/docker-compose.yml down
```

## Reset Database

```bash
docker compose -f deploy/production/docker-compose.yml down
rm -rf deploy/production/runtime/postgres/data
```
