# Wazuh Lab

This lab installs an official Wazuh single-node Docker stack for validation and log collection. It is separate from `deploy/production/docker-compose.yml` because SOC DSS is the product under test, while Wazuh is the alert source used for experiments.

The lab uses the upstream `wazuh/wazuh-docker` repository, pinned by `WAZUH_VERSION`, and stores the cloned runtime under `deploy/wazuh-lab/runtime/`.

## Requirements

- Docker Engine or Docker Desktop
- Docker Compose plugin
- Git
- At least 4 CPU cores, 8 GB RAM, and 50 GB free disk space for the Wazuh single-node stack

On Linux, Wazuh Indexer also requires:

```bash
sudo sysctl -w vm.max_map_count=262144
```

## Start Wazuh

```bash
cp deploy/wazuh-lab/.env.example deploy/wazuh-lab/.env
make wazuh-lab-up
```

The script clones the official Wazuh Docker repo, generates self-signed certificates if needed, and starts the single-node stack.

Wazuh dashboard:

```text
https://localhost
```

Default lab credentials:

```text
Username: admin
Password: SecretPassword
```

## Generate Alerts

Use the Wazuh dashboard or an enrolled Wazuh agent to generate test alerts. The manager alert file used by SOC DSS is:

```text
/var/ossec/logs/alerts/alerts.json
```

## Export Alerts

```bash
make wazuh-lab-export
```

Default output:

```text
data/results/wazuh-alerts.json
```

You can choose another output file:

```bash
./scripts/wazuh-export-alerts.sh data/results/experiment-01-alerts.json
```

## Import Into SOC DSS

Start the SOC DSS product first:

```bash
make up
```

Then export Wazuh alerts and import them into SOC DSS:

```bash
make wazuh-lab-import
```

This calls:

```text
POST /api/v1/import/wazuh-alerts
POST /api/v1/incidents/correlate
```

## Stop Wazuh

```bash
make wazuh-lab-down
```

To remove Wazuh volumes completely, run from the generated runtime directory:

```bash
cd deploy/wazuh-lab/runtime/wazuh-docker/single-node
docker compose down -v
```
