# Wazuh Integration

The product can import Wazuh alerts from a JSON-lines `alerts.json` file.

## Wazuh Alert Source

On a Wazuh Manager, alerts are commonly available at:

```bash
/var/ossec/logs/alerts/alerts.json
```

Export alerts to the product host:

```bash
sudo cp /var/ossec/logs/alerts/alerts.json ./wazuh-alerts.json
sudo chown $USER:$USER ./wazuh-alerts.json
```

Then upload the file from the dashboard or use the API:

```bash
curl -F "file=@wazuh-alerts.json" http://localhost:8080/api/v1/import/wazuh-alerts
curl -X POST http://localhost:8080/api/v1/incidents/correlate
```

## Supported Fields

The importer extracts:

- `timestamp`
- `rule.id`
- `rule.level`
- `rule.description`
- `rule.groups`
- `rule.mitre.tactic`
- `rule.mitre.technique`
- `agent.name`
- `agent.ip`
- `data.srcip`, `data.src_ip`, `data.src`
- raw JSON

## Future Production Integration

The current MVP imports `alerts.json` for reliable research validation. Future work can add direct Wazuh Indexer API queries for scheduled or near-real-time ingestion.
