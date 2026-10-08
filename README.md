# SOAR MCP Platform

An experimental **Security Orchestration, Automation, and Response (SOAR)** platform that uses the Model Context Protocol (MCP) to collect logs, normalize behavior, correlate events, perform AI-assisted analysis, and generate incident response plans.

> This project is a research prototype. Actions such as blocking an IP address, isolating a container, or sending an alert are currently represented in response results. The platform does not yet include executors that apply these actions to a firewall, Docker environment, Telegram, or ticketing system.

## Architecture

```text
Wazuh Indexer ───────────────┐
                            │
Web/Auth/DB/Audit/Firewall ─┴─> Collector MCP
                                      │
                                      v
                                Translator MCP
                                      │
                                      v
                                Correlator MCP
                                      │
                         ┌────────────┴────────────┐
                         │                         │
                   Wazuh confirmed          Behavioral chain
                         │                         │
                         v                         v
                  Immediate response         AI Reasoning MCP
                         │                         │
                         └────────────┬────────────┘
                                      v
                                 Response MCP

                     MCP Host orchestrates the pipeline
```

The platform consists of six services:

| Service | Host port | Responsibility |
|---|---:|---|
| `collector_server` | 8101 | Collects Wazuh alerts and logs from local sources |
| `translator_server` | 8102 | Normalizes logs and identifies security-related behavior |
| `correlator_server` | 8103 | Groups session events, calculates risk, and determines the attack stage |
| `reasoning_server` | 8104 | Analyzes behavioral chains through a configured AI provider |
| `response_server` | 8105 | Generates response plans or describes active-response actions |
| `soar_host` | — | Polls data sources and orchestrates the MCP services |

The MCP servers use SSE transport and listen on port `8000` inside the Docker network.

## Processing Flows

### Branch A — Wazuh Alert

1. The host polls Wazuh for a new alert every 10 seconds.
2. The collector retrieves related data from all available sources.
3. The translator converts raw logs into behavioral events.
4. The correlator accumulates events, calculates risk, and builds an attack story.
5. When the payload contains a Wazuh alert, the system selects the `wazuh_confirmed` branch.
6. The response server generates immediate-response actions while the reasoning server creates an incident report.

### Branch B — Behavioral Analysis

1. The host scans web logs every 30 seconds for active source IP addresses.
2. The collector retrieves web, authentication, database, audit, container, and firewall logs without querying Wazuh alerts.
3. The translator identifies both normal and malicious behavior.
4. The correlator sends the behavioral chain to the AI service when any of these conditions is met:
   - At least 30 events have accumulated.
   - The risk score is 40 or higher.
   - At least two distinct attack behaviors are present.
   - The session has been inactive for 30 minutes.
5. If the AI service classifies the activity as suspicious, the response server creates a plan for administrator review.

## Detection Capabilities

The translator currently includes rules for detecting:

- SQL injection and authentication bypass attempts.
- Local and remote file inclusion.
- Command injection and reverse shells.
- Cross-site scripting.
- Server-side request forgery.
- Webshell execution.
- SSH brute-force attempts and user enumeration.
- Privilege escalation.
- Port scans and access to sensitive paths.
- High-severity Wazuh alerts.
- Normal web behavior such as browsing, login, API calls, searches, and form submissions.

Input is URL-decoded, converted to lowercase, and normalized for selected encoding and comment patterns before the detection rules are applied.

## Repository Structure

```text
.
├── docker-compose.yml
├── mcp_host/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py              # Dual-trigger polling loop
│       ├── orchestrator.py      # Pipeline orchestration
│       ├── mcp_client.py        # MCP SSE client
│       ├── ai_engine.py         # Reasoning MCP client
│       ├── response_engine.py   # Response MCP client
│       ├── wazuh_client.py      # Wazuh Indexer polling
│       └── config.py            # Prototype configuration
├── mcp_servers/
│   ├── collector_server/
│   ├── translator_server/
│   ├── correlator_server/
│   ├── reasoning_server/
│   └── response_server/
└── test_pipeline.py             # Translator and correlator logic tests
```

## Requirements

- Docker Engine and Docker Compose.
- A shared Docker network named `backend_net`.
- A log directory that can be mounted read-only at `/shared_logs`.
- A Wazuh Indexer accessible from `backend_net`.
- An API key for a supported AI provider when AI reasoning is required.

The reasoning server supports `groq`, `gemini`, `claude`, and `openai`.

## Configuration

### 1. Docker Network

The Compose file uses an external network, so the network must exist before the services are started:

```bash
docker network create backend_net
```

Skip this command if the network already exists.

### 2. Log Volume

Update the host path in `docker-compose.yml` for the target environment:

```yaml
volumes:
  - /path/to/shared_logs:/shared_logs:ro
```

The collector reads log sources below `/shared_logs`. The actual directory structure and file names must match the paths defined in `mcp_servers/collector_server/server.py`.

### 3. Wazuh

Update the Wazuh URL and credentials in:

- `mcp_host/app/wazuh_client.py`
- `mcp_host/app/config.py`
- The `collector_server` environment variables when environment-based configuration is used.

The values currently stored in the source are intended for a lab environment only. Do not commit real credentials to the repository.

### 4. AI Provider

Configure the provider and API key for `reasoning_server`:

```yaml
reasoning_server:
  environment:
    AI_PROVIDER: groq
    AI_API_KEY: ${AI_API_KEY}
```

Export the secret from the shell or store it in an environment file that is excluded from version control:

```bash
export AI_API_KEY="your-api-key"
```

When no API key is configured, the reasoning server returns an `analysis_failed` result instead of calling a provider.

## Starting the Platform

```bash
docker compose up --build -d
```

Follow the host orchestrator logs:

```bash
docker compose logs -f soar_host
```

Check container status:

```bash
docker compose ps
```

Stop the platform:

```bash
docker compose down
```

## MCP Tool Surface

### Collector

- `fetch_web_logs`
- `fetch_container_logs`
- `fetch_auth_logs`
- `fetch_db_logs`
- `fetch_audit_logs`
- `fetch_firewall_logs`
- `fetch_wazuh_alerts`
- `fetch_all_sources`

### Translator

- `translate_behavior`
- `translate_batch`

### Correlator

- `add_event`
- `add_event_batch`
- `update_ai_context`
- `get_session_status`
- `get_forensic_snapshot`
- `list_active_sessions`

### Reasoning

- `reason_about_attack`

### Response

- `generate_response`
- `execute_active_response`

## Logic Tests

`test_pipeline.py` tests the translator and correlator with local fixtures. It includes the following scenarios:

- `recon`
- `sqli`
- `lfi`
- `brute`
- `apt`
- `noise_only`
- `wazuh_passthrough`

Examples:

```bash
python test_pipeline.py
python test_pipeline.py -v
python test_pipeline.py --scenario apt
```

These tests do not replace integration testing with Docker, MCP transport, Wazuh, or a real AI provider.

## Current Status and Limitations

- Active response currently generates a list of actions without applying infrastructure changes.
- MCP endpoints do not yet have application-level authentication or TLS.
- The correlator stores sessions in `/app/session_store.json`; the current Compose file does not mount a persistent volume for this file.
- Sessions are identified primarily by source IP, which may be inaccurate in environments that use NAT or proxies.
- Wazuh credentials and selected endpoints are configured directly for the lab environment.
- Python dependency versions are not pinned.

Do not connect this prototype directly to a production network or allow it to block or isolate resources automatically until authentication, secret management, audit logging, persistent storage, and an approval mechanism have been implemented.

## License

See [LICENSE](LICENSE).
