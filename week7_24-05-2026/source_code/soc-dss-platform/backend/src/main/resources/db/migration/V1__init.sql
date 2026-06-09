CREATE TABLE IF NOT EXISTS assets (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(64),
    criticality VARCHAR(32) NOT NULL,
    exposure VARCHAR(32) NOT NULL,
    owner VARCHAR(255),
    environment VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id BIGSERIAL PRIMARY KEY,
    event_timestamp TIMESTAMP WITH TIME ZONE,
    source VARCHAR(64) NOT NULL,
    external_id VARCHAR(255),
    wazuh_rule_id VARCHAR(64),
    wazuh_rule_level INTEGER NOT NULL,
    agent_name VARCHAR(255),
    agent_ip VARCHAR(64),
    source_ip VARCHAR(64),
    destination_ip VARCHAR(64),
    description TEXT,
    mitre_tactic VARCHAR(255),
    mitre_technique VARCHAR(255),
    incident_type VARCHAR(255),
    raw_json TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    incident_type VARCHAR(255) NOT NULL,
    risk_score DOUBLE PRECISION NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    source_ip VARCHAR(64),
    target_asset VARCHAR(255),
    alert_count INTEGER NOT NULL,
    max_rule_level INTEGER NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    mitre_tactic VARCHAR(255),
    mitre_technique VARCHAR(255),
    recommendation TEXT,
    explanation TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id BIGINT NOT NULL REFERENCES security_alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

INSERT INTO assets (name, ip_address, criticality, exposure, owner, environment)
VALUES
    ('ubuntu-victim', '192.168.56.20', 'High', 'Internal', 'SOC Lab', 'Validation'),
    ('web-server', '192.168.56.30', 'Critical', 'Public', 'Application Team', 'Production-like'),
    ('linux-server', '192.168.56.21', 'Medium', 'Internal', 'Infrastructure Team', 'Validation')
ON CONFLICT (name) DO NOTHING;
