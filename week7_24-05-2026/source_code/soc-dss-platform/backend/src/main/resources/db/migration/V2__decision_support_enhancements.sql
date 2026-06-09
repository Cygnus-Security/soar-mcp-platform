ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS analyst_verdict VARCHAR(32),
    ADD COLUMN IF NOT EXISTS analyst_notes TEXT,
    ADD COLUMN IF NOT EXISTS decision_status VARCHAR(32);

CREATE TABLE IF NOT EXISTS risk_model_config (
    id BIGSERIAL PRIMARY KEY,
    severity_weight DOUBLE PRECISION NOT NULL,
    asset_weight DOUBLE PRECISION NOT NULL,
    frequency_weight DOUBLE PRECISION NOT NULL,
    mitre_weight DOUBLE PRECISION NOT NULL,
    exposure_weight DOUBLE PRECISION NOT NULL,
    vulnerability_weight DOUBLE PRECISION NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO risk_model_config (
    severity_weight,
    asset_weight,
    frequency_weight,
    mitre_weight,
    exposure_weight,
    vulnerability_weight
)
SELECT 0.30, 0.20, 0.15, 0.15, 0.10, 0.10
WHERE NOT EXISTS (SELECT 1 FROM risk_model_config);
