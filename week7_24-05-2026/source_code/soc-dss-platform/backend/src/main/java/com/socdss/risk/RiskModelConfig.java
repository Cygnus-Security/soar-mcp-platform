package com.socdss.risk;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "risk_model_config")
public class RiskModelConfig {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Double severityWeight = 0.30;
    private Double assetWeight = 0.20;
    private Double frequencyWeight = 0.15;
    private Double mitreWeight = 0.15;
    private Double exposureWeight = 0.10;
    private Double vulnerabilityWeight = 0.10;

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Double getSeverityWeight() { return severityWeight; }
    public void setSeverityWeight(Double severityWeight) { this.severityWeight = severityWeight; }
    public Double getAssetWeight() { return assetWeight; }
    public void setAssetWeight(Double assetWeight) { this.assetWeight = assetWeight; }
    public Double getFrequencyWeight() { return frequencyWeight; }
    public void setFrequencyWeight(Double frequencyWeight) { this.frequencyWeight = frequencyWeight; }
    public Double getMitreWeight() { return mitreWeight; }
    public void setMitreWeight(Double mitreWeight) { this.mitreWeight = mitreWeight; }
    public Double getExposureWeight() { return exposureWeight; }
    public void setExposureWeight(Double exposureWeight) { this.exposureWeight = exposureWeight; }
    public Double getVulnerabilityWeight() { return vulnerabilityWeight; }
    public void setVulnerabilityWeight(Double vulnerabilityWeight) { this.vulnerabilityWeight = vulnerabilityWeight; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
