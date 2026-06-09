package com.socdss.incident;

import com.socdss.alert.SecurityAlert;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "incidents")
public class Incident {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false)
    private String incidentType;

    @Column(nullable = false)
    private Double riskScore;

    @Column(nullable = false)
    private String riskLevel;

    @Column(nullable = false)
    private String status = "Open";

    private String sourceIp;
    private String targetAsset;
    private Integer alertCount;
    private Integer maxRuleLevel;
    private Instant firstSeen;
    private Instant lastSeen;
    private String mitreTactic;
    private String mitreTechnique;
    private String analystVerdict;
    private String decisionStatus;

    @Column(columnDefinition = "TEXT")
    private String recommendation;

    @Column(columnDefinition = "TEXT")
    private String explanation;

    @Column(columnDefinition = "TEXT")
    private String analystNotes;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "incident_alerts",
            joinColumns = @JoinColumn(name = "incident_id"),
            inverseJoinColumns = @JoinColumn(name = "alert_id")
    )
    private Set<SecurityAlert> alerts = new HashSet<>();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getIncidentType() { return incidentType; }
    public void setIncidentType(String incidentType) { this.incidentType = incidentType; }
    public Double getRiskScore() { return riskScore; }
    public void setRiskScore(Double riskScore) { this.riskScore = riskScore; }
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getTargetAsset() { return targetAsset; }
    public void setTargetAsset(String targetAsset) { this.targetAsset = targetAsset; }
    public Integer getAlertCount() { return alertCount; }
    public void setAlertCount(Integer alertCount) { this.alertCount = alertCount; }
    public Integer getMaxRuleLevel() { return maxRuleLevel; }
    public void setMaxRuleLevel(Integer maxRuleLevel) { this.maxRuleLevel = maxRuleLevel; }
    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }
    public String getMitreTactic() { return mitreTactic; }
    public void setMitreTactic(String mitreTactic) { this.mitreTactic = mitreTactic; }
    public String getMitreTechnique() { return mitreTechnique; }
    public void setMitreTechnique(String mitreTechnique) { this.mitreTechnique = mitreTechnique; }
    public String getAnalystVerdict() { return analystVerdict; }
    public void setAnalystVerdict(String analystVerdict) { this.analystVerdict = analystVerdict; }
    public String getDecisionStatus() { return decisionStatus; }
    public void setDecisionStatus(String decisionStatus) { this.decisionStatus = decisionStatus; }
    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }
    public String getAnalystNotes() { return analystNotes; }
    public void setAnalystNotes(String analystNotes) { this.analystNotes = analystNotes; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Set<SecurityAlert> getAlerts() { return alerts; }
    public void setAlerts(Set<SecurityAlert> alerts) { this.alerts = alerts; }
}
