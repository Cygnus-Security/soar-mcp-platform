package com.socdss.alert;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "security_alerts")
public class SecurityAlert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Instant eventTimestamp;

    @Column(nullable = false)
    private String source = "Wazuh";

    private String externalId;
    private String wazuhRuleId;

    @Column(nullable = false)
    private Integer wazuhRuleLevel = 0;

    private String agentName;
    private String agentIp;
    private String sourceIp;
    private String destinationIp;

    @Column(columnDefinition = "TEXT")
    private String description;

    private String mitreTactic;
    private String mitreTechnique;
    private String incidentType;

    @Column(columnDefinition = "TEXT")
    private String rawJson;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Instant getEventTimestamp() { return eventTimestamp; }
    public void setEventTimestamp(Instant eventTimestamp) { this.eventTimestamp = eventTimestamp; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public String getExternalId() { return externalId; }
    public void setExternalId(String externalId) { this.externalId = externalId; }
    public String getWazuhRuleId() { return wazuhRuleId; }
    public void setWazuhRuleId(String wazuhRuleId) { this.wazuhRuleId = wazuhRuleId; }
    public Integer getWazuhRuleLevel() { return wazuhRuleLevel; }
    public void setWazuhRuleLevel(Integer wazuhRuleLevel) { this.wazuhRuleLevel = wazuhRuleLevel; }
    public String getAgentName() { return agentName; }
    public void setAgentName(String agentName) { this.agentName = agentName; }
    public String getAgentIp() { return agentIp; }
    public void setAgentIp(String agentIp) { this.agentIp = agentIp; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getDestinationIp() { return destinationIp; }
    public void setDestinationIp(String destinationIp) { this.destinationIp = destinationIp; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getMitreTactic() { return mitreTactic; }
    public void setMitreTactic(String mitreTactic) { this.mitreTactic = mitreTactic; }
    public String getMitreTechnique() { return mitreTechnique; }
    public void setMitreTechnique(String mitreTechnique) { this.mitreTechnique = mitreTechnique; }
    public String getIncidentType() { return incidentType; }
    public void setIncidentType(String incidentType) { this.incidentType = incidentType; }
    public String getRawJson() { return rawJson; }
    public void setRawJson(String rawJson) { this.rawJson = rawJson; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
