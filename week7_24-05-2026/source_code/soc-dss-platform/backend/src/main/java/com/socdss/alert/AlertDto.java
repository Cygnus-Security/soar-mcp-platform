package com.socdss.alert;

import java.time.Instant;

public record AlertDto(
        Long id,
        Instant eventTimestamp,
        String source,
        String wazuhRuleId,
        Integer wazuhRuleLevel,
        String agentName,
        String agentIp,
        String sourceIp,
        String description,
        String mitreTactic,
        String mitreTechnique,
        String incidentType
) {
    public static AlertDto from(SecurityAlert alert) {
        return new AlertDto(
                alert.getId(),
                alert.getEventTimestamp(),
                alert.getSource(),
                alert.getWazuhRuleId(),
                alert.getWazuhRuleLevel(),
                alert.getAgentName(),
                alert.getAgentIp(),
                alert.getSourceIp(),
                alert.getDescription(),
                alert.getMitreTactic(),
                alert.getMitreTechnique(),
                alert.getIncidentType()
        );
    }
}
