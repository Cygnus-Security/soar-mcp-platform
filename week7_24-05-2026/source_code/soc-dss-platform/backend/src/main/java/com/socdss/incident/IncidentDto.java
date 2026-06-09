package com.socdss.incident;

import com.socdss.alert.AlertDto;
import com.socdss.decision.DecisionAdvice;
import com.socdss.risk.RiskFactor;
import java.time.Instant;
import java.util.List;

public record IncidentDto(
        Long id,
        String title,
        String incidentType,
        Double riskScore,
        String riskLevel,
        String status,
        String sourceIp,
        String targetAsset,
        Integer alertCount,
        Integer maxRuleLevel,
        Instant firstSeen,
        Instant lastSeen,
        String mitreTactic,
        String mitreTechnique,
        String recommendation,
        String explanation,
        String analystVerdict,
        String analystNotes,
        String decisionStatus,
        DecisionAdvice decisionAdvice,
        List<RiskFactor> riskFactors,
        List<AlertDto> relatedAlerts
) {
    public static IncidentDto from(Incident incident, boolean includeAlerts, List<RiskFactor> riskFactors, DecisionAdvice decisionAdvice) {
        List<AlertDto> alerts = includeAlerts
                ? incident.getAlerts().stream().map(AlertDto::from).toList()
                : List.of();
        return new IncidentDto(
                incident.getId(),
                incident.getTitle(),
                incident.getIncidentType(),
                incident.getRiskScore(),
                incident.getRiskLevel(),
                incident.getStatus(),
                incident.getSourceIp(),
                incident.getTargetAsset(),
                incident.getAlertCount(),
                incident.getMaxRuleLevel(),
                incident.getFirstSeen(),
                incident.getLastSeen(),
                incident.getMitreTactic(),
                incident.getMitreTechnique(),
                incident.getRecommendation(),
                incident.getExplanation(),
                incident.getAnalystVerdict(),
                incident.getAnalystNotes(),
                incident.getDecisionStatus(),
                decisionAdvice,
                riskFactors,
                alerts
        );
    }

    public static IncidentDto from(Incident incident, boolean includeAlerts, List<RiskFactor> riskFactors) {
        return from(incident, includeAlerts, riskFactors, null);
    }

    public static IncidentDto from(Incident incident, boolean includeAlerts) {
        return from(incident, includeAlerts, List.of());
    }
}
