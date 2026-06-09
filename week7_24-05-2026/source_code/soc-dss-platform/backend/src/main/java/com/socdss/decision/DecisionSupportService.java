package com.socdss.decision;

import com.socdss.incident.Incident;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DecisionSupportService {
    public DecisionAdvice advise(Incident incident) {
        double score = incident.getRiskScore() == null ? 0 : incident.getRiskScore();
        int alertCount = incident.getAlertCount() == null ? 0 : incident.getAlertCount();
        int maxRuleLevel = incident.getMaxRuleLevel() == null ? 0 : incident.getMaxRuleLevel();
        String type = incident.getIncidentType() == null ? "" : incident.getIncidentType();
        String level = incident.getRiskLevel() == null ? "Low" : incident.getRiskLevel();

        String priority = priority(level, score);
        int slaHours = slaHours(priority);
        double confidence = confidence(score, alertCount, maxRuleLevel);
        String escalation = escalation(priority, type);
        List<String> actions = nextActions(priority, type, incident.getTargetAsset());
        String rationale = "Decision priority " + priority + " is based on risk level " + level +
                ", score " + score + ", " + alertCount + " correlated alerts and max rule level " + maxRuleLevel + ".";

        return new DecisionAdvice(priority, slaHours, confidence, escalation, rationale, actions);
    }

    private String priority(String level, double score) {
        if ("Critical".equalsIgnoreCase(level) || score >= 85) return "P1";
        if ("High".equalsIgnoreCase(level) || score >= 65) return "P2";
        if ("Medium".equalsIgnoreCase(level) || score >= 40) return "P3";
        return "P4";
    }

    private int slaHours(String priority) {
        return switch (priority) {
            case "P1" -> 1;
            case "P2" -> 4;
            case "P3" -> 24;
            default -> 72;
        };
    }

    private double confidence(double score, int alertCount, int maxRuleLevel) {
        double value = 0.35 + Math.min(alertCount, 20) * 0.02 + Math.min(maxRuleLevel, 16) * 0.02 + score * 0.002;
        return Math.round(Math.min(value, 0.99) * 100.0) / 100.0;
    }

    private String escalation(String priority, String type) {
        if ("P1".equals(priority)) return "Escalate immediately to L2 incident response and notify asset owner.";
        if ("P2".equals(priority)) return "Escalate to L2 if validation confirms malicious activity.";
        if (type.contains("Anomaly")) return "Queue for analyst validation and feedback labeling.";
        return "Handle in L1 triage queue.";
    }

    private List<String> nextActions(String priority, String type, String asset) {
        String target = asset == null || asset.isBlank() ? "affected asset" : asset;
        List<String> actions = new ArrayList<>();
        actions.add("Validate whether the alert pattern is true positive or benign.");
        if ("P1".equals(priority) || "P2".equals(priority)) {
            actions.add("Preserve raw logs and evidence for " + target + ".");
            actions.add("Apply containment if exploitation or compromise is confirmed.");
        }
        if (type.contains("Vulnerability")) actions.add("Open remediation ticket and track patch owner/SLA.");
        if (type.contains("Authentication")) actions.add("Review successful login and privilege escalation events.");
        if (type.contains("DNS")) actions.add("Check queried domains against threat intelligence and proxy logs.");
        actions.add("Record analyst verdict to improve future decision quality.");
        return actions;
    }
}
