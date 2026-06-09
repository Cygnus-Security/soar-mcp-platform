package com.socdss.recommendation;

import org.springframework.stereotype.Service;

@Service
public class RecommendationService {
    public String recommend(String incidentType, String riskLevel) {
        return recommend(incidentType, riskLevel, null, null);
    }

    public String recommend(String incidentType, String riskLevel, String mitreTactic, String assetName) {
        String type = incidentType == null ? "" : incidentType;
        boolean highRisk = "High".equalsIgnoreCase(riskLevel) || "Critical".equalsIgnoreCase(riskLevel);
        String asset = assetName == null || assetName.isBlank() ? "affected asset" : assetName;
        String tactic = mitreTactic == null || mitreTactic.isBlank() ? "N/A" : mitreTactic;

        if (type.contains("SSH Brute Force")) {
            return highRisk
                    ? playbook("P1", tactic, "Block source IP and disable suspected account on " + asset, "Review successful login events, MFA status and sudo activity.", "Reset credentials and escalate to L2.")
                    : playbook("P3", tactic, "Monitor source IP.", "Review authentication logs for repeated failures.", "Tune thresholds if false positive.");
        }
        if (type.contains("File Integrity")) {
            return highRisk
                    ? playbook("P1", tactic, "Preserve changed file and isolate " + asset + " if webshell is suspected.", "Compare hash/path with approved change records.", "Restore known-good file and open incident response ticket.")
                    : playbook("P3", tactic, "Do not isolate yet.", "Verify change against maintenance window.", "Close as approved change or escalate.");
        }
        if (type.contains("Vulnerability")) {
            return highRisk
                    ? playbook("P1", tactic, "Reduce external exposure for " + asset + ".", "Confirm CVE, affected package and exploitability.", "Apply mitigation/patch and create remediation ticket.")
                    : playbook("P3", tactic, "Keep monitoring.", "Validate asset inventory and patch state.", "Schedule patching in maintenance window.");
        }
        if (type.contains("Web Attack")) {
            return highRisk
                    ? playbook("P1", tactic, "Block attacker IP/WAF signature if confirmed.", "Review request payloads and app logs for exploitation.", "Patch vulnerable endpoint and escalate to app owner.")
                    : playbook("P3", tactic, "Monitor web request pattern.", "Check false-positive indicators.", "Tune detection rules if benign.");
        }
        if (type.contains("Reconnaissance")) {
            return highRisk
                    ? playbook("P2", tactic, "Rate-limit or block persistent scanner.", "Check for exploitation attempts after scan.", "Increase monitoring on " + asset + ".")
                    : playbook("P4", tactic, "No immediate containment.", "Track scanner over the next correlation window.", "Escalate only if follow-up attack appears.");
        }
        if (type.contains("DNS Anomaly") || type.contains("Log Anomaly") || type.contains("Authentication Anomaly")) {
            return highRisk
                    ? playbook("P2", tactic, "Preserve raw logs and isolate only if malicious command/control is confirmed.", "Review AMiner anomaly context, affected values and source host.", "Escalate recurring or high-confidence anomalies.")
                    : playbook("P4", tactic, "No containment.", "Label analyst verdict after review.", "Use feedback to tune anomaly thresholds.");
        }
        return highRisk
                ? playbook("P2", tactic, "Collect related logs and preserve evidence.", "Enrich alert context and validate affected asset.", "Escalate to SOC analyst.")
                : playbook("P4", tactic, "Monitor only.", "Enrich context before escalation.", "Close or escalate based on analyst feedback.");
    }

    private String playbook(String priority, String tactic, String containment, String investigation, String remediation) {
        return "Priority: " + priority +
                "\nMITRE tactic: " + tactic +
                "\nContainment: " + containment +
                "\nInvestigation: " + investigation +
                "\nRemediation/Escalation: " + remediation;
    }
}
