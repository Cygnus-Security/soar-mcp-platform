package com.socdss.risk;

import com.socdss.alert.SecurityAlert;
import com.socdss.asset.Asset;
import com.socdss.asset.AssetRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Comparator;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class RiskAssessmentService {
    private final AssetRepository assetRepository;
    private final RiskModelConfigRepository configRepository;

    private static final Map<String, Integer> CRITICALITY_SCORE = Map.of(
            "Low", 25,
            "Medium", 50,
            "High", 75,
            "Critical", 100
    );

    private static final Map<String, Integer> EXPOSURE_SCORE = Map.of(
            "Internal", 50,
            "Public", 100
    );

    private static final Map<String, Integer> TACTIC_WEIGHT = Map.ofEntries(
            Map.entry("Reconnaissance", 45),
            Map.entry("Initial Access", 75),
            Map.entry("Execution", 80),
            Map.entry("Persistence", 80),
            Map.entry("Privilege Escalation", 85),
            Map.entry("Defense Evasion", 85),
            Map.entry("Credential Access", 90),
            Map.entry("Discovery", 50),
            Map.entry("Lateral Movement", 85),
            Map.entry("Collection", 70),
            Map.entry("Command and Control", 90),
            Map.entry("Exfiltration", 95),
            Map.entry("Impact", 95)
    );

    public RiskAssessmentService(AssetRepository assetRepository, RiskModelConfigRepository configRepository) {
        this.assetRepository = assetRepository;
        this.configRepository = configRepository;
    }

    public RiskAssessmentResult assess(List<SecurityAlert> alerts) {
        if (alerts == null || alerts.isEmpty()) {
            return new RiskAssessmentResult(0, "Low", "No alerts available for risk assessment.");
        }

        SecurityAlert representative = alerts.get(0);
        AssetContext asset = resolveAsset(representative);

        int maxRuleLevel = alerts.stream().map(SecurityAlert::getWazuhRuleLevel).max(Comparator.naturalOrder()).orElse(0);
        double severityScore = Math.min((maxRuleLevel / 16.0) * 100.0, 100.0);
        double assetScore = CRITICALITY_SCORE.getOrDefault(asset.criticality(), 50);
        double frequencyScore = Math.min(alerts.size() * 10.0, 100.0);
        double mitreScore = TACTIC_WEIGHT.getOrDefault(blankToDefault(representative.getMitreTactic(), ""), 35);
        double exposureScore = EXPOSURE_SCORE.getOrDefault(asset.exposure(), 50);
        double vulnerabilityScore = containsVulnerabilityContext(alerts) ? 80.0 : 0.0;

        RiskModelDto model = currentModel();
        List<RiskFactor> factors = factors(
                severityScore,
                model.severityWeight(),
                "Wazuh/AMiner severity",
                "Maximum normalized rule level is " + maxRuleLevel,
                assetScore,
                model.assetWeight(),
                "Asset criticality",
                "Target asset criticality is " + asset.criticality(),
                frequencyScore,
                model.frequencyWeight(),
                "Alert frequency",
                alerts.size() + " related alerts are grouped into this incident",
                mitreScore,
                model.mitreWeight(),
                "MITRE tactic",
                "Representative tactic is " + blankToDefault(representative.getMitreTactic(), "N/A"),
                exposureScore,
                model.exposureWeight(),
                "Asset exposure",
                "Asset exposure is " + asset.exposure(),
                vulnerabilityScore,
                model.vulnerabilityWeight(),
                "Vulnerability context",
                vulnerabilityScore > 0 ? "CVE/vulnerability terms detected" : "No vulnerability terms detected"
        );

        double score = factors.stream().mapToDouble(RiskFactor::contribution).sum();

        double rounded = Math.round(score * 100.0) / 100.0;
        String level = riskLevel(rounded);

        String explanation = String.format(
                "Risk score %.2f was calculated using severity %.1f, asset criticality %s, frequency %.1f, MITRE tactic %s, exposure %s and vulnerability context %s.",
                rounded,
                severityScore,
                asset.criticality(),
                frequencyScore,
                blankToDefault(representative.getMitreTactic(), "N/A"),
                asset.exposure(),
                vulnerabilityScore > 0 ? "present" : "not detected"
        );

        return new RiskAssessmentResult(rounded, level, explanation, factors);
    }

    public RiskAssessmentResult assessWhatIf(WhatIfRequest request) {
        int maxRuleLevel = request.maxRuleLevel() == null ? 6 : clamp(request.maxRuleLevel(), 0, 16);
        int alertCount = request.alertCount() == null ? 1 : clamp(request.alertCount(), 1, 1000);
        String criticality = blankToDefault(request.assetCriticality(), "Medium");
        String exposure = blankToDefault(request.exposure(), "Internal");
        String tactic = blankToDefault(request.mitreTactic(), "");
        boolean vulnerability = Boolean.TRUE.equals(request.vulnerabilityContext());

        double severityScore = Math.min((maxRuleLevel / 16.0) * 100.0, 100.0);
        double assetScore = CRITICALITY_SCORE.getOrDefault(criticality, 50);
        double frequencyScore = Math.min(alertCount * 10.0, 100.0);
        double mitreScore = TACTIC_WEIGHT.getOrDefault(tactic, 35);
        double exposureScore = EXPOSURE_SCORE.getOrDefault(exposure, 50);
        double vulnerabilityScore = vulnerability ? 80.0 : 0.0;
        RiskModelDto model = currentModel();

        List<RiskFactor> factors = factors(
                severityScore, model.severityWeight(), "Severity", "Simulated max rule level is " + maxRuleLevel,
                assetScore, model.assetWeight(), "Asset criticality", "Simulated criticality is " + criticality,
                frequencyScore, model.frequencyWeight(), "Alert frequency", "Simulated related alert count is " + alertCount,
                mitreScore, model.mitreWeight(), "MITRE tactic", "Simulated tactic is " + blankToDefault(tactic, "N/A"),
                exposureScore, model.exposureWeight(), "Exposure", "Simulated exposure is " + exposure,
                vulnerabilityScore, model.vulnerabilityWeight(), "Vulnerability context", vulnerability ? "Present" : "Not detected"
        );
        double score = Math.round(factors.stream().mapToDouble(RiskFactor::contribution).sum() * 100.0) / 100.0;
        return new RiskAssessmentResult(score, riskLevel(score), "What-if score based on simulated decision criteria.", factors);
    }

    public RiskModelDto currentModel() {
        return RiskModelDto.from(configRepository.findAll().stream().findFirst().orElseGet(this::defaultConfig));
    }

    public RiskModelDto updateModel(RiskModelDto dto) {
        RiskModelConfig config = configRepository.findAll().stream().findFirst().orElseGet(this::defaultConfig);
        config.setSeverityWeight(safeWeight(dto.severityWeight()));
        config.setAssetWeight(safeWeight(dto.assetWeight()));
        config.setFrequencyWeight(safeWeight(dto.frequencyWeight()));
        config.setMitreWeight(safeWeight(dto.mitreWeight()));
        config.setExposureWeight(safeWeight(dto.exposureWeight()));
        config.setVulnerabilityWeight(safeWeight(dto.vulnerabilityWeight()));
        config.setUpdatedAt(Instant.now());
        return RiskModelDto.from(configRepository.save(config));
    }

    private RiskModelConfig defaultConfig() {
        return configRepository.save(new RiskModelConfig());
    }

    private double safeWeight(double value) {
        if (!Double.isFinite(value)) {
            return 0.0;
        }
        return Math.min(Math.max(value, 0.0), 10.0);
    }

    private int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private List<RiskFactor> factors(Object... values) {
        double totalWeight = 0.0;
        for (int i = 1; i < values.length; i += 4) {
            totalWeight += (double) values[i];
        }
        if (totalWeight <= 0) {
            totalWeight = 1.0;
        }
        List<RiskFactor> factors = new ArrayList<>();
        for (int i = 0; i < values.length; i += 4) {
            double rawScore = (double) values[i];
            double normalizedWeight = (double) values[i + 1] / totalWeight;
            String name = (String) values[i + 2];
            String reason = (String) values[i + 3];
            double contribution = Math.round(rawScore * normalizedWeight * 100.0) / 100.0;
            factors.add(new RiskFactor(name, rawScore, Math.round(normalizedWeight * 100.0) / 100.0, contribution, reason));
        }
        return factors;
    }

    private AssetContext resolveAsset(SecurityAlert alert) {
        if (alert.getAgentName() != null) {
            return assetRepository.findByName(alert.getAgentName())
                    .map(a -> new AssetContext(a.getCriticality(), a.getExposure()))
                    .orElseGet(() -> findByIp(alert));
        }
        return findByIp(alert);
    }

    private AssetContext findByIp(SecurityAlert alert) {
        if (alert.getAgentIp() != null) {
            return assetRepository.findByIpAddress(alert.getAgentIp())
                    .map(a -> new AssetContext(a.getCriticality(), a.getExposure()))
                    .orElse(new AssetContext("Medium", "Internal"));
        }
        return new AssetContext("Medium", "Internal");
    }

    private boolean containsVulnerabilityContext(List<SecurityAlert> alerts) {
        return alerts.stream().anyMatch(a -> {
            String text = ((a.getDescription() == null ? "" : a.getDescription()) + " " +
                    (a.getIncidentType() == null ? "" : a.getIncidentType())).toLowerCase();
            return text.contains("cve") || text.contains("vulnerab");
        });
    }

    private String riskLevel(double score) {
        if (score >= 80) return "Critical";
        if (score >= 60) return "High";
        if (score >= 40) return "Medium";
        return "Low";
    }

    private String blankToDefault(String value, String defaultValue) {
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private record AssetContext(String criticality, String exposure) {}
}
