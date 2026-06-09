package com.socdss.risk;

public record RiskModelDto(
        double severityWeight,
        double assetWeight,
        double frequencyWeight,
        double mitreWeight,
        double exposureWeight,
        double vulnerabilityWeight
) {
    public static RiskModelDto from(RiskModelConfig config) {
        return new RiskModelDto(
                config.getSeverityWeight(),
                config.getAssetWeight(),
                config.getFrequencyWeight(),
                config.getMitreWeight(),
                config.getExposureWeight(),
                config.getVulnerabilityWeight()
        );
    }
}
