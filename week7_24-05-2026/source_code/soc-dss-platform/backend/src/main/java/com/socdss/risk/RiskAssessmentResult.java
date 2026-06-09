package com.socdss.risk;

import java.util.List;

public record RiskAssessmentResult(
        double score,
        String level,
        String explanation,
        List<RiskFactor> factors
) {
    public RiskAssessmentResult(double score, String level, String explanation) {
        this(score, level, explanation, List.of());
    }
}
