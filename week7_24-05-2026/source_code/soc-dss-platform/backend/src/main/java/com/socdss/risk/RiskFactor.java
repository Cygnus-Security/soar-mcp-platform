package com.socdss.risk;

public record RiskFactor(
        String name,
        double rawScore,
        double weight,
        double contribution,
        String reason
) {}
