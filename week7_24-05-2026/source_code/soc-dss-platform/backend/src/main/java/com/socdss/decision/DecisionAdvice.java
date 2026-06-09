package com.socdss.decision;

import java.util.List;

public record DecisionAdvice(
        String priority,
        int slaHours,
        double confidence,
        String escalation,
        String rationale,
        List<String> nextActions
) {}
