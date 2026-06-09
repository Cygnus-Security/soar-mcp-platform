package com.socdss.dashboard;

import java.util.Map;

public record DashboardSummary(
        long totalAlerts,
        long totalIncidents,
        long criticalIncidents,
        long highIncidents,
        double alertReductionRate,
        Map<String, Long> incidentsByRiskLevel
) {}
