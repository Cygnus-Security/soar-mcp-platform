package com.socdss.dashboard;

import com.socdss.alert.SecurityAlertRepository;
import com.socdss.incident.Incident;
import com.socdss.incident.IncidentRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/dashboard")
public class DashboardController {
    private final SecurityAlertRepository alertRepository;
    private final IncidentRepository incidentRepository;

    public DashboardController(SecurityAlertRepository alertRepository, IncidentRepository incidentRepository) {
        this.alertRepository = alertRepository;
        this.incidentRepository = incidentRepository;
    }

    @GetMapping("/summary")
    public DashboardSummary summary() {
        long alerts = alertRepository.count();
        long incidents = incidentRepository.count();
        double reduction = alerts > 0 ? ((alerts - incidents) * 100.0 / alerts) : 0.0;

        Map<String, Long> byLevel = incidentRepository.findAll().stream()
                .collect(Collectors.groupingBy(Incident::getRiskLevel, Collectors.counting()));

        return new DashboardSummary(
                alerts,
                incidents,
                incidentRepository.countByRiskLevel("Critical"),
                incidentRepository.countByRiskLevel("High"),
                Math.round(reduction * 100.0) / 100.0,
                byLevel
        );
    }
}
