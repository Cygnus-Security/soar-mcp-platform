package com.socdss.incident;

import com.socdss.correlation.CorrelationService;
import com.socdss.correlation.CorrelationJobStatus;
import com.socdss.decision.DecisionSupportService;
import com.socdss.risk.RiskAssessmentService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/incidents")
public class IncidentController {
    private final IncidentRepository incidentRepository;
    private final CorrelationService correlationService;
    private final RiskAssessmentService riskAssessmentService;
    private final DecisionSupportService decisionSupportService;

    public IncidentController(IncidentRepository incidentRepository, CorrelationService correlationService, RiskAssessmentService riskAssessmentService, DecisionSupportService decisionSupportService) {
        this.incidentRepository = incidentRepository;
        this.correlationService = correlationService;
        this.riskAssessmentService = riskAssessmentService;
        this.decisionSupportService = decisionSupportService;
    }

    @GetMapping
    public List<IncidentDto> list() {
        return incidentRepository.findAllByOrderByRiskScoreDesc().stream()
                .map(i -> IncidentDto.from(i, false, List.of(), decisionSupportService.advise(i)))
                .toList();
    }

    @GetMapping("/{id}")
    @Transactional(readOnly = true)
    public ResponseEntity<IncidentDto> detail(@PathVariable Long id) {
        return incidentRepository.findById(id)
                .map(i -> ResponseEntity.ok(IncidentDto.from(i, true, riskAssessmentService.assess(i.getAlerts().stream().toList()).factors(), decisionSupportService.advise(i))))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PatchMapping("/{id}/feedback")
    public ResponseEntity<IncidentDto> feedback(@PathVariable Long id, @Valid @RequestBody IncidentFeedbackRequest feedback) {
        return incidentRepository.findById(id)
                .map(incident -> {
                    incident.setAnalystVerdict(feedback.analystVerdict());
                    incident.setAnalystNotes(feedback.analystNotes());
                    incident.setDecisionStatus(feedback.decisionStatus());
                    Incident saved = incidentRepository.save(incident);
                    return ResponseEntity.ok(IncidentDto.from(saved, false, List.of(), decisionSupportService.advise(saved)));
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/correlate")
    public ResponseEntity<CorrelationJobStatus> correlate() {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(correlationService.startCorrelationJob());
    }

    @GetMapping("/correlation/status")
    public CorrelationJobStatus correlationStatus() {
        return correlationService.jobStatus();
    }
}
