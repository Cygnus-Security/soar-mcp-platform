package com.socdss.risk;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/risk-model")
public class RiskModelController {
    private final RiskAssessmentService riskAssessmentService;

    public RiskModelController(RiskAssessmentService riskAssessmentService) {
        this.riskAssessmentService = riskAssessmentService;
    }

    @GetMapping
    public RiskModelDto current() {
        return riskAssessmentService.currentModel();
    }

    @PutMapping
    public RiskModelDto update(@Valid @RequestBody RiskModelDto model) {
        return riskAssessmentService.updateModel(model);
    }

    @PostMapping("/what-if")
    public RiskAssessmentResult whatIf(@Valid @RequestBody WhatIfRequest request) {
        return riskAssessmentService.assessWhatIf(request);
    }
}
