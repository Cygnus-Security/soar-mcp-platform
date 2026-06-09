package com.socdss.incident;

import jakarta.validation.constraints.Size;

public record IncidentFeedbackRequest(
        @Size(max = 40)
        String analystVerdict,
        @Size(max = 4000)
        String analystNotes,
        @Size(max = 40)
        String decisionStatus
) {}
