package com.socdss.risk;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

public record WhatIfRequest(
        @Size(max = 40)
        String assetCriticality,
        @Size(max = 40)
        String exposure,
        @Min(1) @Max(1000)
        Integer alertCount,
        @Min(0) @Max(16)
        Integer maxRuleLevel,
        @Size(max = 80)
        String mitreTactic,
        Boolean vulnerabilityContext
) {}
