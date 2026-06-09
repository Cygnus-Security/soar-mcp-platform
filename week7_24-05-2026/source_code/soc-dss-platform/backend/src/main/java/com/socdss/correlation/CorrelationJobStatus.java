package com.socdss.correlation;

import java.time.Instant;

public record CorrelationJobStatus(
        String status,
        Instant startedAt,
        Instant finishedAt,
        Integer incidentCount,
        String message
) {}
