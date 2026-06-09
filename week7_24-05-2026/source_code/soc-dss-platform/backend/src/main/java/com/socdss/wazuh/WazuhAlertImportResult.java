package com.socdss.wazuh;

public record WazuhAlertImportResult(
        int totalLines,
        int importedAlerts,
        int skippedLines
) {}
