package com.socdss.wazuh;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/import")
public class WazuhImportController {
    private final WazuhAlertImportService importService;

    public WazuhImportController(WazuhAlertImportService importService) {
        this.importService = importService;
    }

    @PostMapping("/wazuh-alerts")
    public WazuhAlertImportResult importAlerts(@RequestPart("file") MultipartFile file) {
        return importService.importJsonLines(file);
    }
}
