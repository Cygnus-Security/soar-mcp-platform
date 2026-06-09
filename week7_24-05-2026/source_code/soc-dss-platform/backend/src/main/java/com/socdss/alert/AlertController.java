package com.socdss.alert;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/alerts")
public class AlertController {
    private final SecurityAlertRepository repository;

    public AlertController(SecurityAlertRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public List<AlertDto> list() {
        return repository.findAll().stream().map(AlertDto::from).toList();
    }
}
