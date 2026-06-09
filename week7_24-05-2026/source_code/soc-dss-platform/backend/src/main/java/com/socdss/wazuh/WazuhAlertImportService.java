package com.socdss.wazuh;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.socdss.alert.SecurityAlert;
import com.socdss.alert.SecurityAlertRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class WazuhAlertImportService {
    private static final Pattern IPV4_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    private final SecurityAlertRepository alertRepository;
    private final ObjectMapper objectMapper;

    public WazuhAlertImportService(SecurityAlertRepository alertRepository, ObjectMapper objectMapper) {
        this.alertRepository = alertRepository;
        this.objectMapper = objectMapper;
    }

    public WazuhAlertImportResult importJsonLines(MultipartFile file) {
        int total = 0;
        int skipped = 0;
        List<SecurityAlert> alerts = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                total++;
                line = line.trim();
                if (line.isEmpty()) {
                    skipped++;
                    continue;
                }
                try {
                    JsonNode root = alertRoot(objectMapper.readTree(line));
                    SecurityAlert alert = root.has("AnalysisComponent") && root.has("LogData")
                            ? toAminerAlert(root, line)
                            : toSecurityAlert(root, line);
                    if (alert.getWazuhRuleLevel() >= 3) {
                        alerts.add(alert);
                    } else {
                        skipped++;
                    }
                } catch (Exception e) {
                    skipped++;
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to import Wazuh alerts: " + e.getMessage(), e);
        }

        alertRepository.saveAll(alerts);
        return new WazuhAlertImportResult(total, alerts.size(), skipped);
    }

    private JsonNode alertRoot(JsonNode root) {
        if (root.has("_source")) {
            return root.path("_source");
        }
        return root;
    }

    private SecurityAlert toSecurityAlert(JsonNode root, String raw) {
        JsonNode rule = root.path("rule");
        JsonNode agent = root.path("agent");
        JsonNode data = root.path("data");
        JsonNode dataAlert = data.path("alert");
        JsonNode mitre = rule.path("mitre");

        String ruleId = firstNonBlank(text(rule, "id", null), text(dataAlert, "signature_id", null), "unknown");
        String description = firstNonBlank(text(rule, "description", null), text(dataAlert, "signature", null), text(root, "full_log", null), "");
        String groups = firstNonBlank(rule.path("groups").toString(), text(dataAlert, "category", null), "");

        SecurityAlert alert = new SecurityAlert();
        alert.setSource("Wazuh");
        alert.setExternalId(text(root, "id", null));
        alert.setEventTimestamp(parseTimestamp(firstNonBlank(text(root, "timestamp", null), text(root, "@timestamp", null), text(data, "timestamp", null))));
        alert.setWazuhRuleId(ruleId);
        alert.setWazuhRuleLevel(resolveRuleLevel(rule, dataAlert));
        alert.setAgentName(text(agent, "name", "unknown"));
        alert.setAgentIp(text(agent, "ip", null));
        alert.setSourceIp(firstNonBlank(
                text(data, "srcip", null),
                text(data, "src_ip", null),
                text(data, "src", null),
                text(root, "srcip", null),
                "unknown"
        ));
        alert.setDestinationIp(firstNonBlank(text(data, "dstip", null), text(data, "dst_ip", null), text(data, "dest_ip", null), null));
        alert.setDescription(description);
        alert.setMitreTactic(firstArrayText(mitre.path("tactic")));
        alert.setMitreTechnique(firstArrayText(mitre.path("technique")));
        alert.setIncidentType(AlertClassifier.classify(ruleId, description, groups));
        alert.setRawJson(raw);
        return alert;
    }

    private SecurityAlert toAminerAlert(JsonNode root, String raw) {
        JsonNode component = root.path("AnalysisComponent");
        JsonNode logData = root.path("LogData");
        JsonNode aminer = root.path("AMiner");

        String componentId = text(component, "AnalysisComponentIdentifier", "unknown");
        String componentName = text(component, "AnalysisComponentName", "AMiner anomaly");
        String componentType = text(component, "AnalysisComponentType", "");
        String message = text(component, "Message", "");
        String rawLog = firstArrayText(logData.path("RawLogData"));
        String resource = firstArrayText(logData.path("LogResources"));
        String sourceIp = firstNonBlank(extractIp(rawLog), text(aminer, "ID", null), "unknown");
        String description = firstNonBlank(componentName + " " + message, rawLog, "AMiner anomaly");

        SecurityAlert alert = new SecurityAlert();
        alert.setSource("AMiner");
        alert.setExternalId(componentId + ":" + firstNonBlank(text(logData, "DetectionTimestamp", null), text(logData, "Timestamps", null), ""));
        alert.setEventTimestamp(parseAminerTimestamp(logData));
        alert.setWazuhRuleId("aminer-" + componentId);
        alert.setWazuhRuleLevel(resolveAminerLevel(component, root.path("CountData")));
        alert.setAgentName(firstNonBlank(resource, "AMiner sensor"));
        alert.setAgentIp(text(aminer, "ID", null));
        alert.setSourceIp(sourceIp);
        alert.setDescription(description);
        alert.setIncidentType(AlertClassifier.classify("aminer-" + componentId, description + " " + rawLog, componentType));
        alert.setRawJson(raw);
        return alert;
    }

    private int resolveAminerLevel(JsonNode component, JsonNode countData) {
        boolean trainingMode = component.path("TrainingMode").asBoolean(false);
        double confidence = countData.path("Confidence").asDouble(0.0);
        String type = text(component, "AnalysisComponentType", "").toLowerCase();

        if (!trainingMode && confidence >= 0.95) return 8;
        if (!trainingMode && confidence >= 0.75) return 6;
        if (type.contains("eventcount") || type.contains("frequency")) return 6;
        return 3;
    }

    private Instant parseAminerTimestamp(JsonNode logData) {
        JsonNode detection = logData.path("DetectionTimestamp");
        JsonNode timestamps = logData.path("Timestamps");
        JsonNode value = detection.isArray() && detection.size() > 0 ? detection.get(0)
                : timestamps.isArray() && timestamps.size() > 0 ? timestamps.get(0)
                : null;

        if (value == null || value.isMissingNode() || value.isNull()) {
            return Instant.now();
        }
        return Instant.ofEpochMilli(Math.round(value.asDouble() * 1000));
    }

    private String extractIp(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        Matcher matcher = IPV4_PATTERN.matcher(text);
        String last = null;
        while (matcher.find()) {
            last = matcher.group();
        }
        return last;
    }

    private int resolveRuleLevel(JsonNode rule, JsonNode dataAlert) {
        int ruleLevel = rule.path("level").asInt(0);
        if (ruleLevel > 0) {
            return ruleLevel;
        }

        int severity = dataAlert.path("severity").asInt(0);
        if (severity > 0) {
            return Math.max(3, 12 - severity);
        }

        return 0;
    }

    private String text(JsonNode node, String field, String defaultValue) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) {
            return defaultValue;
        }
        String text = value.asText();
        return text == null || text.isBlank() ? defaultValue : text;
    }

    private String firstArrayText(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return "";
        }
        if (node.isArray() && node.size() > 0) {
            return node.get(0).asText("");
        }
        return node.asText("");
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private Instant parseTimestamp(String timestamp) {
        if (timestamp == null || timestamp.isBlank()) {
            return Instant.now();
        }
        try {
            String normalized = timestamp.replace("Z", "+00:00");
            if (normalized.matches(".*[+-]\\d{4}$")) {
                normalized = normalized.substring(0, normalized.length() - 5)
                        + normalized.substring(normalized.length() - 5, normalized.length() - 2)
                        + ":"
                        + normalized.substring(normalized.length() - 2);
            }
            return OffsetDateTime.parse(normalized).toInstant();
        } catch (Exception ignored) {
            try {
                return LocalDateTime.parse(timestamp).toInstant(ZoneOffset.UTC);
            } catch (Exception ignoredAgain) {
                return Instant.now();
            }
        }
    }
}
