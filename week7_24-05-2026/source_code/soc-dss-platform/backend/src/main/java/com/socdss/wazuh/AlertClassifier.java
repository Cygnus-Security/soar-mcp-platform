package com.socdss.wazuh;

public class AlertClassifier {
    private AlertClassifier() {}

    public static String classify(String ruleId, String description, String groups) {
        String text = ((ruleId == null ? "" : ruleId) + " " +
                (description == null ? "" : description) + " " +
                (groups == null ? "" : groups)).toLowerCase();

        // SOAR alerts — check rule ID trước để ưu tiên cao nhất
        if (text.contains("soar-xss"))   return "XSS Attack";
        if (text.contains("soar-sqli"))  return "SQL Injection Attack";
        if (text.contains("soar-lfi"))   return "Local File Inclusion Attack";
        if (text.contains("soar-cmdi"))  return "Command Injection Attack";
        if (text.contains("soar-brute")) return "Brute Force Attack";
        if (text.contains("soar-recon")) return "Reconnaissance / Network Scan";
        if (text.contains("soar-"))      return "Web Attack";

        // Wazuh alerts gốc — bỏ "authentication" khỏi SSH check
        if (containsAny(text, "sshd", "invalid user", "login failed", "brute", "5710", "5712")) {
            return "SSH Brute Force / Authentication Attack";
        }
        if (containsAny(text, "syscheck", "fim", "integrity", "file added", "file modified", "webshell")) {
            return "File Integrity Incident";
        }
        if (containsAny(text, "cve", "vulnerability", "vulnerab")) {
            return "Vulnerability Incident";
        }
        if (containsAny(text, "sql injection", "xss", "web attack", "apache", "nginx", "http", "directory traversal")) {
            return "Web Attack";
        }
        if (containsAny(text, "authentication", "login failed", "brute force")) {
            return "SSH Brute Force / Authentication Attack";
        }
        if (containsAny(text, "nmap", "scan", "recon", "suricata")) {
            return "Reconnaissance / Network Scan";
        }
        if (containsAny(text, "aminer", "frequency anomaly", "eventcount", "new event type", "new value")) {
            if (containsAny(text, "dns", "query")) {
                return "DNS Anomaly";
            }
            if (containsAny(text, "audit", "login", "user_auth", "user_login", "pam")) {
                return "Authentication Anomaly";
            }
            return "Log Anomaly";
        }
        return "General Security Alert";
    }

    private static boolean containsAny(String text, String... patterns) {
        for (String pattern : patterns) {
            if (text.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
}
