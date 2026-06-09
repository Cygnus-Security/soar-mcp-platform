"""
DSS Connector — Map SOAR incident sang format DSS Platform.
Auto login, push multipart file, auto correlate.
Risk score mapping: session_risk → rule.level để DSS tính đúng severity.
"""
import requests
import json
import os
from datetime import datetime, timezone, timedelta

DSS_URL      = os.environ.get("DSS_URL",      "http://172.17.0.1:8090")
DSS_USERNAME = os.environ.get("DSS_USERNAME", "admin")
DSS_PASSWORD = os.environ.get("DSS_PASSWORD", "12345678")

VN_TZ = timezone(timedelta(hours=7))

_session: requests.Session | None = None
_csrf_token: str = ""


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


# ── MITRE mapping ──────────────────────────────────────────────────────────────
_MITRE_MAP = {
    "sqli":           {"tactic": ["Initial Access"],    "technique": ["Exploit Public-Facing Application"]},
    "xss":            {"tactic": ["Initial Access"],    "technique": ["Exploit Public-Facing Application"]},
    "lfi":            {"tactic": ["Initial Access", "Discovery"], "technique": ["Exploit Public-Facing Application", "File and Directory Discovery"]},
    "rfi":            {"tactic": ["Execution"],         "technique": ["Server Software Component"]},
    "cmdi":           {"tactic": ["Execution"],         "technique": ["Command and Scripting Interpreter"]},
    "brute_force":    {"tactic": ["Credential Access"], "technique": ["Brute Force"]},
    "ssrf":           {"tactic": ["Discovery"],         "technique": ["Internal Spearphishing"]},
    "webshell":       {"tactic": ["Persistence"],       "technique": ["Server Software Component"]},
    "reconnaissance": {"tactic": ["Reconnaissance"],    "technique": ["Active Scanning"]},
    "other":          {"tactic": ["Initial Access"],    "technique": ["Exploit Public-Facing Application"]},
}

# Minimum rule level theo severity
_SEVERITY_MIN_LEVEL = {"low": 3, "medium": 5, "high": 8, "critical": 12, "unknown": 5}


def _session_risk_to_level(session_risk: float, severity: str) -> int:
    """
    Map session_risk (0-100) → Wazuh rule level (1-15).
    DSS tính: severityScore = (level / 16.0) * 100
    → level = session_risk * 16 / 100
    Đảm bảo minimum theo severity string.
    """
    level = max(1, min(round(session_risk * 16 / 100), 15))
    min_level = _SEVERITY_MIN_LEVEL.get(severity.lower(), 5)
    return max(level, min_level)


def _normalize_attack_type(attack_type: str) -> str:
    """
    Normalize attack_type từ AI — đôi khi AI trả 'sqli | xss' hay 'sqli+xss'.
    Lấy type đầu tiên để map MITRE.
    """
    if not attack_type:
        return "other"
    # Split theo |, +, ,
    for sep in ["|", "+", ","]:
        if sep in attack_type:
            attack_type = attack_type.split(sep)[0]
    return attack_type.strip().lower().replace(" ", "_").replace("-", "_")


# ── Auth ───────────────────────────────────────────────────────────────────────

def _login() -> bool:
    global _session, _csrf_token
    _session = requests.Session()
    try:
        r = _session.post(
            f"{DSS_URL}/api/v1/auth/login",
            json={"username": DSS_USERNAME, "password": DSS_PASSWORD},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            _csrf_token = data.get("csrfToken", "")
            return True
        return False
    except Exception:
        return False


def _get_session() -> tuple[requests.Session, str]:
    global _session, _csrf_token
    if _session is None:
        _login()
    return _session, _csrf_token


# ── Alert builder ──────────────────────────────────────────────────────────────

def soar_to_dss_alert(
    source_ip: str,
    ai_result: dict,
    pipeline_summary: dict,
    agent_name: str = "dvwa-target",
    agent_ip: str   = "172.20.0.2"
) -> dict:
    severity     = ai_result.get("severity",     "medium").lower()
    attack_type  = _normalize_attack_type(ai_result.get("attack_type", "other"))
    risk_summary = ai_result.get("risk_summary", "Security Incident")
    verdict      = ai_result.get("verdict",      "unknown")
    attack_chain = ai_result.get("attack_chain", [])
    confidence   = float(ai_result.get("confidence",   0.0))
    session_risk = float(ai_result.get("session_risk", 0))

    mitre      = _MITRE_MAP.get(attack_type, _MITRE_MAP["other"])
    rule_level = _session_risk_to_level(session_risk, severity)

    # Normalize chain — xóa "authentication" khỏi chain để không confuse AlertClassifier
    def _norm_step(s):
        return s.replace("authentication_bypass_attempt", "auth_bypass")                 .replace("authentication_bypass", "auth_bypass")                 .replace("authentication_attempt", "login_attempt")
    chain_norm  = [_norm_step(s) for s in attack_chain]
    chain_str   = " → ".join(chain_norm) if chain_norm else risk_summary
    # Prefix description bằng attack_type keyword để AlertClassifier bắt đúng
    _type_prefix = {
        "sqli":           "SQL Injection",
        "xss":            "XSS",
        "lfi":            "Directory Traversal LFI",
        "rfi":            "HTTP RFI",
        "cmdi":           "Web Attack Command Injection",
        "brute_force":    "Brute Force Authentication",
        "ssrf":           "HTTP SSRF",
        "webshell":       "Webshell File Added",
        "reconnaissance": "Nmap Scan Reconnaissance",
        "other":          "Web Attack",
    }
    prefix      = _type_prefix.get(attack_type, "Web Attack")
    description = f"[SOAR] {prefix} — {risk_summary}: {chain_str}"

    # Groups + description keywords để DSS AlertClassifier phân loại đúng
    _type_groups = {
        "sqli":           ["web", "apache", "attack", "sql injection"],
        "xss":            ["web", "apache", "attack", "xss"],
        "lfi":            ["web", "apache", "attack", "directory traversal"],
        "rfi":            ["web", "apache", "attack", "http"],
        "cmdi":           ["web", "apache", "attack"],
        "brute_force":    ["syslog", "authentication", "brute", "login failed"],
        "ssrf":           ["web", "apache", "attack", "http"],
        "webshell":       ["syscheck", "fim", "webshell", "file added"],
        "reconnaissance": ["suricata", "scan", "recon", "nmap"],
        "other":          ["web", "apache", "attack"],
    }
    groups = ["soar", "behavioral-analysis"] + _type_groups.get(attack_type, ["web", "attack"])

    return {
        "timestamp": now_utc(),
        "rule": {
            "id":          f"SOAR-{attack_type.upper()}-{int(session_risk)}",
            "level":       rule_level,
            "description": description,
            "groups":      groups,
            "mitre":       mitre
        },
        "agent": {"id": "soar-001", "name": agent_name, "ip": agent_ip},
        "data": {
            "srcip":       source_ip,
            "verdict":     verdict,
            "risk_score":  round(session_risk, 2),
            "confidence":  confidence,
            "attack_type": attack_type,
            "soar_mode":   ai_result.get("mode", "behavioral_analysis")
        }
    }


# ── Push & Correlate ───────────────────────────────────────────────────────────

def _push_multipart(alerts: list) -> dict:
    session, csrf = _get_session()
    if not session:
        return {"status": "error", "reason": "login failed"}

    ndjson = "\n".join(json.dumps(a) for a in alerts).encode("utf-8")

    try:
        r = session.post(
            f"{DSS_URL}/api/v1/import/wazuh-alerts",
            headers={"X-CSRF-Token": csrf},
            files={"file": ("soar_alerts.json", ndjson, "application/json")},
            timeout=15
        )
        if r.status_code == 200:
            return {"status": "ok", "pushed": len(alerts), "response": r.json()}

        if r.status_code in (401, 403):
            global _session, _csrf_token
            _session = None
            if _login():
                session, csrf = _session, _csrf_token
                r2 = session.post(
                    f"{DSS_URL}/api/v1/import/wazuh-alerts",
                    headers={"X-CSRF-Token": csrf},
                    files={"file": ("soar_alerts.json", ndjson, "application/json")},
                    timeout=15
                )
                if r2.status_code == 200:
                    return {"status": "ok", "pushed": len(alerts), "response": r2.json()}

        return {"status": "error", "code": r.status_code, "reason": r.text[:200]}
    except Exception as e:
        return {"status": "error", "reason": str(e)}


def _trigger_correlate() -> dict:
    session, csrf = _get_session()
    if not session:
        return {"status": "error", "reason": "no session"}
    try:
        r = session.post(
            f"{DSS_URL}/api/v1/incidents/correlate",
            headers={"X-CSRF-Token": csrf},
            timeout=10
        )
        # 202 = accepted (async) — đúng behavior
        if r.status_code in (200, 202):
            try:
                return r.json()
            except Exception:
                return {"status": "accepted", "code": r.status_code}
        return {"status": "error", "code": r.status_code}
    except Exception as e:
        return {"status": "error", "reason": str(e)}


def push_incident_to_dss(
    source_ip: str,
    ai_result: dict,
    pipeline_summary: dict
) -> dict:
    """
    Main function: convert SOAR incident → push to DSS → auto correlate.
    """
    alert = soar_to_dss_alert(source_ip, ai_result, pipeline_summary)
    push_result = _push_multipart([alert])

    correlate_result = {}
    if push_result.get("status") == "ok":
        correlate_result = _trigger_correlate()

    return {
        "push":      push_result,
        "correlate": correlate_result,
    }
