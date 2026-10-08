from fastmcp import FastMCP
import base64
import hashlib
import hmac
import json
import os
import threading
import uuid
import requests
from datetime import datetime, timezone, timedelta

mcp = FastMCP("response-server")

VN_TZ = timezone(timedelta(hours=7))
APPROVAL_SECRET = os.environ.get("ACTION_APPROVAL_SECRET", "change-this-development-secret-32-characters").encode()
EXECUTION_MODE = os.environ.get("SOAR_EXECUTION_MODE", "dry-run").lower()
AUDIT_FILE = os.environ.get("ACTION_AUDIT_FILE", "/app/data/action_audit.jsonl")
ALLOWED_ACTIONS = {
    value.strip() for value in os.environ.get(
        "SOAR_ACTION_ALLOWLIST",
        "temporary_ip_block,rate_limit_ip,session_invalidation,increase_monitoring,create_ticket"
    ).split(",") if value.strip()
}
AUTO_ACTIONS = {
    value.strip() for value in os.environ.get(
        "SOAR_AUTO_ACTION_ALLOWLIST", "rate_limit_ip,increase_monitoring,create_ticket"
    ).split(",") if value.strip()
}
ACTION_WEBHOOK_URL = os.environ.get("SOAR_ACTION_WEBHOOK_URL", "")
ACTION_WEBHOOK_TOKEN = os.environ.get("SOAR_ACTION_WEBHOOK_TOKEN", "")
_audit_lock = threading.Lock()


def _decoded_token(token: str) -> tuple[list[str], str]:
    encoded, supplied_signature = token.split(".", 1)
    expected = base64.urlsafe_b64encode(
        hmac.new(APPROVAL_SECRET, encoded.encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    if not hmac.compare_digest(supplied_signature, expected):
        raise ValueError("invalid_approval_signature")
    padding = "=" * (-len(encoded) % 4)
    payload = base64.urlsafe_b64decode(encoded + padding).decode()
    return payload.split("|"), encoded


def _validate_approval(request: dict):
    required = ("action_id", "incident_id", "action_type", "target", "expires_at", "approval_token")
    if any(request.get(key) in (None, "") for key in required):
        raise ValueError("missing_approval_fields")
    if request["action_type"] not in ALLOWED_ACTIONS:
        raise ValueError("action_not_allowlisted")
    fields, _ = _decoded_token(request["approval_token"])
    expected = [
        str(request["action_id"]), str(request["incident_id"]), request["action_type"],
        request["target"], str(int(datetime.fromisoformat(request["expires_at"].replace("Z", "+00:00")).timestamp()))
    ]
    if fields != expected:
        raise ValueError("approval_payload_mismatch")
    if datetime.now(timezone.utc) >= datetime.fromisoformat(request["expires_at"].replace("Z", "+00:00")):
        raise ValueError("approval_expired")


def _already_processed(action_id: str) -> bool:
    if not os.path.exists(AUDIT_FILE):
        return False
    with _audit_lock, open(AUDIT_FILE, "r", encoding="utf-8") as stream:
        return any(json.loads(line).get("action_id") == action_id for line in stream if line.strip())


def _write_audit(entry: dict):
    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
    with _audit_lock, open(AUDIT_FILE, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, separators=(",", ":")) + "\n")


def _execute_adapter(action_id: str, action_type: str, target: str, context: dict) -> dict:
    if EXECUTION_MODE != "live":
        return {
            "status": "DRY_RUN",
            "message": f"Validated {action_type} for {target}; no infrastructure change was made",
            "execution_mode": EXECUTION_MODE,
        }
    if not ACTION_WEBHOOK_URL:
        return {
            "status": "FAILED",
            "message": f"No live adapter configured for {action_type}",
            "execution_mode": EXECUTION_MODE,
        }
    headers = {"Content-Type": "application/json"}
    if ACTION_WEBHOOK_TOKEN:
        headers["Authorization"] = f"Bearer {ACTION_WEBHOOK_TOKEN}"
    try:
        response = requests.post(
            ACTION_WEBHOOK_URL,
            headers=headers,
            json={
                "action_id": action_id,
                "action_type": action_type,
                "target": target,
                "context": context,
            },
            timeout=15,
        )
        response.raise_for_status()
        return {
            "status": "EXECUTED",
            "message": f"{action_type} completed by action gateway",
            "execution_mode": EXECUTION_MODE,
            "adapter_status": response.status_code,
        }
    except Exception as error:
        return {
            "status": "FAILED",
            "message": f"Action gateway failed: {error}",
            "execution_mode": EXECUTION_MODE,
        }


def now_vn():
    return datetime.now(VN_TZ).strftime("%Y-%m-%dT%H:%M:%S+07:00")


def build_response_plan(ai_result: dict) -> dict:
    severity   = ai_result.get("severity", "low").lower()
    confidence = float(ai_result.get("confidence", 0))
    source_ip  = ai_result.get("source_ip", "unknown")
    attack_chain = ai_result.get("attack_chain", [])

    actions    = []
    escalation = "none"
    require_admin = False

    if severity == "low":
        actions += ["log_incident", "store_behavior_trace"]

    elif severity == "medium":
        actions += ["log_incident", "telegram_alert", "create_incident_ticket"]
        escalation = "security_team"

    elif severity == "high":
        actions += ["telegram_alert", "create_incident_ticket", "temporary_ip_block", "sandbox_validation"]
        escalation    = "soc_team"
        require_admin = True

    elif severity == "critical":
        actions += ["telegram_alert", "create_incident_ticket", "block_source_ip",
                    "isolate_container", "preserve_forensics", "manual_admin_intervention"]
        escalation    = "incident_response_team"
        require_admin = True

    if confidence >= 0.95:
        actions.append("auto_execute_allowed")

    return {
        "timestamp":              now_vn(),
        "attack_chain":           attack_chain,
        "source_ip":              source_ip,
        "severity":               severity,
        "confidence":             confidence,
        "response_plan":          actions,
        "escalation_target":      escalation,
        "admin_approval_required": require_admin,
        "status":                 "ready_for_execution"
    }


@mcp.tool()
def generate_response(ai_reasoning: str) -> dict:
    """
    Nhánh B — Convert AI behavioral analysis verdict
    into SOAR response plan for admin decision.
    """
    try:
        ai_result = json.loads(ai_reasoning) if isinstance(ai_reasoning, str) else ai_reasoning
    except Exception:
        return {"status": "failed", "reason": "invalid_ai_reasoning_payload"}

    return build_response_plan(ai_result)


@mcp.tool()
def execute_active_response(source_ip: str, session_stage: str, metrics: str) -> dict:
    """
    Nhánh A — Wazuh confirmed attack.
    Execute immediate automated response without waiting for AI or admin.
    Actions executed instantly: session invalidation, IP throttle, SOC alert.
    """
    try:
        m = json.loads(metrics) if isinstance(metrics, str) else metrics
    except Exception:
        m = {}

    risk          = m.get("session_risk", 0)
    critical_count = m.get("critical_count", 0)
    attack_count  = m.get("attack_event_count", 0)

    # Quyết định mức độ response dựa trên stage và risk
    executed = []

    executed += ["create_ticket", "increase_monitoring"]

    if session_stage in ("active_intrusion", "post_exploitation"):
        executed += ["temporary_ip_block", "session_invalidation"]
    elif session_stage == "initial_compromise":
        executed += ["temporary_ip_block", "session_invalidation"]
    elif session_stage in ("reconnaissance", "suspicious_activity"):
        executed += ["rate_limit_ip"]

    if critical_count > 0 or risk >= 80:
        executed.append("temporary_ip_block")

    executed = list(dict.fromkeys(action for action in executed if action in AUTO_ACTIONS and action in ALLOWED_ACTIONS))
    adapter_results = [
        _execute_adapter(str(uuid.uuid4()), action, source_ip, {"session_stage": session_stage, "metrics": m})
        for action in executed
    ]
    if not adapter_results:
        execution_status = "FAILED"
    elif all(result["status"] == "EXECUTED" for result in adapter_results):
        execution_status = "EXECUTED"
    elif all(result["status"] == "DRY_RUN" for result in adapter_results):
        execution_status = "DRY_RUN"
    else:
        execution_status = "FAILED"

    return {
        "timestamp":       now_vn(),
        "source_ip":       source_ip,
        "session_stage":   session_stage,
        "session_risk":    risk,
        "executed_actions": executed,
        "action_results":   adapter_results,
        "status":          execution_status,
        "execution_mode":  EXECUTION_MODE,
        "note":            "Policy response evaluated. Dry-run makes no infrastructure change; live mode requires configured adapters."
    }


@mcp.tool()
def execute_approved_action(action_request: str) -> dict:
    """Validate a single-use DSS approval and execute only allowlisted actions."""
    try:
        request = json.loads(action_request) if isinstance(action_request, str) else action_request
        _validate_approval(request)
        if _already_processed(request["action_id"]):
            return {
                "status": "EXECUTED",
                "message": "Action was already processed; duplicate request ignored",
                "idempotent_replay": True,
            }

        adapter_result = _execute_adapter(
            request["action_id"], request["action_type"], request["target"], request
        )

        result = {
            "action_id": request["action_id"],
            "action_type": request["action_type"],
            "target": request["target"],
            "status": adapter_result["status"],
            "message": adapter_result["message"],
            "execution_mode": EXECUTION_MODE,
            "timestamp": now_vn(),
            "adapter": adapter_result,
        }
        _write_audit(result)
        return result
    except Exception as error:
        return {"status": "FAILED", "message": str(error), "timestamp": now_vn()}


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
