"""
Response Server — MCP tool cho SOAR pipeline.
Nhánh A (Wazuh): tự động execute ngay — block IP + Telegram thông báo
Nhánh B (Behavioral): gửi Telegram hỏi admin APPROVE/REJECT
  - APPROVE → block IP + log
  - REJECT  → chỉ log
  - Timeout 15 phút → tự động execute
Mỗi IP chỉ hỏi 1 lần trong session.
"""
from fastmcp import FastMCP
import json
import os
import time
import threading
import requests
from datetime import datetime, timezone, timedelta

mcp = FastMCP("response-server")

VN_TZ = timezone(timedelta(hours=7))

# ── Config ────────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN",
                                     "")
TELEGRAM_CHAT_ID    = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_API        = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
FIREWALL_AGENT_URL  = os.environ.get("FIREWALL_AGENT_URL", "http://localhost:9999")
APPROVAL_TIMEOUT    = int(os.environ.get("APPROVAL_TIMEOUT", "900"))  # 15 phút

# ── Pending approval store ────────────────────────────────────────────────────
# message_id → {ip, severity, attack_chain, expire_at, timer}
_pending: dict = {}
_pending_lock = threading.Lock()

# IPs đã bị block trong session — không hỏi lại
_blocked_ips: set = set()


def now_vn() -> str:
    return datetime.now(VN_TZ).strftime("%Y-%m-%dT%H:%M:%S+07:00")


# ── Firewall Agent calls ──────────────────────────────────────────────────────

def call_firewall_block(ip: str, duration: int = 1800) -> dict:
    """Gọi firewall_agent block IP. Trả về result dict."""
    try:
        r = requests.post(
            f"{FIREWALL_AGENT_URL}/block",
            json={"ip": ip, "duration": duration},
            timeout=10
        )
        return r.json()
    except Exception as e:
        return {"status": "error", "reason": str(e)}


def call_firewall_unblock(ip: str) -> dict:
    try:
        r = requests.post(
            f"{FIREWALL_AGENT_URL}/unblock",
            json={"ip": ip},
            timeout=10
        )
        return r.json()
    except Exception as e:
        return {"status": "error", "reason": str(e)}


# ── Telegram helpers ──────────────────────────────────────────────────────────

def send_telegram(text: str, parse_mode: str = "HTML") -> dict:
    try:
        r = requests.post(f"{TELEGRAM_API}/sendMessage", json={
            "chat_id":    TELEGRAM_CHAT_ID,
            "text":       text,
            "parse_mode": parse_mode,
        }, timeout=10)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}


def send_approval_request(ip: str, severity: str, verdict: str,
                          attack_chain: list, risk_summary: str,
                          session_stage: str, session_risk: float) -> int | None:
    """
    Gửi Telegram với inline keyboard APPROVE/REJECT.
    Trả về message_id để track callback.
    """
    severity_emoji = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "🚨"}.get(severity, "🔴")
    chain_text = "\n".join(f"  • {s}" for s in attack_chain) if attack_chain else "  • N/A"

    text = f"""{severity_emoji} <b>SOAR — CẦN PHÊ DUYỆT</b>

🌐 <b>Source IP:</b> <code>{ip}</code>
📊 <b>Risk Score:</b> {session_risk:.1f}/100
🎯 <b>Verdict:</b> {verdict}
🔎 <b>Summary:</b> {risk_summary}
📍 <b>Stage:</b> {session_stage}

⛓ <b>Attack Chain:</b>
{chain_text}

⏰ <b>Tự động BLOCK sau 15 phút nếu không phản hồi</b>
🕐 {now_vn()}"""

    try:
        r = requests.post(f"{TELEGRAM_API}/sendMessage", json={
            "chat_id":    TELEGRAM_CHAT_ID,
            "text":       text,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "✅ APPROVE — Block IP", "callback_data": f"approve:{ip}"},
                    {"text": "❌ REJECT — Chỉ log",   "callback_data": f"reject:{ip}"},
                ]]
            }
        }, timeout=10)
        data = r.json()
        if data.get("ok"):
            return data["result"]["message_id"]
    except Exception:
        pass
    return None


def edit_message_approved(message_id: int, ip: str):
    """Cập nhật message sau khi admin APPROVE."""
    try:
        requests.post(f"{TELEGRAM_API}/editMessageReplyMarkup", json={
            "chat_id":      TELEGRAM_CHAT_ID,
            "message_id":   message_id,
            "reply_markup": {"inline_keyboard": []}
        }, timeout=10)
        send_telegram(f"✅ <b>APPROVED</b> — Đã block <code>{ip}</code>")
    except Exception:
        pass


def edit_message_rejected(message_id: int, ip: str):
    """Cập nhật message sau khi admin REJECT."""
    try:
        requests.post(f"{TELEGRAM_API}/editMessageReplyMarkup", json={
            "chat_id":      TELEGRAM_CHAT_ID,
            "message_id":   message_id,
            "reply_markup": {"inline_keyboard": []}
        }, timeout=10)
        send_telegram(f"❌ <b>REJECTED</b> — <code>{ip}</code> chỉ được log, tiếp tục monitor")
    except Exception:
        pass


def edit_message_timeout(message_id: int, ip: str):
    """Cập nhật message khi timeout tự động execute."""
    try:
        requests.post(f"{TELEGRAM_API}/editMessageReplyMarkup", json={
            "chat_id":      TELEGRAM_CHAT_ID,
            "message_id":   message_id,
            "reply_markup": {"inline_keyboard": []}
        }, timeout=10)
        send_telegram(f"⏰ <b>TIMEOUT</b> — Tự động block <code>{ip}</code> (không có phản hồi sau 15 phút)")
    except Exception:
        pass


# ── Approval flow ─────────────────────────────────────────────────────────────

def _execute_block(ip: str) -> dict:
    """Thực thi block IP thật qua firewall agent."""
    result = call_firewall_block(ip)
    _blocked_ips.add(ip)
    return result


def _timeout_handler(ip: str, message_id: int):
    """Chạy sau APPROVAL_TIMEOUT giây nếu admin không reply."""
    with _pending_lock:
        if message_id not in _pending:
            return  # đã được xử lý bởi callback
        _pending.pop(message_id)

    # Tự động execute
    block_result = _execute_block(ip)
    edit_message_timeout(message_id, ip)


def request_approval(ip: str, severity: str, verdict: str,
                     attack_chain: list, risk_summary: str,
                     session_stage: str, session_risk: float) -> dict:
    """
    Gửi approval request đến admin.
    Nếu IP đã bị block trong session → skip, không hỏi lại.
    """
    if ip in _blocked_ips:
        return {"status": "already_blocked", "ip": ip, "action": "skipped"}

    message_id = send_approval_request(
        ip, severity, verdict, attack_chain,
        risk_summary, session_stage, session_risk
    )

    if not message_id:
        # Telegram fail → tự động execute để đảm bảo an toàn
        block_result = _execute_block(ip)
        return {"status": "telegram_failed_auto_executed", "ip": ip,
                "block_result": block_result}

    # Lưu pending + set timer timeout
    timer = threading.Timer(
        APPROVAL_TIMEOUT, _timeout_handler, args=[ip, message_id]
    )
    timer.daemon = True
    timer.start()

    with _pending_lock:
        _pending[message_id] = {
            "ip":           ip,
            "severity":     severity,
            "attack_chain": attack_chain,
            "expire_at":    time.time() + APPROVAL_TIMEOUT,
            "timer":        timer,
        }

    return {
        "status":     "pending_approval",
        "ip":         ip,
        "message_id": message_id,
        "expires_in": APPROVAL_TIMEOUT,
    }


# ── Response plan builder ─────────────────────────────────────────────────────

def build_telegram_alert(ip, severity, verdict, attack_chain,
                         risk_summary, session_stage, session_risk, mode="behavioral") -> str:
    severity_emoji = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "🚨"}.get(severity, "🔴")
    mode_label     = "🔍 Behavioral Analysis" if mode == "behavioral" else "⚠️ Wazuh Confirmed"
    chain_text     = "\n".join(f"  • {s}" for s in attack_chain) if attack_chain else "  • N/A"

    return f"""{severity_emoji} <b>SOAR ALERT — {severity.upper()}</b>
{mode_label}

🌐 <b>Source IP:</b> <code>{ip}</code>
📊 <b>Risk Score:</b> {session_risk:.1f}/100
🎯 <b>Verdict:</b> {verdict}
🔎 <b>Summary:</b> {risk_summary}
📍 <b>Stage:</b> {session_stage}

⛓ <b>Attack Chain:</b>
{chain_text}

🕐 {now_vn()}"""


def build_response_plan(ai_result: dict) -> dict:
    severity      = ai_result.get("severity", "low").lower()
    confidence    = float(ai_result.get("confidence", 0))
    ip            = ai_result.get("source_ip", "unknown")
    attack_chain  = ai_result.get("attack_chain", [])
    verdict       = ai_result.get("verdict", "unknown")
    risk_summary  = ai_result.get("risk_summary", "")
    session_stage = ai_result.get("session_stage", "unknown")
    session_risk  = float(ai_result.get("session_risk", 0))

    actions        = []
    escalation     = "none"
    require_admin  = False
    telegram_sent  = False
    approval_result = None

    if severity == "low":
        actions += ["log_incident", "store_behavior_trace"]

    elif severity == "medium":
        actions += ["log_incident", "telegram_alert", "create_incident_ticket"]
        escalation = "security_team"
        # Hỏi admin
        approval_result = request_approval(
            ip, severity, verdict, attack_chain,
            risk_summary, session_stage, session_risk
        )
        telegram_sent = True

    elif severity == "high":
        actions += ["telegram_alert", "create_incident_ticket",
                    "temporary_ip_block", "sandbox_validation"]
        escalation    = "soc_team"
        require_admin = True
        approval_result = request_approval(
            ip, severity, verdict, attack_chain,
            risk_summary, session_stage, session_risk
        )
        telegram_sent = True

    elif severity == "critical":
        actions += ["telegram_alert", "create_incident_ticket",
                    "block_source_ip", "isolate_container",
                    "preserve_forensics", "manual_admin_intervention"]
        escalation    = "incident_response_team"
        require_admin = True
        approval_result = request_approval(
            ip, severity, verdict, attack_chain,
            risk_summary, session_stage, session_risk
        )
        telegram_sent = True

    if confidence >= 0.95:
        actions.append("auto_execute_allowed")

    return {
        "timestamp":               now_vn(),
        "attack_chain":            attack_chain,
        "source_ip":               ip,
        "severity":                severity,
        "confidence":              confidence,
        "response_plan":           actions,
        "escalation_target":       escalation,
        "admin_approval_required": require_admin,
        "telegram_sent":           telegram_sent,
        "approval_result":         approval_result,
        "status":                  "ready_for_execution"
    }


# ── MCP Tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def generate_response(ai_reasoning: str) -> dict:
    """
    Nhánh B — Behavioral analysis.
    Gửi Telegram APPROVE/REJECT cho admin.
    Timeout 15 phút → tự động execute.
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
    Tự động execute ngay: block IP + Telegram thông báo (không hỏi admin).
    """
    try:
        m = json.loads(metrics) if isinstance(metrics, str) else metrics
    except Exception:
        m = {}

    risk           = m.get("session_risk", 0)
    critical_count = m.get("critical_count", 0)
    attack_count   = m.get("attack_event_count", 0)

    executed = [
        "session_invalidation",
        "temporary_ip_throttle",
        "create_incident_ticket",
        "preserve_forensic_snapshot"
    ]

    if session_stage in ("active_intrusion", "post_exploitation"):
        executed += ["block_source_ip", "isolate_affected_container", "escalate_to_ciso"]
        severity = "critical"
    elif session_stage == "initial_compromise":
        executed += ["temporary_ip_block", "force_logout_all_sessions", "escalate_to_soc_lead"]
        severity = "high"
    elif session_stage in ("reconnaissance", "suspicious_activity"):
        executed += ["rate_limit_ip", "increase_monitoring_level"]
        severity = "medium"
    else:
        severity = "medium"

    if critical_count > 0 or risk >= 80:
        executed.append("trigger_incident_response_playbook")

    # Block IP thật qua firewall agent
    block_result = _execute_block(source_ip)
    executed.append("ip_blocked_iptables")

    # Telegram thông báo đã execute (không hỏi)
    severity_emoji = {"medium": "🟠", "high": "🔴", "critical": "🚨"}.get(severity, "🔴")
    msg = f"""{severity_emoji} <b>🚨 WAZUH CONFIRMED — AUTO EXECUTED</b>

🌐 <b>Source IP:</b> <code>{source_ip}</code>
📊 <b>Risk Score:</b> {risk:.1f}/100
📍 <b>Stage:</b> {session_stage}
⚡ <b>Attack Events:</b> {attack_count}
🚫 <b>IP Status:</b> {block_result.get("status", "unknown")}

✅ <b>Actions Executed:</b>
{chr(10).join(f"  • {a}" for a in executed)}

🕐 {now_vn()}
⚠️ Admin review required."""

    telegram_result = send_telegram(msg)
    executed.append("telegram_alert_soc")

    return {
        "timestamp":        now_vn(),
        "source_ip":        source_ip,
        "session_stage":    session_stage,
        "session_risk":     risk,
        "executed_actions": executed,
        "block_result":     block_result,
        "telegram_sent":    telegram_result.get("ok", False),
        "status":           "active_response_executed",
        "note":             "Wazuh-confirmed attack. Automated response executed. Admin review required."
    }


@mcp.tool()
def handle_telegram_callback(callback_data: str, message_id: int) -> dict:
    """
    Xử lý callback từ Telegram inline keyboard.
    Gọi từ main.py khi nhận được webhook callback.
    callback_data: "approve:IP" hoặc "reject:IP"
    """
    parts = callback_data.split(":", 1)
    if len(parts) != 2:
        return {"status": "error", "reason": "invalid callback_data"}

    action, ip = parts[0], parts[1]

    with _pending_lock:
        pending = _pending.pop(message_id, None)

    if not pending:
        return {"status": "already_handled", "ip": ip}

    # Cancel timeout timer
    pending["timer"].cancel()

    if action == "approve":
        block_result = _execute_block(ip)
        edit_message_approved(message_id, ip)
        return {
            "status":       "approved",
            "ip":           ip,
            "block_result": block_result,
            "action":       "ip_blocked"
        }

    elif action == "reject":
        edit_message_rejected(message_id, ip)
        return {
            "status": "rejected",
            "ip":     ip,
            "action": "logged_only"
        }

    return {"status": "unknown_action", "ip": ip}


@mcp.tool()
def get_blocked_ips() -> dict:
    """Trả về danh sách IP đang bị block."""
    try:
        r = requests.get(f"{FIREWALL_AGENT_URL}/status", timeout=5)
        return r.json()
    except Exception as e:
        return {"error": str(e), "blocked": list(_blocked_ips)}



@mcp.tool()
def generate_incident_report(
    source_ip: str,
    ai_result: str,
    pipeline_summary: str,
    mode: str = "behavioral"
) -> dict:
    """
    Generate incident report dạng markdown.
    Lưu vào /reports/ và gửi qua Telegram dưới dạng file document.
    mode: "wazuh" | "behavioral"
    """
    import os, pathlib

    try:
        ai   = json.loads(ai_result)   if isinstance(ai_result, str)        else ai_result
        summ = json.loads(pipeline_summary) if isinstance(pipeline_summary, str) else pipeline_summary
    except Exception as e:
        return {"status": "error", "reason": f"parse error: {e}"}

    # ── Build markdown content ─────────────────────────────────────────────
    ts        = now_vn()
    severity  = ai.get("severity", "unknown").upper()
    verdict   = ai.get("verdict", "unknown")
    attack_type = ai.get("attack_type", "N/A")
    risk_summary = ai.get("risk_summary", "N/A")
    reasoning = ai.get("reasoning", "N/A")
    impact    = ai.get("impact_assessment", "N/A")
    patch     = ai.get("patch_suggestion", "N/A")
    chain     = ai.get("attack_chain", [])
    actions   = ai.get("recommended_action", [])
    confidence = ai.get("confidence", 0)
    session_risk = ai.get("session_risk", 0)
    session_stage = ai.get("session_stage", "unknown")

    chain_md   = "\n".join(f"- {s}" for s in chain)   if chain   else "- N/A"
    actions_md = "\n".join(f"- {a}" for a in actions) if actions else "- N/A"

    mode_label = "🔴 Wazuh Confirmed Attack" if mode == "wazuh" else "🔍 Behavioral Analysis"

    raw_events  = summ.get("raw_events_collected", 0)
    behaviors   = summ.get("behaviors_translated", 0)
    normal_b    = summ.get("normal_behaviors", 0)
    attack_b    = summ.get("attack_behaviors", 0)
    sources     = ", ".join(summ.get("sources_queried", []))

    md = f"""# SOAR Incident Report
**{mode_label}**

---

## 1. Thông tin chung
| Trường | Giá trị |
|--------|---------|
| **Thời gian** | {ts} |
| **Source IP** | `{source_ip}` |
| **Severity** | {severity} |
| **Verdict** | {verdict} |
| **Confidence** | {confidence:.0%} |
| **Risk Score** | {session_risk:.1f}/100 |
| **Session Stage** | {session_stage} |
| **Attack Type** | {attack_type} |

---

## 2. Tóm tắt
**{risk_summary}**

{reasoning}

---

## 3. Chuỗi tấn công (Attack Chain)
{chain_md}

---

## 4. Đánh giá tác động
{impact}

---

## 5. Khuyến nghị xử lý
{actions_md}

---

## 6. Đề xuất vá lỗi
{patch}

---

## 7. Thống kê pipeline
| Chỉ số | Giá trị |
|--------|---------|
| Raw events collected | {raw_events} |
| Behaviors translated | {behaviors} |
| Normal behaviors | {normal_b} |
| Attack behaviors | {attack_b} |
| Sources queried | {sources} |

---
*Generated by SOAR MCP Platform — {ts}*
"""

    # ── Lưu file ──────────────────────────────────────────────────────────
    reports_dir = pathlib.Path("/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    safe_ts  = ts.replace(":", "-").replace("+", "").replace(" ", "_")
    filename = f"incident_{source_ip.replace('.', '_')}_{safe_ts}.md"
    filepath = reports_dir / filename

    try:
        filepath.write_text(md, encoding="utf-8")
        saved = True
    except Exception as e:
        saved = False

    # ── Gửi Telegram dưới dạng document ───────────────────────────────────
    telegram_sent = False
    try:
        caption = (
            f"📋 <b>Incident Report</b>\n"
            f"🌐 IP: <code>{source_ip}</code>\n"
            f"🎯 {severity} — {risk_summary}\n"
            f"🕐 {ts}"
        )
        files = {"document": (filename, md.encode("utf-8"), "text/markdown")}
        r = requests.post(
            f"{TELEGRAM_API}/sendDocument",
            data={"chat_id": TELEGRAM_CHAT_ID, "caption": caption, "parse_mode": "HTML"},
            files=files,
            timeout=15
        )
        telegram_sent = r.status_code == 200
    except Exception:
        telegram_sent = False

# ── Push to DSS Platform ──────────────────────────────────────────────
    dss_result = {}
    try:
        from dss_connector import push_incident_to_dss
        dss_result = push_incident_to_dss(source_ip, ai, summ)
    except Exception as e:
        dss_result = {"status": "error", "reason": str(e)}

    return {
        "status":        "ok",
        "filename":      filename,
        "saved":         saved,
        "telegram_sent": telegram_sent,
        "filepath":      str(filepath),
        "dss_push":      dss_result,
    }


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
