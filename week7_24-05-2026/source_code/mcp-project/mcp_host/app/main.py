import asyncio
import json
import time
import pathlib
import os
import requests
from datetime import datetime, timezone, timedelta
from app.wazuh_client import WazuhClient
from app.orchestrator import SOAROrchestrator

POLL_INTERVAL        = 15
WEB_LOG_INTERVAL     = 15
TELEGRAM_POLL_INTERVAL = 5   # poll Telegram callback mỗi 5 giây
SINCE_FILE           = pathlib.Path("/tmp/soar_data/ip_since.json")
VN_TZ                = timezone(timedelta(hours=7))

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_API       = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# Track update_id Telegram đã xử lý
_last_update_id = 0


def load_ip_since() -> dict:
    try:
        return json.loads(SINCE_FILE.read_text())
    except Exception:
        return {}


def save_ip_since(ip_since: dict):
    try:
        SINCE_FILE.parent.mkdir(parents=True, exist_ok=True)
        SINCE_FILE.write_text(json.dumps(ip_since))
    except Exception:
        pass


def log_ts_to_vn(ts_str: str) -> str:
    try:
        ts = ts_str.split(" ")[0]
        day, mon_str, rest = ts.split("/")
        year, hour, minute, second = rest.split(":")
        month = _MONTH_MAP.get(mon_str, 0)
        if not month:
            return ts_str[:20]
        dt_utc = datetime(int(year), month, int(day),
                          int(hour), int(minute), int(second),
                          tzinfo=timezone.utc)
        dt_vn = dt_utc.astimezone(VN_TZ)
        return dt_vn.strftime("%d/%m %H:%M:%S +07")
    except Exception:
        return ts_str[:20]


def ts_newer(new_ts: str, old_ts: str) -> bool:
    def parse(ts):
        try:
            ts = ts.split(" ")[0]
            day, mon_str, rest = ts.split("/")
            year, h, m, s = rest.split(":")
            month = _MONTH_MAP.get(mon_str, 0)
            return datetime(int(year), month, int(day), int(h), int(m), int(s))
        except Exception:
            return datetime.min
    return parse(new_ts) > parse(old_ts)


async def get_active_ips_from_web_log(orchestrator: SOAROrchestrator) -> set:
    try:
        result = await orchestrator._call(
            orchestrator.collector_mcp,
            "fetch_web_logs",
            {"keyword": "HTTP/1", "session_id": "ip_scan", "since": ""}
        )
        ips = set()
        for event in result.get("events", []):
            raw   = event.get("raw", "")
            parts = raw.split()
            if parts:
                ip = parts[0]
                if ip.count(".") == 3 and not ip.startswith("127."):
                    ips.add(ip)
        return ips
    except Exception as e:
        print(f"[WEB LOG] Error getting IPs: {e}")
        return set()


async def poll_telegram_callbacks(orchestrator: SOAROrchestrator):
    """
    Poll Telegram getUpdates để nhận callback từ inline keyboard.
    Khi admin nhấn APPROVE/REJECT → gọi handle_telegram_callback trên response MCP.
    """
    global _last_update_id
    if not TELEGRAM_BOT_TOKEN:
        return

    try:
        r = requests.get(
            f"{TELEGRAM_API}/getUpdates",
            params={"offset": _last_update_id + 1, "timeout": 0},
            timeout=10
        )
        data = r.json()
        if not data.get("ok"):
            return

        for update in data.get("result", []):
            _last_update_id = update["update_id"]

            # Chỉ xử lý callback_query (inline keyboard)
            callback = update.get("callback_query")
            if not callback:
                continue

            callback_data = callback.get("data", "")
            message_id    = callback.get("message", {}).get("message_id")

            if not callback_data or not message_id:
                continue

            # Trả lời callback để Telegram bỏ loading spinner
            try:
                requests.post(f"{TELEGRAM_API}/answerCallbackQuery",
                              json={"callback_query_id": callback["id"]},
                              timeout=5)
            except Exception:
                pass

            # Gọi response MCP xử lý
            try:
                result = await orchestrator._call(
                    orchestrator.response_mcp,
                    "handle_telegram_callback",
                    {"callback_data": callback_data, "message_id": message_id}
                )
                action = result.get("status", "unknown")
                ip     = result.get("ip", "?")
                print(f"\n[TELEGRAM CALLBACK] {action.upper()} for {ip}")
                if result.get("block_result"):
                    print(f"  block_result: {result['block_result']}")
            except Exception as e:
                print(f"[TELEGRAM CALLBACK ERROR] {e}")

    except Exception:
        pass


async def main():
    import time as _time
    _time.sleep(5)

    wazuh        = WazuhClient()
    orchestrator = SOAROrchestrator()

    processed_alert_ids = set()
    processed_web_ips   = {}
    ip_since            = load_ip_since()

    if ip_since:
        print(f"[+] Loaded ip_since for {len(ip_since)} IPs from previous session")

    print("[+] SOAR Host started — Dual trigger mode")
    print("[+] Trigger 1: Wazuh alerts (real-time attack detection)")
    print("[+] Trigger 2: Web log polling (behavioral chain monitoring)")
    print("[+] Trigger 3: Telegram callback polling (human-in-the-loop)")
    print()

    last_web_poll      = 0.0
    last_telegram_poll = 0.0

    while True:
        # ══════════════════════════════════════════════════════════════════
        # TRIGGER 1 — Wazuh alert
        # ══════════════════════════════════════════════════════════════════
        try:
            alert = await wazuh.get_latest_alert()
            if alert:
                alert_id = alert.get("id")
                if alert_id and alert_id not in processed_alert_ids:
                    processed_alert_ids.add(alert_id)
                    if len(processed_alert_ids) > 1000:
                        processed_alert_ids.pop()

                    print("=" * 70)
                    print(f"[!] WAZUH ALERT: {alert_id}")
                    print("=" * 70)

                    result = await orchestrator.process_alert(alert)
                    _print_result(result)

        except Exception as e:
            import traceback
            print(f"[WAZUH ERROR] {e}")
            traceback.print_exc()

        # ══════════════════════════════════════════════════════════════════
        # TRIGGER 2 — Web log polling
        # ══════════════════════════════════════════════════════════════════
        now = time.time()
        if now - last_web_poll >= WEB_LOG_INTERVAL:
            last_web_poll = now
            try:
                active_ips = await get_active_ips_from_web_log(orchestrator)

                for ip in active_ips:
                    last_time = processed_web_ips.get(ip, 0)
                    if now - last_time < 60:
                        continue

                    processed_web_ips[ip] = now
                    since = ip_since.get(ip, {})

                    if since:
                        web_since     = since.get("web", "")
                        since_display = log_ts_to_vn(web_since) if web_since else "unknown"
                        print(f"[~] WEB LOG TRIGGER: {ip} (since={since_display})")
                    else:
                        print(f"[~] WEB LOG TRIGGER: {ip} (first scan)")

                    result = await orchestrator.process_web_ip(ip, since=since)

                    new_timestamps = result.get("last_timestamps", {})
                    if new_timestamps:
                        if ip not in ip_since:
                            ip_since[ip] = {}
                        updated = False
                        for src, ts in new_timestamps.items():
                            if ts and ts_newer(str(ts), str(ip_since[ip].get(src, ""))):
                                ip_since[ip][src] = ts
                                updated = True
                        if updated:
                            save_ip_since(ip_since)

                    _print_result(result)

                cutoff = now - 1800
                processed_web_ips = {ip: t for ip, t in processed_web_ips.items() if t > cutoff}
                ip_since = {ip: s for ip, s in ip_since.items()
                            if processed_web_ips.get(ip, 0) > cutoff}

            except Exception as e:
                print(f"[WEB LOG ERROR] {e}")

        # ══════════════════════════════════════════════════════════════════
        # TRIGGER 3 — Telegram callback polling
        # ══════════════════════════════════════════════════════════════════
        now = time.time()
        if now - last_telegram_poll >= TELEGRAM_POLL_INTERVAL:
            last_telegram_poll = now
            await poll_telegram_callbacks(orchestrator)

        await asyncio.sleep(POLL_INTERVAL)


def _print_result(result: dict):
    status    = result.get("status", "unknown")
    branch    = result.get("branch", "")
    source_ip = result.get("source_ip", "?")

    print(f"\n[STATUS] {status}", end="")
    if branch:
        print(f" | branch={branch}", end="")
    print()

    summary = result.get("pipeline_summary")
    if summary:
        print("\n[PIPELINE SUMMARY]")
        print(json.dumps(summary, indent=2, ensure_ascii=False))

    if status == "buffering":
        print(f"  queue_size   : {result.get('queue_size')}")
        print(f"  current_risk : {result.get('current_risk')}")
        print(f"  session_stage: {result.get('session_stage')}")
        print(f"  trigger      : {result.get('trigger_source')}")
        return

    if status == "attack_confirmed":
        imm = result.get("immediate_response", {})
        if imm:
            print("\n[!! IMMEDIATE RESPONSE EXECUTED]")
            print(json.dumps(imm, indent=2, ensure_ascii=False))
        ai = result.get("ai_incident_report", {})
        if ai:
            print("\n[AI INCIDENT REPORT]")
            print(json.dumps(ai, indent=2, ensure_ascii=False))
        print(f"\n[!!] ATTACK CONFIRMED — Active response executed for {source_ip}\n")
        return

    if status == "suspicious_detected":
        ai = result.get("ai_reasoning", {})
        if ai:
            print("\n[AI REASONING — SUSPICIOUS]")
            print(json.dumps(ai, indent=2, ensure_ascii=False))
        plan = result.get("response_plan", {})
        if plan:
            print("\n[SOAR RESPONSE PLAN]")
            print(json.dumps(plan, indent=2, ensure_ascii=False))
        approval = plan.get("approval_result", {}) if plan else {}
        if approval:
            status_str = approval.get("status", "")
            if status_str == "pending_approval":
                print(f"\n[⏳] Chờ admin phê duyệt — timeout 15 phút sẽ tự động execute")
            elif status_str == "already_blocked":
                print(f"\n[🚫] IP đã bị block trong session này — skip")
        print(f"\n[!] SUSPICIOUS ACTIVITY — Report sent to admin for {source_ip}\n")
        return

    if status == "normal_activity":
        print(f"  verdict   : {result.get('ai_verdict', 'benign')}")
        print(f"  reasoning : {str(result.get('ai_reasoning', ''))[:120]}")
        print(f"  forensic  : {result.get('forensic_note', '')}")
        print(f"  [OK] Normal activity for {source_ip} — forensic queued\n")
        return

    if result.get("error"):
        print(f"  error: {result.get('error')}")
    print(f"\n[✓] Processed {source_ip}\n")


if __name__ == "__main__":
    asyncio.run(main())
