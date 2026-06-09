import json
from app.mcp_client import MCPClient
from app.ai_engine import AIEngine
from app.response_engine import ResponseEngine


class SOAROrchestrator:
    """
    SOAR pipeline — MCP-native, dual-branch design.

    Trigger 1 (Wazuh alert) → fetch_all_sources (7 nguồn kể cả Wazuh)
      → has_wazuh_alert=True → Nhánh A: active response ngay

    Trigger 2 (web log) → chỉ fetch_web_logs + fetch_firewall_logs
      → has_wazuh_alert=False → Nhánh B: AI phân tích behavioral chain
      → Web log có since filter → không duplicate
      → Firewall log ít thay đổi → OK
    """

    def __init__(self):
        self.collector_mcp   = MCPClient("http://collector_server:8000")
        self.translator_mcp  = MCPClient("http://translator_server:8000")
        self.correlator_mcp  = MCPClient("http://correlator_server:8000")
        self.response_mcp    = MCPClient("http://response_server:8000")
        self.ai_engine       = AIEngine()
        self.response_engine = ResponseEngine()

    async def _call(self, client: MCPClient, tool: str, payload: dict) -> dict:
        result = await client.call_tool(tool, payload)
        if isinstance(result, str):
            result = json.loads(result)
        return result or {}

    async def _run_pipeline(
        self,
        source_ip: str,
        trigger_source: str,
        alert_id: str,
        url: str,
        rule_description: str,
        collector_result: dict,
    ) -> dict:
        """Shared pipeline từ bước translate trở đi."""
        raw_events = collector_result.get("events", [])
        if not raw_events:
            return {
                "alert_id": alert_id, "source_ip": source_ip,
                "status": "no_events_collected",
                "last_timestamps": collector_result.get("last_timestamps", {})
            }

        # ── STEP 2: TRANSLATE ─────────────────────────────────────────────
        try:
            translate_result = await self._call(
                self.translator_mcp, "translate_batch", {"events": raw_events}
            )
        except Exception as e:
            return {"alert_id": alert_id, "source_ip": source_ip,
                    "status": "translator_error", "error": str(e)}

        translated_events = translate_result.get("translated", [])
        if not translated_events:
            return {
                "alert_id": alert_id, "source_ip": source_ip,
                "status": "no_behaviors_detected",
                "skipped_count": translate_result.get("skipped_count", 0),
                "last_timestamps": collector_result.get("last_timestamps", {})
            }

        # ── STEP 3: CORRELATE ─────────────────────────────────────────────
        try:
            correlation_result = await self._call(
                self.correlator_mcp, "add_event_batch",
                {"events": translated_events, "user_id": source_ip}
            )
        except Exception as e:
            return {"alert_id": alert_id, "source_ip": source_ip,
                    "status": "correlator_error", "error": str(e)}

        # ── STEP 4: BUFFER CHECK ──────────────────────────────────────────
        if not correlation_result.get("ready_for_ai"):
            return {
                "alert_id": alert_id, "source_ip": source_ip, "url": url,
                "status": "buffering",
                "queue_size": correlation_result.get("queue_size", 0),
                "current_risk": correlation_result.get("current_risk", 0),
                "session_stage": correlation_result.get("session_stage"),
                "trigger_source": trigger_source,
                "last_timestamps": collector_result.get("last_timestamps", {})
            }

        payload_to_ai   = correlation_result.get("payload_to_ai", {})
        has_wazuh_alert = payload_to_ai.get("has_wazuh_alert", False)
        session_stage   = correlation_result.get("session_stage", "normal_activity")

        pipeline_summary = {
            "raw_events_collected": len(raw_events),
            "behaviors_translated": len(translated_events),
            "normal_behaviors":  sum(1 for e in translated_events if not e.get("is_attack")),
            "attack_behaviors":  sum(1 for e in translated_events if e.get("is_attack")),
            "skipped_noise":     translate_result.get("skipped_count", 0),
            "sources_queried":   collector_result.get("sources_queried", []),
            "session_stage":     session_stage,
            "session_risk":      correlation_result.get("current_risk", 0),
            "trigger_source":    trigger_source,
        }

        # ══════════════════════════════════════════════════════════════════
        # NHÁNH A — có Wazuh alert → chắc chắn tấn công
        # ══════════════════════════════════════════════════════════════════
        if has_wazuh_alert:
            try:
                immediate_response = await self.response_engine.active_response(
                    source_ip=source_ip, session_stage=session_stage, payload=payload_to_ai
                )
            except Exception as e:
                immediate_response = {"error": str(e), "actions": []}

            try:
                ai_result = await self.ai_engine.analyze_confirmed_attack(
                    behavior_sequence=payload_to_ai,
                    session_id=source_ip, source_ip=source_ip
                )
            except Exception as e:
                ai_result = {"error": str(e), "verdict": "analysis_failed"}

            try:
                await self._call(self.correlator_mcp, "update_ai_context",
                                 {"user_id": source_ip, "ai_result": ai_result})
            except Exception:
                pass

            # Generate incident report
            try:
                await self._call(self.response_mcp, "generate_incident_report", {
                    "source_ip":        source_ip,
                    "ai_result":        json.dumps(ai_result),
                    "pipeline_summary": json.dumps(pipeline_summary),
                    "mode":             "wazuh"
                })
            except Exception:
                pass

            return {
                "alert_id": alert_id, "source_ip": source_ip,
                "url": url, "rule_description": rule_description,
                "status": "attack_confirmed", "branch": "wazuh_confirmed",
                "pipeline_summary": pipeline_summary,
                "immediate_response": immediate_response,
                "ai_incident_report": ai_result,
                "last_timestamps": collector_result.get("last_timestamps", {})
            }

        # ══════════════════════════════════════════════════════════════════
        # NHÁNH B — không có Wazuh alert → AI phân tích behavioral chain
        # ══════════════════════════════════════════════════════════════════
        try:
            ai_result = await self.ai_engine.analyze_attack_chain(
                behavior_sequence=payload_to_ai,
                session_id=source_ip, source_ip=source_ip
            )
        except Exception as e:
            ai_result = {"error": str(e), "verdict": "analysis_failed",
                         "is_suspicious": False, "risk_summary": "unknown"}

        # Thêm context từ pipeline vào ai_result để Telegram hiển thị đúng
        ai_result["session_risk"]  = payload_to_ai.get("metrics", {}).get("session_risk", 0)
        ai_result["session_stage"] = session_stage

        try:
            await self._call(self.correlator_mcp, "update_ai_context",
                             {"user_id": source_ip, "ai_result": ai_result})
        except Exception:
            pass

        verdict       = ai_result.get("verdict", "benign")
        is_suspicious = ai_result.get("is_suspicious", False) or verdict in (
            "attack_confirmed", "probe_detected", "suspicious"
        )

        if is_suspicious:
            try:
                response_plan = await self.response_engine.generate_response_plan(ai_result)
            except Exception as e:
                response_plan = {"error": str(e), "actions": []}

            # Generate incident report
            try:
                await self._call(self.response_mcp, "generate_incident_report", {
                    "source_ip":        source_ip,
                    "ai_result":        json.dumps(ai_result),
                    "pipeline_summary": json.dumps(pipeline_summary),
                    "mode":             "behavioral"
                })
            except Exception:
                pass

            return {
                "alert_id": alert_id, "source_ip": source_ip, "url": url,
                "status": "suspicious_detected", "branch": "behavioral_analysis",
                "pipeline_summary": pipeline_summary,
                "ai_reasoning": ai_result, "response_plan": response_plan,
                "last_timestamps": collector_result.get("last_timestamps", {})
            }

        return {
            "alert_id": alert_id, "source_ip": source_ip,
            "status": "normal_activity", "branch": "behavioral_analysis",
            "pipeline_summary": pipeline_summary,
            "ai_verdict": verdict,
            "ai_reasoning": ai_result.get("reasoning", ""),
            "forensic_note": "Queue retained 30 minutes for investigation if needed",
            "last_timestamps": collector_result.get("last_timestamps", {})
        }

    async def process_alert(self, alert: dict) -> dict:
        """Trigger 1 — Wazuh alert. Dùng fetch_all_sources (7 nguồn kể cả Wazuh)."""
        data      = alert.get("data", {})
        source_ip = data.get("srcip", "unknown")

        try:
            collector_result = await self._call(
                self.collector_mcp, "fetch_all_sources",
                {"keyword": source_ip, "src_ip": source_ip, "session_id": source_ip}
            )
        except Exception as e:
            return {"alert_id": alert.get("id"), "source_ip": source_ip,
                    "status": "collector_error", "error": str(e)}

        return await self._run_pipeline(
            source_ip=source_ip, trigger_source="wazuh",
            alert_id=alert.get("id", "no_alert"),
            url=data.get("url", "/"),
            rule_description=alert.get("rule", {}).get("description", "N/A"),
            collector_result=collector_result,
        )

    async def process_web_ip(self, source_ip: str, since: dict = None) -> dict:
        """
        Trigger 2 — Web log polling.
        CHỈ lấy web_logs + firewall_logs — KHÔNG lấy Wazuh, auth, audit, container.
        - Web logs: có since filter → chỉ lấy log mới, không duplicate
        - Firewall logs: ít thay đổi, chấp nhận được
        - Auth/audit/container: bỏ qua vì không có since filter → gây loop 4 events
        """
        since          = since or {}
        session_id     = source_ip
        all_events     = []
        last_timestamps = {}

        # ── Web logs — nguồn chính, có since filter ──────────────────────
        try:
            r = await self._call(self.collector_mcp, "fetch_web_logs", {
                "keyword":    source_ip,
                "session_id": session_id,
                "since":      since.get("web", "")
            })
            all_events.extend(r.get("events", []))
            if r.get("last_timestamp"):
                last_timestamps["web"] = r["last_timestamp"]
        except Exception:
            pass

        # ── Container/error logs — DISABLED ─────────────────────────────
        # Apache error.log format: [Fri May 22 13:34:04.496992 2026]
        # Khác hoàn toàn với access.log → filter_since không parse được
        # → lấy lại cùng events mỗi trigger → gây loop
        # Chỉ chứa Apache startup messages, không có giá trị behavioral
        # Bật lại nếu error.log có request-level errors liên quan đến user
        # try:
        #     r = await self._call(self.collector_mcp, "fetch_container_logs", {
        #         "keyword":    source_ip,
        #         "session_id": session_id,
        #         "since":      since.get("container", "")
        #     })
        #     all_events.extend(r.get("events", []))
        #     if r.get("last_timestamp"):
        #         last_timestamps["container"] = r["last_timestamp"]
        # except Exception:
        #     pass

        # ── DB logs — có since_epoch filter ───────────────────────────
        try:
            r = await self._call(self.collector_mcp, "fetch_db_logs", {
                "keyword":     source_ip,
                "session_id":  session_id,
                "since_epoch": since.get("db_epoch", 0.0)
            })
            all_events.extend(r.get("events", []))
            if r.get("last_epoch"):
                last_timestamps["db_epoch"] = r["last_epoch"]
        except Exception:
            pass

        # ── Firewall logs ──────────────────────────────────────────────
        try:
            r = await self._call(self.collector_mcp, "fetch_firewall_logs", {
                "src_ip":     source_ip,
                "session_id": session_id
            })
            all_events.extend(r.get("events", []))
        except Exception:
            pass

        # ── Auth logs — DISABLED: /var/log/auth.log không tồn tại trong container ──
        # Bật lại khi deploy trên host thật có auth log
        # try:
        #     r = await self._call(self.collector_mcp, "fetch_auth_logs", {
        #         "keyword":    source_ip,
        #         "session_id": session_id,
        #         "since":      since.get("auth", "")
        #     })
        #     all_events.extend(r.get("events", []))
        #     if r.get("last_timestamp"):
        #         last_timestamps["auth"] = r["last_timestamp"]
        # except Exception:
        #     pass

        # ── Audit logs — DISABLED: /var/log/audit/audit.log không tồn tại trong container ──
        # Bật lại khi deploy trên host thật có auditd
        # try:
        #     r = await self._call(self.collector_mcp, "fetch_audit_logs", {
        #         "keyword":    source_ip,
        #         "session_id": session_id,
        #         "since":      since.get("audit", "")
        #     })
        #     all_events.extend(r.get("events", []))
        #     if r.get("last_timestamp"):
        #         last_timestamps["audit"] = r["last_timestamp"]
        # except Exception:
        #     pass

        sources_queried = ["web", "db", "firewall"]
        # sources_queried += ["auth", "audit", "container"]  # thêm vào khi bật lại

        collector_result = {
            "events":          all_events,
            "event_count":     len(all_events),
            "sources_queried": sources_queried,
            "last_timestamps": last_timestamps
        }

        return await self._run_pipeline(
            source_ip=source_ip, trigger_source="web_log",
            alert_id=f"web_{source_ip}", url="/",
            rule_description="Web log behavioral trigger",
            collector_result=collector_result,
        )

    async def get_session_status(self, source_ip: str) -> dict:
        return await self._call(self.correlator_mcp, "get_session_status", {"user_id": source_ip})

    async def get_forensic_snapshot(self, source_ip: str) -> dict:
        return await self._call(self.correlator_mcp, "get_forensic_snapshot", {"user_id": source_ip})

    async def list_active_sessions(self) -> dict:
        return await self._call(self.correlator_mcp, "list_active_sessions", {})
