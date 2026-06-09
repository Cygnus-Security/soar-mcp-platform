"""
Firewall Agent — chạy trên host network với quyền NET_ADMIN.
Nhận lệnh block/unblock IP từ response_server qua HTTP.
Tự động unblock sau thời gian timeout.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess
import json
import threading
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FIREWALL] %(message)s")
log = logging.getLogger(__name__)

# IP → unblock_time (epoch)
_blocked: dict = {}
_lock = threading.Lock()

DEFAULT_BLOCK_DURATION = 1800  # 30 phút


def run_iptables(args: list) -> tuple[bool, str]:
    """Chạy lệnh iptables, trả về (success, output)."""
    try:
        r = subprocess.run(
            ["iptables"] + args,
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return True, r.stdout.strip()
        return False, r.stderr.strip()
    except Exception as e:
        return False, str(e)


def block_ip(ip: str, duration: int = DEFAULT_BLOCK_DURATION) -> dict:
    """Block IP bằng iptables DROP, tự unblock sau duration giây."""
    with _lock:
        if ip in _blocked:
            return {"status": "already_blocked", "ip": ip,
                    "unblock_at": _blocked[ip]}

        # Thêm rule DROP
        ok, out = run_iptables(["-I", "INPUT", "-s", ip, "-j", "DROP"])
        if not ok:
            log.error(f"block {ip} failed: {out}")
            return {"status": "error", "ip": ip, "reason": out}

        unblock_at = time.time() + duration
        _blocked[ip] = unblock_at
        log.info(f"BLOCKED {ip} for {duration}s (until {time.ctime(unblock_at)})")

        # Schedule tự unblock
        t = threading.Timer(duration, _auto_unblock, args=[ip])
        t.daemon = True
        t.start()

        return {"status": "blocked", "ip": ip,
                "duration": duration, "unblock_at": unblock_at}


def unblock_ip(ip: str) -> dict:
    """Xóa rule DROP cho IP."""
    with _lock:
        ok, out = run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])
        _blocked.pop(ip, None)
        if ok:
            log.info(f"UNBLOCKED {ip}")
            return {"status": "unblocked", "ip": ip}
        return {"status": "error", "ip": ip, "reason": out}


def _auto_unblock(ip: str):
    """Tự động unblock sau timeout."""
    with _lock:
        if ip not in _blocked:
            return
        run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])
        _blocked.pop(ip, None)
        log.info(f"AUTO-UNBLOCKED {ip}")


def list_blocked() -> list:
    """Trả về danh sách IP đang bị block."""
    with _lock:
        now = time.time()
        return [
            {"ip": ip, "remaining": round(t - now, 0)}
            for ip, t in _blocked.items()
            if t > now
        ]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # tắt default HTTP log

    def _send(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length)) if length else {}

        if self.path == "/block":
            ip       = body.get("ip")
            duration = int(body.get("duration", DEFAULT_BLOCK_DURATION))
            if not ip:
                self._send(400, {"error": "missing ip"})
                return
            self._send(200, block_ip(ip, duration))

        elif self.path == "/unblock":
            ip = body.get("ip")
            if not ip:
                self._send(400, {"error": "missing ip"})
                return
            self._send(200, unblock_ip(ip))

        else:
            self._send(404, {"error": "unknown endpoint"})

    def do_GET(self):
        if self.path == "/status":
            self._send(200, {"blocked": list_blocked(), "count": len(_blocked)})
        elif self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "unknown endpoint"})


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 9999), Handler)
    log.info("Firewall Agent listening on :9999")
    server.serve_forever()
