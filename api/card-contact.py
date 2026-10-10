from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib import request as urlrequest, error as urlerror
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = Path(__file__).with_name("card-runtime-config.json")
DEFAULT_REGISTRA = Path(os.environ.get(
    "REGISTRA_CONTATTO_SCRIPT",
    "/root/.openclaw/workspace/skills/registra-contatto/tools/registra_contatto.py",
))
ROBOTS = "noindex, nofollow, noarchive, nosnippet, noimageindex"
MAX_BODY = 12_000
RATE_WINDOW_SECONDS = 600
RATE_MAX = 6


def _json(status, payload, extra_headers=None):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Robots-Tag": ROBOTS,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-Card-Request-Id",
    }
    headers.update(extra_headers or {})
    return status, headers, body


def _origin_headers(origin):
    allowed = [o.strip() for o in os.environ.get("CARD_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    if not allowed:
        allowed = [
            "https://pages.riccardoromano.biz",
            "https://riccardoromano-site.vercel.app",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]
    if origin and origin in allowed:
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
    return {}


def _clean(value, limit=140):
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _email(value):
    v = _clean(value, 180).lower()
    if not v:
        return ""
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
        raise ValueError("Email non valida")
    return v


def _phone(value):
    v = _clean(value, 40)
    if not v:
        return ""
    if not re.fullmatch(r"[+()\d .\-]{7,40}", v):
        raise ValueError("Telefono non valido")
    return v


def _client_key(headers):
    raw = headers.get("x-forwarded-for") or headers.get("x-real-ip") or "unknown"
    ip = raw.split(",")[0].strip()
    return hashlib.sha256(ip.encode()).hexdigest()[:24]


def _rate_limit(headers):
    key = _client_key(headers)
    now = int(time.time())
    bucket = Path("/tmp") / f"card-contact-{key}.json"
    events = []
    if bucket.exists():
        try:
            events = json.loads(bucket.read_text())
        except Exception:
            events = []
    events = [ts for ts in events if now - int(ts) < RATE_WINDOW_SECONDS]
    if len(events) >= RATE_MAX:
        return False
    events.append(now)
    bucket.write_text(json.dumps(events))
    return True


def _read_runtime_config():
    url = os.environ.get("CARD_RUNTIME_CONFIG_URL", "").strip()
    if url:
        with urlrequest.urlopen(url, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    return json.loads(DEFAULT_CONFIG.read_text())


def _crm_context():
    cfg = _read_runtime_config()
    bc = cfg.get("business_card") or {}
    return _clean(bc.get("crm_context") or "Business card digitale", 220)


def _verify_turnstile(token, remote_ip):
    secret = (os.environ.get("TURNSTILE_SECRET_KEY") or os.environ.get("CLOUDFLARE_TURNSTILE_SECRET_KEY") or "").strip()
    if not secret:
        return True, "not_configured"
    if not token:
        return False, "missing_token"
    data = json.dumps({"secret": secret, "response": token, "remoteip": remote_ip or ""}).encode()
    req = urlrequest.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=6) as res:
            payload = json.loads(res.read().decode("utf-8"))
            return bool(payload.get("success")), "verified" if payload.get("success") else "failed"
    except (urlerror.URLError, TimeoutError, ValueError):
        return False, "verification_error"


def _canonical_text(payload, context):
    parts = [
        "/contatto",
        f"Nome: {payload['firstName']}",
        f"Cognome: {payload.get('lastName') or ''}",
        f"Email personale: {payload.get('email') or ''}",
        f"Telefono: {payload.get('phone') or ''}",
        "Provenienza: Business Card",
        f"Contesto: {context}",
        "Relazione: Inbound da business card digitale",
        "Note: Acquisito tramite form pubblico /card",
    ]
    return "\n".join(parts)


def _write_crm(payload, context, request_id):
    script = Path(os.environ.get("REGISTRA_CONTATTO_SCRIPT", str(DEFAULT_REGISTRA)))
    if not script.exists():
        raise RuntimeError("REGISTRA_CONTATTO_SCRIPT non disponibile sul runtime server-side")
    cmd = [sys.executable, str(script), _canonical_text(payload, context), "--sheet-only", "--request-id", request_id]
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    proc = subprocess.run(cmd, cwd=str(script.parents[3]) if len(script.parents) >= 4 else None, env=env, text=True, capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "CRM writer failed")[-900:])
    return proc.stdout[-1200:]


def handle(method, raw_body, headers):
    origin_headers = _origin_headers(headers.get("Origin"))
    if method == "OPTIONS":
        return _json(204, {}, origin_headers)
    if method != "POST":
        return _json(405, {"ok": False, "error": "method_not_allowed"}, origin_headers)
    if not _rate_limit(headers):
        return _json(429, {"ok": False, "error": "rate_limited"}, origin_headers)
    if len(raw_body or b"") > MAX_BODY:
        return _json(413, {"ok": False, "error": "payload_too_large"}, origin_headers)
    try:
        data = json.loads((raw_body or b"{}").decode("utf-8"))
        if _clean(data.get("website"), 80):
            return _json(200, {"ok": True, "status": "accepted"}, origin_headers)
        payload = {
            "firstName": _clean(data.get("firstName"), 80),
            "lastName": _clean(data.get("lastName"), 80),
            "email": _email(data.get("email")),
            "phone": _phone(data.get("phone")),
        }
        if not payload["firstName"]:
            raise ValueError("Nome obbligatorio")
        if not payload["email"] and not payload["phone"]:
            raise ValueError("Inserisci almeno email o telefono")
        remote_ip = (headers.get("x-forwarded-for") or "").split(",")[0].strip()
        ok, turnstile_status = _verify_turnstile(data.get("turnstileToken"), remote_ip)
        if not ok:
            return _json(400, {"ok": False, "error": "turnstile_failed", "status": turnstile_status}, origin_headers)
        request_id = _clean(headers.get("X-Card-Request-Id"), 80) or f"card-{uuid.uuid4().hex[:16]}"
        context = _crm_context()
        _write_crm(payload, context, request_id)
        return _json(200, {"ok": True, "message": "Perfetto, restiamo in contatto."}, origin_headers)
    except ValueError as exc:
        return _json(400, {"ok": False, "error": str(exc)}, origin_headers)
    except Exception:
        return _json(500, {"ok": False, "error": "crm_unavailable"}, origin_headers)


class handler(BaseHTTPRequestHandler):
    def _send(self, result):
        status, headers, body = result
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(handle("OPTIONS", b"", self.headers))

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        self._send(handle("POST", self.rfile.read(length), self.headers))

    def do_GET(self):
        self._send(_json(405, {"ok": False, "error": "method_not_allowed"}, _origin_headers(self.headers.get("Origin"))))
