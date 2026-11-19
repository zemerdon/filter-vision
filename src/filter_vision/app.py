"""Network-restricted, passwordless Filter Vision WebUI.

No IMAP credentials are accepted and no mailbox mutation code exists in this build.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .analysis import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, inspect_eml, suggestions, validate_rule
from .storage import Store
from .updates import status as update_status, request_update

# Restrict passwordless administration to explicitly trusted local networks.
# The installer adds the instance network to the trusted list at deployment.
TRUSTED_DEFAULT = ("127.0.0.1/32,::1/128,"
                   "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
COOKIE = "fv_browser"
RELEASE_API = "https://api.github.com/repos/zemerdon/filter-vision/releases/latest"
BASE = Path(__file__).parent


def create_app(data_dir: str | Path | None = None) -> FastAPI:
    data_dir = data_dir or os.environ.get("FV_DATA_DIR", str(Path.home() / ".local/share/filter-vision"))
    store = Store(data_dir)
    templates = Jinja2Templates(directory=str(BASE / "templates"))
    app = FastAPI(title="Filter Vision", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.state.latest = {}
    trusted = tuple(ipaddress.ip_network(c.strip(), strict=False) for c in
                    os.environ.get("FV_TRUSTED_CIDRS", TRUSTED_DEFAULT).split(",") if c.strip())
    if not trusted:
        raise ValueError("FV_TRUSTED_CIDRS cannot be empty")

    def browser_session(request: Request) -> tuple[dict, str | None]:
        cookie = request.cookies.get(COOKIE, "")
        parts = cookie.split(".")
        valid = False
        if len(parts) == 2 and 40 <= len(parts[0]) <= 90 and len(parts[1]) == 64:
            signature = hmac.new(store.browser_key, parts[0].encode(), hashlib.sha256).hexdigest()
            valid = hmac.compare_digest(signature, parts[1])
        if valid:
            token, new_cookie = parts[0], None
        else:
            token = secrets.token_urlsafe(32)
            signature = hmac.new(store.browser_key, token.encode(), hashlib.sha256).hexdigest()
            new_cookie = token + "." + signature
        csrf = hmac.new(store.browser_key, ("csrf:" + token).encode(), hashlib.sha256).hexdigest()
        return {"csrf": csrf}, new_cookie
    app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        try:
            client_ip = ipaddress.ip_address(request.client.host if request.client else "")
            allowed = any(client_ip in network for network in trusted)
        except ValueError:
            allowed = False
        if not allowed:
            return JSONResponse({"detail": "Trusted network access only"}, status_code=403)
        valid_hosts = {h.strip().lower() for h in os.environ.get(
            "FV_ALLOWED_HOSTS", "filter-vision,127.0.0.1,localhost").split(",")}
        requested_host = (request.url.hostname or "").lower()
        if requested_host not in valid_hosts:
            return JSONResponse({"detail": "Untrusted Host header"}, status_code=400)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if origin:
                from urllib.parse import urlsplit
                origin_host = urlsplit(origin).netloc.lower()
                if origin_host != request.headers.get("host", "").lower():
                    return JSONResponse({"detail": "Invalid request origin"}, status_code=403)
        sess, cookie_to_set = browser_session(request)
        request.state.fv_browser_session = sess
        size = request.headers.get("content-length")
        if size and (not size.isdecimal() or int(size) > MAX_TOTAL_BYTES + 150_000):
            return JSONResponse({"detail": "Request too large"}, status_code=413)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        if cookie_to_set:
            response.set_cookie(COOKIE, cookie_to_set, httponly=True,
                                samesite="strict", secure=True, path="/")
        return response

    def session(request: Request):
        return request.state.fv_browser_session

    def render(request, template, active="", status=200, sess=None, **kwargs):
        ctx = {"request": request, "version": __version__, "active": active,
               "logged_in": sess is not None, "csrf": sess["csrf"] if sess else "",
               "offline": True, **kwargs}
        return templates.TemplateResponse(request, template, ctx, status_code=status)

    def guard(request):
        # Network gate and signed browser session are enforced by middleware.
        return session(request), None

    def valid_csrf(sess, value):
        return bool(sess and value and hmac.compare_digest(sess["csrf"], value))

    def invalid_csrf():
        return HTMLResponse("Invalid session or CSRF token", status_code=403)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "filter-vision"}

    @app.get("/setup")
    @app.get("/login")
    def legacy_auth_redirect():
        return RedirectResponse("/", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        with store.db() as con:
            account_count = con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
            rule_count = con.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        return render(request, "dashboard.html", active="dashboard", sess=sess,
                      account_count=account_count, rule_count=rule_count)

    @app.get("/accounts", response_class=HTMLResponse)
    def accounts(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        with store.db() as con:
            accounts = [dict(x) for x in con.execute("SELECT * FROM accounts ORDER BY id DESC")]
        return render(request, "accounts.html", active="accounts", sess=sess, accounts=accounts)

    @app.post("/accounts", response_class=HTMLResponse)
    def account_add(request: Request, csrf: str = Form(""), label: str = Form(""),
                    provider: str = Form("custom"), host: str = Form(""),
                    port: int = Form(993), username: str = Form(""),
                    folder: str = Form("Junk"), interval: int = Form(30)):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if (provider not in {"outlook", "gmail", "custom"}
                or not 1 <= len(label.strip()) <= 80
                or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host)
                or not 1 <= port <= 65535 or not 1 <= interval <= 1440
                or not 3 <= len(username.strip()) <= 254 or not 1 <= len(folder.strip()) <= 120):
            return HTMLResponse("Invalid account configuration", status_code=400)
        with store.db() as con:
            con.execute("INSERT INTO accounts(label,provider,host,port,username,folder,interval_minutes,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (label.strip(), provider, host.lower(), port, username.strip(),
                         folder.strip(), interval, int(time.time())))
        store.audit("account_draft_created", "A disabled account connection draft was saved")
        return RedirectResponse("/accounts", status_code=303)

    @app.get("/analyze", response_class=HTMLResponse)
    def analyze(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        return render(request, "analyze.html", active="analyze", sess=sess, samples=[], suggestions=[])

    @app.post("/analyze", response_class=HTMLResponse)
    async def analyze_post(request: Request, csrf: str = Form(""),
                           files: list[UploadFile] = File(...)):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if not 1 <= len(files) <= MAX_FILES:
            return HTMLResponse("Upload between 1 and 20 .eml files", status_code=400)
        samples, total = [], 0
        try:
            for item in files:
                chunks, size = [], 0
                while chunk := await item.read(64 * 1024):
                    size += len(chunk)
                    total += len(chunk)
                    if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                        raise ValueError("Upload exceeds size limit")
                    chunks.append(chunk)
                samples.append(inspect_eml(item.filename or "", b"".join(chunks)))
        except ValueError as exc:
            return render(request, "analyze.html", active="analyze", sess=sess, samples=[],
                          suggestions=[], error=str(exc), status=400)
        return render(request, "analyze.html", active="analyze", sess=sess,
                      samples=samples, suggestions=suggestions(samples))

    @app.post("/rules", response_class=HTMLResponse)
    def rule_add(request: Request, csrf: str = Form(""), kind: str = Form(""),
                 field: str = Form(""), value: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        try:
            value = validate_rule(kind, field, value)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=400)
        label = f"{field}: {value}"[:200]
        with store.db() as con:
            con.execute("INSERT INTO rules(label,kind,field,pattern,created_at) VALUES(?,?,?,?,?)",
                        (label, kind, field, value, int(time.time())))
        store.audit("rule_draft_created", "An inactive filtering rule was created")
        return RedirectResponse("/rules", status_code=303)

    @app.get("/rules", response_class=HTMLResponse)
    def rules(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        with store.db() as con:
            rules = [dict(x) for x in con.execute("SELECT * FROM rules ORDER BY id DESC")]
        return render(request, "rules.html", active="rules", sess=sess, rules=rules)

    @app.get("/activity", response_class=HTMLResponse)
    def activity(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        with store.db() as con:
            events = [dict(x) for x in con.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT 50")]
        return render(request, "activity.html", active="activity", sess=sess, events=events)

    @app.get("/updates", response_class=HTMLResponse)
    def updates(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        return render(request, "updates.html", active="updates", sess=sess,
                      latest=app.state.latest, update_status=update_status(),
                      request_pending=(store.directory / "update-request").exists())

    @app.post("/updates/check", response_class=HTMLResponse)
    def update_check(request: Request, csrf: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        try:
            request_obj = urllib.request.Request(
                RELEASE_API, headers={"Accept": "application/vnd.github+json",
                                      "User-Agent": f"FilterVision/{__version__}"})
            with urllib.request.urlopen(request_obj, timeout=7) as response:
                blob = response.read(128 * 1024 + 1)
                if len(blob) > 128 * 1024:
                    raise ValueError("Release metadata too large")
                payload = json.loads(blob)
            tag = str(payload.get("tag_name", ""))
            url = str(payload.get("html_url", ""))
            if (not re.fullmatch(r"v\d+\.\d+\.\d+", tag)
                    or payload.get("prerelease") or payload.get("draft")
                    or payload.get("target_commitish") != "stable"):
                raise ValueError("Release must be stable branch, not a draft or prerelease")
            if not url.startswith("https://github.com/zemerdon/filter-vision/releases/tag/"):
                raise ValueError("Unexpected release URL")
            app.state.latest = {"tag": tag, "url": url, "error": "",
                                "is_newer": tuple(map(int, tag[1:].split("."))) >
                                            tuple(map(int, __version__.split(".")))}
        except (urllib.error.URLError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            app.state.latest = {"error": f"Stable release check unavailable: {type(exc).__name__}"}
        return RedirectResponse("/updates", status_code=303)

    @app.post("/updates/apply", response_class=HTMLResponse)
    def apply_stable(request: Request, csrf: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if not app.state.latest.get("is_newer"):
            return HTMLResponse("Check for a newer stable release first", status_code=409)
        try:
            accepted = request_update(store.directory)
        except OSError:
            return HTMLResponse("Cannot queue stable update", status_code=503)
        if not accepted:
            return HTMLResponse("Stable update already queued", status_code=409)
        store.audit("stable_update_requested", "Requested latest stable release (no version override)")
        return RedirectResponse("/updates", status_code=303)

    @app.get("/settings", response_class=HTMLResponse)
    def settings(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        return render(request, "settings.html", active="settings", sess=sess)

    return app
