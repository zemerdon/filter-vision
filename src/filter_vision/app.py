"""Authenticated, offline-only Filter Vision WebUI v0.1.0.

No IMAP credentials are accepted and no mailbox mutation code exists in this build.
"""
from __future__ import annotations

import hashlib
import hmac
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

SALT_ITERATIONS = 450_000
SESSION_SECONDS = 12 * 3600
RELEASE_API = "https://api.github.com/repos/zemerdon/filter-vision/releases/latest"
BASE = Path(__file__).parent


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(24)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, SALT_ITERATIONS)
    return f"pbkdf2_sha256:{SALT_ITERATIONS}:{salt.hex()}:{key.hex()}"


def password_ok(password: str, hashed: str) -> bool:
    try:
        algorithm, rounds, salt, expected = hashed.split(":")
        if algorithm != "pbkdf2_sha256" or not 100_000 <= int(rounds) <= 1_000_000:
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(calc, bytes.fromhex(expected))
    except (TypeError, ValueError):
        return False


def create_app(data_dir: str | Path | None = None) -> FastAPI:
    data_dir = data_dir or os.environ.get("FV_DATA_DIR", str(Path.home() / ".local/share/filter-vision"))
    store = Store(data_dir)
    templates = Jinja2Templates(directory=str(BASE / "templates"))
    app = FastAPI(title="Filter Vision", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.state.latest = {}
    app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
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
        return response

    def session(request: Request):
        token = request.cookies.get("fv_session", "")
        if not 35 <= len(token) <= 100:
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        with store.db() as con:
            row = con.execute("SELECT token_hash, csrf, expires_at FROM sessions "
                              "WHERE token_hash=? AND expires_at>?", (digest, int(time.time()))).fetchone()
            return dict(row) if row else None

    def render(request, template, active="", status=200, sess=None, **kwargs):
        ctx = {"request": request, "version": __version__, "active": active,
               "logged_in": sess is not None, "csrf": sess["csrf"] if sess else "",
               "offline": True, **kwargs}
        return templates.TemplateResponse(request, template, ctx, status_code=status)

    def guard(request):
        sess = session(request)
        return sess, None if sess else RedirectResponse("/login", status_code=303)

    def valid_csrf(sess, value):
        return bool(sess and value and hmac.compare_digest(sess["csrf"], value))

    def invalid_csrf():
        return HTMLResponse("Invalid session or CSRF token", status_code=403)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "filter-vision"}

    @app.get("/setup", response_class=HTMLResponse)
    def setup(request: Request):
        if store.has_admin():
            return RedirectResponse("/login", status_code=303)
        return render(request, "setup.html", active="setup")

    @app.post("/setup", response_class=HTMLResponse)
    def setup_post(request: Request, setup_code: str = Form(""),
                   password: str = Form(""), password_confirm: str = Form("")):
        if store.has_admin():
            return RedirectResponse("/login", status_code=303)
        if not store.setup_path.exists() or not hmac.compare_digest(
            setup_code.strip(), store.setup_path.read_text().strip()
        ):
            return render(request, "setup.html", status=400, error="Invalid setup code")
        if len(password) < 12 or len(password) > 200 or password != password_confirm:
            return render(request, "setup.html", status=400,
                          error="Passwords must match and contain 12–200 characters")
        try:
            with store.db() as con:
                con.execute("INSERT INTO admins (id,password_hash,created_at) VALUES (1,?,?)",
                            (password_hash(password), int(time.time())))
        except sqlite3.IntegrityError:
            return RedirectResponse("/login", status_code=303)
        store.setup_path.unlink(missing_ok=True)
        store.audit("admin_initialized", "Local administrator created")
        return RedirectResponse("/login?created=1", status_code=303)

    @app.get("/login", response_class=HTMLResponse)
    def login(request: Request):
        if not store.has_admin():
            return RedirectResponse("/setup", status_code=303)
        if session(request):
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", active="login",
                      notice="Administrator created. Sign in." if request.query_params.get("created") else None)

    @app.post("/login", response_class=HTMLResponse)
    def login_post(request: Request, password: str = Form("")):
        if not store.has_admin():
            return RedirectResponse("/setup", status_code=303)
        client = (request.client.host if request.client else "unknown")[:80]
        now = int(time.time())
        with store.db() as con:
            attempt = con.execute("SELECT count,last_attempt FROM login_attempts WHERE client=?",
                                  (client,)).fetchone()
            if attempt and attempt["last_attempt"] > now - 900 and attempt["count"] >= 8:
                return render(request, "login.html", status=429, error="Too many attempts. Try again later.")
            admin = con.execute("SELECT password_hash FROM admins WHERE id=1").fetchone()
            if not admin or not password_ok(password, admin["password_hash"]):
                count = attempt["count"] + 1 if attempt and attempt["last_attempt"] > now - 900 else 1
                con.execute("INSERT INTO login_attempts(client,count,last_attempt) VALUES(?,?,?) "
                            "ON CONFLICT(client) DO UPDATE SET count=excluded.count,last_attempt=excluded.last_attempt",
                            (client, count, now))
                return render(request, "login.html", status=401, error="Incorrect password")
            con.execute("DELETE FROM login_attempts WHERE client=?", (client,))
            token = secrets.token_urlsafe(40)
            digest = hashlib.sha256(token.encode()).hexdigest()
            csrf = secrets.token_urlsafe(32)
            con.execute("INSERT INTO sessions(token_hash,admin_id,csrf,expires_at) VALUES(?,1,?,?)",
                        (digest, csrf, now + SESSION_SECONDS))
        response = RedirectResponse("/", status_code=303)
        response.set_cookie("fv_session", token, max_age=SESSION_SECONDS, httponly=True,
                            samesite="strict", secure=os.environ.get("FV_SECURE_COOKIES", "0") == "1",
                            path="/")
        return response

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        with store.db() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (sess["token_hash"],))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie("fv_session", path="/")
        return response

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        if not store.has_admin():
            return RedirectResponse("/setup", status_code=303)
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
        return render(request, "updates.html", active="updates", sess=sess, latest=app.state.latest)

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
            if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
                raise ValueError("No valid stable release tag returned")
            if not url.startswith("https://github.com/zemerdon/filter-vision/releases/tag/"):
                raise ValueError("Unexpected release URL")
            app.state.latest = {"tag": tag, "url": url, "error": "",
                                "is_newer": tuple(map(int, tag[1:].split("."))) >
                                            tuple(map(int, __version__.split(".")))}
        except (urllib.error.URLError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            app.state.latest = {"error": f"Stable release check unavailable: {type(exc).__name__}"}
        return RedirectResponse("/updates", status_code=303)

    @app.get("/settings", response_class=HTMLResponse)
    def settings(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        return render(request, "settings.html", active="settings", sess=sess)

    return app
