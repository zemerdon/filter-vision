"""Network-restricted, passwordless Filter Vision WebUI.

Microsoft OAuth2 authorization and read-only IMAP previews are supported;
no automated message-deleting worker exists in this release.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import threading
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .analysis import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, inspect_eml, suggestions, validate_rule
from .storage import Store
from .updates import status as update_status, request_update
from .oauth import (TokenVault, OAuthError, start_device_auth, poll_device_auth,
                    verify_imap_auth, access_token_for,
                    start_browser_auth, redeem_browser_auth)
from .preview import scan_junk_preview, PreviewError

# Restrict passwordless administration to explicitly trusted local networks.
# The installer adds the instance network to the trusted list at deployment.
TRUSTED_DEFAULT = ("127.0.0.1/32,::1/128,"
                   "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
COOKIE = "fv_browser"
RELEASE_API = "https://api.github.com/repos/zemerdon/filter-vision/releases/latest"
BASE = Path(__file__).parent


def is_acceptable_form_origin(origin: str | None, host_header: str, fetch_site: str | None) -> bool:
    """Defence in depth for HTTPS form posts in a passwordless, CSRF-protected UI.

    Browser-origin serialization can omit the default HTTPS port even when
    a reverse-proxy or alternate listener includes a port in Host. Same-host
    implicit-port forms are accepted ONLY because every mutating endpoint
    still verifies a signed, browser-bound CSRF token.

    Explicit different ports, different hosts, HTTP, cross-site fetches and
    malformed Origins remain rejected. Opaque Origins ('null') rely on the
    signed SameSite browser cookie + per-request CSRF validation.
    """
    if fetch_site and fetch_site.lower().strip() == "cross-site":
        return False
    if not origin or not origin.strip():
        return True
    if origin.strip().lower() == "null":
        return True
    try:
        source = urlsplit(origin)
        target = urlsplit("//" + host_header)
        if source.scheme != "https":
            return False
        if not source.hostname or not target.hostname:
            return False
        if source.hostname.lower() != target.hostname.lower():
            return False
        if any((source.username, source.password, source.path, source.query, source.fragment)):
            return False
        # Require port equality when explicitly specified on BOTH sides.
        if source.port is not None and target.port is not None and source.port != target.port:
            return False
        return True
    except ValueError:
        return False


def create_app(data_dir: str | Path | None = None) -> FastAPI:
    data_dir = data_dir or os.environ.get("FV_DATA_DIR", str(Path.home() / ".local/share/filter-vision"))
    store = Store(data_dir)
    templates = Jinja2Templates(directory=str(BASE / "templates"))
    app = FastAPI(title="Filter Vision", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.state.latest = {}
    app.state.oauth_flows = {}
    app.state.oauth_code_flows = {}
    app.state.previews = {}
    app.state.oauth_lock = threading.RLock()
    app.state.token_vault = TokenVault(store.directory)
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
            if not is_acceptable_form_origin(
                request.headers.get("origin"),
                request.headers.get("host", ""),
                request.headers.get("sec-fetch-site"),
            ):
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
        for account in accounts:
            account["oauth_connected"] = app.state.token_vault.connected(account["id"])
            account["preview"] = app.state.previews.get(account["id"])
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

    def oauth_account(account_id: int) -> dict:
        with store.db() as con:
            account = con.execute(
                "SELECT id,label,provider,username FROM accounts WHERE id=?", (account_id,)
            ).fetchone()
        if not account or account["provider"] != "outlook":
            raise HTTPException(status_code=404, detail="Microsoft account not found")
        return dict(account)

    def oauth_page(request: Request, account: dict, error=None, notice=None):
        sess = session(request)
        with app.state.oauth_lock:
            pending = app.state.oauth_flows.get(account["id"])
            if pending and pending["expires_at"] <= int(time.time()):
                app.state.oauth_flows.pop(account["id"], None)
                pending = None
            safe_flow = {
                "user_code": pending["user_code"],
                # Microsoft documents this stable, public device-code entry URL.
                # The response's login.microsoft.com/device URL is not an
                # application callback. The device code stays in the WebUI.
                "verification_uri": "https://microsoft.com/devicelogin",
                "expires_at": pending["expires_at"],
            } if pending else None
            browser_flow = app.state.oauth_code_flows.get(account["id"])
            if browser_flow and browser_flow["expires_at"] <= int(time.time()):
                app.state.oauth_code_flows.pop(account["id"], None)
                browser_flow = None
            safe_browser = {
                "authorization_url": browser_flow["authorization_url"],
                "expires_at": browser_flow["expires_at"],
            } if browser_flow and browser_flow["owner_csrf"] == sess["csrf"] else None
        return render(request, "oauth.html", active="accounts", sess=sess,
                      account=account, flow=safe_flow, browser_flow=safe_browser,
                      error=error, notice=notice,
                      connected=app.state.token_vault.connected(account["id"]))

    @app.get("/accounts/{account_id}/oauth", response_class=HTMLResponse)
    def oauth_view(request: Request, account_id: int):
        return oauth_page(request, oauth_account(account_id))

    @app.post("/accounts/{account_id}/oauth/start", response_class=HTMLResponse)
    def oauth_start(request: Request, account_id: int, csrf: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        account = oauth_account(account_id)
        try:
            flow = start_device_auth(account["username"])
        except OAuthError as error:
            return oauth_page(request, account, error=str(error))
        with app.state.oauth_lock:
            app.state.oauth_flows[account_id] = flow
        return RedirectResponse(f"/accounts/{account_id}/oauth", status_code=303)

    @app.post("/accounts/{account_id}/oauth/poll", response_class=HTMLResponse)
    def oauth_poll(request: Request, account_id: int, csrf: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        account = oauth_account(account_id)
        with app.state.oauth_lock:
            flow = app.state.oauth_flows.get(account_id)
            if not flow:
                return oauth_page(request, account, error="Start Microsoft authorization first")
            try:
                result = poll_device_auth(flow)
            except OAuthError as error:
                return oauth_page(request, account, error=str(error))
            if result["pending"]:
                message = result["detail"]
            else:
                message = None
                tokens = result["tokens"]
        if message:
            return oauth_page(request, account, notice=message)
        try:
            verify_imap_auth(account["username"], tokens["access_token"])
            app.state.token_vault.save(account_id, tokens)
        except OAuthError as error:
            return oauth_page(request, account, error=str(error))
        finally:
            # Avoid leaving authorization response references after completion.
            tokens.clear()
        with app.state.oauth_lock:
            app.state.oauth_flows.pop(account_id, None)
        store.audit("microsoft_oauth_connected", "Account OAuth2 and read-only IMAP authentication verified")
        return RedirectResponse("/accounts", status_code=303)

    @app.post("/accounts/{account_id}/oauth/browser/start", response_class=HTMLResponse)
    def oauth_browser_start(request: Request, account_id: int, csrf: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        account = oauth_account(account_id)
        try:
            flow = start_browser_auth(account["username"])
        except OAuthError as error:
            return oauth_page(request, account, error=str(error))
        flow["owner_csrf"] = sess["csrf"]
        with app.state.oauth_lock:
            app.state.oauth_code_flows[account_id] = flow
        return RedirectResponse(f"/accounts/{account_id}/oauth", status_code=303)

    @app.post("/accounts/{account_id}/oauth/browser/finish", response_class=HTMLResponse)
    def oauth_browser_finish(request: Request, account_id: int,
                             csrf: str = Form(""), callback_url: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        account = oauth_account(account_id)
        with app.state.oauth_lock:
            flow = app.state.oauth_code_flows.pop(account_id, None)
        if not flow or flow["owner_csrf"] != sess["csrf"]:
            return oauth_page(request, account, error="Start a fresh browser sign-in first")
        tokens = None
        try:
            tokens = redeem_browser_auth(flow, callback_url)
            verify_imap_auth(account["username"], tokens["access_token"])
            app.state.token_vault.save(account_id, tokens)
        except OAuthError as error:
            return oauth_page(request, account, error=str(error))
        finally:
            if tokens is not None:
                tokens.clear()
            # Discard verifier and OAuth state after exactly one callback attempt.
            flow.clear()
        store.audit("microsoft_oauth_connected",
                    "Browser authorization + read-only IMAP authentication verified")
        return RedirectResponse("/accounts", status_code=303)

    @app.post("/accounts/{account_id}/preview", response_class=HTMLResponse)
    def preview_account(request: Request, account_id: int, csrf: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        account = oauth_account(account_id)
        if not app.state.token_vault.connected(account_id):
            return HTMLResponse("Authorize this account with Microsoft first", status_code=409)
        with store.db() as con:
            account_row = con.execute("SELECT folder FROM accounts WHERE id=?",
                                      (account_id,)).fetchone()
            rules = [dict(row) for row in con.execute(
                "SELECT r.id,r.kind,r.pattern FROM rules r "
                "JOIN rule_scopes s ON s.rule_id=r.id "
                "WHERE s.account_id=? AND r.kind='legacy_raw_header' "
                "ORDER BY r.id", (account_id,)
            )]
        try:
            token = access_token_for(account_id, account["username"], app.state.token_vault)
            result = scan_junk_preview(account["username"], account_row["folder"], rules, token)
        except (OAuthError, PreviewError):
            return HTMLResponse("Read-only preview failed; check account authorization and Junk access",
                                status_code=502)
        app.state.previews[account_id] = result
        store.audit("read_only_preview",
                    f"Examined {result['examined']}, matched {result['matched']}, "
                    f"truncated={result['truncated']}")
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
