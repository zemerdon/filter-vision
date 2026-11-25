"""Network-restricted, passwordless Filter Vision WebUI.

Microsoft browser authorization, read-only previews and root-approved
legacy-compatible live Junk filtering are supported.
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
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import FastAPI, File, Form, Request, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .analysis import (MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES,
                       inspect_eml, suggestions, coverage_options, validate_rule,
                       candidate_signature, candidate_token)
from .rule_management import (
    RULE_DEFINITIONS, DRAFT_KINDS, RuleManagementError, draft_guard,
    update_draft, duplicate_draft, delete_draft,
)
from .rule_reviews import (
    LEGACY_CODE, source_snapshot, queue_review, load_review,
    revise_review, cancel_review,
)
from .storage import Store, ACTIVITY_LIMITS
from .history import report as history_report
from .release_notes import changelog_items
from .updates import status as update_status, request_update
from .oauth import (TokenVault, OAuthError, start_device_auth, poll_device_auth,
                    verify_imap_auth, access_token_for,
                    start_browser_auth, redeem_browser_auth)
from .preview import scan_junk_preview, PreviewError
from .junk_browse import list_junk, fetch_selected, BrowseError, MAX_SELECTED
from .analysis_session import AnalysisMemory
from .draft_saving import (saved_signatures, save_disabled_drafts,
                           save_enable_candidates, MAX_BATCH_DRAFTS)
from .manual_eval import evaluate, FIELD_OPTIONS, OPERATORS
from .live import load_policy, LiveSafetyError
from .control import (control_view, request_control, ControlError,
                      INTERVALS, ACTIONS, service_status)
from .rule_activation import (read_approvals, source_digest, ActivationError,
                              _draft_rule)
from .activation_preview import preview_rule, preview_rules, ApprovalPreviewError
from .control import (request_rule_control, request_managed_control,
                      request_batch_enable, request_rules_bulk)
from .managed_rules import (read_managed, effective, normalize, ManagedError)
from .bulk_rule_management import (validate_ids, duplicate_rules, delete_rules,
                                    MAX_RULES_BULK)



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
    # One-use, browser-bound status only. Never store callback URLs or codes.
    app.state.oauth_feedback = {}
    app.state.previews = {}
    app.state.analysis_memory = AnalysisMemory()
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
            "script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
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
        live_count = len(live_account_ids())
        schedule_active = service_status()["schedule_active"]
        return render(request, "dashboard.html", active="dashboard", sess=sess,
                      account_count=account_count, rule_count=rule_count,
                      live_count=live_count, schedule_active=schedule_active)

    def live_account_ids():
        try:
            return set(load_policy()["accounts"])
        except (LiveSafetyError, OSError, ValueError, KeyError):
            return set()

    @app.get("/accounts", response_class=HTMLResponse)
    def accounts(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        with store.db() as con:
            accounts = [dict(x) for x in con.execute("SELECT * FROM accounts ORDER BY id DESC")]
        live_ids = live_account_ids()
        schedule = service_status()
        for account in accounts:
            account["oauth_connected"] = app.state.token_vault.connected(account["id"])
            account["preview"] = app.state.previews.get(account["id"])
            account["live_active"] = account["id"] in live_ids
        return render(request, "accounts.html", active="accounts", sess=sess,
                      accounts=accounts, live_count=len(live_ids),
                      schedule_active=schedule["schedule_active"],
                      effective_interval=schedule["interval"])

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

    def oauth_page(request: Request, account: dict, error=None, notice=None,
                   browser_error=None):
        sess = session(request)
        with app.state.oauth_lock:
            flash = app.state.oauth_feedback.pop((account["id"], sess["csrf"]), None)
            if flash:
                browser_error = flash["message"]
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
                      error=error, notice=notice, browser_error=browser_error,
                      live_active=account["id"] in live_account_ids(),
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

        def failed(stage: str, message: str):
            # The callback URL contains a one-time secret: NEVER log it, store it,
            # return it to the browser, or include a source exception in an audit.
            # Restrict the stage and message to predefined, safe status categories.
            known = {
                "missing_flow", "callback", "microsoft_error",
                "token_exchange", "imap_validation", "token_storage",
            }
            assert stage in known
            message = str(message)[:400]
            with app.state.oauth_lock:
                app.state.oauth_feedback[(account_id, sess["csrf"])] = {
                    "message": message,
                }
            store.audit("microsoft_browser_auth_failed", "stage=" + stage)
            # A redirect with an anchor scrolls to the result beside the form,
            # especially on phones. It also prevents accidental POST replay.
            return RedirectResponse(
                f"/accounts/{account_id}/oauth#browser-result", status_code=303
            )

        with app.state.oauth_lock:
            flow = app.state.oauth_code_flows.pop(account_id, None)
        if not flow or flow["owner_csrf"] != sess["csrf"]:
            return failed("missing_flow",
                          "No active browser authorization was found for this tab. "
                          "Start Microsoft Browser Sign-In again and complete it in the same browser.")
        tokens = None
        try:
            try:
                tokens = redeem_browser_auth(flow, callback_url)
            except OAuthError as error:
                reason = str(error)
                if reason.startswith("Microsoft denied browser authorization"):
                    return failed("microsoft_error", reason +
                                  ". Start a fresh browser sign-in after resolving Microsoft's error.")
                if (reason.startswith("Microsoft could not redeem")
                        or reason.startswith("Microsoft authorization service")):
                    return failed("token_exchange", reason +
                                  ". The one-time code has been consumed or may have expired; "
                                  "start a fresh sign-in.")
                return failed("callback", reason +
                              ". No account was connected; start a fresh browser sign-in and paste "
                              "the complete final localhost URL with code and state.")
            try:
                verify_imap_auth(account["username"], tokens["access_token"])
            except OAuthError:
                return failed("imap_validation",
                              "Microsoft issued authorization, but Outlook IMAP rejected the login "
                              "or could not be reached. No account was connected. "
                              "Please start a fresh sign-in; IMAP diagnostics may be needed.")
            try:
                app.state.token_vault.save(account_id, tokens)
            except (OSError, OAuthError, ValueError):
                return failed("token_storage",
                              "Microsoft authorization and IMAP validation succeeded, but "
                              "the encrypted credentials could not be saved. No account was connected.")
        finally:
            if tokens is not None:
                tokens.clear()
            # Never retain a one-use state, verifier or authorization URL after POST.
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

    def connected_junk_accounts() -> list[dict]:
        """Only already-authorized, properly configured Microsoft Junk accounts."""
        with store.db() as con:
            rows = [dict(x) for x in con.execute(
                "SELECT id,label,provider,host,port,username,folder FROM accounts "
                "WHERE provider='outlook' AND host='outlook.office365.com' "
                "AND port=993 AND folder='Junk' ORDER BY id")]
        return [row for row in rows if app.state.token_vault.connected(row["id"])][:8]

    def analyze_page(request: Request, sess: dict, *, error=None,
                     manual_report=None, manual_input=None, status=200):
        state = app.state.analysis_memory.read(sess["csrf"])
        samples = state["samples"]
        with store.db() as con:
            existing = saved_signatures(con)
        available = [candidate for candidate in suggestions(samples)
                     if not candidate.get("can_save")
                     or candidate_signature(candidate["kind"], candidate["field"],
                                            candidate["value"]) not in existing]
        saved = request.query_params.get("saved", "")
        saved_count = int(saved) if saved.isdecimal() and int(saved) <= MAX_BATCH_DRAFTS else None
        batch = state.get("batch")
        batch_status = ""
        batch_waiting = False
        if batch:
            current = control_view(store.directory)
            last = current["last_action"]
            if last.get("batch_id") == batch["batch_id"] and last.get("state") == "success":
                try:
                    approvals = {entry["id"]: entry for entry in read_approvals()}
                    confirmed = all(
                        item["id"] in approvals
                        and approvals[item["id"]]["sha256"] == item["sha256"]
                        and set(batch["accounts"]).issubset(
                            approvals[item["id"]]["accounts"])
                        for item in batch["entries"])
                except (ActivationError, OSError):
                    confirmed = False
                batch_status = (f"{len(batch['entries'])} rules enabled on "
                                f"{len(batch['accounts'])} account(s)." if confirmed
                                else "Batch finished, but protected approval could not be verified.")
            elif last.get("batch_id") == batch["batch_id"] and last.get("state") == "failed":
                batch_status = "Batch enable failed. Drafts remain disabled; review Rules."
            elif (current["request_pending"]
                  or (last.get("batch_id") == batch["batch_id"]
                      and last.get("state") == "processing")):
                batch_waiting = True
                batch_status = ("Enabling selected rules is pending root verification. "
                                "No activation is confirmed yet.")
            else:
                batch_status = ("Batch activation not confirmed. "
                                "Saved drafts remain on the Rules page.")
        available = [dict(candidate, token=candidate_token(candidate))
                     for candidate in available]
        return render(request, "analyze.html", active="analyze", sess=sess,
                      samples=samples, suggestions=available,
                      coverage_options=sorted(
                          coverage_options(samples, existing),
                          key=lambda p: {"sender_domain": 0, "compact": 1,
                                         "sender_exact": 2}.get(p["kind"], 3)),
                      saved_count=saved_count, batch_status=batch_status,
                      batch_waiting=batch_waiting,
                      catalog=state["catalog"], catalog_scanned=state["catalog_scanned"],
                      connected_accounts=connected_junk_accounts(),
                      manual_fields=FIELD_OPTIONS, manual_operators=OPERATORS,
                      manual_report=manual_report, manual_input=manual_input or {},
                      error=error, status=status)

    @app.get("/analyze", response_class=HTMLResponse)
    def analyze(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        return analyze_page(request, sess)

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
            return analyze_page(request, sess, error=str(exc), status=400)
        app.state.analysis_memory.write(sess["csrf"], samples=samples)
        store.audit("analyze_uploaded", f"count={len(samples)}")
        return analyze_page(request, sess)

    @app.post("/analyze/junk/scan", response_class=HTMLResponse)
    def scan_junk_for_analysis(request: Request, csrf: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        accounts = connected_junk_accounts()
        if not accounts:
            return analyze_page(request, sess,
                                error="Connect a Microsoft Outlook/Hotmail account first",
                                status=409)
        catalog = []
        failures = 0
        for account in accounts:
            try:
                token = access_token_for(
                    account["id"], account["username"], app.state.token_vault)
                catalog.extend(list_junk(account, token))
            except (OAuthError, BrowseError):
                failures += 1
        app.state.analysis_memory.write(
            sess["csrf"], catalog=catalog, samples=[], catalog_scanned=True)
        store.audit("analyze_junk_scanned",
                    f"accounts={len(accounts)} listed={len(catalog)} failed={failures}")
        if failures:
            return analyze_page(request, sess,
                                error=f"{failures} Junk folder(s) could not be read. "
                                      "Reconnect an affected Microsoft account and scan again.",
                                status=502 if not catalog else 200)
        return analyze_page(request, sess)

    @app.post("/analyze/junk/select", response_class=HTMLResponse)
    def analyze_selected_junk(request: Request, csrf: str = Form(""),
                              selected: list[str] = Form([]),
                              select_all: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        catalog = app.state.analysis_memory.read(sess["csrf"])["catalog"]
        # Without JS the master checkbox still works, capped to 20 UIDs.
        if select_all == "yes":
            selected = [row["ref"] for row in catalog[:MAX_SELECTED]]
        elif select_all:
            return analyze_page(request, sess, error="Invalid selection option", status=400)
        if not 1 <= len(selected) <= MAX_SELECTED or len(set(selected)) != len(selected):
            return analyze_page(request, sess, error="Select 1–20 distinct Junk messages",
                                status=400)
        choices = {row["ref"]: row for row in catalog}
        if any(ref not in choices for ref in selected):
            return analyze_page(request, sess, error="Selection expired. Scan Junk again.",
                                status=410)
        connected = {row["id"]: row for row in connected_junk_accounts()}
        buckets: dict[int, list[dict]] = {}
        for ref in selected:
            row = choices[ref]
            if row["account_id"] not in connected:
                return analyze_page(request, sess,
                                    error="Connected account changed. Scan Junk again.",
                                    status=409)
            buckets.setdefault(row["account_id"], []).append(row)
        samples = []
        try:
            for account_id, items in buckets.items():
                account = connected[account_id]
                token = access_token_for(
                    account_id, account["username"], app.state.token_vault)
                batch = fetch_selected(account, items, token,
                                       remaining_budget=MAX_TOTAL_BYTES -
                                       sum(sample.get("_analysis_size", 0)
                                           for sample in samples))
                samples.extend(batch)
        except (BrowseError, OAuthError, ValueError):
            return analyze_page(request, sess,
                                error="Read-only selection failed or messages changed. "
                                      "Scan Junk and select again.", status=409)
        for sample in samples:
            sample.pop("_analysis_size", None)
        app.state.analysis_memory.write(sess["csrf"], samples=samples)
        store.audit("analyze_junk_selected",
                    f"count={len(samples)} accounts={len(buckets)}")
        return analyze_page(request, sess)

    @app.post("/analyze/manual", response_class=HTMLResponse)
    def evaluate_manual(request: Request, csrf: str = Form(""),
                        field: str = Form("from_domain"),
                        operator: str = Form("wildcard"),
                        value: str = Form(""), header_name: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        state = app.state.analysis_memory.read(sess["csrf"])
        inputs = {"field": field, "operator": operator,
                  "value": value, "header_name": header_name}
        try:
            result = evaluate(state["samples"], field, operator, value, header_name)
        except ValueError as error:
            return analyze_page(request, sess, error=str(error),
                                manual_input=inputs, status=400)
        store.audit("analyze_manual_evaluated",
                    f"sample_count={result['total']} matched={result['count']}")
        return analyze_page(request, sess, manual_report=result, manual_input=inputs)

    @app.post("/analyze/candidate", response_class=HTMLResponse)
    def save_analyzed_candidate(request: Request, csrf: str = Form(""),
                                token: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        samples = app.state.analysis_memory.read(sess["csrf"])["samples"]
        if not samples:
            return HTMLResponse("Analysis expired; analyze messages again", status_code=410)
        with store.db() as con:
            existing = saved_signatures(con)
        available = [candidate for candidate in suggestions(samples)
                     if candidate.get("can_save")
                     and candidate_signature(candidate["kind"], candidate["field"],
                                             candidate["value"]) not in existing]
        candidate = next((c for c in available if candidate_token(c) == token), None)
        if candidate is None:
            return HTMLResponse("Rule was not offered or has already been saved", status_code=409)
        added = save_disabled_drafts(store, [(
            candidate["kind"], candidate["field"], candidate["value"])])
        return RedirectResponse(f"/analyze?saved={added}", status_code=303)

    @app.post("/analyze/drafts", response_class=HTMLResponse)
    def save_analysis_drafts(request: Request, csrf: str = Form(""),
                             plan: str = Form(""),
                             selected: list[str] = Form([]),
                             select_all: str = Form(""),
                             single: str = Form(""),
                             intent: str = Form("save")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if select_all not in ("", "yes") or intent not in ("save", "enable"):
            return HTMLResponse("Invalid selection option", status_code=400)
        if single and intent != "save":
            return HTMLResponse("Invalid individual rule action", status_code=400)
        samples = app.state.analysis_memory.read(sess["csrf"])["samples"]
        if not samples:
            return HTMLResponse("Analysis expired; analyze messages again", status_code=410)
        with store.db() as con:
            existing = saved_signatures(con)
        current = next((candidate for candidate in coverage_options(samples, existing)
                        if candidate["kind"] == plan), None)
        if current is None:
            return HTMLResponse("No new candidates in this plan", status_code=409)
        offered = {item["token"]: item for item in current["items"]}
        if single:
            tokens = [single]
        elif select_all == "yes":
            tokens = list(offered)
        else:
            tokens = selected
        if (not 1 <= len(tokens) <= MAX_BATCH_DRAFTS or
                len(set(tokens)) != len(tokens) or
                any(token not in offered for token in tokens)):
            return HTMLResponse("Invalid or stale rule selection", status_code=400)
        rows = [(offered[token]["kind"], offered[token]["field"],
                 offered[token]["value"]) for token in tokens]
        if intent == "enable":
            if len(rows) > 32:
                return HTMLResponse("Select no more than 32 rules for activation", status_code=400)
            try:
                control = control_view(store.directory)
                if not control["control_installed"] or control["request_pending"]:
                    return HTMLResponse("Protected rule control unavailable or busy",
                                        status_code=409)
                policy = load_policy()
                accounts = sorted(policy["accounts"])
                if not accounts or not all(app.state.token_vault.connected(i)
                                           for i in accounts):
                    return HTMLResponse("Approved Microsoft accounts must be connected",
                                        status_code=409)
                if len(read_approvals()) + len(rows) > 64:
                    return HTMLResponse("Custom rule approval limit reached", status_code=409)
                # One read-only Junk pass for all rules, both approved accounts.
                # A failed result for even one account blocks the whole batch.
                preview_rules(store, [
                    {"kind": kind, "field": field, "pattern": value,
                     "label": "Candidate preview"} for kind, field, value in rows
                ], accounts, app.state.token_vault)
                entries = save_enable_candidates(store, rows)
                batch_id = secrets.token_hex(12)
                queued = request_batch_enable(store.directory, entries, accounts, batch_id)
                if not queued:
                    return HTMLResponse(
                        "Rules saved as disabled drafts, but another control action "
                        "started. No activation was queued.", status_code=409)
                app.state.analysis_memory.set_batch(sess["csrf"], {
                    "batch_id": batch_id, "entries": entries, "accounts": accounts})
                store.audit("rule_batch_enable_queued", f"count={len(entries)}")
            except (LiveSafetyError, ActivationError, ApprovalPreviewError,
                    ControlError, OSError, ValueError, TypeError):
                return HTMLResponse(
                    "Batch activation not approved. No rule was enabled; "
                    "check saved drafts before retrying.", status_code=409)
            return RedirectResponse("/analyze", status_code=303)
        try:
            added = save_disabled_drafts(store, rows)
        except ValueError:
            return HTMLResponse("Selected rule definition is no longer valid",
                                status_code=400)
        return RedirectResponse(f"/analyze?saved={added}", status_code=303)

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
        save_disabled_drafts(store, [(kind, field, value)])
        return RedirectResponse("/rules", status_code=303)

    @app.get("/rules", response_class=HTMLResponse)
    def rules(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        with store.db() as con:
            rules = [dict(x) for x in con.execute("SELECT * FROM rules ORDER BY id DESC")]
            scope_ids = {r[0] for r in con.execute("SELECT DISTINCT rule_id FROM rule_scopes")}
            accounts = [dict(x) for x in con.execute("SELECT id,label FROM accounts ORDER BY id")]
            reviews = [dict(x) for x in con.execute(
                "SELECT * FROM rule_review_requests "
                "WHERE status='pending_review' ORDER BY id DESC LIMIT 100")]
        approved = live_account_ids()
        legacy_ids = {r["id"] for r in rules if r["kind"] == "legacy_raw_header"}
        active_legacy = set(legacy_ids) if approved else set()
        activation_error = ""
        custom_active = {}
        managed_legacy = {}
        managed_custom = {}
        try:
            saved = read_approvals()
            managed = read_managed()
            original = {r["id"]: dict(r) for r in rules}
            for entry in managed["legacy"]:
                source = original.get(entry["id"])
                if (source is None or source["kind"] != "legacy_raw_header"
                        or source_digest(source) != entry["sha256"]):
                    raise ManagedError("Original rule approval source has changed")
                managed_legacy[entry["id"]] = entry
                if not entry["enabled"]:
                    active_legacy.discard(entry["id"])
            for entry in managed["custom"]:
                source = original.get(entry["id"])
                if (source is None or source["kind"] == "legacy_raw_header"
                        or source_digest(source) != entry["sha256"]):
                    raise ManagedError("Custom rule source has changed")
                managed_custom[entry["id"]] = entry
            for entry in saved:
                source = original.get(entry["id"])
                if (source is None or source_digest(source) != entry["sha256"]
                        or source["kind"] == "legacy_raw_header"):
                    raise ActivationError("An approved custom rule was changed unexpectedly")
                custom_active[entry["id"]] = entry["accounts"]
            for rule in rules:
                overlay = (managed_legacy.get(rule["id"]) if rule["id"] in legacy_ids
                           else managed_custom.get(rule["id"]))
                if overlay is not None:
                    rule.update(effective(original[rule["id"]], overlay))
        except (ActivationError, ManagedError):
            activation_error = (
                "Protected rule approval needs attention. Rule controls are unavailable.")
            custom_active = {}
            active_legacy = set()
        editable_ids = {r["id"] for r in rules if
                        r["id"] not in legacy_ids
                        and r["enabled"] == 0 and r["action"] == "draft"
                        and (r["kind"] in DRAFT_KINDS or r["id"] in managed_custom)
                        and r["id"] not in scope_ids}
        approved_ids = active_legacy
        control = control_view(store.directory)
        changed = request.query_params.get("changed", "")
        requested = request.query_params.get("action", "")
        result = ""
        waiting = False
        if changed.isdecimal() and requested in ("enable", "disable", "edit"):
            rule_id = int(changed)
            active = (rule_id in active_legacy if rule_id in legacy_ids
                      else rule_id in custom_active)
            last = control["last_action"]
            expected = ({"legacy-enable", "legacy-disable", "legacy-edit"}
                        if rule_id in legacy_ids else
                        {"enable-rule", "disable-rule", "custom-edit"})
            relevant = last.get("rule_id") == rule_id and last.get("action") in expected
            if control["request_pending"] or (relevant and last.get("state") == "processing"):
                waiting = True
                result = "Applying rule change…"
            elif relevant and last.get("state") == "failed":
                result = "Rule change failed; no activation confirmed"
            elif (requested == "enable" and active and
                  (not relevant or last.get("state") == "success")):
                result = f"Activated rule #{rule_id}"
            elif (requested == "disable" and not active and
                  (not relevant or last.get("state") == "success")):
                result = f"Disabled rule #{rule_id}"
            elif requested == "edit" and relevant and last.get("state") == "success":
                result = f"Saved rule #{rule_id}"
            else:
                waiting = bool(relevant and last.get("state") == "success")
                result = ("Applying rule change…" if waiting else
                          "Rule change not confirmed; check service status")
        bulk_message = ""
        bulk_waiting = False
        done = request.query_params.get("bulk_done","")
        count = request.query_params.get("count","")
        if done in ("deleted","duplicated") and count.isdecimal() and 0 < int(count) <= MAX_RULES_BULK:
            bulk_message = f"{int(count)} selected rule(s) {done}."
        elif done == "unchanged":
            bulk_message = "Selected rules already have the requested activation state."
        bulk_id = request.query_params.get("bulk", "")
        state = app.state.analysis_memory.read(sess["csrf"])
        batch = state.get("rules_batch")
        if batch and batch["batch_id"] == bulk_id:
            last = control["last_action"]
            matches = (last.get("batch_id") == batch["batch_id"]
                       and last.get("action") == "rules-" + batch["action"])
            if matches and last.get("state") == "success":
                observed = all((rid in active_legacy if rid in legacy_ids
                                else rid in custom_active) == batch["activate"]
                               for rid in batch["ids"])
                bulk_message = (f"Bulk {batch['action']} verified for "
                                f"{len(batch['ids'])} selected rule(s)." if observed
                                else "Bulk change finished but the protected rule state could not be confirmed.")
            elif matches and last.get("state") == "failed":
                bulk_message = "Bulk rule operation failed. Check protected control status."
            elif control["request_pending"] or (matches and last.get("state") == "processing"):
                bulk_waiting = True
                bulk_message = "Bulk rule change pending root verification; no activation confirmed."
            else:
                bulk_message = "Bulk action not confirmed. Review protected rule status."
        return render(request, "rules.html", active="rules", sess=sess,
                      rules=rules, approved_ids=approved_ids,
                      legacy_ids=legacy_ids, editable_ids=editable_ids,
                      custom_active=custom_active, managed_custom=managed_custom,
                      activation_error=activation_error,
                      accounts=accounts, review_requests=reviews,
                      control=control, change_result=result,
                      change_waiting=waiting or bulk_waiting,
                      bulk_message=bulk_message)


    @app.post("/rules/bulk", response_class=HTMLResponse)
    def rules_bulk_action(request: Request, csrf: str = Form(""),
                          selected: list[str] = Form([]),
                          select_all: str = Form(""),
                          operation: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if operation not in ("delete","duplicate","enable","disable") or (
                select_all not in ("","yes")):
            return HTMLResponse("Invalid bulk rule operation", status_code=400)
        try:
            if select_all == "yes":
                with store.db() as con:
                    ids = [int(row[0]) for row in con.execute(
                        "SELECT id FROM rules ORDER BY id DESC")]
            else:
                if not selected or len(selected) > MAX_RULES_BULK or any(
                        not v.isdecimal() or not 1 <= int(v) < 2**63
                        for v in selected):
                    return HTMLResponse("Invalid selected rule IDs", status_code=400)
                ids = [int(i) for i in selected]
            validate_ids(ids)
            if operation == "delete":
                count = delete_rules(store, ids)
                return RedirectResponse(f"/rules?bulk_done=deleted&count={count}", status_code=303)
            if operation == "duplicate":
                count = duplicate_rules(store, ids)
                return RedirectResponse(f"/rules?bulk_done=duplicated&count={count}", status_code=303)

            control = control_view(store.directory)
            if not control["control_installed"] or control["request_pending"]:
                return HTMLResponse("Protected rule control unavailable or busy",
                                    status_code=409)
            policy = load_policy()
            accounts = sorted(policy["accounts"])
            approvals = {x["id"]:x for x in read_approvals()}
            managed = read_managed()
            off_legacy = {x["id"] for x in managed["legacy"] if not x["enabled"]}
            managed_map = {
                group:{x["id"]:x for x in managed[group]}
                for group in ("legacy","custom")}
            enabled = operation == "enable"
            actionable = []
            preview = []
            with store.db() as con:
                for rid in ids:
                    row = con.execute("SELECT * FROM rules WHERE id=?",(rid,)).fetchone()
                    if row is None:
                        return HTMLResponse("Selected rule was removed", status_code=409)
                    source = dict(row)
                    legacy = source["kind"] == "legacy_raw_header"
                    active = rid not in off_legacy if legacy else rid in approvals
                    if active == enabled:
                        continue
                    if not legacy:
                        _draft_rule(con, rid)
                    else:
                        scope = {int(r[0]) for r in con.execute(
                            "SELECT account_id FROM rule_scopes WHERE rule_id=?",(rid,))}
                        if scope != set(accounts):
                            return HTMLResponse("Protected rule scope mismatch",status_code=409)
                    overlay = managed_map["legacy" if legacy else "custom"].get(rid)
                    if overlay is not None and overlay["sha256"] != source_digest(source):
                        return HTMLResponse("Managed rule source changed",status_code=409)
                    if not legacy and rid in approvals and (
                            approvals[rid]["sha256"] != source_digest(source)
                            or approvals[rid]["accounts"] != accounts):
                        return HTMLResponse("Existing rule approval mismatch",status_code=409)
                    actionable.append({"id":rid,"sha256":source_digest(source)})
                    if enabled:
                        preview.append(effective(source,overlay))
            if not actionable:
                return RedirectResponse("/rules?bulk_done=unchanged",status_code=303)
            if enabled:
                if not all(app.state.token_vault.connected(i) for i in accounts):
                    return HTMLResponse("Approved Microsoft accounts must be connected",
                                        status_code=409)
                if len(approvals) + sum(x["id"] not in managed_map["legacy"]
                                        for x in actionable) > 64:
                    return HTMLResponse("Approval limit exceeded",status_code=409)
                preview_rules(store, preview, accounts, app.state.token_vault)
            batch_id = secrets.token_hex(12)
            if not request_rules_bulk(
                    store.directory, actionable, accounts,
                    "rules-" + operation, batch_id):
                return HTMLResponse("Another protected rule action is pending",
                                    status_code=409)
            app.state.analysis_memory.set_rules_batch(sess["csrf"], {
                "batch_id": batch_id, "ids": [item["id"] for item in actionable],
                "activate": enabled, "action": operation})
            store.audit("rules_bulk_control_queued",
                        f"count={len(actionable)} action={operation}")
            return RedirectResponse(f"/rules?bulk={batch_id}",status_code=303)
        except (RuleManagementError, ActivationError, ManagedError, LiveSafetyError,
                ApprovalPreviewError, ControlError, OSError, ValueError, TypeError) as exc:
            if isinstance(exc, RuleManagementError):
                return HTMLResponse(str(exc),status_code=exc.status_code)
            return HTMLResponse(
                "Bulk rule request rejected; no protected state was changed",
                status_code=409)

    @app.post("/rules/{rule_id}/toggle", response_class=HTMLResponse)
    def toggle_custom_rule(request: Request, rule_id: int,
                           csrf: str = Form(""), action: str = Form("")):
        """Exactly one click: automatic read-only preview, root-validated write.

        No checkbox or approval confirmation form. The UI shows success only
        after the root-owned policy actually reflects the requested state.
        """
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if action not in ("enable", "disable"):
            return HTMLResponse("Unsupported rule action", status_code=400)
        try:
            root = load_policy()
            with store.db() as con:
                baseline = con.execute(
                    "SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
                if baseline is None:
                    return HTMLResponse("Rule not found", status_code=404)
                baseline = dict(baseline)
            original = baseline["kind"] == "legacy_raw_header"
            snapshot = read_managed()
            overlay = next((item for item in snapshot[
                "legacy" if original else "custom"] if item["id"] == rule_id), None)
            active_approvals = {
                item["id"]: item for item in read_approvals()}
            if original:
                currently_active = overlay is None or overlay["enabled"]
                if currently_active == (action == "enable"):
                    return RedirectResponse("/rules", status_code=303)
                if action == "enable":
                    rule = effective(baseline, overlay)
                    if not all(app.state.token_vault.connected(i) for i in root["accounts"]):
                        return HTMLResponse("Both Microsoft accounts must be connected",
                                            status_code=409)
                    preview_rule(store, rule, sorted(root["accounts"]),
                                 app.state.token_vault)
                control_action = "legacy-enable" if action == "enable" else "legacy-disable"
                ok = request_managed_control(
                    store.directory, control_action, rule_id, source_digest(baseline))
            else:
                if action == "enable":
                    if rule_id in active_approvals:
                        return RedirectResponse("/rules", status_code=303)
                    with store.db() as con:
                        _draft_rule(con, rule_id)
                    rule = effective(baseline, overlay)
                    accounts = sorted(root["accounts"])
                    if not all(app.state.token_vault.connected(i) for i in accounts):
                        return HTMLResponse("Both Microsoft accounts must be connected",
                                            status_code=409)
                    report = preview_rule(store, rule, accounts, app.state.token_vault)
                    store.audit("rule_activation_preview",
                                "rule_id=%d accounts=%d examined=%d matched=%d" %
                                (rule_id, len(report),
                                 sum(item["examined"] for item in report),
                                 sum(item["matched"] for item in report)))
                    fingerprint = source_digest(baseline)
                    control_action = "enable-rule"
                else:
                    entry = active_approvals.get(rule_id)
                    if entry is None:
                        return RedirectResponse("/rules", status_code=303)
                    accounts = entry["accounts"]
                    fingerprint = entry["sha256"]
                    control_action = "disable-rule"
                ok = request_rule_control(store.directory, control_action,
                                          rule_id, accounts, fingerprint)
        except (LiveSafetyError, ActivationError, ApprovalPreviewError,
                ControlError, ManagedError, OSError, TypeError):
            return HTMLResponse(
                "Rule change could not be verified or queued; no change applied",
                status_code=409)
        if not ok:
            return HTMLResponse("Another cleaner operation is pending",
                                status_code=409)
        store.audit("rule_control_queued",
                    "rule_id=%d action=%s" % (rule_id, control_action))
        return RedirectResponse(
            f"/rules?changed={rule_id}&action={action}", status_code=303)

    @app.get("/rules/{rule_id}/edit", response_class=HTMLResponse)
    def edit_draft_form(request: Request, rule_id: int):
        sess, denial = guard(request)
        if denial:
            return denial
        with store.db() as con:
            source = con.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
        if source is None:
            return HTMLResponse("Rule not found", status_code=404)
        source = dict(source)
        try:
            config = read_managed()
            kind = "legacy" if source["kind"] == "legacy_raw_header" else "custom"
            overlay = next((item for item in config[kind] if item["id"] == rule_id), None)
            rule = effective(source, overlay)
            proposal = False
            legacy_edit = kind == "legacy"
        except ManagedError:
            return HTMLResponse("Managed rule approval unavailable", status_code=409)
        current_code = f"{rule['kind']}:{rule['field']}"
        definitions = list(RULE_DEFINITIONS)
        if legacy_edit:
            definitions.append(("legacy_raw_header", "raw", "Original raw-header substring"))
        if current_code not in {f"{k}:{f}" for k, f, _ in definitions}:
            # Older drafts may use noncanonical header casing.
            matches = [f"{k}:{f}" for k, f, _ in definitions if k == rule["kind"]]
            if not matches:
                return HTMLResponse("Unsupported rule kind", status_code=409)
            current_code = matches[0]
        try:
            root_status = read_approvals()
            is_active = ((overlay is None or overlay["enabled"]) if legacy_edit
                         else any(x["id"] == rule_id for x in root_status))
        except ActivationError:
            return HTMLResponse("Root rule approvals unavailable", status_code=409)
        return render(request, "rule_edit.html", active="rules", sess=sess,
                      rule=rule, proposal=proposal, is_active=is_active,
                      legacy_edit=legacy_edit,
                      definitions=definitions, selected_definition=current_code,
                      editor_action=f"/rules/{rule_id}/edit")

    @app.post("/rules/{rule_id}/edit", response_class=HTMLResponse)
    def save_edited_draft(request: Request, rule_id: int, csrf: str = Form(""),
                          definition: str = Form(""), value: str = Form(""),
                          label: str = Form(""),
                          enable_after_save: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if enable_after_save not in ("", "yes"):
            return HTMLResponse("Invalid rule edit action", status_code=400)
        try:
            with store.db() as con:
                source = con.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
            if source is None:
                return HTMLResponse("Rule not found", status_code=404)
            source = dict(source)
            if definition == "legacy_raw_header:raw":
                if source["kind"] != "legacy_raw_header":
                    return HTMLResponse("Legacy type is reserved for imported rules",
                                        status_code=400)
                override = normalize("legacy_raw_header", "raw", value, label)
            else:
                from .rule_management import parse_edit
                kind, field, pattern, title = parse_edit(definition, value, label)
                override = normalize(kind, field, pattern, title)
            config = read_managed()
            original = source["kind"] == "legacy_raw_header"
            group = "legacy" if original else "custom"
            overlay = next((item for item in config[group] if item["id"] == rule_id), None)
            custom_active = {x["id"]: x for x in read_approvals()}
            active = ((overlay is None or overlay["enabled"]) if original
                      else rule_id in custom_active)
            managed = original or active or overlay is not None
            if not managed:
                update_draft(store, rule_id, definition, value, label)
                if enable_after_save == "yes":
                    return toggle_custom_rule(
                        request, rule_id, csrf=csrf, action="enable")
                return RedirectResponse("/rules", status_code=303)
            root = load_policy()
            will_be_active = active or enable_after_save == "yes"
            if will_be_active:
                if not all(app.state.token_vault.connected(i) for i in root["accounts"]):
                    return HTMLResponse("Both Microsoft accounts must be connected",
                                        status_code=409)
                preview_rule(store, {"id": rule_id, **override},
                             sorted(root["accounts"]), app.state.token_vault)
            action = "legacy-edit" if original else "custom-edit"
            ok = request_managed_control(
                store.directory, action, rule_id, source_digest(source),
                override, activate=enable_after_save == "yes")
        except RuleManagementError as error:
            return HTMLResponse(str(error), status_code=error.status_code)
        except (ManagedError, ControlError, ActivationError,
                LiveSafetyError, ApprovalPreviewError, OSError, TypeError):
            return HTMLResponse(
                "Rule edit not applied: invalid rule or protected service unavailable",
                status_code=409)
        if not ok:
            return HTMLResponse("Another rule operation is pending", status_code=409)
        store.audit("rule_edit_queued",
                    "rule_id=%d action=%s" % (rule_id, action))
        return RedirectResponse(
            f"/rules?changed={rule_id}&action={'enable' if enable_after_save == 'yes' else 'edit'}",
            status_code=303)

    @app.post("/rules/{rule_id}/duplicate", response_class=HTMLResponse)
    def copy_draft(request: Request, rule_id: int, csrf: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        try:
            with store.db() as con:
                source = con.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
            if source is None:
                return HTMLResponse("Rule not found", status_code=404)
            source = dict(source)
            group = "legacy" if source["kind"] == "legacy_raw_header" else "custom"
            config = read_managed()
            overlay = next((item for item in config[group] if item["id"] == rule_id), None)
            resolved = effective(source, overlay)
            if source["kind"] == "legacy_raw_header" and resolved["kind"] == "legacy_raw_header":
                resolved["kind"], resolved["field"] = "custom_raw_header", "All raw headers"
            # Never duplicate active scopes or effective permission; the copy
            # is always an entirely new, disabled, unscoped rule.
            if resolved["kind"] not in DRAFT_KINDS:
                return HTMLResponse("Unsupported rule type for duplication", status_code=409)
            proposed = normalize(
                resolved["kind"], resolved["field"], resolved["pattern"],
                ("Copy of " + resolved["label"])[:200])
            with store.db() as con:
                con.execute("BEGIN IMMEDIATE")
                cur = con.execute(
                    "INSERT INTO rules(label,kind,field,pattern,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (proposed["label"], proposed["kind"], proposed["field"],
                     proposed["pattern"], int(time.time())))
                new_id = cur.lastrowid
            store.audit("rule_draft_duplicated",
                        "source_rule_id=%d new_rule_id=%d" % (rule_id, new_id))
        except (ManagedError, RuleManagementError, OSError, TypeError):
            return HTMLResponse("Rule cannot be duplicated", status_code=409)
        return RedirectResponse(f"/rules/{new_id}/edit", status_code=303)

    @app.post("/rules/{rule_id}/request", response_class=HTMLResponse)
    def request_rule_toggle(request: Request, rule_id: int, csrf: str = Form(""),
                            operation: str = Form(""), confirm: str = Form(""),
                            account_ids: list[int] = Form([])):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if confirm != "request_review" or operation not in {"enable", "disable"}:
            return HTMLResponse("Exact rule review confirmation required", status_code=400)
        try:
            # A queued request changes NO live rules or root-owned permissions.
            queue_review(store, rule_id, operation, account_ids=account_ids)
        except RuleManagementError as error:
            return HTMLResponse(str(error), status_code=error.status_code)
        return RedirectResponse("/rules", status_code=303)

    @app.get("/rule-reviews/{request_id}/edit", response_class=HTMLResponse)
    def edit_rule_review_form(request: Request, request_id: int):
        sess, denial = guard(request)
        if denial:
            return denial
        try:
            rule = load_review(store, request_id)
        except RuleManagementError as error:
            return HTMLResponse(str(error), status_code=error.status_code)
        if rule["operation"] not in ("edit", "duplicate") or rule["status"] != "pending_review":
            return HTMLResponse("This review request is not editable", status_code=409)
        definitions = list(RULE_DEFINITIONS) + [
            ("legacy_raw_header", "raw", "Legacy raw header (review only)")]
        current_code = f"{rule['kind']}:{rule['field']}"
        if current_code not in {f"{k}:{f}" for k, f, _ in definitions}:
            return HTMLResponse("Unsupported review definition", status_code=409)
        return render(request, "rule_edit.html", active="rules", sess=sess,
                      rule=rule, proposal=True, is_active=False, definitions=definitions,
                      selected_definition=current_code,
                      editor_action=f"/rule-reviews/{request_id}/edit")

    @app.post("/rule-reviews/{request_id}/edit", response_class=HTMLResponse)
    def save_rule_review(request: Request, request_id: int, csrf: str = Form(""),
                         definition: str = Form(""), value: str = Form(""),
                         label: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        try:
            revise_review(store, request_id, definition, value, label)
        except RuleManagementError as error:
            return HTMLResponse(str(error), status_code=error.status_code)
        return RedirectResponse("/rules", status_code=303)

    @app.post("/rule-reviews/{request_id}/cancel", response_class=HTMLResponse)
    def cancel_rule_review(request: Request, request_id: int, csrf: str = Form(""),
                           confirm: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        try:
            cancel_review(store, request_id)
        except RuleManagementError as error:
            return HTMLResponse(str(error), status_code=error.status_code)
        return RedirectResponse("/rules", status_code=303)

    @app.post("/rules/{rule_id}/delete", response_class=HTMLResponse)
    def remove_draft(request: Request, rule_id: int, csrf: str = Form(""),
                      confirm: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        try:
            delete_draft(store, rule_id)
        except RuleManagementError as error:
            return HTMLResponse(str(error), status_code=error.status_code)
        return RedirectResponse("/rules", status_code=303)

    @app.get("/activity", response_class=HTMLResponse)
    def activity(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        history = history_report(store)
        return render(request, "activity.html", active="activity", sess=sess, history=history)

    @app.get("/updates", response_class=HTMLResponse)
    def updates(request: Request):
        sess, denial = guard(request)
        if denial:
            return denial
        state = update_status()
        latest = dict(app.state.latest)
        if latest.get("tag"):
            latest["is_newer"] = (
                tuple(map(int, latest["tag"][1:].split("."))) >
                tuple(map(int, __version__.split(".")))
            )
        status_version = str(state.get("version", "")).removeprefix("v")
        restart_pending = bool(
            state.get("state") == "success"
            and re.fullmatch(r"\d+\.\d+\.\d+", status_version)
            and tuple(map(int, status_version.split("."))) >
                tuple(map(int, __version__.split(".")))
        )
        return render(request, "updates.html", active="updates", sess=sess,
                      latest=latest, update_status=state,
                      restart_pending=restart_pending,
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
            if url != f"https://github.com/zemerdon/filter-vision/releases/tag/{tag}":
                raise ValueError("Unexpected release URL")
            app.state.latest = {"tag": tag, "url": url, "error": "",
                                "notes": changelog_items(payload.get("body", "")),
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
        latest = app.state.latest.get("tag", "")
        if (not re.fullmatch(r"v\d+\.\d+\.\d+", latest)
                or tuple(map(int, latest[1:].split("."))) <=
                   tuple(map(int, __version__.split(".")))):
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
        cleaner = control_view(store.directory)
        approved = live_account_ids()
        with store.db() as db:
            last = db.execute(
                "SELECT created_at,detail FROM audit_events WHERE event='live_scan' "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            failed_count = db.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event='live_scan_failed'"
            ).fetchone()[0]
        last_scan = None
        if last:
            last_scan = {
                "when": datetime.fromtimestamp(
                    int(last["created_at"]), ZoneInfo("Australia/Brisbane")
                ).strftime("%d %b %Y, %I:%M %p AEST"),
                "detail": str(last["detail"])[:180],
            }
        return render(request, "settings.html", active="settings", sess=sess,
                      cleaner=cleaner, approved_count=len(approved),
                      intervals=INTERVALS, last_scan=last_scan,
                      failed_scans=failed_count, activity_limit=store.activity_limit(),
                      activity_options=ACTIVITY_LIMITS)

    @app.post("/settings/activity", response_class=HTMLResponse)
    def save_activity_settings(request: Request, csrf: str = Form(""),
                               activity_limit: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if not activity_limit.isdecimal():
            return HTMLResponse("Invalid Activity limit", status_code=400)
        try:
            store.set_activity_limit(int(activity_limit))
        except ValueError:
            return HTMLResponse("Unsupported Activity limit", status_code=400)
        store.audit("activity_settings_changed",
                    "activity_entries=" + str(activity_limit))
        return RedirectResponse("/settings#activity-settings", status_code=303)

    @app.post("/settings/cleaner", response_class=HTMLResponse)
    def cleaner_control(request: Request, csrf: str = Form(""),
                        action: str = Form(""), interval: str = Form(""),
                        confirm_run: str = Form("")):
        sess, denial = guard(request)
        if denial:
            return denial
        if not valid_csrf(sess, csrf):
            return invalid_csrf()
        if not control_view(store.directory)["control_installed"]:
            return HTMLResponse("Cleaner service controls are not installed", status_code=503)
        if action not in ACTIONS:
            return HTMLResponse("Unsupported cleaner control request", status_code=400)
        if action == "run-now" and confirm_run != "yes":
            return HTMLResponse("Confirm that the immediate scan may permanently delete "
                                "matching Junk mail", status_code=400)
        if action != "run-now" and confirm_run:
            return HTMLResponse("Unexpected cleaner control confirmation", status_code=400)
        try:
            if action == "set-interval":
                if not interval.isdecimal():
                    raise ControlError("Invalid cleaner interval")
                minutes = int(interval)
                if minutes not in INTERVALS:
                    raise ControlError("Unsupported cleaner interval")
            else:
                if interval:
                    raise ControlError("Unexpected cleaner interval")
                minutes = None
            accepted = request_control(store.directory, action, minutes)
        except ControlError:
            return HTMLResponse("Unsupported cleaner control request", status_code=400)
        except OSError:
            return HTMLResponse("Cleaner service control is temporarily unavailable",
                                status_code=503)
        if not accepted:
            return HTMLResponse("Cleaner operation already pending", status_code=409)
        store.audit("cleaner_control_requested",
                    f"action={action}" +
                    (f" interval_minutes={minutes}" if minutes is not None else ""))
        return RedirectResponse("/settings#cleaner-service", status_code=303)

    return app
