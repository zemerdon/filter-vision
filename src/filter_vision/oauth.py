"""Microsoft device authorization with local encrypted token storage.

This module never logs or returns OAuth access/refresh tokens to the browser.
Imported accounts remain inactive for scanning until separately validated.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


class OAuthError(RuntimeError):
    pass


def _json_post(url: str, fields: dict[str, str], timeout: int = 18) -> dict:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Accept": "application/json", "User-Agent": "FilterVision/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            blob = response.read(16 * 1024 + 1)
    except urllib.error.HTTPError as error:
        blob = error.read(8192 + 1)
        if len(blob) > 8192:
            raise OAuthError("Microsoft returned an oversized error") from None
        try:
            payload = json.loads(blob)
        except (ValueError, UnicodeError):
            raise OAuthError("Microsoft authorization HTTP error") from None
        if not isinstance(payload, dict):
            raise OAuthError("Unexpected Microsoft error") from None
        return {"_error": str(payload.get("error", "unknown"))[:80]}
    except (OSError, TimeoutError):
        raise OAuthError("Microsoft authorization service could not be reached") from None
    if len(blob) > 16 * 1024:
        raise OAuthError("Oversized Microsoft token response")
    try:
        payload = json.loads(blob)
    except (ValueError, UnicodeError):
        raise OAuthError("Invalid Microsoft response") from None
    if not isinstance(payload, dict):
        raise OAuthError("Invalid Microsoft response")
    return payload


def _config_path() -> Path:
    return Path(os.environ.get("FV_OAUTH_CLIENTS_PATH",
                               "/etc/filter-vision/oauth-clients.json"))


def client_settings(email: str) -> dict:
    try:
        data = json.loads(_config_path().read_bytes())
        row = data[email]
    except (OSError, ValueError, KeyError, TypeError):
        raise OAuthError("Microsoft OAuth client settings unavailable") from None
    if not isinstance(row, dict):
        raise OAuthError("Invalid Microsoft OAuth client settings")
    client = str(row.get("client_id", ""))
    permission = str(row.get("permission_url", ""))
    token = str(row.get("token_url", ""))
    scope = str(row.get("oauth2_scope", ""))
    expected = "https://login.microsoftonline.com/"
    if (not re.fullmatch(r"[a-zA-Z0-9-]{20,80}", client)
            or not permission.startswith(expected)
            or not permission.endswith("/oauth2/v2.0/authorize")
            or not token.startswith(expected)
            or not token.endswith("/oauth2/v2.0/token")
            or "https://outlook.office.com/IMAP.AccessAsUser.All" not in scope.split()
            or "offline_access" not in scope.split()):
        raise OAuthError("Unsupported Microsoft OAuth client configuration")
    return {
        "client_id": client,
        "device_url": permission.removesuffix("/authorize") + "/devicecode",
        "token_url": token,
        "scope": scope,
    }


class TokenVault:
    def __init__(self, data_dir: Path):
        self.directory = Path(data_dir) / "oauth"
        self.directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.key_path = self.directory / "fernet.key"
        if not self.key_path.exists():
            try:
                fd = os.open(self.key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as file:
                    file.write(Fernet.generate_key())
        os.chmod(self.key_path, 0o600)
        self.crypt = Fernet(self.key_path.read_bytes())

    def _path(self, account_id: int) -> Path:
        if not isinstance(account_id, int) or account_id <= 0 or account_id > 10000000:
            raise OAuthError("Invalid account identifier")
        return self.directory / f"{account_id}.token"

    def connected(self, account_id: int) -> bool:
        return self._path(account_id).is_file()

    def save(self, account_id: int, tokens: dict):
        access = tokens.get("access_token")
        refresh = tokens.get("refresh_token")
        if not isinstance(access, str) or len(access) < 50:
            raise OAuthError("Microsoft access token missing")
        if not isinstance(refresh, str) or len(refresh) < 50:
            raise OAuthError("Microsoft refresh token missing")
        ttl = int(tokens.get("expires_in", 0))
        if not 30 <= ttl <= 86400:
            raise OAuthError("Unexpected Microsoft token expiry")
        body = {
            "access_token": access,
            "refresh_token": refresh,
            "expires_at": int(time.time()) + ttl,
        }
        target = self._path(account_id)
        tmp = self.directory / (f".{account_id}-{secrets.token_hex(8)}.tmp")
        encrypted = self.crypt.encrypt(json.dumps(body).encode())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(encrypted)
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp, target)
        finally:
            tmp.unlink(missing_ok=True)

    def load(self, account_id: int) -> dict:
        try:
            data = self._path(account_id).read_bytes()
            return json.loads(self.crypt.decrypt(data))
        except (OSError, ValueError, InvalidToken):
            raise OAuthError("Account authentication needs renewal") from None


def start_device_auth(email: str) -> dict:
    settings = client_settings(email)
    result = _json_post(settings["device_url"], {
        "client_id": settings["client_id"], "scope": settings["scope"],
    })
    if "_error" in result:
        raise OAuthError("Microsoft device authorization unavailable: " + result["_error"])
    code = result.get("device_code")
    user_code = result.get("user_code")
    verify_uri = result.get("verification_uri", "")
    ttl = int(result.get("expires_in", 0))
    interval = max(5, int(result.get("interval", 5)))
    if (not isinstance(code, str) or not 20 <= len(code) <= 4096
            or not isinstance(user_code, str) or not 4 <= len(user_code) <= 40
            or not isinstance(verify_uri, str)
            or urllib.parse.urlsplit(verify_uri).hostname not in
                ("microsoft.com", "www.microsoft.com", "login.microsoftonline.com")
            or not 60 <= ttl <= 1800):
        raise OAuthError("Unexpected Microsoft device authorization response")
    return {
        "device_code": code,
        "user_code": user_code,
        "verification_uri": verify_uri,
        "expires_at": int(time.time()) + ttl,
        "interval": interval,
        "last_poll_at": 0,
        "settings": settings,
    }


def poll_device_auth(flow: dict) -> dict:
    now = int(time.time())
    if now >= flow["expires_at"]:
        raise OAuthError("Microsoft authorization expired. Start again.")
    if now < flow["last_poll_at"] + flow["interval"]:
        return {"pending": True, "detail": "Wait before checking again"}
    flow["last_poll_at"] = now
    settings = flow["settings"]
    result = _json_post(settings["token_url"], {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": settings["client_id"],
        "device_code": flow["device_code"],
    })
    error = result.get("_error")
    if error == "authorization_pending":
        return {"pending": True, "detail": "Waiting for Microsoft approval"}
    if error == "slow_down":
        flow["interval"] += 5
        return {"pending": True, "detail": "Microsoft requested a slower retry"}
    if error in {"expired_token", "authorization_declined", "bad_verification_code"}:
        raise OAuthError("Authorization expired or declined. Start again.")
    if error:
        raise OAuthError("Microsoft authorization unsuccessful: " + error)
    if not result.get("refresh_token"):
        raise OAuthError("Microsoft did not return an offline refresh token")
    return {"pending": False, "tokens": result}


def access_token_for(account_id: int, email: str, vault: TokenVault) -> str:
    """Return a current IMAP token, refreshing and rotating it if required."""
    import fcntl

    lockfile = vault.directory / f"{account_id}.lock"
    with open(lockfile, "a+b") as guard:
        os.chmod(lockfile, 0o600)
        fcntl.flock(guard.fileno(), fcntl.LOCK_EX)
        current = vault.load(account_id)
        if current.get("expires_at", 0) > int(time.time()) + 180:
            return current["access_token"]
        settings = client_settings(email)
        response = _json_post(settings["token_url"], {
            "grant_type": "refresh_token",
            "client_id": settings["client_id"],
            "refresh_token": current["refresh_token"],
            "scope": settings["scope"],
        })
        if "_error" in response:
            raise OAuthError("Microsoft refresh failed; reauthorize this account")
        if "refresh_token" not in response:
            response["refresh_token"] = current["refresh_token"]
        vault.save(account_id, response)
        return response["access_token"]


def verify_imap_auth(email: str, access_token: str) -> None:
    """Validate credentials against Microsoft IMAP without selecting a folder."""
    import imaplib
    connection = None
    try:
        connection = imaplib.IMAP4_SSL(
            "outlook.office365.com", 993, ssl_context=ssl.create_default_context(),
            timeout=20,
        )
        payload = f"user={email}\\x01auth=Bearer {access_token}\\x01\\x01".encode()
        kind, _ = connection.authenticate("XOAUTH2", lambda _: payload)
        if kind != "OK":
            raise OAuthError("Microsoft IMAP did not authenticate the selected account")
    except (imaplib.IMAP4.error, OSError, TimeoutError):
        raise OAuthError("Microsoft IMAP authentication failed for this account") from None
    finally:
        if connection is not None:
            try:
                connection.logout()
            except Exception:
                pass
