"""Browse and select Outlook Junk email via read-only IMAP and bounded FETCH.

No STORE, DELETE, COPY, MOVE or EXPUNGE. A cached opaque selection is always
revalidated against mailbox UIDVALIDITY and original headers before analysis.
"""
from __future__ import annotations

import hashlib
import imaplib
import re
import secrets
import ssl

from .analysis import MAX_FILE_BYTES, MAX_TOTAL_BYTES, inspect_eml
from .preview import _raw_headers

MAX_LIST_PER_ACCOUNT = 40
MAX_SELECTED = 20


class BrowseError(RuntimeError):
    pass


def _connect(email: str, token: str, connector=None):
    connection = (connector() if connector is not None else imaplib.IMAP4_SSL(
        "outlook.office365.com", 993, ssl_context=ssl.create_default_context(), timeout=20
    ))
    try:
        payload = f"user={email}\x01auth=Bearer {token}\x01\x01".encode()
        kind, _ = connection.authenticate("XOAUTH2", lambda _: payload)
        if kind != "OK":
            raise BrowseError("Microsoft IMAP authentication failed")
        kind, _ = connection.select("Junk", readonly=True)
        if kind != "OK":
            raise BrowseError("Junk folder is unavailable")
        kind, response = connection.response("UIDVALIDITY")
        if kind != "UIDVALIDITY" or not response or not response[0]:
            raise BrowseError("Junk folder UIDVALIDITY unavailable")
        value = response[0]
        if isinstance(value, bytes):
            value = value.decode("ascii", errors="ignore")
        if not str(value).isdigit() or not 1 <= int(value) < 2**63:
            raise BrowseError("Invalid mailbox UIDVALIDITY")
        return connection, int(value)
    except Exception:
        try:
            connection.logout()
        except Exception:
            pass
        raise


def _close(connection):
    try:
        connection.logout()
    except Exception:
        pass


def _headers(uid, connection) -> bytes:
    kind, response = connection.uid("FETCH", uid, "(BODY.PEEK[HEADER])")
    if kind != "OK":
        raise BrowseError("Read-only Junk header retrieval failed")
    headers = _raw_headers(response)
    if not headers or len(headers) > 256 * 1024:
        raise BrowseError("Invalid or oversized Junk headers")
    return headers


def list_junk(account: dict, token: str, connector=None) -> list[dict]:
    """Return metadata for the latest N Junk messages, not message bodies."""
    if (account["provider"] != "outlook" or
            account["host"] != "outlook.office365.com" or
            int(account["port"]) != 993 or account["folder"] != "Junk"):
        raise BrowseError("Only configured Outlook Junk is supported")
    connection = None
    try:
        connection, validity = _connect(account["username"], token, connector)
        kind, response = connection.uid("SEARCH", None, "ALL")
        if kind != "OK" or not response:
            raise BrowseError("Cannot list Junk message UIDs")
        uids = response[0].split() if response[0] else []
        if any(not re.fullmatch(rb"[1-9][0-9]{0,18}", uid) for uid in uids):
            raise BrowseError("IMAP supplied an invalid message UID")
        rows = []
        for uid in reversed(uids[-MAX_LIST_PER_ACCOUNT:]):
            headers = _headers(uid, connection)
            try:
                sample = inspect_eml("message.eml", headers + b"\r\n\r\n")
            except ValueError:
                # One malformed message must not stop the entire Junk listing.
                continue
            rows.append({
                "ref": secrets.token_urlsafe(16),
                "account_id": account["id"],
                "account_label": account["label"][:80],
                "uid": int(uid),
                "uidvalidity": validity,
                "header_sha256": hashlib.sha256(headers).hexdigest(),
                "sender": sample["sender"][:254],
                "subject": sample["subject"][:200],
                "date": sample["manual_headers"].get("date", [""])[0][:100],
            })
        return rows
    except (imaplib.IMAP4.error, OSError, TimeoutError, ValueError) as error:
        raise BrowseError("Cannot inspect connected Junk folder read-only") from None
    finally:
        if connection is not None:
            _close(connection)


def fetch_selected(account: dict, items: list[dict], token: str,
                   connector=None, remaining_budget: int = MAX_TOTAL_BYTES) -> list[dict]:
    """Fetch selected full messages read-only (max 2 MiB each), safely."""
    if not items or len(items) > MAX_SELECTED:
        raise BrowseError("Select between 1 and 20 messages")
    if (account["provider"] != "outlook" or account["folder"] != "Junk"
            or account["host"] != "outlook.office365.com"
            or int(account["port"]) != 993):
        raise BrowseError("Only configured Outlook Junk is supported")
    if not 1 <= remaining_budget <= MAX_TOTAL_BYTES:
        raise BrowseError("Invalid analysis size budget")
    connection = None
    try:
        connection, validity = _connect(account["username"], token, connector)
        if any(int(item["uidvalidity"]) != validity or
               item["account_id"] != account["id"] for item in items):
            raise BrowseError("Junk mailbox changed. Scan again before selecting messages")
        samples = []
        spent = 0
        for item in items:
            uid = str(item["uid"]).encode()
            if not re.fullmatch(rb"[1-9][0-9]{0,18}", uid):
                raise BrowseError("Invalid message selection")
            headers = _headers(uid, connection)
            if hashlib.sha256(headers).hexdigest() != item["header_sha256"]:
                raise BrowseError("Junk message changed. Scan again before analysis")
            kind, data = connection.uid("FETCH", uid, "(RFC822.SIZE)")
            if kind != "OK" or not data:
                raise BrowseError("Cannot validate selected message size")
            response = b" ".join(x for x in data if isinstance(x, bytes))
            size = re.search(rb"RFC822\.SIZE\s+([0-9]+)", response, re.I)
            if not size or int(size[1]) > MAX_FILE_BYTES:
                raise BrowseError("Selected email exceeds the 2 MiB analysis limit")
            if spent + int(size[1]) > remaining_budget:
                raise BrowseError("Selected messages exceed the 10 MiB analysis limit")
            kind, data = connection.uid(
                "FETCH", uid, f"(BODY.PEEK[]<0.{MAX_FILE_BYTES + 1}>)")
            if kind != "OK":
                raise BrowseError("Read-only message fetch failed")
            payload = _raw_headers(data)
            if not payload or len(payload) > MAX_FILE_BYTES:
                raise BrowseError("Selected email exceeds the 2 MiB analysis limit")
            # Avoid assuming server responses contain the selected UID's data
            # without first authenticating the mailbox identity and headers.
            spent += len(payload)
            if spent > remaining_budget:
                raise BrowseError("Selected messages exceed the 10 MiB analysis limit")
            sample = inspect_eml(f"Junk message {item['uid']}.eml", payload)
            sample["_analysis_size"] = len(payload)
            if (sample["sender"] != item["sender"] or
                    sample["subject"] != item["subject"]):
                raise BrowseError("Junk message metadata changed. Scan again")
            sample["account_label"] = item["account_label"]
            samples.append(sample)
        return samples
    except (imaplib.IMAP4.error, OSError, TimeoutError, ValueError):
        raise BrowseError("Junk message selection failed read-only") from None
    finally:
        if connection is not None:
            _close(connection)
