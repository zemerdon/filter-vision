import pytest

from filter_vision.preview import scan_junk_preview, PreviewError, MAX_MESSAGES


class ReadOnlyIMAP:
    def __init__(self):
        self.read_only = None
        self.commands = []
        self.logout_called = False

    def authenticate(self, mechanism, respond):
        assert mechanism == "XOAUTH2"
        assert b"auth=Bearer" in respond(b"")
        return "OK", [b"auth"]

    def select(self, folder, readonly=False):
        assert folder == "Junk"
        self.read_only = readonly
        return "OK", [b"3"]

    def uid(self, command, *args):
        self.commands.append(command)
        if command == "SEARCH":
            return "OK", [b"1 2 3"]
        assert command == "FETCH"
        uid = args[0]
        assert args[1] == "(BODY.PEEK[HEADER])"
        data = {
            b"1": b"From: benign@example.invalid\r\nX-MS-Exchange-Organization-SCL: 9\r\n\r\n",
            b"2": b"From: scam@evil.invalid\r\nFeedback-ID: ABC:7404:422441:posti\r\n\r\n",
            b"3": b"From: scam@evil.invalid\r\nX-Relaying-Domain: bad.invalid\r\n\r\n",
        }
        return "OK", [(b"HEADER", data[uid])]

    def logout(self):
        self.logout_called = True


RULES = [
    {"id": 10, "kind": "legacy_raw_header", "pattern": "7404:422441:posti"},
    {"id": 11, "kind": "legacy_raw_header", "pattern": "X-Relaying-Domain: bad.invalid"},
]


def test_preview_uses_readonly_and_does_not_mutate_mail():
    backend = ReadOnlyIMAP()
    result = scan_junk_preview("sample@hotmail.com", "Junk", RULES,
                               "A" * 100, connector=lambda: backend)
    assert result["total_junk_uids"] == 3
    assert result["examined"] == 3 and result["matched"] == 2
    assert result["per_rule_matches"] == {10: 1, 11: 1}
    assert result["truncated"] is False
    assert backend.read_only is True
    assert backend.commands == ["SEARCH", "FETCH", "FETCH", "FETCH"]
    assert backend.logout_called


def test_preview_refuses_unsafe_scope():
    with pytest.raises(PreviewError):
        scan_junk_preview("x@example.invalid", "Inbox", RULES, "A" * 100,
                          connector=ReadOnlyIMAP)
    with pytest.raises(PreviewError):
        scan_junk_preview("x@example.invalid", "Junk", [], "A" * 100,
                          connector=ReadOnlyIMAP)
    with pytest.raises(PreviewError):
        scan_junk_preview("x@example.invalid", "Junk",
                          [{"kind": "sender_domain", "id": 1, "pattern": "example.com"}],
                          "A" * 100, connector=ReadOnlyIMAP)


def test_scl_nine_alone_does_not_match_any_rule():
    class SCLIMAP(ReadOnlyIMAP):
        def uid(self, command, *args):
            if command == "SEARCH":
                return "OK", [b"1"]
            if command == "FETCH":
                return "OK", [(b"HEADER", b"X-MS-Exchange-Organization-SCL: 9\r\n\r\n")]
            raise RuntimeError("mutation attempted")
    result = scan_junk_preview("sample@hotmail.com", "Junk", RULES,
                               "A" * 100, connector=SCLIMAP)
    assert result["matched"] == 0


def test_token_refresh_rotates_secret(tmp_path, monkeypatch):
    import json
    from filter_vision import oauth
    config = tmp_path / "settings.json"
    config.write_text(json.dumps({"a@hotmail.com": {
        "client_id": "12345678-1234-1234-1234-123456789000",
        "permission_url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        "oauth2_scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
    }}))
    monkeypatch.setenv("FV_OAUTH_CLIENTS_PATH", str(config))
    vault = oauth.TokenVault(tmp_path)
    vault.save(1, {"access_token": "O" * 120, "refresh_token": "P" * 120,
                   "expires_in": 3600})
    token_path = tmp_path / "oauth" / "1.token"
    original = token_path.read_bytes()
    assert oauth.access_token_for(1, "a@hotmail.com", vault) == "O" * 120
    assert original == token_path.read_bytes()
    monkeypatch.setattr(oauth.time, "time", lambda: 20000000000)
    monkeypatch.setattr(oauth, "_json_post",
                        lambda *args,**kw: {"access_token": "N" * 120,
                                           "refresh_token": "R" * 120,
                                           "expires_in": 3600})
    assert oauth.access_token_for(1, "a@hotmail.com", vault) == "N" * 120
    assert vault.load(1)["refresh_token"] == "R" * 120
    assert original != token_path.read_bytes()
