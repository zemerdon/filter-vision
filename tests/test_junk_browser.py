"""IMAP browse never mutates a mailbox and rechecks UID identity/size."""
import pytest
from filter_vision.junk_browse import list_junk, fetch_selected, BrowseError


def email(sender, subject):
    return (f"From: {sender}\r\nSubject: {subject}\r\n"
            f"Date: Fri, 20 Nov 2026 14:00:00 +1000\r\n"
            f"MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhello").encode()


MESSAGES={
    11:email("one@novahockey.com","Campaign A"),
    12:email("two@example.com","Campaign B"),
}


class ReadOnly:
    def __init__(self,validity=55, changed=False, large=False):
        self.calls=[]
        self.validity=validity
        self.changed=changed
        self.large=large
        self.readonly=False
        self.closed=False

    def authenticate(self,method,callback):
        self.calls.append("AUTH")
        assert method=="XOAUTH2" and b"Bearer" in callback(b"")
        return "OK",[b"ok"]

    def select(self,folder,readonly=False):
        self.calls.append("SELECT")
        assert folder=="Junk"
        self.readonly=readonly
        return "OK",[b"2"]

    def response(self,name):
        assert name=="UIDVALIDITY"
        return name,[str(self.validity).encode()]

    def uid(self,command,*args):
        self.calls.append(command)
        assert command in ("SEARCH","FETCH")
        if command=="SEARCH":
            return "OK",[b"11 12"]
        uid=int(args[0])
        source=MESSAGES[uid]
        if self.changed:
            source=email("other@example.net","Changed since listing")
        if args[1]=="(BODY.PEEK[HEADER])":
            return "OK",[(b"HEADER",source.split(b"\r\n\r\n")[0]+b"\r\n")]
        if args[1]=="(RFC822.SIZE)":
            size=4*1024*1024 if self.large else len(source)
            return "OK",[f"{uid} (RFC822.SIZE {size})".encode()]
        assert args[1]=="(BODY.PEEK[]<0.2097153>)"
        return "OK",[(b"BODY",source)]

    def logout(self):
        self.closed=True


def account(**values):
    return {
        "id":1,"label":"Mailbox 1","provider":"outlook",
        "host":"outlook.office365.com","port":993,"username":"sample@example.invalid",
        "folder":"Junk",**values,
    }


def test_listing_and_selection_are_only_readonly():
    connections=[]
    def connect():
        conn=ReadOnly()
        connections.append(conn)
        return conn
    rows=list_junk(account(),"test",connector=connect)
    assert len(rows)==2
    assert {r["subject"] for r in rows}=={"Campaign A","Campaign B"}
    assert all(len(r["ref"])>15 for r in rows)
    selected=fetch_selected(account(),rows,"test",connector=connect)
    assert {r["subject"] for r in selected}=={"Campaign A","Campaign B"}
    assert all(r.get("manual_headers") for r in selected)
    assert all(c.readonly and c.closed for c in connections)
    assert all(set(c.calls)<={"AUTH","SELECT","FETCH","SEARCH"} for c in connections)


def test_stale_uid_fails_without_body_fetch():
    rows=list_junk(account(),"test",connector=ReadOnly)
    for backend in (ReadOnly(validity=66),ReadOnly(changed=True),ReadOnly(large=True)):
        with pytest.raises(BrowseError):
            fetch_selected(account(),rows,"test",connector=lambda:backend)
        assert "STORE" not in backend.calls and "EXPUNGE" not in backend.calls
        assert backend.closed


@pytest.mark.parametrize("change",[
    {"folder":"Inbox"}, {"provider":"gmail"}, {"port":143},
    {"host":"malicious.example.invalid"},
])
def test_unapproved_or_non_junk_source_rejected(change):
    config=account()
    config.update(change)
    with pytest.raises(BrowseError):
        list_junk(config,"test",connector=ReadOnly)


def test_selection_rejects_budget_and_nonexistent_source():
    rows=list_junk(account(),"test",connector=ReadOnly)
    with pytest.raises(BrowseError):
        fetch_selected(account(),rows,"test",connector=ReadOnly,remaining_budget=10)
    with pytest.raises(BrowseError):
        fetch_selected(account(),[], "test",connector=ReadOnly)
