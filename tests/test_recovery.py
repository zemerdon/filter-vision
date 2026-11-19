import sqlite3

import pytest

from filter_vision.recovery import (
    BackupError, create_key, backup, verify, restore_staging,
)
from filter_vision.oauth import TokenVault
from filter_vision.storage import Store


def _state(tmp_path):
    data, cfg = tmp_path / "data", tmp_path / "config"
    store = Store(data)
    token = TokenVault(data)
    token.save(1, {"access_token": "A" * 100, "refresh_token": "R" * 100,
                   "expires_in": 3600})
    token.save(2, {"access_token": "B" * 100, "refresh_token": "S" * 100,
                   "expires_in": 3600})
    cfg.mkdir(mode=0o700)
    (cfg/"oauth-clients.json").write_text('{"test": true}')
    (cfg/"web.env").write_text("FV_ALLOWED_HOSTS=localhost")
    return data,cfg


def test_encrypted_backup_verify_restore_includes_both_oauth_keys(tmp_path):
    data,cfg=_state(tmp_path)
    key=tmp_path/"recover.key"
    create_key(key)
    archive=tmp_path/"full.fvb"
    backup(data,cfg,archive,key)
    assert archive.stat().st_mode & 0o777 == 0o600
    assert key.stat().st_mode & 0o777 == 0o600
    content=archive.read_bytes()
    assert b"R"*35 not in content
    assert b"FV_ALLOWED_HOSTS" not in content
    files=verify(archive,key)
    assert "data/oauth/fernet.key" in files
    assert "data/oauth/1.token" in files
    assert "data/oauth/2.token" in files
    assert "data/browser-session.key" in files
    assert "data/filter-vision.sqlite3" in files
    report=restore_staging(archive,key,tmp_path/"restored-data",tmp_path/"restored-config")
    assert report["token_files"]==2
    again=TokenVault(tmp_path/"restored-data")
    assert again.load(1)["refresh_token"]=="R"*100
    assert again.load(2)["refresh_token"]=="S"*100
    con=sqlite3.connect(tmp_path/"restored-data"/"filter-vision.sqlite3")
    assert con.execute("PRAGMA integrity_check").fetchone()[0]=="ok"
    con.close()
    with pytest.raises(BackupError,match="must not exist"):
        restore_staging(archive,key,tmp_path/"restored-data",tmp_path/"restored-config")


def test_recovery_detects_modified_archive_or_wrong_key(tmp_path):
    data,cfg=_state(tmp_path)
    key=tmp_path/"recover.key";create_key(key)
    archive=tmp_path/"backup.fvb";backup(data,cfg,archive,key)
    wrong=tmp_path/"wrong.key";create_key(wrong)
    with pytest.raises(BackupError,match="decrypt"):
        verify(archive,wrong)
    original=archive.read_bytes()
    archive.write_bytes(original[:-1]+bytes([original[-1]^1]))
    with pytest.raises(BackupError,match="decrypt"):
        verify(archive,key)


def test_recovery_blocks_symlink_files(tmp_path):
    data,cfg=_state(tmp_path)
    key=tmp_path/"recover.key";create_key(key)
    target=data/"browser-session.key"
    target.unlink()
    target.symlink_to(tmp_path/"other")
    with pytest.raises(BackupError,match="unsafe"):
        backup(data,cfg,tmp_path/"backup.fvb",key)
