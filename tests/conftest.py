import pytest
from fastapi.testclient import TestClient
from filter_vision.app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app(tmp_path / "state")


@pytest.fixture
def client(app):
    with TestClient(app) as test:
        yield test


@pytest.fixture
def signed_in(client, app):
    code = app.state.store.setup_path.read_text().strip()
    result = client.post("/setup", data={
        "setup_code": code, "password": "LongRandomTestPassword-2026!",
        "password_confirm": "LongRandomTestPassword-2026!",
    }, follow_redirects=False)
    assert result.status_code == 303
    assert not app.state.store.setup_path.exists()
    result = client.post("/login", data={"password": "LongRandomTestPassword-2026!"},
                         follow_redirects=False)
    assert result.status_code == 303
    assert "fv_session" in client.cookies
    with app.state.store.db() as con:
        csrf = con.execute("SELECT csrf FROM sessions").fetchone()[0]
    return client, csrf
