import re
import pytest
from fastapi.testclient import TestClient
from filter_vision.app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app(tmp_path / "state")


@pytest.fixture
def client(app):
    # Browser on a trusted private LAN, connecting over HTTPS.
    with TestClient(app, base_url="https://filter-vision",
                    client=("192.168.1.69", 50000)) as test:
        yield test


@pytest.fixture
def signed_in(client):
    # Compatibility name for existing tests: in passwordless mode, no login.
    response = client.get("/accounts")
    assert response.status_code == 200
    match = re.search(r'name="csrf" value="([0-9a-f]{64})"', response.text)
    assert match
    return client, match.group(1)
