import pytest
from fastapi.testclient import TestClient
from api.main import app

@pytest.fixture
def client():
    """Provides a TestClient instance for making requests to the app."""
    return TestClient(app)
