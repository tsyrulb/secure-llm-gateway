import pytest
from fastapi.testclient import TestClient
import importlib

# Import the modules that need to be reloaded for tests
from api import config, main
from api.firewall import context_firewall
from api.policy import local_policy

@pytest.fixture
def client():
    """
    This fixture provides a TestClient for the FastAPI app.
    Crucially, it reloads the application and its configuration modules
    for every test, ensuring that any patches applied by monkeypatch
    are correctly reflected in the application instance being tested.
    """
    # Reload modules to ensure test-specific configuration is applied
    importlib.reload(config)
    importlib.reload(context_firewall)
    importlib.reload(local_policy)
    importlib.reload(main) # Reload the main app module as well

    # Create a new TestClient with the reloaded app
    return TestClient(main.app)