# tests/conftest.py
import pytest
from fastapi.testclient import TestClient
import importlib

# Import the main app and the settings dependency function
from api.main import app
from api.config import get_settings

@pytest.fixture
def client():
    """
    This is the definitive fixture for providing a clean TestClient.
    
    It programmatically resets the app's dependency overrides before
    every test. This is the key to ensuring that tests are isolated
    and do not interfere with each other's configurations.
    """
    # Ensure a clean state for every test
    app.dependency_overrides = {}
    
    # Yield the client to the test function
    yield TestClient(app)
    
    # Teardown: Clean up the overrides after the test is done
    app.dependency_overrides = {}