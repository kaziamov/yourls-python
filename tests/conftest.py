import pytest
from src.app import app as flask_app # Import your Flask app instance

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Configure the app for testing
    flask_app.config.update({
        "TESTING": True,
        "SECRET_KEY": "testing-secret-key", # Use a fixed key for tests
        "WTF_CSRF_ENABLED": False, # Disable CSRF for easier testing (if using Flask-WTF later)
        # Suppress flashing messages in tests unless specifically tested
        # "DISABLE_FLASH_MESSAGES_IN_TESTING": True 
        # If you use a test database, configure it here
        # "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", 
    })
    
    # TODO: Set up any necessary test database actions here (creation, seeding)
    
    yield flask_app
    
    # TODO: Clean up any test database actions here (dropping tables, closing connections)

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands (if any)."""
    return app.test_cli_runner() 