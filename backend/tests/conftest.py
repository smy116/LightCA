import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

import os
import sys

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set test environment variables before importing app
os.environ["MASTER_KEY"] = "test_master_key_32_characters_minimum_length"
os.environ["ADMIN_PASSWORD"] = "admin_password"
os.environ["DB_TYPE"] = "sqlite"
# Use file-based SQLite with check_same_thread=False for thread safety in tests
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["DEBUG"] = "true"
os.environ["HOST"] = "0.0.0.0"
os.environ["PORT"] = "8000"

# Import app after setting environment variables
from app.main import app
from app.database import Base, get_db, engine as app_engine

# Import all models to ensure tables are created
from app.models.key import Key
from app.models.certificate import Certificate
from app.models.template import Template
from app.models.crl import CRL


@pytest.fixture(scope="function")
def db() -> Generator[Session, None, None]:
    """Create a fresh database for each test"""
    connection = app_engine.connect()
    transaction = connection.begin()

    # Create all tables
    Base.metadata.create_all(bind=connection)

    # Create a session bound to the connection
    TestingSessionLocal = sessionmaker(bind=connection)
    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture(scope="function")
def client(db: Session) -> Generator[TestClient, None, None]:
    """Create a test client with database override"""

    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def auth_token(client: TestClient) -> str:
    """Get authentication token for testing"""
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin_password"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    return data["token"]


@pytest.fixture
def auth_headers(auth_token: str) -> dict:
    """Get headers with authentication token"""
    return {"Authorization": f"Bearer {auth_token}"}
