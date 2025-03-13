import pytest
from typing import Generator
from sqlmodel import create_engine, Session, select, SQLModel
from sqlalchemy import Engine
from fastapi.testclient import TestClient
from utils.db import get_session
from utils.models import User, PasswordResetToken, Organization, Role, Account, Permission
from utils.auth import get_password_hash, create_access_token, create_refresh_token
from utils.enums import ValidPermissions
from main import app


# Define a custom exception for test setup errors
class SetupError(Exception):
    """Exception raised for errors in the test setup process."""
    def __init__(self, message="An error occurred during test setup"):
        self.message = message
        super().__init__(self.message)


@pytest.fixture(scope="session")
def engine() -> Engine:
    """
    Create a new SQLModel engine for the test database.
    Use an in-memory SQLite database for testing.
    """
    # Use in-memory SQLite for testing
    engine = create_engine("sqlite:///:memory:")
    return engine


@pytest.fixture(scope="session", autouse=True)
def set_up_database(engine) -> Generator[None, None, None]:
    """
    Set up the test database before running the test suite.
    Drop all tables and recreate them to ensure a clean state.
    """
    # Create all tables in the in-memory database
    SQLModel.metadata.create_all(engine)
    
    # Create permissions
    with Session(engine) as session:
        # Check if permissions already exist
        existing_permissions = session.exec(select(Permission)).all()
        if not existing_permissions:
            # Create all permissions from the ValidPermissions enum
            for permission in ValidPermissions:
                session.add(Permission(name=permission))
            session.commit()
    
    yield
    # Drop all tables
    SQLModel.metadata.drop_all(engine)


@pytest.fixture
def session(engine) -> Generator[Session, None, None]:
    """
    Provide a session for database operations in tests.
    """
    with Session(engine) as session:
        yield session


@pytest.fixture(autouse=True)
def clean_db(session: Session) -> None:
    """
    Cleans up the database tables before each test.
    """
    # Don't delete permissions as they are required for tests
    for model in (PasswordResetToken, User, Role, Organization, Account):
        for record in session.exec(select(model)).all():
            session.delete(record)

    session.commit()


@pytest.fixture()
def test_account(session: Session) -> Account:
    """
    Creates a test account in the database.
    """
    account = Account(
        email="test@example.com",
        hashed_password=get_password_hash("Test123!@#")
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    return account


@pytest.fixture()
def test_user(session: Session, test_account: Account) -> User:
    """
    Creates a test user in the database.
    """
    user = User(
        name="Test User",
        account_id=test_account.id
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture()
def unauth_client(session: Session) -> Generator[TestClient, None, None]:
    """
    Provides a TestClient instance without authentication.
    """
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture()
def auth_client(session: Session, test_account: Account) -> Generator[TestClient, None, None]:
    """
    Provides a TestClient instance with valid authentication tokens.
    """
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)

    # Create and set valid tokens
    access_token = create_access_token({"sub": test_account.email})
    refresh_token = create_refresh_token({"sub": test_account.email})

    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)

    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def test_organization(session: Session) -> Organization:
    """Create a test organization for use in tests"""
    organization = Organization(name="Test Organization")
    session.add(organization)
    session.commit()
    return organization
