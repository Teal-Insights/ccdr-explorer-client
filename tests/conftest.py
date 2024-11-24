import pytest
from dotenv import load_dotenv
from sqlmodel import create_engine, Session, delete
from fastapi.testclient import TestClient
from utils.db import get_connection_url, set_up_db, tear_down_db, get_session
from utils.models import User, PasswordResetToken
from utils.auth import get_password_hash
from main import app

load_dotenv()


@pytest.fixture(scope="session")
def engine():
    """
    Create a new SQLModel engine for the test database.
    Use an in-memory SQLite database for testing.
    """
    engine = create_engine(
        get_connection_url()
    )
    return engine


@pytest.fixture(scope="session", autouse=True)
def set_up_database(engine):
    """
    Set up the test database before running the test suite.
    Drop all tables and recreate them to ensure a clean state.
    """
    set_up_db(drop=True)
    yield
    tear_down_db()


@pytest.fixture
def session(engine):
    """
    Provide a session for database operations in tests.
    """
    with Session(engine) as session:
        yield session


@pytest.fixture(autouse=True)
def clean_db(session: Session):
    """
    Cleans up the database tables before each test.
    """
    # Exempt from mypy until SQLModel overload properly supports delete()
    session.exec(delete(PasswordResetToken))  # type: ignore
    session.exec(delete(User))  # type: ignore

    session.commit()


# Test client fixture
@pytest.fixture()
def client(session: Session):
    """
    Provides a TestClient instance with the session fixture.
    Overrides the get_session dependency to use the test session.
    """
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


# Test user fixture
@pytest.fixture()
def test_user(session: Session):
    """
    Creates a test user in the database.
    """
    user = User(
        name="Test User",
        email="test@example.com",
        hashed_password=get_password_hash("Test123!@#")
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user
