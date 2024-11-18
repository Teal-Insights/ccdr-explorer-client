import pytest
from sqlmodel import create_engine, Session, delete
from utils.db import get_connection_url, set_up_db, tear_down_db
from utils.models import User, PasswordResetToken
from dotenv import load_dotenv

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
