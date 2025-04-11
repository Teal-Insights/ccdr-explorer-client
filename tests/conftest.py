import pytest
from typing import Generator
from sqlmodel import create_engine, Session, select
from sqlalchemy import Engine
from fastapi.testclient import TestClient
from dotenv import load_dotenv
from utils.core.db import get_connection_url, tear_down_db, set_up_db, create_default_roles
from utils.core.models import User, PasswordResetToken, EmailUpdateToken, Organization, Role, Account
from utils.core.auth import get_password_hash, create_access_token, create_refresh_token
from main import app

# Load environment variables
load_dotenv(override=True)

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
    Use PostgreSQL for testing to match production environment.
    """
    # Use PostgreSQL for testing to match production environment
    engine = create_engine(get_connection_url())
    return engine


@pytest.fixture(scope="session", autouse=True)
def set_up_database(engine) -> Generator[None, None, None]:
    """
    Set up the test database before running the test suite.
    Drop all tables and recreate them to ensure a clean state.
    """
    # Drop and recreate all tables using the helpers from db.py
    tear_down_db()
    set_up_db(drop=False)
    
    yield
    
    # Clean up after tests
    tear_down_db()


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
    for model in (PasswordResetToken, EmailUpdateToken, User, Role, Organization, Account):
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
    Creates a test user in the database linked to the test account.
    """
    user = User(
        name="Test User",
        account_id=test_account.id
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    
    # Also refresh the account to ensure the relationship is loaded
    session.refresh(test_account)
    return user


@pytest.fixture()
def unauth_client(session: Session) -> Generator[TestClient, None, None]:
    """
    Provides a TestClient instance without authentication.
    """
    client = TestClient(app)
    yield client


@pytest.fixture()
def auth_client(session: Session, test_account: Account, test_user: User) -> Generator[TestClient, None, None]:
    """
    Provides a TestClient instance with valid authentication tokens.
    """
    client = TestClient(app)

    # Create and set valid tokens
    access_token = create_access_token({"sub": test_account.email})
    refresh_token = create_refresh_token({"sub": test_account.email})

    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)

    yield client


@pytest.fixture
def test_organization(session: Session) -> Organization:
    """Create a test organization with default roles and permissions"""
    organization = Organization(name="Test Organization")
    session.add(organization)
    session.flush()

    if organization.id is None:
        pytest.fail("Failed to get organization ID after flush")

    # Use the utility function to create default roles and assign permissions
    # This function handles the commit internally
    create_default_roles(session, organization.id, check_first=False)

    return organization


@pytest.fixture
def org_owner(session: Session, test_organization: Organization) -> User:
    """Create a user who is the owner of the test organization"""
    # Create account
    account = Account(
        email="owner@example.com",
        hashed_password=get_password_hash("Owner123!@#")
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    
    # Create user
    user = User(
        name="Org Owner",
        account_id=account.id
    )
    session.add(user)
    # Find the Owner role for the test organization
    owner_role = session.exec(
        select(Role)
        .where(Role.organization_id == test_organization.id)
        .where(Role.name == "Owner")
    ).first()

    if owner_role is None:
        pytest.fail("Owner role not found for test organization")

    # Assign user to owner role
    user.roles.append(owner_role)
    
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def org_admin_user(session: Session, test_organization: Organization) -> User:
    """Create a user with Administrator role in the test organization"""
    # Create account
    account = Account(
        email="admin@example.com",
        hashed_password=get_password_hash("Admin123!@#")
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    
    # Create user
    user = User(
        name="Admin User",
        account_id=account.id
    )
    session.add(user)
    
    # Find the Admin role for the test organization (already created with permissions)
    admin_role = session.exec(
        select(Role)
        .where(Role.organization_id == test_organization.id)
        .where(Role.name == "Administrator")
    ).first()

    if admin_role is None:
        pytest.fail("Administrator role not found for test organization")

    # Assign role to user
    user.roles.append(admin_role)
    
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def org_member_user(session: Session, test_organization: Organization) -> User:
    """Create a user with basic Member role in the test organization"""
    # Create account
    account = Account(
        email="member@example.com",
        hashed_password=get_password_hash("Member123!@#")
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    
    # Create user
    user = User(
        name="Member User",
        account_id=account.id
    )
    session.add(user)
    
    # Find the Member role for the test organization (already created)
    member_role = session.exec(
        select(Role)
        .where(Role.organization_id == test_organization.id)
        .where(Role.name == "Member")
    ).first()

    if member_role is None:
        pytest.fail("Member role not found for test organization")

    # Assign role to user
    user.roles.append(member_role)
    
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def non_member_user(session: Session) -> User:
    """Create a user who is not a member of the test organization"""
    # Create account
    account = Account(
        email="nonmember@example.com",
        hashed_password=get_password_hash("NonMember123!@#")
    )
    session.add(account)
    session.commit()
    
    # Create user
    user = User(
        name="Non-Member User",
        account_id=account.id
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def auth_client_owner(session: Session, org_owner: User) -> Generator[TestClient, None, None]:
    """Provides a TestClient authenticated as the organization owner"""
    client = TestClient(app)
    
    # Initialize tokens
    access_token = ""
    refresh_token = ""
    
    # Create and set valid tokens
    if org_owner.account:
        access_token = create_access_token({"sub": org_owner.account.email})
        refresh_token = create_refresh_token({"sub": org_owner.account.email})
        
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    
    yield client


@pytest.fixture
def auth_client_admin(session: Session, org_admin_user: User) -> Generator[TestClient, None, None]:
    """Provides a TestClient authenticated as an organization administrator"""
    client = TestClient(app)
    
    # Initialize tokens
    access_token = ""
    refresh_token = ""
    
    # Create and set valid tokens
    if org_admin_user.account:
        access_token = create_access_token({"sub": org_admin_user.account.email})
        refresh_token = create_refresh_token({"sub": org_admin_user.account.email})
        
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    
    yield client


@pytest.fixture
def auth_client_member(session: Session, org_member_user: User) -> Generator[TestClient, None, None]:
    """Provides a TestClient authenticated as the organization member"""
    client = TestClient(app)
    
    # Initialize tokens
    access_token = ""
    refresh_token = ""
    
    # Create and set valid tokens
    if org_member_user.account:
        access_token = create_access_token({"sub": org_member_user.account.email})
        refresh_token = create_refresh_token({"sub": org_member_user.account.email})
        
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    
    yield client


@pytest.fixture
def auth_client_non_member(session: Session, non_member_user: User) -> Generator[TestClient, None, None]:
    """Provides a TestClient authenticated as a non-member"""
    client = TestClient(app)
    
    # Initialize tokens
    access_token = ""
    refresh_token = ""
    
    # Create and set valid tokens
    if non_member_user.account:
        access_token = create_access_token({"sub": non_member_user.account.email})
        refresh_token = create_refresh_token({"sub": non_member_user.account.email})
        
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    
    yield client


@pytest.fixture
def second_test_organization(session: Session) -> Organization:
    """Create a second test organization for multi-organization tests"""
    organization = Organization(name="Second Test Organization")
    session.add(organization)
    session.commit()
    return organization