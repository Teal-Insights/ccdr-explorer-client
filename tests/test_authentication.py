import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import URLPath
from sqlmodel import Session, select
from datetime import timedelta
from unittest.mock import patch
import resend
from urllib.parse import urlparse, parse_qs

from main import app
from utils.models import User, PasswordResetToken
from utils.db import get_session
from utils.auth import (
    create_access_token,
    create_refresh_token,
    verify_password,
    get_password_hash,
    validate_token,
    generate_password_reset_url
)


# --- Fixture setup ---


# Test client fixture
@pytest.fixture(name="client")
def client_fixture(session: Session):
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
@pytest.fixture(name="test_user")
def test_user_fixture(session: Session):
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


# Mock email response fixture
@pytest.fixture
def mock_email_response():
    """
    Returns a mock Email response object
    """
    return resend.Email(id="6229f547-f3f6-4eb8-b0dc-82c1b09121b6")


@pytest.fixture
def mock_resend_send(mock_email_response):
    """
    Patches resend.Emails.send to return a mock response
    """
    with patch('resend.Emails.send', return_value=mock_email_response) as mock:
        yield mock


# --- Authentication Helper Function Tests ---


def test_password_hashing():
    password = "Test123!@#"
    hashed = get_password_hash(password)
    assert verify_password(password, hashed)
    assert not verify_password("wrong_password", hashed)


def test_token_creation_and_validation():
    data = {"sub": "test@example.com"}

    # Test access token
    access_token = create_access_token(data)
    decoded = validate_token(access_token, "access")
    assert decoded is not None
    assert decoded["sub"] == data["sub"]
    assert decoded["type"] == "access"

    # Test refresh token
    refresh_token = create_refresh_token(data)
    decoded = validate_token(refresh_token, "refresh")
    assert decoded is not None
    assert decoded["sub"] == data["sub"]
    assert decoded["type"] == "refresh"


def test_expired_token():
    data = {"sub": "test@example.com"}
    expired_delta = timedelta(minutes=-10)
    expired_token = create_access_token(data, expired_delta)
    decoded = validate_token(expired_token, "access")
    assert decoded is None


def test_invalid_token_type():
    data = {"sub": "test@example.com"}
    access_token = create_access_token(data)
    decoded = validate_token(access_token, "refresh")
    assert decoded is None


# --- API Endpoint Tests ---


def test_register_endpoint(client: TestClient, session: Session):
    response = client.post(
        "/auth/register",
        data={
            "name": "New User",
            "email": "new@example.com",
            "password": "NewPass123!@#",
            "confirm_password": "NewPass123!@#"
        },
        follow_redirects=False
    )
    assert response.status_code == 303

    # Check if user was created in database
    user = session.exec(select(User).where(
        User.email == "new@example.com")).first()
    assert user is not None
    assert user.name == "New User"
    assert verify_password("NewPass123!@#", user.hashed_password)


def test_login_endpoint(client: TestClient, test_user: User):
    response = client.post(
        "/auth/login",
        data={
            "email": test_user.email,
            "password": "Test123!@#"
        },
        follow_redirects=False
    )
    assert response.status_code == 303

    # Check if cookies are set
    cookies = response.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies


def test_refresh_token_endpoint(client: TestClient, test_user: User):
    # Create expired access token and valid refresh token
    access_token = create_access_token(
        {"sub": test_user.email},
        timedelta(minutes=-10)
    )
    refresh_token = create_refresh_token({"sub": test_user.email})

    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)

    response = client.post("/auth/refresh", follow_redirects=False)
    assert response.status_code == 303

    # Check for new tokens in headers
    cookie_headers = response.headers.get_list("set-cookie")
    assert any("access_token=" in cookie for cookie in cookie_headers)
    assert any("refresh_token=" in cookie for cookie in cookie_headers)

    # Get the new access token from headers for validation
    access_token_cookie = next(
        cookie for cookie in cookie_headers if "access_token=" in cookie
    )
    new_access_token = access_token_cookie.split(";")[0].split("=")[1]

    # Verify new access token is valid
    decoded = validate_token(new_access_token, "access")
    assert decoded is not None
    assert decoded["sub"] == test_user.email


def test_password_reset_flow(client: TestClient, session: Session, test_user: User, mock_resend_send):
    # Test forgot password request
    response = client.post(
        "/auth/forgot_password",
        data={"email": test_user.email},
        follow_redirects=False
    )
    assert response.status_code == 303

    # Verify the email was "sent" with correct parameters
    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args[0][0]  # Get the SendParams argument

    # Verify SendParams structure and required fields
    assert isinstance(call_args, dict)
    assert isinstance(call_args["from"], str)
    assert isinstance(call_args["to"], list)
    assert isinstance(call_args["subject"], str)
    assert isinstance(call_args["html"], str)

    # Verify content
    assert call_args["to"] == [test_user.email]
    assert call_args["from"] == "noreply@promptlytechnologies.com"
    assert "Password Reset Request" in call_args["subject"]
    assert "reset_password" in call_args["html"]

    # Verify reset token was created
    reset_token = session.exec(select(PasswordResetToken)
                               .where(PasswordResetToken.user_id == test_user.id)).first()
    assert reset_token is not None
    assert not reset_token.used

    # Test password reset
    response = client.post(
        "/auth/reset_password",
        data={
            "email": test_user.email,
            "token": reset_token.token,
            "new_password": "NewPass123!@#",
            "confirm_new_password": "NewPass123!@#"
        },
        follow_redirects=False
    )
    assert response.status_code == 303

    # Verify password was updated and token was marked as used
    session.refresh(test_user)
    session.refresh(reset_token)
    assert verify_password("NewPass123!@#", test_user.hashed_password)
    assert reset_token.used


def test_logout_endpoint(client: TestClient):
    # First set some cookies
    client.cookies.set("access_token", "some_access_token")
    client.cookies.set("refresh_token", "some_refresh_token")

    response = client.get("/auth/logout", follow_redirects=False)
    assert response.status_code == 303

    # Check for cookie deletion in headers
    cookie_headers = response.headers.get_list("set-cookie")
    assert any(
        "access_token=" in cookie and "Max-Age=0" in cookie for cookie in cookie_headers)
    assert any(
        "refresh_token=" in cookie and "Max-Age=0" in cookie for cookie in cookie_headers)


# --- Error Case Tests ---


def test_register_with_existing_email(client: TestClient, test_user: User):
    """Test that registration fails with an existing non-deleted user's email"""
    # Ensure test user is not deleted
    assert not test_user.deleted

    response = client.post(
        "/auth/register",
        data={
            "name": "Another User",
            "email": test_user.email,
            "password": "Test123!@#",
            "confirm_password": "Test123!@#"
        }
    )
    assert response.status_code == 400


def test_register_with_deleted_user_email(client: TestClient, test_user: User, session: Session):
    """Test that registration succeeds with a deleted user's email"""
    # Mark test user as deleted
    test_user.deleted = True
    session.add(test_user)
    session.commit()

    response = client.post(
        "/auth/register",
        data={
            "name": "New User",
            "email": test_user.email,
            "password": "Test123!@#",
            "confirm_password": "Test123!@#"
        },
        follow_redirects=False
    )
    assert response.status_code == 303

    # Verify new user was created
    new_user = session.exec(select(User).where(
        User.email == test_user.email,
        User.deleted == False
    )).first()
    assert new_user is not None
    assert new_user.id != test_user.id


def test_login_with_invalid_credentials(client: TestClient, test_user: User):
    response = client.post(
        "/auth/login",
        data={
            "email": test_user.email,
            "password": "WrongPass123!@#"
        }
    )
    assert response.status_code == 400


def test_password_reset_with_invalid_token(client: TestClient, test_user: User):
    response = client.post(
        "/auth/reset_password",
        data={
            "email": test_user.email,
            "token": "invalid_token",
            "new_password": "NewPass123!@#",
            "confirm_new_password": "NewPass123!@#"
        }
    )
    assert response.status_code == 400


def test_password_reset_url_generation(client: TestClient):
    """
    Tests that the password reset URL is correctly formatted and contains
    the required query parameters.
    """
    test_email = "test@example.com"
    test_token = "abc123"

    url = generate_password_reset_url(test_email, test_token)

    # Parse the URL
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    # Get the actual path from the FastAPI app
    reset_password_path: URLPath = app.url_path_for("reset_password")

    # Verify URL path
    assert parsed.path == str(reset_password_path)

    # Verify query parameters
    assert "email" in query_params
    assert "token" in query_params
    assert query_params["email"][0] == test_email
    assert query_params["token"][0] == test_token


def test_password_reset_email_url(client: TestClient, session: Session, test_user: User, mock_resend_send):
    """
    Tests that the password reset email contains a properly formatted reset URL.
    """
    response = client.post(
        "/auth/forgot_password",
        data={"email": test_user.email},
        follow_redirects=False
    )
    assert response.status_code == 303

    # Get the reset token from the database
    reset_token = session.exec(select(PasswordResetToken)
                               .where(PasswordResetToken.user_id == test_user.id)).first()
    assert reset_token is not None

    # Get the actual path from the FastAPI app
    reset_password_path: URLPath = app.url_path_for("reset_password")

    # Verify the email HTML contains the correct URL
    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args[0][0]
    html_content = call_args["html"]

    # Extract URL from HTML
    import re
    url_match = re.search(r'href=[\'"]([^\'"]*)[\'"]', html_content)
    assert url_match is not None
    reset_url = url_match.group(1)

    # Parse and verify the URL
    parsed = urlparse(reset_url)
    query_params = parse_qs(parsed.query)

    assert parsed.path == str(reset_password_path)
    assert query_params["email"][0] == test_user.email
    assert query_params["token"][0] == reset_token.token


def test_deleted_user_cannot_login(client: TestClient, test_user: User, session: Session):
    """Test that a deleted user cannot log in"""
    # First mark the user as deleted
    test_user.deleted = True
    session.add(test_user)
    session.commit()

    response = client.post(
        "/auth/login",
        data={
            "email": test_user.email,
            "password": "Test123!@#"
        }
    )
    assert response.status_code == 400


def test_deleted_user_cannot_use_tokens(client: TestClient, test_user: User, session: Session):
    """Test that a deleted user's tokens become invalid"""
    # Create tokens before marking user as deleted
    access_token = create_access_token({"sub": test_user.email})
    refresh_token = create_refresh_token({"sub": test_user.email})

    # Mark user as deleted
    test_user.deleted = True
    session.add(test_user)
    session.commit()

    # Set tokens in cookies
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)

    # Try to refresh tokens
    response = client.post("/auth/refresh", follow_redirects=False)
    assert response.status_code == 303  # user is redirected to login


def test_deleted_user_cannot_use_reset_token(client: TestClient, session: Session, test_user: User, mock_resend_send):
    """Test that a deleted user cannot use a previously issued reset token"""
    # First create a reset token
    response = client.post(
        "/auth/forgot_password",
        data={"email": test_user.email},
        follow_redirects=False
    )
    assert response.status_code == 303

    # Get the reset token
    reset_token = session.exec(select(PasswordResetToken)
                               .where(PasswordResetToken.user_id == test_user.id)).first()
    assert reset_token is not None

    # Now mark user as deleted
    test_user.deleted = True
    session.add(test_user)
    session.commit()

    # Try to use the reset token
    response = client.post(
        "/auth/reset_password",
        data={
            "email": test_user.email,
            "token": reset_token.token,
            "new_password": "NewPass123!@#",
            "confirm_new_password": "NewPass123!@#"
        },
        follow_redirects=False
    )
    assert response.status_code == 400
