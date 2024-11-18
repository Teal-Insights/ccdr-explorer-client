import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from datetime import timedelta

from main import app
from utils.models import User, PasswordResetToken
from utils.db import get_session
from utils.auth import (
    create_access_token,
    create_refresh_token,
    verify_password,
    get_password_hash,
    validate_token
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


# # TODO: Mock email sending
# def test_password_reset_flow(client: TestClient, session: Session, test_user: User):
#     # Test forgot password request
#     response = client.post(
#         "/auth/forgot_password",
#         data={"email": test_user.email},
#         follow_redirects=False
#     )
#     assert response.status_code == 303

#     # Verify reset token was created
#     reset_token = session.exec(select(PasswordResetToken)
#                                .where(PasswordResetToken.user_id == test_user.id)).first()
#     assert reset_token is not None
#     assert not reset_token.used

#     # Test password reset
#     response = client.post(
#         "/auth/reset_password",
#         data={
#             "email": test_user.email,
#             "token": reset_token.token,
#             "new_password": "NewPass123!@#",
#             "confirm_new_password": "NewPass123!@#"
#         },
#         follow_redirects=False
#     )
#     assert response.status_code == 303

#     # Verify password was updated and token was marked as used
#     session.refresh(test_user)
#     session.refresh(reset_token)
#     assert verify_password("NewPass123!@#", test_user.hashed_password)
#     assert reset_token.used


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
