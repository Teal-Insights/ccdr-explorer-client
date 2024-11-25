from fastapi.testclient import TestClient
from httpx import Response
from sqlmodel import Session

from main import app
from utils.models import User


def test_update_profile_unauthorized(unauth_client: TestClient):
    """Test that unauthorized users cannot edit profile"""
    response: Response = unauth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": "New Name",
            "email": "new@example.com",
            "avatar_url": "https://example.com/avatar.jpg"
        },
        follow_redirects=False
    )
    assert response.status_code == 303  # Redirect to login
    assert response.headers["location"] == app.url_path_for("read_login")


def test_update_profile_authorized(auth_client: TestClient, test_user: User, session: Session):
    """Test that authorized users can edit their profile"""

    # Update profile
    response: Response = auth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": "Updated Name",
            "email": "updated@example.com",
            "avatar_url": "https://example.com/new-avatar.jpg"
        },
        follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == app.url_path_for("read_profile")

    # Verify changes in database
    session.refresh(test_user)
    assert test_user.name == "Updated Name"
    assert test_user.email == "updated@example.com"
    assert test_user.avatar_url == "https://example.com/new-avatar.jpg"


def test_delete_account_unauthorized(unauth_client: TestClient):
    """Test that unauthorized users cannot delete account"""
    response: Response = unauth_client.post(
        app.url_path_for("delete_account"),
        data={"confirm_delete_password": "Test123!@#"},
        follow_redirects=False
    )
    assert response.status_code == 303  # Redirect to login
    assert response.headers["location"] == app.url_path_for("read_login")


def test_delete_account_wrong_password(auth_client: TestClient, test_user: User):
    """Test that account deletion fails with wrong password"""
    response: Response = auth_client.post(
        app.url_path_for("delete_account"),
        data={"confirm_delete_password": "WrongPassword123!"},
        follow_redirects=False
    )
    assert response.status_code == 400
    assert "Password is incorrect" in response.text.strip()


def test_delete_account_success(auth_client: TestClient, test_user: User, session: Session):
    """Test successful account deletion"""

    # Delete account
    response: Response = auth_client.post(
        app.url_path_for("delete_account"),
        data={"confirm_delete_password": "Test123!@#"},
        follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == app.url_path_for("logout")

    # Verify user is deleted from database
    user = session.get(User, test_user.id)
    assert user is None
