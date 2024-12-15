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
        },
        files={
            "avatar_file": ("test_avatar.jpg", b"fake image data", "image/jpeg")
        },
        follow_redirects=False
    )
    assert response.status_code == 303  # Redirect to login
    assert response.headers["location"] == app.url_path_for("read_login")


def test_update_profile_authorized(auth_client: TestClient, test_user: User, session: Session):
    """Test that authorized users can edit their profile"""
    
    # Create test image data
    test_image_data = b"fake image data"
    
    # Update profile
    response: Response = auth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": "Updated Name",
            "email": "updated@example.com",
        },
        files={
            "avatar_file": ("test_avatar.jpg", test_image_data, "image/jpeg")
        },
        follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == app.url_path_for("read_profile")

    # Verify changes in database
    session.refresh(test_user)
    assert test_user.name == "Updated Name"
    assert test_user.email == "updated@example.com"
    assert test_user.avatar_data == test_image_data
    assert test_user.avatar_content_type == "image/jpeg"


def test_update_profile_without_avatar(auth_client: TestClient, test_user: User, session: Session):
    """Test that profile can be updated without changing the avatar"""
    response: Response = auth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": "Updated Name",
            "email": "updated@example.com",
        },
        follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == app.url_path_for("read_profile")

    # Verify changes in database
    session.refresh(test_user)
    assert test_user.name == "Updated Name"
    assert test_user.email == "updated@example.com"


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
    assert response.status_code == 422
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


def test_get_avatar_authorized(auth_client: TestClient, test_user: User):
    """Test getting user avatar"""
    # First upload an avatar
    test_image_data = b"fake image data"
    auth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": test_user.name,
            "email": test_user.email,
        },
        files={
            "avatar_file": ("test_avatar.jpg", test_image_data, "image/jpeg")
        },
    )

    # Then try to retrieve it
    response = auth_client.get(
        app.url_path_for("get_avatar")
    )
    assert response.status_code == 200
    assert response.content == test_image_data
    assert response.headers["content-type"] == "image/jpeg"


def test_get_avatar_unauthorized(unauth_client: TestClient):
    """Test getting avatar for non-existent user"""
    response = unauth_client.get(
        app.url_path_for("get_avatar"),
        follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == app.url_path_for("read_login")
