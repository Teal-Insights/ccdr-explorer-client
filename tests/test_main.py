from fastapi.testclient import TestClient

from utils.models import User
from main import app


def test_read_profile_unauthorized(unauth_client: TestClient):
    """Test that unauthorized users cannot view profile"""
    response = unauth_client.get(app.url_path_for(
        "read_profile"), follow_redirects=False)
    assert response.status_code == 303  # Redirect to login
    assert response.headers["location"] == app.url_path_for("read_login")


def test_read_profile_authorized(auth_client: TestClient, test_user: User):
    """Test that authorized users can view their profile"""
    response = auth_client.get(app.url_path_for("read_profile"))
    assert response.status_code == 200
    # Check that the response contains the expected HTML content
    assert test_user.email in response.text
    assert test_user.name in response.text
