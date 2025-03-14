from unittest.mock import MagicMock
from datetime import datetime, timedelta, UTC
from utils.models import EmailUpdateToken, User
from utils.dependencies import get_user_from_email_update_token


def test_get_user_from_email_update_token() -> None:
    """
    Tests retrieving a user using an email update token.
    """
    session = MagicMock()

    # Test valid token
    mock_user = User(id=1, email="test@example.com")
    mock_token = EmailUpdateToken(
        user_id=1,
        token="valid_token",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        used=False
    )
    session.exec.return_value.first.return_value = (mock_user, mock_token)

    user, token = get_user_from_email_update_token(1, "valid_token", session)
    assert user == mock_user
    assert token == mock_token

    # Test invalid token
    session.exec.return_value.first.return_value = None
    user, token = get_user_from_email_update_token(1, "invalid_token", session)
    assert user is None
    assert token is None