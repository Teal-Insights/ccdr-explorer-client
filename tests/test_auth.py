import re
import string
import random
from datetime import timedelta
from urllib.parse import urlparse, parse_qs
from starlette.datastructures import URLPath
from main import app
from utils.auth import (
    create_access_token,
    create_refresh_token,
    verify_password,
    get_password_hash,
    validate_token,
    generate_password_reset_url,
    PASSWORD_PATTERN
)


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

def test_password_reset_url_generation():
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

def test_password_pattern():
    """
    Tests that the password pattern is correctly defined. to require at least
    one uppercase letter, one lowercase letter, one digit, and one special
    character, and at least 8 characters long. Allowed special characters are:
    !@#$%^&*()_+-=[]{}|;:,.<>?
    """
    special_characters = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits

    required_elements = {
        "special": special_characters,
        "uppercase": uppercase_letters,
        "lowercase": lowercase_letters,
        "digit": digits
    }
    required_length = 8

    # Randomized valid password tests
    for _ in range(50):
        password = ""
        for element in required_elements:
            n = random.randint(required_length // len(required_elements), required_length)
            password += ''.join(
                random.choice(required_elements[element])
                for _ in range(n)
            )
        # Randomize the order of the characters in the string
        password = ''.join(random.sample(password, len(password)))
        assert re.match(PASSWORD_PATTERN, password) is not None

    # Invalid password tests

    # Empty password
    password = ""
    assert re.match(PASSWORD_PATTERN, password) is None

    # Too short
    password = "aA1!aA1"
    assert re.match(PASSWORD_PATTERN, password) is None

    # No uppercase letter
    password = "a1!" * 3
    assert re.match(PASSWORD_PATTERN, password) is None

    # No lowercase letter
    password = "A1!" * 3
    assert re.match(PASSWORD_PATTERN, password) is None

    # No digit
    password = "aA!" * 3
    assert re.match(PASSWORD_PATTERN, password) is None

    # No special character
    password = "aA1" * 3
    assert re.match(PASSWORD_PATTERN, password) is None
