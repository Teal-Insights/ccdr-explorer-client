# utils.py
import os
import re
import jwt
import uuid
import logging
import resend
from dotenv import load_dotenv
from pydantic import field_validator, ValidationInfo
from sqlmodel import Session, select
from bcrypt import gensalt, hashpw, checkpw
from datetime import UTC, datetime, timedelta
from typing import Optional
from fastapi import Depends, Cookie, HTTPException, status
from utils.db import get_session
from utils.models import User, PasswordResetToken

load_dotenv()
logger = logging.getLogger("uvicorn.error")


# --- AUTH ---

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30


# Define the oauth2 scheme to get the token from the cookie
def oauth2_scheme_cookie(
    access_token: Optional[str] = Cookie(None, alias="access_token"),
    refresh_token: Optional[str] = Cookie(None, alias="refresh_token"),
) -> tuple[Optional[str], Optional[str]]:
    return access_token, refresh_token


class PasswordValidationError(HTTPException):
    def __init__(self, field: str, message: str):
        super().__init__(
            status_code=422,
            detail={
                "field": field,
                "message": message
            }
        )


class PasswordMismatchError(PasswordValidationError):
    def __init__(self, field: str = "confirm_password"):
        super().__init__(
            field=field,
            message="The passwords you entered do not match"
        )


def create_password_validator(field_name: str = "password"):
    """
    Factory function that creates a password validation decorator for Pydantic models.

    Args:
        field_name: Name of the field to validate and use in error messages

    Returns:
        A configured field_validator for password validation
    """
    @field_validator(field_name, check_fields=False)
    def validate_password_strength(v: str) -> str:
        """
        Validate password meets security requirements:
        - At least one number
        - At least one uppercase and one lowercase letter
        - At least one special character
        - At least 8 characters long
        """
        logger.debug(f"Validating password for {field_name}")
        pattern = re.compile(
            r"(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*?&{}<>.,\\'#\-_=+\(\)\[\]:;|~])[A-Za-z\d@$!%*?&{}<>.,\\'#\-_=+\(\)\[\]:;|~]{8,}")
        if not pattern.match(v):
            logger.debug(f"Password for {
                         field_name} does not satisfy the security policy")
            raise PasswordValidationError(
                field=field_name,
                message=f"{field_name} does not satisfy the security policy"
            )
        return v

    return validate_password_strength


def create_passwords_match_validator(password_field: str, confirm_field: str):
    """
    Factory function that creates a password matching validation decorator for Pydantic models.

    Args:
        password_field: Name of the main password field
        confirm_field: Name of the confirmation password field

    Returns:
        A configured field_validator for password matching validation
    """
    @field_validator(confirm_field)
    def passwords_match(v: str, values: ValidationInfo) -> str:
        if password_field in values.data and v != values.data[password_field]:
            raise PasswordMismatchError(field=confirm_field)
        return v

    return passwords_match


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt with a random salt
    """
    # Convert the password to bytes and generate the hash
    password_bytes = password.encode('utf-8')
    salt = gensalt()
    return hashpw(password_bytes, salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a bcrypt hash
    """
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return checkpw(password_bytes, hashed_bytes)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    to_encode.update({"type": "access"})
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(
            UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    to_encode.update({"type": "refresh"})
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def validate_token(token: str, token_type: str = "access") -> Optional[dict]:
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Check if the token has expired
        if decoded_token["exp"] < datetime.now(UTC).timestamp():
            return None

        # Optional: Add additional checks specific to each token type
        if token_type == "refresh" and "refresh" not in decoded_token.get("type", ""):
            return None
        elif token_type == "access" and "access" not in decoded_token.get("type", ""):
            return None

        return decoded_token
    except jwt.PyJWTError:
        return None


def validate_token_and_get_user(
    token: str,
    token_type: str,
    session: Session
) -> tuple[Optional[User], Optional[str], Optional[str]]:
    decoded_token = validate_token(token, token_type=token_type)
    if decoded_token:
        user_email = decoded_token.get("sub")
        user = session.exec(select(User).where(
            User.email == user_email,
            User.deleted == False
        )).first()
        if user:
            if token_type == "refresh":
                new_access_token = create_access_token(
                    data={"sub": user.email})
                new_refresh_token = create_refresh_token(
                    data={"sub": user.email})
                return user, new_access_token, new_refresh_token
            return user, None, None
    return None, None, None


def get_user_from_tokens(
    tokens: tuple[Optional[str], Optional[str]],
    session: Session
) -> tuple[Optional[User], Optional[str], Optional[str]]:
    access_token, refresh_token = tokens

    # Try to validate the access token first
    user, _, _ = validate_token_and_get_user(
        access_token, "access", session) if access_token else (None, None, None)
    if user:
        return user, None, None

    # If access token is invalid or missing, try the refresh token
    if refresh_token:
        user, new_access_token, new_refresh_token = validate_token_and_get_user(
            refresh_token, "refresh", session)
        if user:
            return user, new_access_token, new_refresh_token

    # Return a tuple of None values if no valid user is found
    return None, None, None


def get_authenticated_user(
    tokens: tuple[Optional[str], Optional[str]
                  ] = Depends(oauth2_scheme_cookie),
    session: Session = Depends(get_session),
) -> User:
    user, new_access_token, new_refresh_token = get_user_from_tokens(
        tokens, session)

    if user:
        if new_access_token and new_refresh_token:
            raise NeedsNewTokens(user, new_access_token, new_refresh_token)
        return user

    # If both tokens are invalid or missing, redirect to login
    raise HTTPException(
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        headers={"Location": "/login"}
    )


def get_optional_user(
    tokens: tuple[Optional[str], Optional[str]
                  ] = Depends(oauth2_scheme_cookie),
    session: Session = Depends(get_session)
) -> Optional[User]:
    user, new_access_token, new_refresh_token = get_user_from_tokens(
        tokens, session)

    if user:
        if new_access_token and new_refresh_token:
            raise NeedsNewTokens(user, new_access_token, new_refresh_token)
        return user

    return None


class NeedsNewTokens(Exception):
    def __init__(self, user: User, access_token: str, refresh_token: str):
        self.user = user
        self.access_token = access_token
        self.refresh_token = refresh_token


def generate_password_reset_url(email: str, token: str) -> str:
    """
    Generates the password reset URL with proper query parameters.

    Args:
        email: User's email address
        token: Password reset token

    Returns:
        Complete password reset URL
    """
    base_url = os.getenv('BASE_URL')
    return f"{base_url}/auth/reset_password?email={email}&token={token}"


def send_reset_email(email: str, session: Session):
    # Check for an existing unexpired token
    user = session.exec(select(User).where(
        User.email == email,
        User.deleted == False
    )).first()
    if user:
        existing_token = session.exec(
            select(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.expires_at > datetime.now(UTC),
                PasswordResetToken.used == False
            )
        ).first()

        if existing_token:
            logger.debug("An unexpired token already exists for this user.")
            return

        # Generate a new token
        token = str(uuid.uuid4())
        reset_token = PasswordResetToken(user_id=user.id, token=token)
        session.add(reset_token)

        try:
            reset_url = generate_password_reset_url(email, token)
            params: resend.Emails.SendParams = {
                "from": "noreply@promptlytechnologies.com",
                "to": [email],
                "subject": "Password Reset Request",
                "html": f"<p>Click <a href='{reset_url}'>here</a> to reset your password.</p>",
            }

            sent_email: resend.Email = resend.Emails.send(params)
            logger.debug(f"Password reset email sent: {sent_email.get('id')}")

            session.commit()
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            session.rollback()
    else:
        logger.debug("No user found with the provided email.")


def get_user_from_reset_token(email: str, token: str, session: Session) -> tuple[Optional[User], Optional[PasswordResetToken]]:
    reset_token = session.exec(select(PasswordResetToken).where(
        PasswordResetToken.token == token,
        PasswordResetToken.expires_at > datetime.now(UTC),
        PasswordResetToken.used == False
    )).first()

    if not reset_token:
        return None, None

    user = session.exec(select(User).where(
        User.email == email,
        User.id == reset_token.user_id,
        User.deleted == False
    )).first()

    if not user:
        return None, None

    return user, reset_token
