import os
import jwt
import logging
from dotenv import load_dotenv
from sqlmodel import Session, select, create_engine
from sqlalchemy.engine import URL
from passlib.context import CryptContext
from datetime import UTC, datetime, timedelta
from typing import Optional
from models import User
from fastapi import Depends, Cookie

logger = logging.getLogger("uvicorn.error")

# --- DATABASE ---

load_dotenv()


def get_connection_url() -> URL:
    """
    Creates a SQLModel URL object containing the connection URL to the Postgres database.
    The connection details are obtained from environment variables.
    Returns the URL object.
    """
    database_url: URL = URL.create(
        drivername="postgresql",
        username=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        database=os.getenv("DB_NAME"),
    )

    return database_url


# --- AUTH ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Define the OAuth2 scheme to extract the token from the "Authorization" header

engine = create_engine(get_connection_url())


def get_session():
    with Session(engine) as session:
        yield session


def oauth2_scheme_cookie(token: Optional[str] = Cookie(None)) -> Optional[str]:
    return token


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return (
            decoded_token
            if decoded_token["exp"] >= datetime.now(UTC).timestamp()
            else None
        )
    except jwt.PyJWTError:
        return None


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme_cookie),
    session: Session = Depends(get_session),
) -> Optional[User]:
    if token is None:
        logger.info("No token provided")
        return None

    try:
        decoded_token = decode_access_token(token)
        if decoded_token is None:
            return None
        user_email = decoded_token.get("sub")
        if user_email is None:
            return None
        user = session.exec(select(User).where(User.email == user_email)).first()
        return user
    except jwt.PyJWTError:
        logger.error("Invalid token")
        return None
