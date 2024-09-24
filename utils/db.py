import os
import logging
from typing import Optional, List
from datetime import datetime, UTC
from dotenv import load_dotenv
from sqlalchemy.engine import URL
from sqlmodel import create_engine, Session, SQLModel, Field, Relationship


load_dotenv()

logger = logging.getLogger("uvicorn.error")


# --- Database connection ---


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


engine = create_engine(get_connection_url())


def get_session():
    with Session(engine) as session:
        yield session


# --- Models ---


def utc_time():
    return datetime.now(UTC)


class Organization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)
    deleted: bool = Field(default=False)

    users: List["User"] = Relationship(back_populates="organization")


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(index=True, unique=True)
    hashed_password: str
    avatar_url: Optional[str] = None
    organization_id: Optional[int] = Field(
        default=None, foreign_key="organization.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)
    deleted: bool = Field(default=False)

    organization: Optional["Organization"] = Relationship(
        back_populates="users")
