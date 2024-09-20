from sqlalchemy import CheckConstraint
from sqlmodel import SQLModel, Field, Relationship, Column, Integer
from typing import Optional, List
from datetime import datetime, UTC


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
    organization_id: Optional[int] = Field(default=None, foreign_key="organization.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)
    deleted: bool = Field(default=False)

    organization: Optional["Organization"] = Relationship(back_populates="users")
