from enum import Enum
from uuid import uuid4
from datetime import datetime, UTC, timedelta
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, Enum as SQLAlchemyEnum


def utc_time():
    return datetime.now(UTC)


default_roles = ["Owner", "Administrator", "Member"]


class ValidPermissions(Enum):
    DELETE_ORGANIZATION = "Delete Organization"
    EDIT_ORGANIZATION = "Edit Organization"
    INVITE_USER = "Invite User"
    REMOVE_USER = "Remove User"
    EDIT_USER_ROLE = "Edit User Role"
    CREATE_ROLE = "Create Role"
    DELETE_ROLE = "Delete Role"
    EDIT_ROLE = "Edit Role"


class Organization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    users: List["User"] = Relationship(back_populates="organization")


class Role(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    organization_id: Optional[int] = Field(
        default=None, foreign_key="organization.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    users: List["User"] = Relationship(back_populates="role")
    role_permission_links: List["RolePermissionLink"] = Relationship(
        back_populates="role")


class Permission(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: ValidPermissions = Field(
        sa_column=Column(SQLAlchemyEnum(ValidPermissions, create_type=False)))
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    role_permission_links: List["RolePermissionLink"] = Relationship(
        back_populates="permission")


class RolePermissionLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    role_id: Optional[int] = Field(
        default=None, foreign_key="role.id")
    permission_id: Optional[int] = Field(
        default=None, foreign_key="permission.id")

    role: Optional["Role"] = Relationship(
        back_populates="role_permission_links")
    permission: Optional["Permission"] = Relationship(
        back_populates="role_permission_links")


class PasswordResetToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    token: str = Field(default_factory=lambda: str(
        uuid4()), index=True, unique=True)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC) + timedelta(hours=1))
    used: bool = Field(default=False)

    user: Optional["User"] = Relationship(
        back_populates="password_reset_tokens",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(index=True, unique=True)
    hashed_password: str
    avatar_url: Optional[str] = None
    organization_id: Optional[int] = Field(
        default=None, foreign_key="organization.id")
    role_id: Optional[int] = Field(default=None, foreign_key="role.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    organization: Optional["Organization"] = Relationship(
        back_populates="users")
    role: Optional["Role"] = Relationship(back_populates="users")
    password_reset_tokens: List["PasswordResetToken"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class UserOrganizationLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(
        default=None, foreign_key="user.id")
    organization_id: Optional[int] = Field(
        default=None, foreign_key="organization.id")
