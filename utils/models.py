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


class UserOrganizationLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    organization_id: int = Field(foreign_key="organization.id")
    role_id: int = Field(foreign_key="role.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    user: "User" = Relationship(back_populates="organization_links")
    organization: "Organization" = Relationship(back_populates="user_links")
    role: "Role" = Relationship(back_populates="user_links")


class RolePermissionLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    role_id: int = Field(foreign_key="role.id")
    permission_id: int = Field(foreign_key="permission.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)


class Organization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)
    deleted: bool = Field(default=False)

    user_links: List[UserOrganizationLink] = Relationship(
        back_populates="organization")
    users: List["User"] = Relationship(
        back_populates="organizations",
        link_model=UserOrganizationLink
    )
    roles: List["Role"] = Relationship(back_populates="organization")


class Role(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    organization_id: int = Field(foreign_key="organization.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)
    deleted: bool = Field(default=False)

    organization: Organization = Relationship(back_populates="roles")
    user_links: List[UserOrganizationLink] = Relationship(
        back_populates="role")
    permissions: List["Permission"] = Relationship(
        back_populates="roles",
        link_model=RolePermissionLink
    )


class Permission(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: ValidPermissions = Field(
        sa_column=Column(SQLAlchemyEnum(ValidPermissions, create_type=False)))
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)
    deleted: bool = Field(default=False)

    roles: List["Role"] = Relationship(
        back_populates="permissions",
        link_model=RolePermissionLink
    )


class PasswordResetToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    token: str = Field(default_factory=lambda: str(
        uuid4()), index=True, unique=True)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC) + timedelta(hours=1))
    used: bool = Field(default=False)

    user: Optional["User"] = Relationship(
        back_populates="password_reset_tokens")


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(index=True, unique=True)
    hashed_password: str
    avatar_url: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)
    deleted: bool = Field(default=False)

    organization_links: List[UserOrganizationLink] = Relationship(
        back_populates="user")
    organizations: List["Organization"] = Relationship(
        back_populates="users",
        link_model=UserOrganizationLink
    )
    password_reset_tokens: List["PasswordResetToken"] = Relationship(
        back_populates="user")
