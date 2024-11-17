import os
import logging
from enum import Enum
from uuid import uuid4
from datetime import datetime, UTC, timedelta
from typing import Optional, List
from dotenv import load_dotenv
from sqlalchemy.engine import URL
from sqlmodel import create_engine, Session, SQLModel, Field, Relationship, select
from sqlalchemy import Column, Enum as SQLAlchemyEnum

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
        port=int(os.getenv("DB_PORT") or "5432"),
        database=os.getenv("DB_NAME"),
    )

    return database_url


engine = create_engine(get_connection_url())


def get_session():
    with Session(engine) as session:
        yield session


def set_up_db(drop: bool = False):
    engine = create_engine(get_connection_url())
    if drop:
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        roles_in_db = []
        # Create default roles
        for role_name in default_roles:
            db_role = session.exec(select(Role).where(
                Role.name == role_name)).first()
            if not db_role:
                db_role = Role(name=role_name)
                session.add(db_role)
                roles_in_db.append(db_role)
            else:
                roles_in_db.append(db_role)

        session.commit()  # Commit after adding roles

        # Create default permissions
        for permission in [permission for permission in ValidPermissions]:
            db_permission = session.exec(select(Permission).where(
                Permission.name == permission)).first()
            if not db_permission:
                db_permission = Permission(name=permission)
                session.add(db_permission)

            # Create RolePermissionLink for Owner and Administrator
            # Assuming first two roles are Owner and Administrator
            for role in roles_in_db[:2]:
                db_role_permission_link = session.exec(select(RolePermissionLink).where(
                    RolePermissionLink.role_id == role.id,
                    RolePermissionLink.permission_id == db_permission.id)).first()
                if not db_role_permission_link:
                    if not (permission == ValidPermissions.DELETE_ORGANIZATION and role.name == "Administrator"):
                        role_permission_link = RolePermissionLink(
                            role_id=role.id, permission_id=db_permission.id)
                        session.add(role_permission_link)

        session.commit()  # Commit after adding permissions and links
    engine.dispose()


# --- Models ---


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
    deleted: bool = Field(default=False)

    users: List["User"] = Relationship(back_populates="organization")


class Role(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    organization_id: Optional[int] = Field(
        default=None, foreign_key="organization.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)
    deleted: bool = Field(default=False)

    users: List["User"] = Relationship(back_populates="role")
    role_permission_links: List["RolePermissionLink"] = Relationship(
        back_populates="role")


class Permission(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: ValidPermissions = Field(
        sa_column=Column(SQLAlchemyEnum(ValidPermissions)))
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)
    deleted: bool = Field(default=False)

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
        back_populates="password_reset_tokens")


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
    deleted: bool = Field(default=False)

    organization: Optional["Organization"] = Relationship(
        back_populates="users")
    role: Optional["Role"] = Relationship(back_populates="users")
    password_reset_tokens: List["PasswordResetToken"] = Relationship(
        back_populates="user")


class UserOrganizationLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(
        default=None, foreign_key="user.id")
    organization_id: Optional[int] = Field(
        default=None, foreign_key="organization.id")
