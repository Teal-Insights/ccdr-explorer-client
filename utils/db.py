import os
import logging
from dotenv import load_dotenv
from sqlalchemy.engine import URL
from sqlmodel import create_engine, Session, SQLModel, select
from utils.models import Role, Permission, RolePermissionLink, default_roles, ValidPermissions

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


def create_default_roles(session, organization_id: int, check_first: bool = True):
    """
    Create default roles for an organization in the database if they do not exist.
    """
    roles_in_db = []
    for role_name in default_roles:
        db_role = session.exec(select(Role).where(
            Role.name == role_name,
            Role.organization_id == organization_id
        )).first()
        if not db_role:
            db_role = Role(name=role_name, organization_id=organization_id)
            session.add(db_role)
        roles_in_db.append(db_role)

    # Create RolePermissionLink for Owner and Administrator roles
    for role in roles_in_db[:2]:
        permissions = session.exec(select(Permission)).all()
        for permission in permissions:
            # Check if the role already has the permission
            if check_first:
                db_role_permission_link: RolePermissionLink | None = session.exec(select(RolePermissionLink).where(
                    RolePermissionLink.role_id == role.id,
                    RolePermissionLink.permission_id == permission.id
                )).first()
            else:
                db_role_permission_link = None

            # Skip giving DELETE_ORGANIZATION permission to Administrator
            if not db_role_permission_link and not (
                permission == ValidPermissions.DELETE_ORGANIZATION and
                role.name == "Administrator"
            ):
                role_permission_link = RolePermissionLink(
                    role_id=role.id,
                    permission_id=permission.id
                )
                session.add(role_permission_link)

    return roles_in_db


def create_permissions(session):
    """
    Create default permissions.
    """
    for permission in ValidPermissions:
        db_permission = session.exec(select(Permission).where(
            Permission.name == permission)).first()
        if not db_permission:
            db_permission = Permission(name=permission)
            session.add(db_permission)


def set_up_db(drop: bool = False):
    """
    Set up the database by creating tables and populating them with default roles and permissions.
    """
    engine = create_engine(get_connection_url())
    if drop:
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    # Create default permissions
    with Session(engine) as session:
        create_permissions(session)
        session.commit()
    engine.dispose()


def tear_down_db():
    """
    Tear down the database by dropping all tables.
    """
    engine = create_engine(get_connection_url())
    SQLModel.metadata.drop_all(engine)
    engine.dispose()
