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


def create_roles(session):
    """
    Create default roles in the database if they do not exist.
    """
    roles_in_db = []
    for role_name in default_roles:
        db_role = session.exec(select(Role).where(
            Role.name == role_name)).first()
        if not db_role:
            db_role = Role(name=role_name)
            session.add(db_role)
        roles_in_db.append(db_role)
    return roles_in_db


def create_permissions(session, roles_in_db):
    """
    Create default permissions and link them to roles in the database.
    """
    for permission in ValidPermissions:
        db_permission = session.exec(select(Permission).where(
            Permission.name == permission)).first()
        if not db_permission:
            db_permission = Permission(name=permission)
            session.add(db_permission)

        # Create RolePermissionLink for Owner and Administrator
        for role in roles_in_db[:2]:
            db_role_permission_link = session.exec(select(RolePermissionLink).where(
                RolePermissionLink.role_id == role.id,
                RolePermissionLink.permission_id == db_permission.id)).first()
            if not db_role_permission_link:
                if not (permission == ValidPermissions.DELETE_ORGANIZATION and role.name == "Administrator"):
                    role_permission_link = RolePermissionLink(
                        role_id=role.id, permission_id=db_permission.id)
                    session.add(role_permission_link)


def set_up_db(drop: bool = False):
    """
    Set up the database by creating tables and populating them with default roles and permissions.
    """
    engine = create_engine(get_connection_url())
    if drop:
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        roles_in_db = create_roles(session)
        session.commit()
        create_permissions(session, roles_in_db)
        session.commit()
    engine.dispose()


def tear_down_db():
    """
    Tear down the database by dropping all tables.
    """
    engine = create_engine(get_connection_url())
    SQLModel.metadata.drop_all(engine)
    engine.dispose()
