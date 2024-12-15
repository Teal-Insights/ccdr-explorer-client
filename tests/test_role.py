# test_role.py

import pytest
from utils.models import Role, Permission, ValidPermissions, User
from sqlmodel import Session, select


@pytest.fixture
def admin_user(session: Session, test_user: User, test_organization):
    """Create an admin user with CREATE_ROLE permission"""
    admin_role: Role = Role(
        name="Admin",
        organization_id=test_organization.id
    )

    create_role_permission: Permission | None = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.CREATE_ROLE)
    ).first()

    if create_role_permission is None:
        raise ValueError("Error during test setup: CREATE_ROLE permission not found")
    
    admin_role.permissions.append(create_role_permission)
    session.add(admin_role)

    test_user.roles.append(admin_role)
    session.commit()

    return test_user


def test_create_role_success(auth_client, admin_user, test_organization, session: Session):
    """Test successful role creation"""
    response = auth_client.post(
        "/roles/create",
        data={
            "name": "Test Role",
            "organization_id": test_organization.id,
            "permissions": [ValidPermissions.EDIT_ROLE.value]
        },
        follow_redirects=False
    )

    assert response.status_code == 303

    # Verify role was created in database
    created_role = session.exec(
        select(Role).where(
            Role.name == "Test Role",
            Role.organization_id == test_organization.id
        )
    ).first()

    assert created_role is not None
    assert created_role.name == "Test Role"
    assert len(created_role.permissions) == 1
    assert created_role.permissions[0].name == ValidPermissions.EDIT_ROLE


def test_create_role_unauthorized(auth_client, test_user, test_organization):
    """Test role creation without proper permissions"""
    response = auth_client.post(
        "/roles/create",
        data={
            "name": "Test Role",
            "organization_id": test_organization.id,
            "permissions": [ValidPermissions.EDIT_ROLE.value]
        },
        follow_redirects=False
    )

    assert response.status_code == 403


def test_create_duplicate_role(auth_client, admin_user, test_organization, session: Session):
    """Test creating a role with a name that already exists in the organization"""
    # Create initial role
    existing_role = Role(
        name="Existing Role",
        organization_id=test_organization.id
    )
    session.add(existing_role)
    session.commit()

    # Attempt to create role with same name
    response = auth_client.post(
        "/roles/create",
        data={
            "name": "Existing Role",
            "organization_id": test_organization.id,
            "permissions": [ValidPermissions.EDIT_ROLE.value]
        },
        follow_redirects=False
    )

    assert response.status_code == 400


def test_create_role_unauthenticated(unauth_client, test_organization):
    """Test role creation without authentication"""
    response = unauth_client.post(
        "/roles/create",
        data={
            "name": "Test Role",
            "organization_id": test_organization.id,
            "permissions": [ValidPermissions.EDIT_ROLE.value]
        },
        follow_redirects=False
    )

    assert response.status_code == 303
