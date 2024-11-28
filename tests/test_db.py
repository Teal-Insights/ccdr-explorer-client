from sqlmodel import Session, select
from utils.db import (
    get_connection_url,
    assign_permissions_to_role,
    create_default_roles,
    create_permissions,
)
from utils.models import Role, Permission, Organization, RolePermissionLink, ValidPermissions


def test_get_connection_url():
    """Test that get_connection_url returns a valid URL object"""
    url = get_connection_url()
    assert url.drivername == "postgresql"
    assert url.database is not None


def test_create_permissions(session: Session):
    """Test that create_permissions creates all ValidPermissions"""
    # Clear existing permissions
    existing_permissions = session.exec(select(Permission)).all()
    for permission in existing_permissions:
        session.delete(permission)
    session.commit()

    create_permissions(session)
    session.commit()

    # Check all permissions were created
    db_permissions = session.exec(select(Permission)).all()
    assert len(db_permissions) == len(ValidPermissions)
    assert {p.name for p in db_permissions} == {p for p in ValidPermissions}


def test_create_default_roles(session: Session, test_organization: Organization):
    """Test that create_default_roles creates expected roles with correct permissions"""
    # Create permissions first
    create_permissions(session)
    session.commit()

    # Create roles for test organization
    roles = create_default_roles(session, test_organization.id)
    session.commit()

    # Verify roles were created
    assert len(roles) == 3  # Owner, Administrator, Member

    # Check Owner role permissions
    owner_role = next(r for r in roles if r.name == "Owner")
    owner_permissions = session.exec(
        select(Permission)
        .join(RolePermissionLink)
        .where(RolePermissionLink.role_id == owner_role.id)
    ).all()
    assert len(owner_permissions) == len(ValidPermissions)

    # Check Administrator role permissions
    admin_role = next(r for r in roles if r.name == "Administrator")
    admin_permissions = session.exec(
        select(Permission)
        .join(RolePermissionLink)
        .where(RolePermissionLink.role_id == admin_role.id)
    ).all()
    # Admin should have all permissions except DELETE_ORGANIZATION
    assert len(admin_permissions) == len(ValidPermissions) - 1
    assert ValidPermissions.DELETE_ORGANIZATION not in {
        p.name for p in admin_permissions}


def test_assign_permissions_to_role(session: Session, test_organization: Organization):
    """Test that assign_permissions_to_role correctly assigns permissions"""
    # Create a test role with the organization from fixture
    role = Role(name="Test Role", organization_id=test_organization.id)
    session.add(role)

    # Create test permissions
    perm1 = Permission(name=ValidPermissions.CREATE_ROLE)
    perm2 = Permission(name=ValidPermissions.DELETE_ROLE)
    session.add(perm1)
    session.add(perm2)
    session.commit()

    # Assign permissions
    permissions = [perm1, perm2]
    assign_permissions_to_role(session, role, permissions)
    session.commit()

    # Verify assignments
    db_permissions = session.exec(
        select(Permission)
        .join(RolePermissionLink)
        .where(RolePermissionLink.role_id == role.id)
    ).all()

    assert len(db_permissions) == 2
    assert {p.name for p in db_permissions} == {
        ValidPermissions.CREATE_ROLE, ValidPermissions.DELETE_ROLE}


def test_assign_permissions_to_role_duplicate_check(session: Session, test_organization: Organization):
    """Test that assign_permissions_to_role doesn't create duplicates"""
    # Create a test role with the organization from fixture
    role = Role(name="Test Role", organization_id=test_organization.id)
    perm = Permission(name=ValidPermissions.CREATE_ROLE)
    session.add(role)
    session.add(perm)
    session.commit()

    # Assign same permission twice
    assign_permissions_to_role(session, role, [perm], check_first=True)
    assign_permissions_to_role(session, role, [perm], check_first=True)
    session.commit()

    # Verify only one assignment exists
    link_count = session.exec(
        select(RolePermissionLink)
        .where(
            RolePermissionLink.role_id == role.id,
            RolePermissionLink.permission_id == perm.id
        )
    ).all()
    assert len(link_count) == 1
