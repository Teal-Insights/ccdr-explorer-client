import pytest
from sqlmodel import select, Session
from utils.models import (
    Permission,
    Role,
    RolePermissionLink,
    Organization,
    ValidPermissions,
)


def test_permissions_persist_after_role_deletion(session: Session):
    """
    Test that permissions are not deleted when a related Role is deleted.
    """
    # Create an organization
    organization = Organization(name="Test Organization")
    session.add(organization)
    session.commit()
    session.refresh(organization)

    # Create permissions
    permission1 = Permission(name=ValidPermissions.DELETE_ORGANIZATION)
    permission2 = Permission(name=ValidPermissions.EDIT_ORGANIZATION)
    session.add_all([permission1, permission2])
    session.commit()

    # Create a role and link permissions
    role = Role(name="Test Role", organization_id=organization.id)
    session.add(role)
    session.commit()
    session.refresh(role)

    role_permission_link1 = RolePermissionLink(
        role_id=role.id, permission_id=permission1.id
    )
    role_permission_link2 = RolePermissionLink(
        role_id=role.id, permission_id=permission2.id
    )
    session.add_all([role_permission_link1, role_permission_link2])
    session.commit()

    # Delete the role
    session.delete(role)
    session.commit()

    # Verify that permissions still exist
    remaining_permissions = session.exec(select(Permission)).all()
    assert len(remaining_permissions) == 2
    assert permission1 in remaining_permissions
    assert permission2 in remaining_permissions

    # Verify that RolePermissionLinks are deleted
    remaining_role_permissions = session.exec(select(RolePermissionLink)).all()
    assert len(remaining_role_permissions) == 0
