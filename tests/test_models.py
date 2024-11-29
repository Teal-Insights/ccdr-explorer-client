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
    Permissions links are automatically deleted due to cascade_delete=True.
    """
    # Verify all ValidPermissions exist in database
    all_permissions = session.exec(select(Permission)).all()
    assert len(all_permissions) == len(ValidPermissions)

    # Create an organization
    organization = Organization(name="Test Organization")
    session.add(organization)
    session.commit()
    session.refresh(organization)

    # Create a role and link two specific permissions
    role = Role(name="Test Role", organization_id=organization.id)
    session.add(role)
    session.commit()
    session.refresh(role)

    # Find specific permissions to link
    delete_org_permission = next(
        p for p in all_permissions if p.name == ValidPermissions.DELETE_ORGANIZATION)
    edit_org_permission = next(
        p for p in all_permissions if p.name == ValidPermissions.EDIT_ORGANIZATION)

    role_permission_link1 = RolePermissionLink(
        role_id=role.id, permission_id=delete_org_permission.id
    )
    role_permission_link2 = RolePermissionLink(
        role_id=role.id, permission_id=edit_org_permission.id
    )
    session.add_all([role_permission_link1, role_permission_link2])
    session.commit()

    # Verify that RolePermissionLinks exist before deletion
    role_permissions = session.exec(select(RolePermissionLink)).all()
    assert len(role_permissions) == 2

    # Delete the role (this will cascade delete the permission links)
    session.delete(role)
    session.commit()

    # Verify that all permissions still exist
    remaining_permissions = session.exec(select(Permission)).all()
    assert len(remaining_permissions) == len(ValidPermissions)
    assert delete_org_permission in remaining_permissions
    assert edit_org_permission in remaining_permissions

    # Verify that RolePermissionLinks were cascade deleted
    remaining_role_permissions = session.exec(select(RolePermissionLink)).all()
    assert len(remaining_role_permissions) == 0
