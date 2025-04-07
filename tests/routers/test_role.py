# test_role.py

import pytest
from tests.conftest import SetupError
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


@pytest.fixture
def editor_user(session: Session, test_user: User, test_organization):
    """
    Creates a user who has EDIT_ROLE permission assigned via a role in the
    specified organization.
    """
    editor_role = Role(
        name="Editor Role",
        organization_id=test_organization.id
    )
    edit_permission = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.EDIT_ROLE)
    ).first()
    if not edit_permission:
        raise ValueError("EDIT_ROLE permission not found in the Permission table. Check seeds/setup.")

    editor_role.permissions.append(edit_permission)
    session.add(editor_role)

    # Assign the newly created 'Editor Role' to our test user
    test_user.roles.append(editor_role)
    session.commit()
    return test_user


def test_update_role_success(auth_client, editor_user, test_organization, session: Session):
    """
    Test successfully updating a role's name and permissions.
    Ensures a user with EDIT_ROLE permission can update the role.
    """
    # Create a role we will update
    existing_role = Role(
        name="Old Role Name",
        organization_id=test_organization.id
    )
    session.add(existing_role)
    session.commit()
    session.refresh(existing_role)

    # Add an existing permission to the role so we can test it being removed
    perm_create = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.CREATE_ROLE)
    ).first()
    if not perm_create:
        raise SetupError("Test setup failed; CREATE_ROLE permission not found.")

    existing_role.permissions.append(perm_create)
    session.commit()

    # Verify setup
    assert existing_role.id is not None
    original_id = existing_role.id

    # Update the role using the /roles/update endpoint
    response = auth_client.post(
        "/roles/update",
        data={
            "id": existing_role.id,
            "name": "New Role Name",
            "organization_id": test_organization.id,
            "permissions": [ValidPermissions.EDIT_ROLE.value]  # remove CREATE_ROLE, add EDIT_ROLE
        },
        follow_redirects=False
    )

    assert response.status_code == 303
    
    # Expire all objects in the session to force a refresh from the database
    session.expire_all()

    # Check that the role was updated in the database
    updated_role = session.exec(
        select(Role).where(Role.id == original_id)
    ).first()
    assert updated_role is not None
    assert updated_role.name == "New Role Name"
    perm_names = [p.name for p in updated_role.permissions]
    assert ValidPermissions.CREATE_ROLE not in perm_names
    assert ValidPermissions.EDIT_ROLE in perm_names


def test_update_role_unauthorized(auth_client, test_user, test_organization, session: Session):
    """
    Test that a user without EDIT_ROLE permission cannot update a role.
    A 403 (InsufficientPermissionsError) is expected.
    """
    # Create a role in the same organization that we try to update
    some_role = Role(
        name="Role Without Permission",
        organization_id=test_organization.id
    )
    session.add(some_role)
    session.commit()
    session.refresh(some_role)

    response = auth_client.post(
        "/roles/update",
        data={
            "id": some_role.id,
            "name": "Attempted Update",
            "organization_id": test_organization.id,
            "permissions": [ValidPermissions.EDIT_ROLE.value]
        },
        follow_redirects=True
    )
    # Because the user has no EDIT_ROLE permission, the endpoint should raise 403
    assert response.status_code == 403


def test_update_role_nonexistent(auth_client, editor_user, test_organization):
    """
    Test attempting to update a role that does not exist.
    A 404 (RoleNotFoundError) is expected.
    """
    response = auth_client.post(
        "/roles/update",
        data={
            "id": 9999999,  # A role ID that doesn't exist
            "name": "Nonexistent Role",
            "organization_id": test_organization.id,
            "permissions": [ValidPermissions.EDIT_ROLE.value]
        },
        follow_redirects=True
    )
    assert response.status_code == 404


def test_update_role_duplicate_name(auth_client, editor_user, test_organization, session: Session):
    """
    Test that updating a role to a name that already exists in the same organization
    fails with 400 (RoleAlreadyExistsError).
    """
    # Create two roles in the same organization
    role1 = Role(name="Original Role", organization_id=test_organization.id)
    role2 = Role(name="Conflict Role", organization_id=test_organization.id)
    session.add(role1)
    session.add(role2)
    session.commit()

    # Try to update 'role1' to have the same name as 'role2'
    response = auth_client.post(
        "/roles/update",
        data={
            "id": role1.id,
            "name": "Conflict Role",
            "organization_id": test_organization.id,
            "permissions": [ValidPermissions.EDIT_ROLE.value]
        },
        follow_redirects=True
    )

    assert response.status_code == 400


def test_update_role_invalid_permission(auth_client, editor_user, test_organization, session: Session):
    """
    Test attempting to update a role with an invalid permission
    that is not in the ValidPermissions enum. Expects a 400 status.
    """
    role_to_update = Role(
        name="Role With Bad Permission",
        organization_id=test_organization.id
    )
    session.add(role_to_update)
    session.commit()
    session.refresh(role_to_update)

    # Provide an invalid permission string
    response = auth_client.post(
        "/roles/update",
        data={
            "id": role_to_update.id,
            "name": "Invalid Permission Test",
            "organization_id": test_organization.id,
            "permissions": ["NOT_A_VALID_PERMISSION"]
        },
        follow_redirects=True
    )

    assert response.status_code == 422


def test_update_role_unauthenticated(unauth_client, test_organization, session: Session):
    """
    Test that an unauthenticated user (no valid tokens) will not have access
    to update a role. By default, the router requires login, so it should
    redirect.
    """
    # Create a role
    some_role = Role(
        name="Role For Unauth Test",
        organization_id=test_organization.id
    )
    session.add(some_role)
    session.commit()
    session.refresh(some_role)

    response = unauth_client.post(
        "/roles/update",
        data={
            "id": some_role.id,
            "name": "Should Not Succeed",
            "organization_id": test_organization.id,
            "permissions": [ValidPermissions.EDIT_ROLE.value]
        },
        follow_redirects=False
    )
    assert response.status_code == 303


@pytest.fixture
def delete_role_user(session: Session, test_user: User, test_organization):
    """Create a user with DELETE_ROLE permission"""
    delete_role = Role(
        name="Delete Role Permission",
        organization_id=test_organization.id
    )

    delete_permission: Permission | None = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.DELETE_ROLE)
    ).first()

    if delete_permission is None:
        raise ValueError("Error during test setup: DELETE_ROLE permission not found")
    
    delete_role.permissions.append(delete_permission)
    session.add(delete_role)

    test_user.roles.append(delete_role)
    session.commit()

    return test_user


def test_delete_role_success(auth_client, delete_role_user, test_organization, session: Session):
    """Test successful role deletion"""
    # Create a role to delete
    role_to_delete = Role(
        name="Role To Delete",
        organization_id=test_organization.id
    )
    session.add(role_to_delete)
    session.commit()
    session.refresh(role_to_delete)
    
    # Store the role ID for later verification
    role_id = role_to_delete.id

    response = auth_client.post(
        "/roles/delete",
        data={
            "id": role_id,
            "organization_id": test_organization.id
        },
        follow_redirects=False
    )

    assert response.status_code == 303
    
    # Expire all objects in the session to force a refresh from the database
    session.expire_all()

    # Verify role was deleted from database
    deleted_role = session.exec(
        select(Role).where(Role.id == role_id)
    ).first()
    assert deleted_role is None


def test_delete_role_unauthorized(auth_client, test_user, test_organization, session: Session):
    """Test role deletion without proper permissions"""
    # Create a role to attempt to delete
    role = Role(
        name="Unauthorized Delete",
        organization_id=test_organization.id
    )
    session.add(role)
    session.commit()

    response = auth_client.post(
        "/roles/delete",
        data={
            "id": role.id,
            "organization_id": test_organization.id
        },
        follow_redirects=False
    )

    assert response.status_code == 403


def test_delete_nonexistent_role(auth_client, delete_role_user, test_organization):
    """Test attempting to delete a role that doesn't exist"""
    response = auth_client.post(
        "/roles/delete",
        data={
            "id": 99999,  # Non-existent role ID
            "organization_id": test_organization.id
        },
        follow_redirects=False
    )

    assert response.status_code == 404


def test_delete_role_with_users(auth_client, delete_role_user, test_organization, session: Session):
    """Test attempting to delete a role that has users assigned"""
    # Create a role and assign it to a user
    role_with_users = Role(
        name="Role With Users",
        organization_id=test_organization.id
    )
    session.add(role_with_users)
    session.commit()
    
    # Assign the role to our test user
    delete_role_user.roles.append(role_with_users)
    session.commit()

    response = auth_client.post(
        "/roles/delete",
        data={
            "id": role_with_users.id,
            "organization_id": test_organization.id
        },
        follow_redirects=False
    )

    assert response.status_code == 400


def test_delete_role_unauthenticated(unauth_client, test_organization, session: Session):
    """Test role deletion without authentication"""
    # Create a role to attempt to delete
    role = Role(
        name="Unauthenticated Delete",
        organization_id=test_organization.id
    )
    session.add(role)
    session.commit()

    response = unauth_client.post(
        "/roles/delete",
        data={
            "id": role.id,
            "organization_id": test_organization.id
        },
        follow_redirects=False
    )

    assert response.status_code == 303  # Redirects to login page


# --- Organization Page Role Tests ---

def test_organization_page_role_creation_access(auth_client_owner, auth_client_admin, auth_client_member, test_organization):
    """Test that role creation UI elements are only shown to users with CREATE_ROLE permission"""
    # Owner should see role creation
    owner_response = auth_client_owner.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    assert owner_response.status_code == 200
    assert "Create Role" in owner_response.text
    
    # Admin should see role creation
    admin_response = auth_client_admin.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    assert admin_response.status_code == 200
    assert "Create Role" in admin_response.text
    
    # Member should not see role creation
    member_response = auth_client_member.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    assert member_response.status_code == 200
    assert "Create Role" not in member_response.text


def test_organization_page_role_edit_access(auth_client_owner, auth_client_admin, auth_client_member, test_organization):
    """Test that role editing UI elements are only shown to users with EDIT_ROLE permission"""
    # Owner should see role editing controls
    owner_response = auth_client_owner.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    assert owner_response.status_code == 200
    assert "Edit Role" in owner_response.text
    
    # Admin should see role editing controls
    admin_response = auth_client_admin.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    assert admin_response.status_code == 200
    assert "Edit Role" in admin_response.text
    
    # Member should not see role editing controls
    member_response = auth_client_member.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    assert member_response.status_code == 200
    assert "Edit Role" not in member_response.text


def test_organization_page_role_delete_access(auth_client_owner, auth_client_admin, auth_client_member, test_organization):
    """Test that role deletion UI elements are only shown to users with DELETE_ROLE permission"""
    # Owner should see role deletion controls
    owner_response = auth_client_owner.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    assert owner_response.status_code == 200
    assert "Delete Role" in owner_response.text
    
    # Admin should not see role deletion controls (wasn't given DELETE_ROLE)
    admin_response = auth_client_admin.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    assert admin_response.status_code == 200
    assert "Delete Role" not in admin_response.text
    
    # Member should not see role deletion controls
    member_response = auth_client_member.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    assert member_response.status_code == 200
    assert "Delete Role" not in member_response.text


def test_create_role_form_modal(auth_client_owner, test_organization):
    """Test that the create role modal form contains all required elements"""
    response = auth_client_owner.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    
    assert response.status_code == 200
    
    # Check for modal elements
    assert 'id="createRoleModal"' in response.text
    assert 'action="/roles/create"' in response.text
    assert 'method="post"' in response.text
    assert 'name="name"' in response.text
    assert 'name="organization_id"' in response.text
    assert f'value="{test_organization.id}"' in response.text
    
    # Check for permission checkboxes
    for permission in ValidPermissions:
        assert permission.value in response.text


def test_edit_role_form_modal(auth_client_owner, session, test_organization):
    """Test that the edit role modal form contains all required elements and pre-fills data"""
    # Create a test role to edit
    test_role = Role(
        name="Test Edit Role",
        organization_id=test_organization.id
    )
    
    # Add some permissions
    edit_permission = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.EDIT_ROLE)
    ).first()
    invite_permission = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.INVITE_USER)
    ).first()
    
    test_role.permissions.append(edit_permission)
    test_role.permissions.append(invite_permission)
    
    session.add(test_role)
    session.commit()
    session.refresh(test_role)
    
    response = auth_client_owner.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    
    assert response.status_code == 200
    
    # Check for modal elements
    assert f'id="editRoleModal{test_role.id}"' in response.text
    assert 'action="/roles/update"' in response.text
    assert 'method="post"' in response.text
    assert 'name="name"' in response.text
    assert f'value="{test_role.name}"' in response.text
    assert 'name="id"' in response.text
    assert f'value="{test_role.id}"' in response.text
    assert 'name="organization_id"' in response.text
    assert f'value="{test_organization.id}"' in response.text
    
    # Check for permission checkboxes with correct checked state
    for permission in ValidPermissions:
        assert permission.value in response.text
        
    # These should be checked
    assert f'value="{ValidPermissions.EDIT_ROLE.value}" checked' in response.text
    assert f'value="{ValidPermissions.INVITE_USER.value}" checked' in response.text


def test_delete_role_form(auth_client_owner, session, test_organization):
    """Test that the delete role form contains all required elements"""
    # Create a test role to delete
    test_role = Role(
        name="Test Delete Role",
        organization_id=test_organization.id
    )
    session.add(test_role)
    session.commit()
    session.refresh(test_role)
    
    response = auth_client_owner.get(
        f"/organizations/{test_organization.id}",
        follow_redirects=False
    )
    
    assert response.status_code == 200
    
    # Check for delete form elements
    assert 'action="/roles/delete"' in response.text
    assert 'method="post"' in response.text
    assert 'name="id"' in response.text
    assert f'value="{test_role.id}"' in response.text
    assert 'name="organization_id"' in response.text
    assert f'value="{test_organization.id}"' in response.text
