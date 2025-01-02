from utils.models import Organization, Role, Permission, ValidPermissions
from sqlmodel import select

def test_create_organization_success(auth_client, session, test_user):
    """Test successful organization creation"""
    response = auth_client.post(
        "/organizations/create",
        data={"name": "New Test Organization"},
        follow_redirects=False
    )

    # Check response
    assert response.status_code == 303  # Redirect status code
    assert "/organizations/" in response.headers["location"]

    # Verify database state
    org = session.exec(
        select(Organization)
        .where(Organization.name == "New Test Organization")
    ).first()
    
    assert org is not None
    assert org.name == "New Test Organization"

    # Verify default roles were created
    roles = session.exec(
        select(Role)
        .where(Role.organization_id == org.id)
    ).all()
    
    assert len(roles) > 0
    assert any(role.name == "Owner" for role in roles)

    # Verify test_user was assigned as owner
    owner_role = next(role for role in roles if role.name == "Owner")
    assert test_user in owner_role.users

def test_create_organization_empty_name(auth_client):
    """Test organization creation with empty name"""
    response = auth_client.post(
        "/organizations/create",
        data={"name": "   "}  # Empty or whitespace name
    )
    
    assert response.status_code == 400
    assert "Organization name cannot be empty" in response.text

def test_create_organization_duplicate_name(auth_client, test_organization):
    """Test organization creation with duplicate name"""
    response = auth_client.post(
        "/organizations/create",
        data={"name": test_organization.name}
    )
    
    assert response.status_code == 400
    assert "Organization name already taken" in response.text

def test_create_organization_unauthenticated(unauth_client):
    """Test organization creation without authentication"""
    response = unauth_client.post(
        "/organizations/create",
        data={"name": "Unauthorized Org"},
        follow_redirects=False
    )
    
    assert response.status_code == 303  # Unauthorized

def test_update_organization_success(auth_client, session, test_organization, test_user):
    """Test successful organization update"""
    # Set up test user as owner with edit permission
    owner_role = Role(name="Owner", organization_id=test_organization.id)
    owner_role.permissions = [
        Permission(name=ValidPermissions.EDIT_ORGANIZATION)
    ]
    owner_role.users.append(test_user)
    session.add(owner_role)
    session.commit()

    new_name = "Updated Organization Name"
    response = auth_client.post(
        f"/organizations/update/{test_organization.id}",
        data={"id": test_organization.id, "name": new_name},
        follow_redirects=False
    )

    assert response.status_code == 303  # Redirect status code
    assert "/profile" in response.headers["location"]

    # Verify database update
    updated_org = session.get(Organization, test_organization.id)
    assert updated_org.name == new_name

def test_update_organization_unauthorized(auth_client, session, test_organization, test_user):
    """Test organization update without proper permissions"""
    # Add user to organization but without edit permission
    basic_role = Role(name="Basic", organization_id=test_organization.id)
    basic_role.users.append(test_user)
    session.add(basic_role)
    session.commit()

    response = auth_client.post(
        f"/organizations/update/{test_organization.id}",
        data={
            "id": test_organization.id,
            "name": "Unauthorized Update"
        },
        follow_redirects=False
    )

    assert response.status_code == 403
    assert "permission" in response.text.lower()

def test_update_organization_duplicate_name(auth_client, session, test_organization, test_user):
    """Test organization update with duplicate name"""
    # Create another organization with the target name
    existing_org = Organization(name="Existing Org")
    session.add(existing_org)
    
    # Set up permissions
    owner_role = Role(name="Owner", organization_id=test_organization.id)
    owner_role.permissions = [
        Permission(name=ValidPermissions.EDIT_ORGANIZATION)
    ]
    owner_role.users.append(test_user)
    session.add(owner_role)
    session.commit()

    response = auth_client.post(
        f"/organizations/update/{test_organization.id}",
        data={
            "id": test_organization.id,
            "name": "Existing Org"
        },
        follow_redirects=False
    )

    assert response.status_code == 400
    assert "organization name already taken" in response.text.lower()

def test_update_organization_empty_name(auth_client, session, test_organization, test_user):
    """Test organization update with empty name"""
    # Set up permissions
    owner_role = Role(name="Owner", organization_id=test_organization.id)
    owner_role.permissions = [
        Permission(name=ValidPermissions.EDIT_ORGANIZATION)
    ]
    owner_role.users.append(test_user)
    session.add(owner_role)
    session.commit()

    response = auth_client.post(
        f"/organizations/update/{test_organization.id}",
        data={
            "id": test_organization.id,
            "name": "   "
        },
        follow_redirects=False
    )

    assert response.status_code == 400
    assert "organization name cannot be empty" in response.text.lower()

def test_update_organization_unauthenticated(unauth_client, test_organization):
    """Test organization update without authentication"""
    response = unauth_client.post(
        f"/organizations/update/{test_organization.id}",
        data={
            "id": test_organization.id,
            "name": "Unauthorized Update"
        },
        follow_redirects=False
    )

    assert response.status_code == 303  # Redirect to login

def test_delete_organization_success(auth_client, session, test_organization, test_user):
    """Test successful organization deletion"""
    # Set up test user as owner with delete permission
    owner_role = Role(name="Owner", organization_id=test_organization.id)
    owner_role.permissions = [
        Permission(name=ValidPermissions.DELETE_ORGANIZATION)
    ]
    owner_role.users.append(test_user)
    session.add(owner_role)
    session.commit()

    response = auth_client.post(
        f"/organizations/delete/{test_organization.id}",
        follow_redirects=False
    )

    assert response.status_code == 303  # Redirect status code
    assert "/profile" in response.headers["location"]

    # Verify organization was deleted
    deleted_org = session.get(Organization, test_organization.id)
    assert deleted_org is None

def test_delete_organization_unauthorized(auth_client, session, test_organization, test_user):
    """Test organization deletion without proper permissions"""
    # Add user to organization but without delete permission
    basic_role = Role(name="Owner", organization_id=test_organization.id)
    basic_role.users.append(test_user)
    session.add(basic_role)
    session.commit()

    response = auth_client.post(
        f"/organizations/delete/{test_organization.id}",
        follow_redirects=False
    )

    assert response.status_code == 403
    assert "permission" in response.text.lower()

    # Verify organization still exists
    org = session.get(Organization, test_organization.id)
    assert org is not None

def test_delete_organization_not_member(auth_client, session, test_organization, test_user):
    """Test organization deletion by non-member"""
    response = auth_client.post(
        f"/organizations/delete/{test_organization.id}",
        follow_redirects=False
    )

    assert response.status_code == 403
    assert "permission" in response.text.lower()

    # Verify organization still exists
    org = session.get(Organization, test_organization.id)
    assert org is not None

def test_delete_organization_unauthenticated(unauth_client, test_organization):
    """Test organization deletion without authentication"""
    response = unauth_client.post(
        f"/organizations/delete/{test_organization.id}",
        follow_redirects=False
    )

    assert response.status_code == 303  # Redirect to login

def test_delete_organization_cascade(auth_client, session, test_organization, test_user):
    """Test that deleting organization cascades to roles"""
    # Set up test user as owner with delete permission
    owner_role = Role(name="Owner", organization_id=test_organization.id)
    owner_role.permissions = [
        Permission(name=ValidPermissions.DELETE_ORGANIZATION)
    ]
    owner_role.users.append(test_user)
    
    # Add another role to verify cascade
    member_role = Role(name="Member", organization_id=test_organization.id)
    
    session.add(owner_role)
    session.add(member_role)
    session.commit()

    response = auth_client.post(
        f"/organizations/delete/{test_organization.id}",
        follow_redirects=False
    )

    assert response.status_code == 303

    # Verify roles were also deleted
    roles = session.exec(
        select(Role)
        .where(Role.organization_id == test_organization.id)
    ).all()
    assert len(roles) == 0
