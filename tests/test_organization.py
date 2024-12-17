# test_organization.py

from utils.models import Organization, Role
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
