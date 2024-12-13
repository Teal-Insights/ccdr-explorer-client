# test_organization.py

import pytest
from utils.models import Organization

def test_organization_creation():
    """Test basic organization creation"""
    org = Organization("Test Org", "Test Description")
    assert org.name == "Test Org"
    assert org.description == "Test Description"
    assert org.roles == []
    assert org.members == []

def test_organization_add_role():
    """Test adding a role to organization"""
    org = Organization("Test Org", "Test Description")
    role = {"name": "Admin", "permissions": ["read", "write"]}
    org.add_role(role)
    assert len(org.roles) == 1
    assert org.roles[0] == role

def test_organization_add_member():
    """Test adding a member to organization"""
    org = Organization("Test Org", "Test Description")
    member = {"id": 1, "name": "John Doe"}
    org.add_member(member)
    assert len(org.members) == 1
    assert org.members[0] == member

def test_organization_remove_member():
    """Test removing a member from organization"""
    org = Organization("Test Org", "Test Description")
    member = {"id": 1, "name": "John Doe"}
    org.add_member(member)
    org.remove_member(1)
    assert len(org.members) == 0

def test_organization_get_member():
    """Test getting a member from organization"""
    org = Organization("Test Org", "Test Description")
    member = {"id": 1, "name": "John Doe"}
    org.add_member(member)
    retrieved_member = org.get_member(1)
    assert retrieved_member == member

def test_organization_get_nonexistent_member():
    """Test getting a non-existent member"""
    org = Organization("Test Org", "Test Description")
    assert org.get_member(1) is None

# Additional tests for organization.py

def test_organization_invalid_name():
    """Test organization creation with invalid name"""
    with pytest.raises(ValueError):
        Organization("", "Description")

def test_organization_none_name():
    """Test organization creation with None name"""
    with pytest.raises(ValueError):
        Organization(None, "Description")
