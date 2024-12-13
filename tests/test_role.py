# test_role.py

import pytest
from utils.models import Role

def test_role_creation():
    """Test basic role creation"""
    role = Role("Admin", ["read", "write"])
    assert role.name == "Admin"
    assert role.permissions == ["read", "write"]

def test_role_add_permission():
    """Test adding a permission to role"""
    role = Role("Admin", ["read"])
    role.add_permission("write")
    assert "write" in role.permissions
    assert len(role.permissions) == 2

def test_role_remove_permission():
    """Test removing a permission from role"""
    role = Role("Admin", ["read", "write"])
    role.remove_permission("write")
    assert "write" not in role.permissions
    assert len(role.permissions) == 1

def test_role_has_permission():
    """Test checking if role has specific permission"""
    role = Role("Admin", ["read", "write"])
    assert role.has_permission("read") is True
    assert role.has_permission("delete") is False

def test_role_add_existing_permission():
    """Test adding a permission that already exists"""
    role = Role("Admin", ["read"])
    role.add_permission("read")
    assert len(role.permissions) == 1

def test_role_remove_nonexistent_permission():
    """Test removing a permission that doesn't exist"""
    role = Role("Admin", ["read"])
    role.remove_permission("write")
    assert len(role.permissions) == 1
    assert role.permissions == ["read"]

# Additional tests for role.py

def test_role_invalid_name():
    """Test role creation with invalid name"""
    with pytest.raises(ValueError):
        Role("", ["read"])

def test_role_none_permissions():
    """Test role creation with None permissions"""
    with pytest.raises(ValueError):
        Role("Admin", None)

def test_role_empty_permissions():
    """Test role creation with empty permissions list"""
    role = Role("Admin", [])
    assert len(role.permissions) == 0