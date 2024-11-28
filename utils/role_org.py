from typing import List
from sqlmodel import Session, select
from sqlalchemy import and_
from fastapi import HTTPException
from utils.models import Organization, Role, UserOrganizationLink, RolePermissionLink, Permission, ValidPermissions


class OrganizationNotFoundError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=404,
            detail="Organization not found"
        )


class InsufficientPermissionsError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=403,
            detail="You don't have permission to perform this action"
        )


def get_user_organizations(
    user_id: int,
    session: Session
) -> List[Organization]:
    """
    Retrieve all organizations a user is a member of.

    Args:
        user_id: ID of the user
        session: Database session

    Returns:
        List of Organization objects the user belongs to
    """
    query = (
        select(Organization)
        .join(UserOrganizationLink)
        .where(UserOrganizationLink.user_id == user_id)
    )

    return list(session.exec(query))


def get_organization(
    org_id: int,
    user_id: int,
    session: Session,
) -> Organization:
    """
    Retrieve a specific organization if the user is a member.

    Args:
        org_id: ID of the organization
        user_id: ID of the user
        session: Database session

    Returns:
        Organization object

    Raises:
        OrganizationNotFoundError: If organization doesn't exist
        InsufficientPermissionsError: If user is not a member
    """
    # Check if user is a member of the organization
    user_org = session.exec(
        select(UserOrganizationLink).where(
            and_(
                UserOrganizationLink.user_id == user_id,
                UserOrganizationLink.organization_id == org_id
            )
        )
    ).first()

    if not user_org:
        raise InsufficientPermissionsError()

    db_org = session.get(Organization, org_id)
    if not db_org:
        raise OrganizationNotFoundError()

    return db_org


def check_user_permission(
    user_id: int,
    org_id: int,
    permission: ValidPermissions,
    session: Session,
) -> bool:
    """
    Check if user has the specified permission for the organization.

    Args:
        user_id: ID of the user
        org_id: ID of the organization
        permission: Permission to check
        session: Database session

    Returns:
        True if user has permission, False otherwise
    """
    # Get user's role in the organization
    user_org = session.exec(
        select(UserOrganizationLink).where(
            and_(
                UserOrganizationLink.user_id == user_id,
                UserOrganizationLink.organization_id == org_id
            )
        )
    ).first()

    if not user_org:
        return False

    # Get permission ID
    permission_record = session.exec(
        select(Permission).where(Permission.name == permission)
    ).first()

    if not permission_record:
        return False

    # Check if role has the permission
    role_permission = session.exec(
        select(RolePermissionLink).where(
            and_(
                RolePermissionLink.role_id == user_org.role_id,
                RolePermissionLink.permission_id == permission_record.id
            )
        )
    ).first()

    return bool(role_permission)


def get_organization_roles(
    organization_id: int,
    session: Session
) -> List[Role]:
    """
    Retrieve all roles for an organization.

    Args:
        organization_id: ID of the organization
        session: Database session

    Returns:
        List of Role objects with their associated permissions
    """
    query = select(Role).where(Role.organization_id == organization_id)

    return list(session.exec(query))
