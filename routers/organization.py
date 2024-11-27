from logging import getLogger
from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, field_validator
from sqlmodel import Session, select
from utils.db import get_session
from utils.auth import get_authenticated_user
from utils.models import Organization, User, Role, UserOrganizationLink, ValidPermissions, RolePermissionLink, Permission
from datetime import datetime
from sqlalchemy import and_

logger = getLogger("uvicorn.error")

# -- Custom Exceptions --


class EmptyOrganizationNameError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=400,
            detail="Organization name cannot be empty"
        )


class OrganizationExistsError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=400,
            detail="Organization already exists"
        )


class OrganizationNotFoundError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=404,
            detail="Organization not found"
        )


class OrganizationNameTakenError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=400,
            detail="Organization name already taken"
        )


class InsufficientPermissionsError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=403,
            detail="You don't have permission to perform this action"
        )


router = APIRouter(prefix="/organizations", tags=["organizations"])


# -- Server Request and Response Models --


class OrganizationCreate(BaseModel):
    name: str

    @field_validator('name')
    @classmethod
    def validate_name(cls, name: str) -> str:
        if not name.strip():
            raise EmptyOrganizationNameError()
        return name.strip()

    @classmethod
    async def as_form(cls, name: str = Form(...)):
        return cls(name=name)


class OrganizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    updated_at: datetime
    deleted: bool


class OrganizationUpdate(BaseModel):
    id: int
    name: str

    @field_validator('name')
    @classmethod
    def validate_name(cls, name: str) -> str:
        if not name.strip():
            raise EmptyOrganizationNameError()
        return name.strip()

    @classmethod
    async def as_form(cls, id: int = Form(...), name: str = Form(...)):
        return cls(id=id, name=name)


# -- Routes --

def check_user_permission(
    session: Session,
    user: User,
    org_id: int,
    permission: ValidPermissions
) -> bool:
    """
    Check if user has the specified permission for the organization
    """
    # Get user's role in the organization
    user_org = session.exec(
        select(UserOrganizationLink).where(
            and_(
                UserOrganizationLink.user_id == user.id,
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


@router.post("/", response_class=RedirectResponse)
def create_organization(
    org: OrganizationCreate = Depends(OrganizationCreate.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    db_org = session.exec(select(Organization).where(
        Organization.name == org.name)).first()
    if db_org:
        raise OrganizationExistsError()

    db_org = Organization(name=org.name)
    session.add(db_org)
    session.commit()
    session.refresh(db_org)

    owner_role = session.exec(
        select(Role).where(
            and_(
                Role.organization_id == db_org.id,
                Role.name == "Owner"
            )
        )
    ).first()

    if not owner_role:
        owner_role = Role(
            name="Owner",
            organization_id=db_org.id
        )
        session.add(owner_role)
        session.commit()
        session.refresh(owner_role)

    user_org_link = UserOrganizationLink(
        user_id=user.id,
        organization_id=db_org.id,
        role_id=owner_role.id
    )
    session.add(user_org_link)
    session.commit()

    return RedirectResponse(url=f"/organizations/{db_org.id}", status_code=303)


@router.get("/{org_id}", response_model=OrganizationRead)
def read_organization(
    org_id: int,
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # First check if user is a member of the organization
    user_org = session.exec(
        select(UserOrganizationLink).where(
            and_(
                UserOrganizationLink.user_id == user.id,
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


@router.put("/{org_id}", response_class=RedirectResponse)
def update_organization(
    org: OrganizationUpdate = Depends(OrganizationUpdate.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    if not check_user_permission(session, user, org.id, ValidPermissions.EDIT_ORGANIZATION):
        raise InsufficientPermissionsError()

    db_org = session.get(Organization, org.id)
    if not db_org:
        raise OrganizationNotFoundError()

    # Check if new name already exists for another organization
    existing_org = session.exec(
        select(Organization)
        .where(Organization.name == org.name)
        .where(Organization.id != org.id)
    ).first()
    if existing_org:
        raise OrganizationNameTakenError()

    db_org.name = org.name
    db_org.updated_at = datetime.utcnow()
    session.add(db_org)
    session.commit()
    session.refresh(db_org)

    return RedirectResponse(url=f"/organizations/{org.id}", status_code=303)


@router.delete("/{org_id}", response_class=RedirectResponse)
def delete_organization(
    org_id: int,
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    if not check_user_permission(session, user, org_id, ValidPermissions.DELETE_ORGANIZATION):
        raise InsufficientPermissionsError()

    db_org = session.get(Organization, org_id)
    if not db_org:
        raise OrganizationNotFoundError()

    db_org.deleted = True
    db_org.updated_at = datetime.utcnow()
    session.add(db_org)
    session.commit()

    return RedirectResponse(url="/organizations", status_code=303)
