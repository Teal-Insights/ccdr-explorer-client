from logging import getLogger
from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, field_validator
from sqlmodel import Session, select
from utils.db import get_session
from utils.auth import get_authenticated_user
from utils.models import Organization, User, Role, Permission, UserOrganizationLink, ValidPermissions, utc_time
from datetime import datetime
from sqlalchemy import and_
from utils.role_org import get_organization, check_user_permission

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

    # Create default roles
    default_role_names = ["Owner", "Administrator", "Member"]
    default_roles = []
    for role_name in default_role_names:
        role = Role(name=role_name, organization_id=db_org.id)
        session.add(role)
        default_roles.append(role)
    session.commit()

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

    return RedirectResponse(url=f"/profile", status_code=303)


@router.put("/{org_id}", response_class=RedirectResponse)
def update_organization(
    org: OrganizationUpdate = Depends(OrganizationUpdate.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # This will raise appropriate exceptions if org doesn't exist or user lacks access
    organization = get_organization(org.id, user.id, session)

    if not check_user_permission(user.id, org.id, ValidPermissions.EDIT_ORGANIZATION, session):
        raise InsufficientPermissionsError()

    # Check if new name already exists for another organization
    existing_org = session.exec(
        select(Organization)
        .where(Organization.name == org.name)
        .where(Organization.id != org.id)
    ).first()
    if existing_org:
        raise OrganizationNameTakenError()

    organization.name = org.name
    organization.updated_at = utc_time()
    session.add(organization)
    session.commit()
    session.refresh(organization)

    return RedirectResponse(url=f"/profile", status_code=303)


@router.delete("/{org_id}", response_class=RedirectResponse)
def delete_organization(
    org_id: int,
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # This will raise appropriate exceptions if org doesn't exist or user lacks access
    organization = get_organization(org_id, user.id, session)

    session.delete(organization)
    session.commit()

    return RedirectResponse(url="/profile", status_code=303)
