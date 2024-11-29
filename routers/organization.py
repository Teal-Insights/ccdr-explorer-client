from logging import getLogger
from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, field_validator
from sqlmodel import Session, select
from utils.db import get_session
from utils.auth import get_authenticated_user, get_user_with_relations
from utils.models import Organization, User, Role, utc_time, default_roles
from datetime import datetime

logger = getLogger("uvicorn.error")

# -- Custom Exceptions --


class EmptyOrganizationNameError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=400,
            detail="Organization name cannot be empty"
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

@router.post("/create", name="create_organization", response_class=RedirectResponse)
def create_organization(
    org: OrganizationCreate = Depends(OrganizationCreate.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check if organization already exists
    db_org = session.exec(select(Organization).where(
        Organization.name == org.name)).first()
    if db_org:
        raise OrganizationNameTakenError()

    # Create organization first
    db_org = Organization(name=org.name)
    session.add(db_org)
    # This gets us the org ID without committing
    session.flush()

    # Create default roles with organization_id
    initial_roles = [
        Role(name=name, organization_id=db_org.id)
        for name in default_roles
    ]
    session.add_all(initial_roles)
    session.flush()

    # Get owner role for user assignment
    owner_role = next(role for role in db_org.roles if role.name == "Owner")

    # Assign user to owner role
    user.roles.append(owner_role)

    # Commit changes
    session.commit()
    session.refresh(db_org)

    return RedirectResponse(url=f"/profile", status_code=303)


@router.post("/update/{org_id}", name="update_organization", response_class=RedirectResponse)
def update_organization(
    org: OrganizationUpdate = Depends(OrganizationUpdate.as_form),
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # This will raise appropriate exceptions if org doesn't exist or user lacks access
    organization: Organization = user.organizations.get(org.id)

    if not organization or not any(role.permissions.EDIT_ORGANIZATION for role in organization.roles):
        raise InsufficientPermissionsError()

    # Check if new name already exists for another organization
    existing_org = session.exec(
        select(Organization)
        .where(Organization.name == org.name)
        .where(Organization.id != org.id)
    ).first()
    if existing_org:
        raise OrganizationNameTakenError()

    # Update organization name
    organization.name = org.name
    organization.updated_at = utc_time()
    session.add(organization)
    session.commit()

    return RedirectResponse(url=f"/profile", status_code=303)


@router.post("/delete/{org_id}", name="delete_organization", response_class=RedirectResponse)
def delete_organization(
    org_id: int,
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check if user has permission to delete organization
    organization: Organization = user.organizations.get(org_id)
    if not organization or not any(role.permissions.DELETE_ORGANIZATION for role in organization.roles):
        raise InsufficientPermissionsError()

    # Delete organization
    session.delete(organization)
    session.commit()

    return RedirectResponse(url="/profile", status_code=303)
