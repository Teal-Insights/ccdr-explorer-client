from logging import getLogger
from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, field_validator
from sqlmodel import Session, select
from utils.db import get_session
from utils.auth import get_authenticated_user
from utils.models import Organization, User
from datetime import datetime

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

    return RedirectResponse(url=f"/organizations/{db_org.id}", status_code=303)


@router.get("/{org_id}", response_model=OrganizationRead)
def read_organization(org_id: int, user: User = Depends(get_authenticated_user), session: Session = Depends(get_session)):
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
    db_org = session.get(Organization, org_id)
    if not db_org:
        raise OrganizationNotFoundError()

    db_org.deleted = True
    db_org.updated_at = datetime.utcnow()
    session.add(db_org)
    session.commit()

    return RedirectResponse(url="/organizations", status_code=303)
