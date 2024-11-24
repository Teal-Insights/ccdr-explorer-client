from logging import getLogger
from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict
from sqlmodel import Session, select
from utils.db import get_session
from utils.models import Organization
from datetime import datetime

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/organizations", tags=["organizations"])


class OrganizationCreate(BaseModel):
    name: str

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

    @classmethod
    async def as_form(cls, id: int = Form(...), name: str = Form(...)):
        return cls(id=id, name=name)


@router.post("/", response_class=RedirectResponse)
def create_organization(
    org: OrganizationCreate = Depends(OrganizationCreate.as_form),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Validate organization name is not empty
    if not org.name.strip():
        raise HTTPException(
            status_code=400, detail="Organization name cannot be empty")

    db_org = session.exec(select(Organization).where(
        Organization.name == org.name)).first()
    if db_org:
        raise HTTPException(
            status_code=400, detail="Organization already exists")

    db_org = Organization(name=org.name)
    session.add(db_org)
    session.commit()
    session.refresh(db_org)

    return RedirectResponse(url=f"/organizations/{db_org.id}", status_code=303)


@router.get("/{org_id}", response_model=OrganizationRead)
def read_organization(org_id: int, session: Session = Depends(get_session)):
    db_org = session.get(Organization, org_id)
    if not db_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return db_org


@router.put("/{org_id}", response_class=RedirectResponse)
def update_organization(
    org: OrganizationUpdate = Depends(OrganizationUpdate.as_form),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Validate organization name is not empty
    if not org.name.strip():
        raise HTTPException(
            status_code=400, detail="Organization name cannot be empty")

    db_org = session.get(Organization, org.id)
    if not db_org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check if new name already exists for another organization
    existing_org = session.exec(
        select(Organization)
        .where(Organization.name == org.name)
        .where(Organization.id != org.id)
    ).first()
    if existing_org:
        raise HTTPException(
            status_code=400, detail="Organization name already taken")

    db_org.name = org.name
    db_org.updated_at = datetime.utcnow()
    session.add(db_org)
    session.commit()
    session.refresh(db_org)

    return RedirectResponse(url=f"/organizations/{org.id}", status_code=303)


@router.delete("/{org_id}", response_class=RedirectResponse)
def delete_organization(
    org_id: int,
    session: Session = Depends(get_session)
) -> RedirectResponse:
    db_org = session.get(Organization, org_id)
    if not db_org:
        raise HTTPException(status_code=404, detail="Organization not found")

    session.delete(db_org)
    session.commit()

    return RedirectResponse(url="/organizations", status_code=303)
