from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlmodel import Session, select
from utils.db import Organization, get_session
from datetime import datetime

router = APIRouter(prefix="/organizations", tags=["organizations"])


class OrganizationCreate(BaseModel):
    name: str


class OrganizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    updated_at: datetime
    deleted: bool


class OrganizationUpdate(BaseModel):
    name: str


@router.post("/", response_model=OrganizationRead)
def create_organization(org: OrganizationCreate, session: Session = Depends(get_session)):
    db_org = session.exec(select(Organization).where(
        Organization.name == org.name)).first()
    if db_org:
        raise HTTPException(
            status_code=400, detail="Organization already exists")
    db_org = Organization(name=org.name)
    session.add(db_org)
    session.commit()
    session.refresh(db_org)
    return db_org


@router.get("/{org_id}", response_model=OrganizationRead)
def read_organization(org_id: int, session: Session = Depends(get_session)):
    db_org = session.get(Organization, org_id)
    if not db_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return db_org


@router.put("/{org_id}", response_model=OrganizationRead)
def update_organization(org_id: int, org: OrganizationUpdate, session: Session = Depends(get_session)):
    db_org = session.get(Organization, org_id)
    if not db_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org_data = org.dict(exclude_unset=True)
    for key, value in org_data.items():
        setattr(db_org, key, value)
    db_org.updated_at = datetime.utcnow()
    session.add(db_org)
    session.commit()
    session.refresh(db_org)
    return db_org


@router.delete("/{org_id}")
def delete_organization(org_id: int, session: Session = Depends(get_session)):
    db_org = session.get(Organization, org_id)
    if not db_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    db_org.deleted = True
    db_org.updated_at = datetime.utcnow()
    session.add(db_org)
    session.commit()
    return {"message": "Organization deleted successfully"}
