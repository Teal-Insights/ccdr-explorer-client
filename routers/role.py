from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlmodel import Session, select
from utils.db import Role, RolePermissionLink, ValidPermissions, get_session
from typing import List
from utils.db import utc_time
from datetime import datetime

router = APIRouter(prefix="/roles", tags=["roles"])


class RoleCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    permission_ids: List[int]


class RoleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    updated_at: datetime
    deleted: bool
    permissions: List[str]


class RoleUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    permission_ids: List[int]


@router.post("/", response_model=RoleRead)
def create_role(role: RoleCreate, session: Session = Depends(get_session)):
    db_role = session.exec(select(Role).where(Role.name == role.name)).first()
    if db_role:
        raise HTTPException(status_code=400, detail="Role already exists")
    db_role = Role(name=role.name)
    session.add(db_role)
    session.commit()
    session.refresh(db_role)

    for permission_id in role.permission_ids:
        db_role_permission_link = RolePermissionLink(
            role_id=db_role.id, permission_id=permission_id)
        session.add(db_role_permission_link)

    session.commit()
    session.refresh(db_role)
    return db_role


@router.get("/{role_id}", response_model=RoleRead)
def read_role(role_id: int, session: Session = Depends(get_session)):
    db_role = session.get(Role, role_id)
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")
    permissions = [
        link.permission.name for link in db_role.role_permission_links]
    return RoleRead(
        id=db_role.id,
        name=db_role.name,
        created_at=db_role.created_at,
        updated_at=db_role.updated_at,
        deleted=db_role.deleted,
        permissions=permissions
    )


@router.put("/{role_id}", response_model=RoleRead)
def update_role(role_id: int, role: RoleUpdate, session: Session = Depends(get_session)):
    db_role = session.get(Role, role_id)
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")
    role_data = role.model_dump(exclude_unset=True)
    for key, value in role_data.items():
        setattr(db_role, key, value)
    db_role.updated_at = utc_time()
    session.add(db_role)
    session.commit()

    # Update RolePermissionLinks
    session.exec(select(RolePermissionLink).where(
        RolePermissionLink.role_id == role_id)).delete()
    for permission_id in role.permission_ids:
        db_role_permission_link = RolePermissionLink(
            role_id=db_role.id, permission_id=permission_id)
        session.add(db_role_permission_link)

    session.commit()
    session.refresh(db_role)
    return db_role


@router.delete("/{role_id}")
def delete_role(role_id: int, session: Session = Depends(get_session)):
    db_role = session.get(Role, role_id)
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")
    db_role.deleted = True
    db_role.updated_at = utc_time()
    session.add(db_role)
    session.commit()
    return {"message": "Role deleted successfully"}
