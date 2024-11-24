from typing import List
from datetime import datetime
from logging import getLogger
from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict
from sqlmodel import Session, select
from utils.db import get_session
from utils.models import Role, RolePermissionLink, ValidPermissions, utc_time

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/roles", tags=["roles"])


class RoleCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    permissions: List[ValidPermissions]

    @classmethod
    async def as_form(cls, name: str = Form(...), permissions: List[ValidPermissions] = Form(...)):
        return cls(name=name, permissions=permissions)


class RoleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    updated_at: datetime
    permissions: List[ValidPermissions]


class RoleUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    permissions: List[ValidPermissions]

    @classmethod
    async def as_form(cls, id: int = Form(...), name: str = Form(...), permissions: List[ValidPermissions] = Form(...)):
        return cls(id=id, name=name, permissions=permissions)


@router.post("/", response_class=RedirectResponse)
def create_role(
    role: RoleCreate = Depends(RoleCreate.as_form),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    db_role = session.exec(select(Role).where(Role.name == role.name)).first()
    if db_role:
        raise HTTPException(status_code=400, detail="Role already exists")

    # Create role and permissions in a single transaction
    db_role = Role(name=role.name)

    # Create RolePermissionLink objects and associate them with the role
    db_role.permissions = [
        RolePermissionLink(permission_id=permission.name)
        for permission in role.permissions
    ]

    session.add(db_role)
    session.commit()  # Commit once after all operations

    return RedirectResponse(url="/roles", status_code=303)


@router.get("/{role_id}", response_model=RoleRead)
def read_role(role_id: int, session: Session = Depends(get_session)):
    db_role: Role | None = session.get(Role, role_id)
    if not db_role or not db_role.id:
        raise HTTPException(status_code=404, detail="Role not found")

    permissions = [
        ValidPermissions(link.permission.name)
        for link in db_role.role_permission_links
        if link.permission is not None
    ]

    return RoleRead(
        id=db_role.id,
        name=db_role.name,
        created_at=db_role.created_at,
        updated_at=db_role.updated_at,
        permissions=permissions
    )


@router.put("/{role_id}", response_class=RedirectResponse)
def update_role(
    role: RoleUpdate = Depends(RoleUpdate.as_form),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    db_role: Role | None = session.get(Role, role.id)
    if not db_role or not db_role.id:
        raise HTTPException(status_code=404, detail="Role not found")
    role_data = role.model_dump(exclude_unset=True)
    for key, value in role_data.items():
        setattr(db_role, key, value)
    db_role.updated_at = utc_time()
    session.add(db_role)
    session.commit()

    # Correctly delete RolePermissionLinks for the role
    session.delete(RolePermissionLink.role_id == role.id)

    for permission in role.permissions:
        db_role_permission_link = RolePermissionLink(
            role_id=db_role.id,
            permission_id=permission.name
        )
        session.add(db_role_permission_link)

    session.commit()
    session.refresh(db_role)
    return RedirectResponse(url=f"/roles/{role.id}", status_code=303)


@router.delete("/{role_id}", response_class=RedirectResponse)
def delete_role(
    role_id: int,
    session: Session = Depends(get_session)
) -> RedirectResponse:
    db_role = session.get(Role, role_id)
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")
    session.delete(db_role)
    session.commit()
    return RedirectResponse(url="/roles", status_code=303)
