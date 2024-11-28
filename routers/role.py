from typing import List
from datetime import datetime
from logging import getLogger
from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, field_validator
from sqlmodel import Session, select
from utils.db import get_session
from utils.auth import get_authenticated_user
from utils.models import Role, RolePermissionLink, ValidPermissions, utc_time, User

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/roles", tags=["roles"])


# -- Custom Exceptions --


class RoleAlreadyExistsError(HTTPException):
    """Raised when attempting to create a role with a name that already exists"""

    def __init__(self):
        super().__init__(status_code=400, detail="Role already exists")


class RoleNotFoundError(HTTPException):
    """Raised when a requested role does not exist or is deleted"""

    def __init__(self):
        super().__init__(status_code=404, detail="Role not found")


# -- Server Request Models --

class RoleCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    permissions: List[ValidPermissions]

    @field_validator("name")
    @classmethod
    def validate_unique_name(cls, name: str, info):
        # Note: This requires passing session as a dependency to as_form
        session = info.context.get("session")
        if session and session.exec(select(Role).where(Role.name == name)).first():
            raise RoleAlreadyExistsError()
        return name

    @classmethod
    async def as_form(
        cls,
        name: str = Form(...),
        permissions: List[ValidPermissions] = Form(...),
        session: Session = Depends(get_session)
    ):
        # Pass session to validator context
        return cls(
            name=name,
            permissions=permissions,
            context={"session": session}
        )


class RoleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    updated_at: datetime
    deleted: bool
    permissions: List[ValidPermissions]


class RoleUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    permissions: List[ValidPermissions]

    @field_validator("id")
    @classmethod
    def validate_role_exists(cls, id: int, info):
        session = info.context.get("session")
        if session:
            role = session.get(Role, id)
            if not role or not role.id or role.deleted:
                raise RoleNotFoundError()
        return id

    @classmethod
    async def as_form(
        cls,
        id: int = Form(...),
        name: str = Form(...),
        permissions: List[ValidPermissions] = Form(...),
        session: Session = Depends(get_session)
    ):
        return cls(
            id=id,
            name=name,
            permissions=permissions,
            context={"session": session}
        )


# -- Helper Functions --

def get_organization_roles(
    organization_id: int,
    session: Session,
    include_deleted: bool = False
) -> List[Role]:
    """
    Retrieve all roles for an organization.

    Args:
        organization_id: ID of the organization
        session: Database session
        include_deleted: Whether to include soft-deleted roles

    Returns:
        List of Role objects with their associated permissions
    """
    query = select(Role).where(Role.organization_id == organization_id)
    if not include_deleted:
        query = query.where(Role.deleted == False)

    return list(session.exec(query))


# -- Routes --


@router.post("/", response_class=RedirectResponse)
def create_role(
    role: RoleCreate = Depends(RoleCreate.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Create role and permissions in a single transaction
    db_role = Role(
        name=role.name,
        organization_id=user.organization_id  # Add organization ID to role
    )

    # Create RolePermissionLink objects and associate them with the role
    db_role.permissions = [
        RolePermissionLink(permission_id=permission.name)
        for permission in role.permissions
    ]

    session.add(db_role)
    session.commit()

    return RedirectResponse(url="/roles", status_code=303)


@router.put("/{role_id}", response_class=RedirectResponse)
def update_role(
    role: RoleUpdate = Depends(RoleUpdate.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    db_role: Role | None = session.get(Role, role.id)

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
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    db_role = session.get(Role, role_id)
    if not db_role:
        raise RoleNotFoundError()

    db_role.deleted = True
    db_role.updated_at = utc_time()
    session.add(db_role)
    session.commit()
    return RedirectResponse(url="/roles", status_code=303)
