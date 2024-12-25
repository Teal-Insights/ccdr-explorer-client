# TODO: User with permission to create/edit roles can only assign permissions
# they themselves have.
from typing import List, Sequence, Optional
from logging import getLogger
from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, field_validator
from sqlmodel import Session, select, col
from sqlalchemy.orm import selectinload
from utils.db import get_session
from utils.auth import get_authenticated_user, InsufficientPermissionsError
from utils.models import Role, Permission, ValidPermissions, utc_time, User, DataIntegrityError

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/roles", tags=["roles"])


# -- Custom Exceptions --


class InvalidPermissionError(HTTPException):
    """Raised when a user attempts to assign an invalid permission to a role"""

    def __init__(self, permission: ValidPermissions):
        super().__init__(
            status_code=400,
            detail=f"Invalid permission: {permission}"
        )


class RoleAlreadyExistsError(HTTPException):
    """Raised when attempting to create a role with a name that already exists"""

    def __init__(self):
        super().__init__(status_code=400, detail="Role already exists")


class RoleNotFoundError(HTTPException):
    """Raised when a requested role does not exist"""

    def __init__(self):
        super().__init__(status_code=404, detail="Role not found")


class RoleHasUsersError(HTTPException):
    """Raised when a requested role to be deleted has users"""

    def __init__(self):
        super().__init__(
            status_code=400,
            detail="Role cannot be deleted until users with that role are reassigned"
        )


# -- Server Request Models --

class RoleCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    organization_id: int
    permissions: List[ValidPermissions]

    @classmethod
    async def as_form(
        cls,
        name: str = Form(...),
        organization_id: int = Form(...),
        permissions: List[ValidPermissions] = Form(...)
    ):
        # Pass session to validator context
        return cls(
            name=name,
            organization_id=organization_id,
            permissions=permissions
        )


class RoleUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    organization_id: int
    permissions: List[ValidPermissions]

    @classmethod
    async def as_form(
        cls,
        id: int = Form(...),
        name: str = Form(...),
        organization_id: int = Form(...),
        permissions: List[ValidPermissions] = Form(...)
    ):
        return cls(
            id=id,
            name=name,
            organization_id=organization_id,
            permissions=permissions
        )


class RoleDelete(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int

    @classmethod
    async def as_form(
        cls,
        id: int = Form(...),
        organization_id: int = Form(...)
    ):
        return cls(id=id, organization_id=organization_id)


# -- Routes --


@router.post("/create", response_class=RedirectResponse)
def create_role(
    role: RoleCreate = Depends(RoleCreate.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check that the user-selected role name is unique for the organization
    if session.exec(
        select(Role).where(
            Role.name == role.name,
            Role.organization_id == role.organization_id
        )
    ).first():
        raise RoleAlreadyExistsError()

    # Check that the user is authorized to create roles in the organization
    if not user.has_permission(ValidPermissions.CREATE_ROLE, role.organization_id):
        raise InsufficientPermissionsError()

    # Create role
    db_role = Role(
        name=role.name,
        organization_id=role.organization_id
    )
    session.add(db_role)

    # Select Permission records corresponding to the user-selected permissions
    # and associate them with the newly created role
    permissions: Sequence[Permission] = session.exec(
        select(Permission).where(col(Permission.name).in_(role.permissions))
    ).all()
    db_role.permissions.extend(permissions)

    # Commit transaction
    session.commit()

    return RedirectResponse(url="/profile", status_code=303)


@router.post("/update", response_class=RedirectResponse)
def update_role(
    role: RoleUpdate = Depends(RoleUpdate.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check that the user is authorized to update the role
    if not user.has_permission(ValidPermissions.EDIT_ROLE, role.organization_id):
        raise InsufficientPermissionsError()

    # Select db_role to update, along with its permissions, by ID
    db_role: Optional[Role] = session.exec(
        select(Role).where(Role.id == role.id).options(
            selectinload(Role.permissions))
    ).first()

    if not db_role:
        raise RoleNotFoundError()

    # If any user-selected permissions are not valid, raise an error
    for permission in role.permissions:
        if permission not in ValidPermissions:
            raise InvalidPermissionError(permission)

    # Add any user-selected permissions that are not already associated with the role
    for permission in role.permissions:
        if permission not in [p.name for p in db_role.permissions]:
            db_permission: Optional[Permission] = session.exec(
                select(Permission).where(Permission.name == permission)
            ).first()
            if db_permission:
                db_role.permissions.append(db_permission)
            else:
                raise DataIntegrityError(resource=f"Permission: {permission}")

    # Remove any permissions that are not user-selected
    for db_permission in db_role.permissions:
        if db_permission.name not in role.permissions:
            db_role.permissions.remove(db_permission)

    # Check that no existing organization role has the same name but a different ID
    if session.exec(
        select(Role).where(
            Role.name == role.name,
            Role.organization_id == role.organization_id,
            Role.id != role.id
        )
    ).first():
        raise RoleAlreadyExistsError()

    # Update role name and updated_at timestamp
    db_role.name = role.name
    db_role.updated_at = utc_time()

    session.commit()
    session.refresh(db_role)
    return RedirectResponse(url="/profile", status_code=303)


@router.post("/delete", response_class=RedirectResponse)
def delete_role(
    role: RoleDelete = Depends(RoleDelete.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check that the user is authorized to delete the role
    if not user.has_permission(ValidPermissions.DELETE_ROLE, role.organization_id):
        raise InsufficientPermissionsError()

    # Select the role to delete by ID, along with its users
    db_role: Role | None = session.exec(
        select(Role).where(Role.id == role.id).options(
            selectinload(Role.users)
        )
    ).first()

    if not db_role:
        raise RoleNotFoundError()

    # Check that no users have the role
    if db_role.users:
        raise RoleHasUsersError()

    # Delete the role
    session.delete(db_role)
    session.commit()

    return RedirectResponse(url="/profile", status_code=303)
