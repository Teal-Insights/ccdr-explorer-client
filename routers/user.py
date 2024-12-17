from fastapi import APIRouter, Depends, Form, UploadFile, File
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, EmailStr
from sqlmodel import Session
from typing import Optional
from utils.models import User, DataIntegrityError
from utils.auth import get_session, get_authenticated_user, verify_password, PasswordValidationError
from utils.images import validate_and_process_image

router = APIRouter(prefix="/user", tags=["user"])


# --- Server Request and Response Models ---


class UpdateProfile(BaseModel):
    """Request model for updating user profile information"""
    name: str
    email: EmailStr
    avatar_file: Optional[bytes] = None
    avatar_content_type: Optional[str] = None

    @classmethod
    async def as_form(
        cls,
        name: str = Form(...),
        email: EmailStr = Form(...),
        avatar_file: Optional[UploadFile] = File(None),
    ):
        avatar_data = None
        avatar_content_type = None

        if avatar_file:
            avatar_data = await avatar_file.read()
            avatar_content_type = avatar_file.content_type

        return cls(
            name=name,
            email=email,
            avatar_file=avatar_data,
            avatar_content_type=avatar_content_type
        )


class UserDeleteAccount(BaseModel):
    confirm_delete_password: str

    @classmethod
    async def as_form(
        cls,
        confirm_delete_password: str = Form(...),
    ):
        return cls(confirm_delete_password=confirm_delete_password)


# --- Routes ---


@router.post("/update_profile", response_class=RedirectResponse)
async def update_profile(
    user_profile: UpdateProfile = Depends(UpdateProfile.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # Handle avatar update
    if user_profile.avatar_file:
        processed_image, content_type = validate_and_process_image(
            user_profile.avatar_file,
            user_profile.avatar_content_type
        )
        user_profile.avatar_file = processed_image
        user_profile.avatar_content_type = content_type

    # Update user details
    user.name = user_profile.name
    user.email = user_profile.email
    
    if user_profile.avatar_file:
        user.avatar_data = user_profile.avatar_file
        user.avatar_content_type = user_profile.avatar_content_type

    session.commit()
    session.refresh(user)
    return RedirectResponse(url="/profile", status_code=303)


@router.post("/delete_account", response_class=RedirectResponse)
async def delete_account(
    user_delete_account: UserDeleteAccount = Depends(
        UserDeleteAccount.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    if not user.password:
        raise DataIntegrityError(
            resource="User password"
        )

    if not verify_password(
        user_delete_account.confirm_delete_password,
        user.password.hashed_password
    ):
        raise PasswordValidationError(
            field="confirm_delete_password",
            message="Password is incorrect"
        )

    # Delete the user
    session.delete(user)
    session.commit()

    # Log out the user
    return RedirectResponse(url="/auth/logout", status_code=303)


@router.get("/avatar")
async def get_avatar(
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    """Serve avatar image from database"""
    if not user.avatar_data:
        raise DataIntegrityError(
            resource="User avatar"
        )

    return Response(
        content=user.avatar_data,
        media_type=user.avatar_content_type
    )
