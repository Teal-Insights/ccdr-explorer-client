from fastapi import APIRouter, Depends, Form, UploadFile, File
from fastapi.responses import RedirectResponse, Response
from sqlmodel import Session
from typing import Optional
from utils.models import UserBase, User, DataIntegrityError
from utils.auth import get_session, get_authenticated_user
from utils.images import validate_and_process_image

router = APIRouter(prefix="/user", tags=["user"])


# --- Server Request and Response Models ---


class UpdateUser(UserBase):
    """Request model for updating user profile information"""
    @classmethod
    async def as_form(
        cls,
        name: Optional[str] = Form(None),
        avatar_file: Optional[UploadFile] = File(None),
    ):
        avatar_data = None
        avatar_content_type = None

        if avatar_file:
            avatar_data = await avatar_file.read()
            avatar_content_type = avatar_file.content_type

        return cls(
            name=name,
            avatar_data=avatar_data,
            avatar_content_type=avatar_content_type
        )


# --- Routes ---


@router.post("/update", response_class=RedirectResponse)
async def update_profile(
    user_update: UpdateUser = Depends(UpdateUser.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # Handle avatar update
    if user_update.avatar_data:
        processed_image, content_type = validate_and_process_image(
            user_update.avatar_data,
            user_update.avatar_content_type
        )
        user.avatar_data = processed_image
        user.avatar_content_type = content_type

    # Update user details
    user.name = user_update.name

    session.commit()
    session.refresh(user)
    return RedirectResponse(url="/profile", status_code=303)


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
