from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlmodel import Session
from utils.models import User
from utils.auth import get_session, get_authenticated_user, verify_password

router = APIRouter(prefix="/user", tags=["user"])


# -- Server Request and Response Models --


class UserProfile(BaseModel):
    name: str
    email: EmailStr
    avatar_url: str

    @classmethod
    async def as_form(
        cls,
        name: str = Form(...),
        email: EmailStr = Form(...),
        avatar_url: str = Form(...),
    ):
        return cls(name=name, email=email, avatar_url=avatar_url)


class UserDeleteAccount(BaseModel):
    confirm_delete_password: str

    @classmethod
    async def as_form(
        cls,
        confirm_delete_password: str = Form(...),
    ):
        return cls(confirm_delete_password=confirm_delete_password)


class UpdateProfile(BaseModel):
    """Request model for updating user profile information"""
    name: str
    email: EmailStr
    avatar_url: str

    @classmethod
    async def as_form(
        cls,
        name: str = Form(...),
        email: EmailStr = Form(...),
        avatar_url: str = Form(...),
    ):
        return cls(name=name, email=email, avatar_url=avatar_url)


# -- Routes --


@router.get("/profile", response_class=RedirectResponse)
async def view_profile(
    current_user: User = Depends(get_authenticated_user)
):
    # Render the profile page with the current user's data
    return {"user": current_user}


@router.post("/update_profile", response_class=RedirectResponse)
async def update_profile(
    profile_update: UpdateProfile = Depends(UpdateProfile.as_form),
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # Update user details
    current_user.name = profile_update.name
    current_user.email = profile_update.email
    current_user.avatar_url = profile_update.avatar_url
    session.commit()
    session.refresh(current_user)
    return RedirectResponse(url="/profile", status_code=303)


@router.post("/delete_account", response_class=RedirectResponse)
async def delete_account(
    user_delete_account: UserDeleteAccount = Depends(
        UserDeleteAccount.as_form),
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    if not verify_password(user_delete_account.confirm_delete_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Password is incorrect")

    # Mark the user as deleted
    current_user.deleted = True
    session.commit()

    # Delete the user's access and refresh tokens to force a logout
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response
