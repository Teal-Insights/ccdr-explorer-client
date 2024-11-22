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


# -- Routes --


@router.get("/profile", response_class=RedirectResponse)
async def view_profile(
    current_user: User = Depends(get_authenticated_user)
):
    # Render the profile page with the current user's data
    return {"user": current_user}


@router.post("/edit_profile", response_class=RedirectResponse)
async def edit_profile(
    name: str = Form(...),
    email: str = Form(...),
    avatar_url: str = Form(...),
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # Update user details
    current_user.name = name
    current_user.email = email
    current_user.avatar_url = avatar_url
    session.commit()
    session.refresh(current_user)
    return RedirectResponse(url="/profile", status_code=303)


@router.post("/delete_account", response_class=RedirectResponse)
async def delete_account(
    confirm_delete_password: str = Form(...),
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    if not verify_password(confirm_delete_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Password is incorrect")

    # Mark the user as deleted
    current_user.deleted = True
    session.commit()
    #Logs Out
    router.get("/logout", response_class=RedirectResponse)
    # Deletes user
    session.delete(current_user)
    return RedirectResponse(url="/", status_code=303)
