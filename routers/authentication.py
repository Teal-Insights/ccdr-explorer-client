# auth.py
from logging import getLogger
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Form
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, ConfigDict, field_validator
from sqlmodel import Session, select
from utils.db import User
from utils.auth import (
    get_session,
    get_user_from_reset_token,
    create_password_validator,
    create_passwords_match_validator,
    oauth2_scheme_cookie,
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    validate_token,
    send_reset_email
)

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/auth", tags=["auth"])


# -- Server Request and Response Models --


class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    confirm_password: str

    validate_password_strength = create_password_validator("password")
    validate_passwords_match = create_passwords_match_validator(
        "password", "confirm_password")

    @classmethod
    async def as_form(
        cls,
        name: str = Form(...),
        email: EmailStr = Form(...),
        password: str = Form(...),
        confirm_password: str = Form(...)
    ):
        return cls(
            name=name,
            email=email,
            password=password,
            confirm_password=confirm_password
        )


class UserLogin(BaseModel):
    email: EmailStr
    password: str

    @classmethod
    async def as_form(
        cls,
        email: EmailStr = Form(...),
        password: str = Form(...)
    ):
        return cls(email=email, password=password)


class UserForgotPassword(BaseModel):
    email: EmailStr

    @classmethod
    async def as_form(
        cls,
        email: EmailStr = Form(...)
    ):
        return cls(email=email)


class UserResetPassword(BaseModel):
    email: EmailStr
    token: str
    new_password: str
    confirm_new_password: str

    # Use the factory with a different field name
    validate_password_strength = create_password_validator("new_password")
    validate_passwords_match = create_passwords_match_validator(
        "new_password", "confirm_new_password")

    @classmethod
    async def as_form(
        cls,
        email: EmailStr = Form(...),
        token: str = Form(...),
        new_password: str = Form(...),
        confirm_new_password: str = Form(...)
    ):
        return cls(email=email, token=token,
                   new_password=new_password, confirm_new_password=confirm_new_password)


# -- DB Request and Response Models --


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: EmailStr
    organization_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    deleted: bool


# -- Routes --


@router.post("/register", response_class=RedirectResponse)
async def register(
    user: UserRegister = Depends(UserRegister.as_form),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    db_user = session.exec(select(User).where(
        User.email == user.email)).first()

    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    db_user = User(name=user.name, email=user.email,
                   hashed_password=hashed_password)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    # Create access token
    access_token = create_access_token(data={"sub": db_user.email})
    refresh_token = create_refresh_token(data={"sub": db_user.email})
    # Set cookie
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    response.set_cookie(key="refresh_token",
                        value=refresh_token, httponly=True)

    return response


@router.post("/login", response_class=RedirectResponse)
async def login(
    user: UserLogin = Depends(UserLogin.as_form),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    db_user = session.exec(select(User).where(
        User.email == user.email)).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Create access token
    access_token = create_access_token(
        data={"sub": db_user.email, "fresh": True})
    refresh_token = create_refresh_token(data={"sub": db_user.email})

    # Set cookie
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )

    return response


# Updated refresh_token endpoint
@router.post("/refresh", response_class=RedirectResponse)
async def refresh_token(
    tokens: tuple[Optional[str], Optional[str]
                  ] = Depends(oauth2_scheme_cookie),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    _, refresh_token = tokens
    if not refresh_token:
        return RedirectResponse(url="/login", status_code=303)

    decoded_token = validate_token(refresh_token, token_type="refresh")
    if not decoded_token:
        response = RedirectResponse(url="/login", status_code=303)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response

    user_email = decoded_token.get("sub")
    db_user = session.exec(select(User).where(
        User.email == user_email)).first()
    if not db_user:
        return RedirectResponse(url="/login", status_code=303)

    new_access_token = create_access_token(
        data={"sub": db_user.email, "fresh": False})
    new_refresh_token = create_refresh_token(data={"sub": db_user.email})

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )

    return response


@router.post("/forgot_password")
async def forgot_password(
    background_tasks: BackgroundTasks,
    user: UserForgotPassword = Depends(UserForgotPassword.as_form),
    session: Session = Depends(get_session)
):
    db_user = session.exec(select(User).where(
        User.email == user.email)).first()

    # TODO: Handle this in background task so we don't leak information via timing attacks
    if db_user:
        background_tasks.add_task(send_reset_email, user.email, session)

    return RedirectResponse(url="/forgot_password?show_form=false", status_code=303)


@router.post("/reset_password")
async def reset_password(
    user: UserResetPassword = Depends(UserResetPassword.as_form),
    session: Session = Depends(get_session)
):
    authorized_user, reset_token = get_user_from_reset_token(
        user.email, user.token, session)

    if not authorized_user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # Update password and mark token as used
    authorized_user.hashed_password = get_password_hash(user.new_password)
    reset_token.used = True
    session.commit()
    session.refresh(authorized_user)

    return RedirectResponse(url="/login", status_code=303)


@router.get("/logout", response_class=RedirectResponse)
def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response
