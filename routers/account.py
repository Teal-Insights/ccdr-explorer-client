# auth.py
from logging import getLogger
from typing import Optional
from urllib.parse import urlparse
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr, ConfigDict
from sqlmodel import Session, select
from utils.models import User, Account, DataIntegrityError, User
from utils.db import get_session
from utils.auth import (
    HTML_PASSWORD_PATTERN,
    get_user_from_reset_token,
    create_password_validator,
    create_passwords_match_validator,
    oauth2_scheme_cookie,
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    validate_token,
    send_reset_email,
    send_email_update_confirmation,
    get_user_from_email_update_token,
    get_authenticated_user,
    PasswordValidationError,
    get_optional_user
)

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/account", tags=["account"])
templates = Jinja2Templates(directory="templates")

# --- Custom Exceptions ---


class EmailAlreadyRegisteredError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=409,
            detail="This email is already registered"
        )


class AuthenticationError(HTTPException):
    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(
            status_code=401,
            detail=message
        )


# --- Server Request and Response Models ---


class DeleteAccount(Account):
    @classmethod
    async def as_form(
        cls,
        email: EmailStr = Form(...),
        password: str = Form(...),
    ):
        return cls(email=email, password=password)


class CreateAccount(Account):
    name: str
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


class UpdateEmail(BaseModel):
    new_email: EmailStr

    @classmethod
    async def as_form(
        cls,
        new_email: EmailStr = Form(...)
    ):
        return cls(new_email=new_email)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: EmailStr
    organization_id: Optional[int]
    created_at: datetime
    updated_at: datetime


# --- Routes ---


# TODO: Check the email too
@router.post("/delete", response_class=RedirectResponse)
async def delete_account(
    user_delete_account: DeleteAccount = Depends(
        DeleteAccount.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    if not user.password:
        raise DataIntegrityError(
            resource="User password"
        )

    if not verify_password(
        user_delete_account.password,
        user.password.hashed_password
    ):
        raise PasswordValidationError(
            field="password",
            message="Password is incorrect"
        )

    # Delete the user
    session.delete(user)
    session.commit()

    # Log out the user
    return RedirectResponse(url="/auth/logout", status_code=303)
@router.get("/login")
async def read_login(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    email_updated: Optional[str] = "false"
):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        "authentication/login.html",
        {"request": request, "user": user, "email_updated": email_updated}
    )


@router.get("/register")
async def read_register(
    request: Request,
    user: Optional[User] = Depends(get_optional_user)
):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)

    return templates.TemplateResponse(
        "authentication/register.html",
        {"request": request, "user": user}
    )


@router.get("/forgot_password")
async def read_forgot_password(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    show_form: Optional[str] = "true",
):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)

    return templates.TemplateResponse(
        "authentication/forgot_password.html",
        {"request": request, "user": user, "show_form": show_form == "true"}
    )


@router.get("/reset_password")
async def read_reset_password(
    request: Request,
    email: str,
    token: str,
    user: Optional[User] = Depends(get_optional_user),
    session: Session = Depends(get_session)
):
    authorized_user, _ = get_user_from_reset_token(email, token, session)

    # Raise informative error to let user know the token is invalid and may have expired
    if not authorized_user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    return templates.TemplateResponse(
        "authentication/reset_password.html",
        {"request": request, "user": user, "email": email, "token": token, "password_pattern": HTML_PASSWORD_PATTERN}
    )


# TODO: Use custom error message in the case where the user is already registered
@router.post("/register", response_class=RedirectResponse)
async def register(
    user: UserRegister = Depends(UserRegister.as_form),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    # Check if the email is already registered
    db_user = session.exec(select(User).where(
        User.email == user.email)).first()

    if db_user:
        raise EmailAlreadyRegisteredError()

    # Hash the password
    hashed_password = get_password_hash(user.password)

    # Create the user
    db_user = User(name=user.name, email=user.email,
                   password=UserPassword(hashed_password=hashed_password))
    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    # Create access token
    access_token = create_access_token(data={"sub": db_user.email})
    refresh_token = create_refresh_token(data={"sub": db_user.email})
    # Set cookie
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )

    return response


@router.post("/login", response_class=RedirectResponse)
async def login(
    user: UserLogin = Depends(UserLogin.as_form),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    # Check if the email is registered
    db_user = session.exec(select(User).where(
        User.email == user.email)).first()

    if not db_user or not db_user.password or not verify_password(user.password, db_user.password.hashed_password):
        raise AuthenticationError()

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
    request: Request,
    user: UserForgotPassword = Depends(UserForgotPassword.as_form),
    session: Session = Depends(get_session)
):
    db_user = session.exec(select(User).where(
        User.email == user.email)).first()

    if db_user:
        background_tasks.add_task(send_reset_email, user.email, session)

    # Get the referer header, default to /forgot_password if not present
    referer = request.headers.get("referer", "/forgot_password")

    # Extract the path from the full URL
    redirect_path = urlparse(referer).path

    # Add the query parameter to the redirect path
    return RedirectResponse(url=f"{redirect_path}?show_form=false", status_code=303)


@router.post("/reset_password")
async def reset_password(
    user: UserResetPassword = Depends(UserResetPassword.as_form),
    session: Session = Depends(get_session)
):
    authorized_user, reset_token = get_user_from_reset_token(
        user.email, user.token, session)

    if not authorized_user or not reset_token:
        raise AuthenticationError("Invalid or expired password reset token; please request a new one")

    # Update password and mark token as used
    if authorized_user.password:
        authorized_user.password.hashed_password = get_password_hash(
            user.new_password
        )
    else:
        logger.warning(
            "User password not found during password reset; creating new password for user")
        authorized_user.password = UserPassword(
            hashed_password=get_password_hash(user.new_password)
        )

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


@router.post("/update_email")
async def request_email_update(
    update: UpdateEmail = Depends(UpdateEmail.as_form),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # Check if the new email is already registered
    existing_user = session.exec(
        select(User).where(User.email == update.new_email)
    ).first()

    if existing_user:
        raise EmailAlreadyRegisteredError()

    if not user.id:
        raise DataIntegrityError(resource="User id")

    # Send confirmation email
    send_email_update_confirmation(
        current_email=user.email,
        new_email=update.new_email,
        user_id=user.id,
        session=session
    )

    return RedirectResponse(
        url="/profile?email_update_requested=true",
        status_code=303
    )


@router.get("/confirm_email_update")
async def confirm_email_update(
    user_id: int,
    token: str,
    new_email: str,
    session: Session = Depends(get_session)
):
    user, update_token = get_user_from_email_update_token(
        user_id, token, session
    )

    if not user or not update_token:
        raise AuthenticationError("Invalid or expired email update token; please request a new one")

    # Update email and mark token as used
    user.email = new_email
    update_token.used = True
    session.commit()

    # Create new tokens with the updated email
    access_token = create_access_token(data={"sub": new_email, "fresh": True})
    refresh_token = create_refresh_token(data={"sub": new_email})

    # Set cookies before redirecting
    response = RedirectResponse(
        url="/profile?email_updated=true",
        status_code=303
    )

    # Add secure cookie attributes
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="lax"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax"
    )
    return response
