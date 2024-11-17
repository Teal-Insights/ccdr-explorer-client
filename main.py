# ToDo: Add CSRF protection to all POST, download, and sensitive data routes

import logging
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError, HTTPException, StarletteHTTPException
from sqlmodel import Session
from routers import authentication, organization, role, user
from utils.auth import get_authenticated_user, get_optional_user, NeedsNewTokens, get_user_from_reset_token, PasswordValidationError
from utils.db import User, get_session


logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.DEBUG)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Optional startup logic
    yield
    # Optional shutdown logic


app = FastAPI(lifespan=lifespan)

# Mount static files (e.g., CSS, JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")


# -- Exception Handling Middlewares --


# Handle NeedsNewTokens by setting new tokens and redirecting to same page
@app.exception_handler(NeedsNewTokens)
async def needs_new_tokens_handler(request: Request, exc: NeedsNewTokens):
    response = RedirectResponse(
        url=request.url.path, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response.set_cookie(
        key="access_token",
        value=exc.access_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )
    response.set_cookie(
        key="refresh_token",
        value=exc.refresh_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )
    return response


# Handle PasswordValidationError by rendering the validation_error page
@app.exception_handler(PasswordValidationError)
async def password_validation_exception_handler(request: Request, exc: PasswordValidationError):
    return templates.TemplateResponse(
        "errors/validation_error.html",
        {
            "request": request,
            "status_code": 422,
            "errors": {"error": exc.detail}
        },
        status_code=422,
    )


# Handle RequestValidationError by rendering the validation_error page
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = {}
    for error in exc.errors():
        # Handle different error locations more carefully
        location = error["loc"]

        # Skip type errors for the whole body
        if len(location) == 1 and location[0] == "body":
            continue

        # For form fields, the location might be just (field_name,)
        # For JSON body, it might be (body, field_name)
        field_name = location[-1]  # Take the last item in the location tuple
        errors[field_name] = error["msg"]

    return templates.TemplateResponse(
        "errors/validation_error.html",
        {
            "request": request,
            "status_code": 422,
            "errors": errors
        },
        status_code=422,
    )


# Handle StarletteHTTPException (including 404, 405, etc.) by rendering the error page
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Don't handle redirects
    if exc.status_code in [301, 302, 303, 307, 308]:
        raise exc

    return templates.TemplateResponse(
        "errors/error.html",
        {"request": request, "status_code": exc.status_code, "detail": exc.detail},
        status_code=exc.status_code,
    )


# Add handler for uncaught exceptions (500 Internal Server Error)
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    # Log the error for debugging
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return templates.TemplateResponse(
        "errors/error.html",
        {
            "request": request,
            "status_code": 500,
            "detail": "Internal Server Error"
        },
        status_code=500,
    )


# -- Unauthenticated Routes --


# Define a dependency for common parameters
async def common_unauthenticated_parameters(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    error_message: Optional[str] = None,
) -> dict:
    return {"request": request, "user": user, "error_message": error_message}


@app.get("/")
async def read_home(
    params: dict = Depends(common_unauthenticated_parameters)
):
    if params["user"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("index.html", params)


@app.get("/login")
async def read_login(
    params: dict = Depends(common_unauthenticated_parameters)
):
    if params["user"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("authentication/login.html", params)


@app.get("/register")
async def read_register(
    params: dict = Depends(common_unauthenticated_parameters)
):
    if params["user"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("authentication/register.html", params)


@app.get("/forgot_password")
async def read_forgot_password(
    params: dict = Depends(common_unauthenticated_parameters),
    show_form: Optional[str] = "true",
):
    if params["user"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    params["show_form"] = show_form

    return templates.TemplateResponse("authentication/forgot_password.html", params)


@app.get("/about")
async def read_about(params: dict = Depends(common_unauthenticated_parameters)):
    return templates.TemplateResponse("about.html", params)


@app.get("/privacy_policy")
async def read_privacy_policy(params: dict = Depends(common_unauthenticated_parameters)):
    return templates.TemplateResponse("privacy_policy.html", params)


@app.get("/terms_of_service")
async def read_terms_of_service(params: dict = Depends(common_unauthenticated_parameters)):
    return templates.TemplateResponse("terms_of_service.html", params)


@app.get("/reset_password")
async def read_reset_password(
    email: str,
    token: str,
    params: dict = Depends(common_unauthenticated_parameters),
    session: Session = Depends(get_session)
):
    authorized_user, _ = get_user_from_reset_token(email, token, session)

    # Raise informative error to let user know the token is invalid and may have expired
    if not authorized_user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    params["email"] = email
    params["token"] = token

    return templates.TemplateResponse("authentication/reset_password.html", params)


# -- Authenticated Routes --


# Define a dependency for common parameters
async def common_authenticated_parameters(
    request: Request,
    user: User = Depends(get_authenticated_user),
    error_message: Optional[str] = None,
) -> dict:
    return {"request": request, "user": user, "error_message": error_message}


# Redirect to home if user is not authenticated
@app.get("/dashboard")
async def read_dashboard(
    params: dict = Depends(common_authenticated_parameters)
):
    if not params["user"]:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("dashboard/index.html", params)


@app.get("/profile")
async def read_profile(
    params: dict = Depends(common_authenticated_parameters)
):
    if not params["user"]:
        # Changed to 302
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("users/profile.html", params)


# -- Include Routers --


app.include_router(authentication.router)
app.include_router(organization.router)
app.include_router(role.router)
app.include_router(user.router)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
