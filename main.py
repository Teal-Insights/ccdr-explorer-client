import logging
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import SQLModel, create_engine
from fastapi.exceptions import RequestValidationError, StarletteHTTPException
from routers import auth, organization, score, template, version
from utils import get_current_user, get_connection_url
from models import User


logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    engine = create_engine(get_connection_url())
    SQLModel.metadata.create_all(engine)
    engine.dispose()
    yield
    # Shutdown logic


app = FastAPI(lifespan=lifespan)

# Mount static files (e.g., CSS, JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return templates.TemplateResponse(
        "errors/error.html",
        {"request": request, "status_code": exc.status_code, "detail": exc.detail},
        status_code=exc.status_code,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return templates.TemplateResponse(
        "errors/error.html",
        {"request": request, "status_code": 422, "detail": str(exc)},
        status_code=422,
    )


@app.get("/")
async def read_home(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        "index.html", {"request": request, "user": user, "error_message": error_message}
    )


@app.get("/login")
async def read_login(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        "authentication/login.html",
        {"request": request, "user": user, "error_message": error_message},
    )


@app.get("/register")
async def read_register(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        "authentication/register.html",
        {"request": request, "user": user, "error_message": error_message},
    )


@app.get("/forgot_password")
async def read_forgot_password(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        "authentication/forgot_password.html",
        {"request": request, "user": user, "error_message": error_message},
    )


@app.get("/reset_password")
async def read_reset_password(
    request: Request,
    token: str,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    # TODO: Validate the token here?
    return templates.TemplateResponse(
        "authentication/reset_password.html",
        {
            "request": request,
            "token": token,
            "user": user,
            "error_message": error_message,
        },
    )


@app.get("/dashboard")
async def read_dashboard(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    if not user:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        "dashboard/index.html",
        {"request": request, "user": user, "error_message": error_message},
    )


@app.get("/user_profile")
async def read_user_profile(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    if not user:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        "user_profile/index.html",
        {"request": request, "user": user, "error_message": error_message},
    )


@app.get("/about")
async def read_about(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    return templates.TemplateResponse(
        "about.html", {"request": request, "user": user, "error_message": error_message}
    )


@app.get("/privacy_policy")
async def read_privacy_policy(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    return templates.TemplateResponse(
        "privacy_policy.html",
        {"request": request, "user": user, "error_message": error_message},
    )


@app.get("/terms_of_service")
async def read_terms_of_service(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    error_message: Optional[str] = None,
):
    return templates.TemplateResponse(
        "terms_of_service.html",
        {"request": request, "user": user, "error_message": error_message},
    )


app.include_router(auth.router)
app.include_router(organization.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
