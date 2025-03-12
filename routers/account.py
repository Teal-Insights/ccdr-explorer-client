from fastapi import APIRouter, Depends, Form
from fastapi.responses import RedirectResponse
from sqlmodel import Session
from utils.models import User, AccountBase, DataIntegrityError
from utils.auth import get_session, get_authenticated_user, verify_password, PasswordValidationError, get_password_hash

router = APIRouter(prefix="/account", tags=["account"])

class DeleteAccount(AccountBase):
    @classmethod
    async def as_form(
        cls,
        email: str = Form(...),
        password: str = Form(...),
    ):
        hashed_password = get_password_hash(password)

        return cls(email=email, hashed_password=hashed_password)


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