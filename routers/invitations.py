from uuid import uuid4
from fastapi import APIRouter, Depends, Form
from fastapi.responses import RedirectResponse
from fastapi.exceptions import HTTPException
from pydantic import EmailStr
from sqlmodel import Session, select
from logging import getLogger

from utils.dependencies import get_authenticated_user
from utils.db import get_session
from utils.models import User, Role, Account, Invitation, ValidPermissions, Organization
from utils.invitations import send_invitation_email
from exceptions.http_exceptions import (
    UserIsAlreadyMemberError,
    ActiveInvitationExistsError,
    InvalidRoleForOrganizationError,
    OrganizationNotFoundError,
    InvitationEmailSendError,
)
from exceptions.exceptions import EmailSendFailedError

# Setup logger
logger = getLogger("uvicorn.error")

router = APIRouter(
    prefix="/invitations",
    tags=["invitations"],
)


@router.post("/", name="create_invitation")
async def create_invitation(
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
    invitee_email: EmailStr = Form(...),
    role_id: int = Form(...),
    organization_id: int = Form(...),
):
    # Fetch the organization
    organization = session.get(Organization, organization_id)
    if not organization:
        raise OrganizationNotFoundError()
    
    # Check if the current user has permission to invite users to this organization
    if not current_user.has_permission(ValidPermissions.INVITE_USER, organization):
        raise HTTPException(status_code=403, detail="You don't have permission to invite users to this organization")
    
    # Verify the role exists and belongs to this organization
    role = session.get(Role, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.organization_id != organization_id:
        raise InvalidRoleForOrganizationError()
    
    # Check if invitee is already a member of the organization
    existing_account = session.exec(select(Account).where(Account.email == invitee_email)).first()
    if existing_account:
        # Check if any user with this account is already a member
        existing_user = session.exec(select(User).where(User.account_id == existing_account.id)).first()
        if existing_user:
            # Check if user has any role in this organization
            if any(role.organization_id == organization_id for role in existing_user.roles):
                raise UserIsAlreadyMemberError()
    
    # Check for active invitations with the same email
    active_invitations = Invitation.get_active_for_org(session, organization_id)
    if any(invitation.invitee_email == invitee_email for invitation in active_invitations):
        raise ActiveInvitationExistsError()
    
    # Create the invitation
    token = str(uuid4())
    invitation = Invitation(
        organization_id=organization_id,
        role_id=role_id,
        invitee_email=invitee_email,
        token=token,
    )
    
    session.add(invitation)

    try:
        # Refresh to ensure relationships are loaded *before* sending email
        session.flush() # Ensure invitation gets an ID if needed by email sender, flush changes
        session.refresh(invitation)
        # Ensure organization is loaded before passing to email function
        # (May already be loaded, but explicit refresh is safer)
        if not invitation.organization:
            session.refresh(organization) # Refresh the org object fetched earlier
            invitation.organization = organization # Assign if needed

        # Send email synchronously BEFORE committing
        send_invitation_email(invitation, session)

        # Commit *only* if email sending was successful
        session.commit()
        session.refresh(invitation) # Refresh again after commit if needed elsewhere

    except EmailSendFailedError as e:
        logger.error(f"Invitation email failed for {invitee_email} in org {organization_id}: {e}")
        session.rollback() # Rollback the invitation creation
        raise InvitationEmailSendError() # Raise HTTP 500
    except Exception as e:
        # Catch any other unexpected errors during flush/refresh/email/commit
        logger.error(
            f"Unexpected error during invitation creation/sending for {invitee_email} "
            f"in org {organization_id}: {e}",
            exc_info=True
        )
        session.rollback()
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")

    # Redirect back to organization page (PRG pattern)
    return RedirectResponse(url=f"/organizations/{organization_id}", status_code=303)
