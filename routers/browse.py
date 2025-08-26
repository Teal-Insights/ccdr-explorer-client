from logging import getLogger
from fastapi import APIRouter, Depends, Request, Query, Form
from typing import Optional
from sqlmodel import Session, select
from sqlalchemy.orm import selectinload
from fastapi.templating import Jinja2Templates
from utils.core.dependencies import get_authenticated_user, get_session
from utils.core.models import User
from utils.chat.models import Publication, Document
from fastapi.responses import HTMLResponse


logger = getLogger("uvicorn.error")

router: APIRouter = APIRouter(prefix="/browse", tags=["browse"])

# Jinja2 templates
templates = Jinja2Templates(directory="templates")

# TODO: Separate this into two routes and return HTMX partial responses
@router.get("/")
async def read_browse_index(
    request: Request,
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    available_publications = session.exec(
        select(Publication)
    ).all()
    return templates.TemplateResponse(
        "browse/index.html",
        {
            "request": request,
            "user": user,
            "available_publications": available_publications,
            "selected_document": None,
        },
    )


@router.get("/document")
async def read_browse(
    request: Request,
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
    document_id: int = Query(..., description="The ID of the document to browse"),
) -> HTMLResponse:
    available_publications = session.exec(
        select(Publication).options(selectinload(Publication.documents))
    ).all()
    selected_document: Document = session.get(Document, document_id)
    document_html: str = selected_document.to_html(include_citation_data=True) if selected_document else None
    logger.info(f"Document HTML (first 500 chars): {document_html[:500] if document_html else 'None'}")
    if not document_html:
        document_html = '<p>Document not found</p>'
    return templates.TemplateResponse(
        "browse/index.html",
        {
            "request": request,
            "user": user,
            "available_publications": available_publications,
            "selected_document": selected_document,
            "document_html": document_html
        }
    )


@router.post("/documents")
async def get_documents_for_publication(
    request: Request,
    publication_id: Optional[int] = Form(None, description="ID of the publication"),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """HTMX endpoint to get documents for a selected publication"""
    if publication_id is None:
        # Return default empty state if no publication selected
        return HTMLResponse('<option value="">Select publication first...</option>')
    
    # Load documents for this publication
    publication_with_docs = session.exec(
        select(Publication)
        .options(selectinload(Publication.documents))
        .where(Publication.id == publication_id)
    ).first()
    
    if not publication_with_docs:
        return HTMLResponse('<option value="">No documents found</option>')
    
    return templates.TemplateResponse(
        "browse/document_options.html",
        {
            "request": request,
            "documents": publication_with_docs.documents,
        }
    )