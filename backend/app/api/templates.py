import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_user
from app.models.template import Template
from app.schemas.templates import (
    TemplateCreateRequest,
    TemplateUpdateRequest,
    TemplateDeleteRequest,
)
from app.schemas.common import success_response
from app.services.template_service import (
    create_template,
    update_template,
    delete_template,
    get_template_detail,
)

router = APIRouter(
    prefix="/api/templates", tags=["Templates"], dependencies=[Depends(get_current_user)]
)


def _parse_json(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    return value or {}


def _serialize_template(template) -> dict:
    return {
        "id": template.id,
        "name": template.name,
        "template_type": template.template_type,
        "key_usage": _parse_json(template.key_usage),
        "extended_key_usage": _parse_json(template.extended_key_usage),
        "policy": _parse_json(template.policy),
        "is_builtin": template.is_builtin,
        "created_at": template.created_at.isoformat() if template.created_at else None,
        "updated_at": template.updated_at.isoformat() if template.updated_at else None,
    }


@router.get("/list", summary="List templates", description="List built-in and custom templates.")
async def list_templates_endpoint(
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    template_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Template)
    if template_type:
        query = query.filter(Template.template_type == template_type)

    total = query.count()
    templates = query.offset((page - 1) * per_page).limit(per_page).all()

    return success_response(
        "Templates retrieved",
        {
            "templates": [_serialize_template(t) for t in templates],
            "total": total,
            "page": page,
            "per_page": per_page,
        },
    ).model_dump()


@router.post(
    "/create", summary="Create template", description="Create a custom certificate template."
)
async def create_template_endpoint(
    request: TemplateCreateRequest,
    db: Session = Depends(get_db),
):
    try:
        template = create_template(
            db,
            request.name,
            request.template_type or "leaf",
            request.key_usage,
            request.extended_key_usage,
            request.policy,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return success_response("Template created", {"template_id": template.id}).model_dump()


@router.get("/detail", summary="Get template details", description="Fetch template details by ID.")
async def get_template_detail_endpoint(
    template_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
):
    template = get_template_detail(db, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    return success_response(
        "Template details retrieved", _serialize_template(template)
    ).model_dump()


@router.post("/update", summary="Update template", description="Update a custom template by ID.")
async def update_template_endpoint(
    request: TemplateUpdateRequest,
    db: Session = Depends(get_db),
):
    try:
        template = update_template(
            db,
            request.template_id,
            request.name,
            request.template_type,
            request.key_usage,
            request.extended_key_usage,
            request.policy,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return success_response("Template updated", {"template_id": template.id}).model_dump()


@router.post("/delete", summary="Delete template", description="Delete a custom template by ID.")
async def delete_template_endpoint(
    request: TemplateDeleteRequest,
    db: Session = Depends(get_db),
):
    try:
        delete_template(db, request.template_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return success_response("Template deleted", {"template_id": request.template_id}).model_dump()
