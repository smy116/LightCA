from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sqlalchemy.orm import Session

from app.models.template import Template
from app.schemas.templates import TemplateCreateRequest, TemplateUpdateRequest


def create_template(
    db: Session,
    name: str,
    template_type: str,
    key_usage: Dict[str, Any],
    extended_key_usage: Dict[str, Any],
    policy: Dict[str, Any],
    is_builtin: bool = False,
) -> Template:
    import json

    template = Template(
        name=name,
        template_type=template_type,
        key_usage=json.dumps(key_usage),
        extended_key_usage=json.dumps(extended_key_usage),
        policy=json.dumps(policy),
        is_builtin=is_builtin,
    )

    db.add(template)
    db.commit()
    db.refresh(template)

    return template


def update_template(
    db: Session,
    template_id: int,
    name: Optional[str] = None,
    template_type: Optional[str] = None,
    key_usage: Optional[Dict[str, Any]] = None,
    extended_key_usage: Optional[Dict[str, Any]] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> Template:
    import json

    template = db.query(Template).filter(Template.id == template_id).first()
    if not template:
        raise ValueError("Template not found")

    if name:
        template.name = name
    if template_type:
        template.template_type = template_type
    if key_usage:
        template.key_usage = json.dumps(key_usage)
    if extended_key_usage:
        template.extended_key_usage = json.dumps(extended_key_usage)
    if policy:
        template.policy = json.dumps(policy)

    template.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(template)

    return template


def delete_template(db: Session, template_id: int) -> None:
    template = db.query(Template).filter(Template.id == template_id).first()
    if not template:
        raise ValueError("Template not found")

    db.delete(template)
    db.commit()


def list_templates(
    db: Session,
    page: int = 1,
    per_page: int = 10,
    template_type: Optional[str] = None,
) -> Dict[str, Any]:
    query = db.query(Template).filter(Template.is_builtin == False)

    if template_type:
        query = query.filter(Template.template_type == template_type)

    total = query.count()
    templates = query.offset((page - 1) * per_page).limit(per_page).all()

    return {
        "templates": templates,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


def get_template_detail(db: Session, template_id: int) -> Optional[Template]:
    return db.query(Template).filter(Template.id == template_id).first()


def get_builtin_templates(db: Session) -> list:
    return []


def apply_template(
    db: Session, template_id: int, overrides: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Apply a template, with optional overrides"""
    import json

    template = get_template_detail(db, template_id)
    if not template:
        raise ValueError("Template not found")

    result = {
        "key_usage": json.loads(template.key_usage),
        "extended_key_usage": json.loads(template.extended_key_usage),
        "policy": json.loads(template.policy),
    }

    if overrides:
        if "key_usage" in overrides:
            result["key_usage"].update(overrides["key_usage"])
        if "extended_key_usage" in overrides:
            result["extended_key_usage"].update(overrides["extended_key_usage"])
        if "policy" in overrides:
            result["policy"].update(overrides["policy"])

    return result
