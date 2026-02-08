import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_user
from app.schemas.keys import (
    KeyCreateRequest,
    KeyImportRequest,
    KeyDeleteRequest,
)
from app.schemas.common import success_response
from app.services.key_service import (
    generate_key,
    import_key,
    list_keys,
    get_key_detail,
    delete_key,
    export_key,
)
from app.models.key import Key

router = APIRouter(prefix="/api/keys", tags=["Keys"], dependencies=[Depends(get_current_user)])


def _serialize_key(key: Key) -> dict:
    meta_data = key.meta_data
    if isinstance(meta_data, str):
        try:
            meta_data = json.loads(meta_data)
        except json.JSONDecodeError:
            meta_data = {}

    return {
        "id": key.id,
        "algorithm": key.algorithm,
        "fingerprint": key.fingerprint,
        "is_protected": key.is_protected,
        "meta_data": meta_data,
        "created_at": key.created_at.isoformat() if key.created_at else None,
    }


@router.get(
    "/list",
    summary="List keys",
    description="List stored private keys with pagination and optional algorithm filter.",
)
async def list_keys_endpoint(
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    algorithm: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    result = list_keys(db, page, per_page, algorithm)
    return success_response(
        "Keys retrieved",
        {
            "keys": [_serialize_key(k) for k in result["keys"]],
            "total": result["total"],
            "page": result["page"],
            "per_page": result["per_page"],
        },
    ).model_dump()


@router.post(
    "/create",
    summary="Generate key",
    description="Generate a new RSA, ECDSA, or EdDSA private key.",
)
async def create_key(request: KeyCreateRequest, db: Session = Depends(get_db)):
    key_size = request.key_size
    if request.algorithm.value == "EdDSA":
        if request.curve == "Ed448":
            key_size = 448
        else:
            key_size = 256

    key = generate_key(
        db,
        request.algorithm,
        key_size,
        request.curve,
        request.password,
        request.remember_password,
    )
    return success_response(
        "Key generated", {"key_id": key.id, "fingerprint": key.fingerprint}
    ).model_dump()


@router.post(
    "/import",
    summary="Import key",
    description="Import an existing PEM private key and store it encrypted.",
)
async def import_key_endpoint(request: KeyImportRequest, db: Session = Depends(get_db)):
    key = import_key(db, request.key_pem, request.password, request.remember_password)
    return success_response(
        "Key imported", {"key_id": key.id, "fingerprint": key.fingerprint}
    ).model_dump()


@router.get(
    "/detail",
    summary="Get key details",
    description="Fetch metadata for a key by ID.",
)
async def get_key(
    key_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
):
    key = get_key_detail(db, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    return success_response("Key details retrieved", _serialize_key(key)).model_dump()


@router.post(
    "/delete",
    summary="Delete key",
    description="Soft-delete a key by ID.",
)
async def delete_key_endpoint(request: KeyDeleteRequest, db: Session = Depends(get_db)):
    try:
        delete_key(db, request.key_id)
    except ValueError as exc:
        cert_id = getattr(exc, "certificate_id", None)
        cert_subject_cn = getattr(exc, "subject_cn", None)
        if cert_id is None:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        detail = f"该密钥已关联证书 #{cert_id}，请先删除证书后再删除密钥" + (
            f"（CN: {cert_subject_cn}）" if cert_subject_cn else ""
        )
        return JSONResponse(
            status_code=409,
            content={
                "success": False,
                "message": detail,
                "data": {
                    "certificate_id": cert_id,
                    "certificate_subject_cn": cert_subject_cn,
                    "certificate_detail_url": f"/certificates/detail?certificate_id={cert_id}",
                },
                "error": {
                    "code": "KEY_IN_USE",
                    "detail": detail,
                },
            },
        )
    return success_response("Key deleted", {"key_id": request.key_id}).model_dump()


@router.get(
    "/export",
    summary="Export key",
    description="Export a key in PEM, PKCS#8, or PKCS#12 format.",
)
async def export_key_endpoint(
    key_id: int = Query(..., ge=1),
    format: str = Query(
        "pem",
        pattern="^(pem|pkcs8|pkcs12)$",
        description="Export format",
        examples=["pem", "pkcs8", "pkcs12"],
    ),
    password: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    try:
        content, filename, content_type = export_key(db, key_id, format, password)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
