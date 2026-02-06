from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_user
from app.schemas.crl import CRLGenerateRequest
from app.schemas.common import success_response
from app.models.crl import CRL
from app.services.crl_service import (
    generate_crl_for_ca,
    download_crl_by_id,
    get_revocations_by_crl_id,
    list_crls,
)

router = APIRouter(prefix="/api/crl", tags=["CRL"], dependencies=[Depends(get_current_user)])


@router.get("/list", summary="List CRLs", description="List CRL records with optional CA filter.")
async def list_crls_endpoint(
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    ca_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    result = list_crls(db, page, per_page, ca_id)
    return success_response(
        "CRLs retrieved",
        {
            "crls": [
                {
                    "id": c.id,
                    "ca_id": c.ca_id,
                    "crl_number": c.crl_number,
                    "generated_at": c.generated_at.isoformat() if c.generated_at else None,
                }
                for c in result["crls"]
            ],
            "total": result["total"],
            "page": result["page"],
            "per_page": result["per_page"],
        },
    ).model_dump()


@router.post(
    "/generate", summary="Generate CRL", description="Generate a CRL for a CA certificate."
)
async def generate_crl_endpoint(request: CRLGenerateRequest, db: Session = Depends(get_db)):
    try:
        crl = generate_crl_for_ca(db, request.ca_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return success_response(
        "CRL generated", {"crl_id": crl.id, "crl_number": crl.crl_number}
    ).model_dump()


@router.get("/download", summary="Download CRL", description="Download a CRL file by CRL ID.")
async def download_crl_endpoint(
    crl_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
):
    try:
        crl_der = download_crl_by_id(db, crl_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return Response(
        content=crl_der,
        media_type="application/x-pkcs7-crl",
        headers={"Content-Disposition": f"attachment; filename=crl_{crl_id}.crl"},
    )


@router.get(
    "/revocations", summary="List revocations", description="List revoked certificates for a CRL."
)
async def get_revocations_endpoint(
    crl_id: int = Query(..., ge=1),
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
):
    try:
        result = get_revocations_by_crl_id(db, crl_id, page, per_page)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return success_response("Revocations retrieved", result).model_dump()
