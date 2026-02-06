import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_user
from app.schemas.certificates import (
    CertificateSignRequest,
    CertificateImportRequest,
    CertificateListResponse,
    CertificateExportRequest,
    CertificateChainResponse,
    CertificateDeleteRequest,
    CertificateRevokeRequest,
)
from app.schemas.common import success_response
from app.services.cert_service import (
    sign_certificate,
    import_certificate as import_cert_service,
    list_certificates,
    revoke_certificate,
    export_certificate as export_cert_service,
    get_certificate_chain,
    get_certificate_tree,
    delete_certificate as delete_cert_service,
)
from app.models.certificate import Certificate

router = APIRouter(
    prefix="/api/certificates", tags=["Certificates"], dependencies=[Depends(get_current_user)]
)


def _serialize_certificate(cert: Certificate) -> dict:
    meta_data = cert.meta_data
    if isinstance(meta_data, str):
        try:
            meta_data = json.loads(meta_data)
        except json.JSONDecodeError:
            meta_data = {}

    return {
        "id": cert.id,
        "type": cert.type.value if hasattr(cert.type, "value") else cert.type,
        "parent_id": cert.parent_id,
        "key_id": cert.key_id,
        "serial_number": cert.serial_number,
        "subject_cn": cert.subject_cn,
        "not_before": cert.not_before.isoformat() if cert.not_before else None,
        "not_after": cert.not_after.isoformat() if cert.not_after else None,
        "status": cert.status.value if hasattr(cert.status, "value") else cert.status,
        "meta_data": meta_data,
        "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
        "created_at": cert.created_at.isoformat() if cert.created_at else None,
        "updated_at": cert.updated_at.isoformat() if cert.updated_at else None,
    }


@router.get(
    "/list",
    summary="List certificates",
    description="List certificates with pagination and filters (type/status/parent/search).",
)
async def list_certificates_endpoint(
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    cert_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    parent_id: Optional[int] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query(
        "created_at",
        pattern="^(created_at|not_after|subject_cn)$",
        description="Sort field",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    db: Session = Depends(get_db),
):
    result = list_certificates(
        db,
        page,
        per_page,
        cert_type,
        status,
        parent_id,
        search,
        sort_by,
        sort_order,
    )
    return success_response(
        "Certificates retrieved",
        {
            "certificates": [_serialize_certificate(c) for c in result["certificates"]],
            "total": result["total"],
            "page": result["page"],
            "per_page": result["per_page"],
        },
    ).model_dump()


@router.post(
    "/sign",
    summary="Sign certificate",
    description="Create and sign a root/intermediate/leaf certificate or sign from CSR.",
)
async def sign_certificate_endpoint(request: CertificateSignRequest, db: Session = Depends(get_db)):
    try:
        certificate = sign_certificate(
            db,
            request.issuer_id,
            request.subject,
            request.key_config,
            request.validity_days,
            request.extensions,
            request.csr_pem,
            request.is_ca,
            request.key_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return success_response(
        "Certificate signed",
        {"certificate_id": certificate.id, "serial_number": certificate.serial_number},
    ).model_dump()


@router.post(
    "/import",
    summary="Import certificate",
    description="Import a certificate and optional key into LightCA.",
)
async def import_cert_service_endpoint(
    request: CertificateImportRequest, db: Session = Depends(get_db)
):
    try:
        certificate = import_cert_service(
            db, request.cert_pem, request.key_pem, request.key_password, request.remember_password
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return success_response("Certificate imported", {"certificate_id": certificate.id}).model_dump()


@router.get(
    "/detail",
    summary="Get certificate details",
    description="Fetch certificate details and parsed metadata by certificate ID.",
)
async def get_certificate_detail(
    certificate_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
):
    cert = (
        db.query(Certificate)
        .filter(Certificate.id == certificate_id, Certificate.is_deleted == False)
        .first()
    )
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    return success_response(
        "Certificate details retrieved", _serialize_certificate(cert)
    ).model_dump()


@router.post(
    "/delete",
    summary="Delete certificate",
    description="Soft-delete a certificate and optionally delete the attached key.",
)
async def delete_certificate_endpoint(
    request: CertificateDeleteRequest, db: Session = Depends(get_db)
):
    try:
        delete_cert_service(db, request.certificate_id, request.delete_key)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return success_response(
        "Certificate deleted", {"certificate_id": request.certificate_id}
    ).model_dump()


@router.post(
    "/revoke",
    summary="Revoke certificate",
    description="Revoke a certificate and persist revocation metadata.",
)
async def revoke_certificate_endpoint(
    request: CertificateRevokeRequest, db: Session = Depends(get_db)
):
    try:
        revoke_certificate(db, request.certificate_id, request.reason, request.issuer_password)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return success_response(
        "Certificate revoked", {"certificate_id": request.certificate_id}
    ).model_dump()


@router.get(
    "/export",
    summary="Export certificate",
    description="Export certificate content in PEM/DER/P12/bundle variants.",
)
async def export_certificate_endpoint(
    certificate_id: int = Query(..., ge=1),
    format: str = Query(
        "pem",
        pattern="^(pem|der|p12|pem-chain|pem-bundle)$",
        description="Export format",
        examples=["pem", "der", "p12", "pem-chain", "pem-bundle"],
    ),
    password: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    try:
        content, filename, content_type = export_cert_service(db, certificate_id, format, password)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get(
    "/chain",
    summary="Get certificate chain",
    description="Return trust chain from the certificate up to root.",
)
async def get_certificate_chain_endpoint(
    certificate_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
):
    try:
        chain = get_certificate_chain(db, certificate_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return success_response(
        "Certificate chain retrieved", {"chain": [_serialize_certificate(c) for c in chain]}
    ).model_dump()


@router.get(
    "/tree",
    summary="Get certificate tree",
    description="Return nested CA/certificate topology for UI tree rendering.",
)
async def get_certificate_tree_endpoint(db: Session = Depends(get_db)):
    tree = get_certificate_tree(db)
    return success_response("Certificate tree retrieved", {"tree": tree}).model_dump()
