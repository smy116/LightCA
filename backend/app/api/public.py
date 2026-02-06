from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.certificate import Certificate, CertificateType

router = APIRouter(prefix="/public", tags=["Public"])


@router.get("/health", summary="Health check", description="Public health probe endpoint.")
async def health_check():
    return {"status": "healthy"}


@router.get(
    "/crl/{ca_id}.crl", summary="Download public CRL", description="Public CRL download by CA ID."
)
async def download_crl(ca_id: int, db: Session = Depends(get_db)) -> Response:
    ca = (
        db.query(Certificate)
        .filter(
            Certificate.id == ca_id,
            Certificate.is_deleted == False,
            Certificate.type == CertificateType.ROOT,
        )
        .first()
    )
    if not ca:
        raise HTTPException(status_code=404, detail="CA not found")

    crl = ca.crls[-1] if ca.crls else None
    if not crl:
        raise HTTPException(status_code=404, detail="CRL not found")

    return Response(
        content=crl.crl_der,
        media_type="application/x-pkcs7-crl",
        headers={"Content-Disposition": f"attachment; filename=ca_{ca_id}.crl"},
    )


@router.get(
    "/ca/{ca_id}.crt",
    summary="Download CA certificate",
    description="Public CA certificate download by CA ID.",
)
async def download_ca_cert(ca_id: int, db: Session = Depends(get_db)) -> Response:
    ca = (
        db.query(Certificate)
        .filter(
            Certificate.id == ca_id,
            Certificate.is_deleted == False,
            Certificate.type == CertificateType.ROOT,
        )
        .first()
    )
    if not ca:
        raise HTTPException(status_code=404, detail="CA not found")

    return Response(
        content=ca.certificate_der,
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": f"attachment; filename=ca_{ca_id}.crt"},
    )
