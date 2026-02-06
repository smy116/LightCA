from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models.certificate import Certificate, CertificateStatus
from app.models.certificate import CertificateType
from app.models.crl import CRL
from app.models.key import Key
from app.models.template import Template
from app.schemas.common import success_response

router = APIRouter(
    prefix="/api/stats", tags=["Statistics"], dependencies=[Depends(get_current_user)]
)


@router.get(
    "",
    summary="Get dashboard statistics",
    description="Return certificate/key/template/CRL counters.",
)
async def get_stats(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expiring_date = now + timedelta(days=30)

    certificates_total = db.query(Certificate).filter(Certificate.is_deleted == False).count()
    certificates_ca_total = (
        db.query(Certificate)
        .filter(
            Certificate.is_deleted == False,
            Certificate.type.in_([CertificateType.ROOT, CertificateType.INTERMEDIATE]),
        )
        .count()
    )
    certificates_valid = (
        db.query(Certificate)
        .filter(Certificate.is_deleted == False, Certificate.status == CertificateStatus.VALID)
        .count()
    )
    certificates_revoked = (
        db.query(Certificate)
        .filter(Certificate.is_deleted == False, Certificate.status == CertificateStatus.REVOKED)
        .count()
    )
    certificates_expiring = (
        db.query(Certificate)
        .filter(
            Certificate.is_deleted == False,
            Certificate.status == CertificateStatus.VALID,
            Certificate.not_after > now,
            Certificate.not_after <= expiring_date,
        )
        .count()
    )

    keys_total = db.query(Key).filter(Key.is_deleted == False).count()
    templates_total = db.query(Template).count()
    crls_total = db.query(CRL).count()

    return success_response(
        "Statistics retrieved",
        {
            "certificates": {
                "total": certificates_total,
                "ca_total": certificates_ca_total,
                "valid": certificates_valid,
                "revoked": certificates_revoked,
                "expiring": certificates_expiring,
            },
            "keys": {"total": keys_total},
            "templates": {"total": templates_total},
            "crls": {"total": crls_total},
        },
    ).model_dump()
