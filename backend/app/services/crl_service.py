from datetime import datetime, timezone
from typing import Optional
import json

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from sqlalchemy.orm import Session

from app.models.certificate import Certificate, CertificateStatus, CertificateType
from app.models.key import Key
from app.models.crl import CRL
from app.security import decrypt_private_key, decrypt_key_password
from app.services.crypto_service import generate_crl
from app.services.key_service import get_key_detail


def generate_crl_for_ca(db: Session, ca_id: int) -> CRL:
    from cryptography import x509

    ca = (
        db.query(Certificate)
        .filter(
            Certificate.id == ca_id,
            Certificate.is_deleted == False,
        )
        .first()
    )
    if not ca:
        raise ValueError("CA not found")

    if ca.type not in [CertificateType.ROOT, CertificateType.INTERMEDIATE]:
        raise ValueError("Must be a CA certificate")

    # Get revoked certificates for this CA
    revoked = (
        db.query(Certificate)
        .filter(
            Certificate.status == CertificateStatus.REVOKED,
            Certificate.is_deleted == False,
        )
        .all()
    )

    # Filter to only certificates issued by this CA or its sub-CAs
    def is_issued_by_ca(cert_id: int) -> bool:
        cert = (
            db.query(Certificate)
            .filter(
                Certificate.id == cert_id,
                Certificate.is_deleted == False,
            )
            .first()
        )
        if not cert:
            return False

        while cert.parent_id:
            if cert.parent_id == ca_id:
                return True
            cert = (
                db.query(Certificate)
                .filter(
                    Certificate.id == cert.parent_id,
                    Certificate.is_deleted == False,
                )
                .first()
            )
            if not cert:
                return False

        return False

    revoked_certs = [c for c in revoked if is_issued_by_ca(c.id)]
    revoked_cert_payload = [
        {
            "certificate_der": cert.certificate_der,
            "reason": "unspecified",
        }
        for cert in revoked_certs
    ]

    # Get CA key
    if not ca.key_id:
        raise ValueError("CA has no key")

    key = get_key_detail(db, ca.key_id)
    if not key:
        raise ValueError("Key not found")

    private_key_pem = decrypt_private_key(key.encrypted_pem)
    private_key = load_pem_private_key(private_key_pem.encode(), password=None)

    # Generate CRL
    ca_cert = x509.load_der_x509_certificate(ca.certificate_der)
    crl_number = len(db.query(CRL).filter(CRL.ca_id == ca_id).all()) + 1

    crl_der = generate_crl(ca_cert, private_key, revoked_cert_payload, crl_number)

    crl = CRL(
        ca_id=ca_id,
        crl_number=crl_number,
        crl_der=crl_der,
        generated_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )

    db.add(crl)
    db.commit()
    db.refresh(crl)

    return crl


def download_crl(db: Session, ca_id: int) -> bytes:
    crl = db.query(CRL).filter(CRL.ca_id == ca_id).order_by(CRL.generated_at.desc()).first()
    if not crl:
        raise ValueError("No CRL found for this CA")

    return crl.crl_der


def download_crl_by_id(db: Session, crl_id: int) -> bytes:
    crl = db.query(CRL).filter(CRL.id == crl_id).first()
    if not crl:
        raise ValueError("CRL not found")
    return crl.crl_der


def get_revocations(db: Session, ca_id: int, page: int = 1, per_page: int = 10) -> dict:
    crl = db.query(CRL).filter(CRL.ca_id == ca_id).order_by(CRL.generated_at.desc()).first()
    if not crl:
        return {"revocations": [], "total": 0}

    revoked = (
        db.query(Certificate)
        .filter(
            Certificate.status == CertificateStatus.REVOKED,
            Certificate.is_deleted == False,
        )
        .all()
    )

    revocations = []
    for cert in revoked:
        meta_data = cert.meta_data
        if isinstance(meta_data, str):
            try:
                meta_data = json.loads(meta_data)
            except json.JSONDecodeError:
                meta_data = {}

        if cert.parent_id == ca_id:
            revocations.append(
                {
                    "certificate_id": cert.id,
                    "serial_number": cert.serial_number,
                    "subject_cn": cert.subject_cn,
                    "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
                    "reason": meta_data.get("revocation_reason", "unspecified"),
                }
            )

    return {
        "revocations": revocations[(page - 1) * per_page : page * per_page],
        "total": len(revocations),
    }


def get_revocations_by_crl_id(db: Session, crl_id: int, page: int = 1, per_page: int = 10) -> dict:
    crl = db.query(CRL).filter(CRL.id == crl_id).first()
    if not crl:
        raise ValueError("CRL not found")
    return get_revocations(db, crl.ca_id, page, per_page)


def list_crls(db: Session, page: int = 1, per_page: int = 10, ca_id: Optional[int] = None) -> dict:
    query = db.query(CRL)

    if ca_id:
        query = query.filter(CRL.ca_id == ca_id)

    total = query.count()
    crls = query.offset((page - 1) * per_page).limit(per_page).all()

    return {
        "crls": crls,
        "total": total,
        "page": page,
        "per_page": per_page,
    }
