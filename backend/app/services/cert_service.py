import json
from datetime import datetime, timezone

from typing import Optional, Dict, Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12PrivateKeyTypes
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.certificate import Certificate, CertificateType, CertificateStatus
from app.models.key import Key, KeyAlgorithm
from app.models.crl import CRL
from app.security import decrypt_private_key, decrypt_key_password
from app.services.key_service import generate_key
from app.services.crypto_service import (
    create_ca_certificate,
    create_leaf_certificate,
    parse_certificate,
    generate_crl,
)


def sign_certificate(
    db: Session,
    issuer_id: int,
    subject: Optional[Dict[str, str]],
    key_config: Optional[Dict[str, Any]] = None,
    validity_days: int = 365,
    extensions: Optional[Dict[str, Any]] = None,
    csr_pem: Optional[str] = None,
    is_ca: bool = False,
    key_id: Optional[int] = None,
) -> Certificate:
    subject_data = subject or {"CN": "Unnamed"}

    if key_id is None and key_config and not csr_pem:
        algorithm_name = str(key_config.get("algorithm") or "RSA")
        try:
            algorithm = KeyAlgorithm(algorithm_name)
        except ValueError as exc:
            raise ValueError(f"Unsupported key algorithm: {algorithm_name}") from exc

        curve = key_config.get("curve")
        key_size = key_config.get("key_size")
        if algorithm == KeyAlgorithm.EdDSA:
            key_size = 448 if curve == "Ed448" else 256

        generated_key = generate_key(
            db,
            algorithm,
            key_size,
            curve,
            key_config.get("password"),
            bool(key_config.get("remember_password", False)),
        )
        key_id = generated_key.id

    # Handle self-signed root CA case
    if issuer_id == 0 or issuer_id is None:
        if not key_id:
            raise ValueError("key_id is required for self-signed certificate")

        # Get the key for self-signed root CA
        signing_key = db.query(Key).filter(Key.id == key_id).first()
        if not signing_key:
            raise ValueError("Key not found")

        password = None
        if signing_key.is_protected and signing_key.encrypted_password:
            password = decrypt_key_password(signing_key.encrypted_password)
        elif signing_key.is_protected:
            raise ValueError("Signing key password is required but not remembered")

        private_key_pem = decrypt_private_key(signing_key.encrypted_pem, password)

        # Load the private key from PEM
        private_key = load_pem_private_key(
            private_key_pem.encode(),
            password=None,
        )

        if is_ca:
            cert_der = create_ca_certificate(
                private_key,
                private_key.public_key(),
                subject_data,
                validity_days,
                extensions,
                private_key,
                None,
            )
            cert_type = CertificateType.ROOT
        else:
            cert_der = create_leaf_certificate(
                private_key,
                private_key.public_key(),
                None,
                subject_data,
                validity_days,
                extensions,
                None,
            )
            cert_type = CertificateType.LEAF
        parent_id = None
        key_id_used = signing_key.id
    else:
        # Normal certificate signing with issuer
        issuer = (
            db.query(Certificate)
            .filter(
                Certificate.id == issuer_id,
                Certificate.is_deleted == False,
                Certificate.status == CertificateStatus.VALID,
            )
            .first()
        )
        if not issuer:
            raise ValueError("Issuer not found or invalid")

        if (
            not issuer.type == CertificateType.ROOT
            and not issuer.type == CertificateType.INTERMEDIATE
        ):
            raise ValueError("Issuer must be a CA certificate")

        # Get issuer signing key
        issuer_key = db.query(Key).filter(Key.id == issuer.key_id).first()
        if not issuer_key:
            raise ValueError("Issuer key not found")

        issuer_password = None
        if issuer_key.is_protected and issuer_key.encrypted_password:
            issuer_password = decrypt_key_password(issuer_key.encrypted_password)
        elif issuer_key.is_protected:
            raise ValueError("Issuer key password is required but not remembered")

        issuer_private_key_pem = decrypt_private_key(issuer_key.encrypted_pem, issuer_password)

        issuer_private_key = load_pem_private_key(
            issuer_private_key_pem.encode(),
            password=None,
        )

        issuer_cert = x509.load_der_x509_certificate(issuer.certificate_der)

        key_id_used = key_id
        subject_private_key = None
        subject_public_key = None

        if key_id is not None:
            subject_key = db.query(Key).filter(Key.id == key_id, Key.is_deleted == False).first()
            if not subject_key:
                raise ValueError("Key not found")

            subject_password = None
            if subject_key.is_protected and subject_key.encrypted_password:
                subject_password = decrypt_key_password(subject_key.encrypted_password)
            elif subject_key.is_protected:
                raise ValueError("Subject key password is required but not remembered")

            subject_private_key_pem = decrypt_private_key(
                subject_key.encrypted_pem, subject_password
            )

            subject_private_key = load_pem_private_key(
                subject_private_key_pem.encode(),
                password=None,
            )
            subject_public_key = subject_private_key.public_key()

        if csr_pem:
            cert_der = create_leaf_certificate(
                issuer_private_key,
                subject_public_key or issuer_private_key.public_key(),
                issuer_cert,
                subject_data,
                validity_days,
                extensions,
                csr_pem,
            )
            cert_type = CertificateType.LEAF
            key_id_used = key_id
        else:
            if is_ca:
                cert_type = CertificateType.INTERMEDIATE
                cert_der = create_ca_certificate(
                    subject_private_key or issuer_private_key,
                    subject_public_key or issuer_private_key.public_key(),
                    subject_data,
                    validity_days,
                    extensions,
                    issuer_private_key,
                    issuer_cert,
                )
            else:
                cert_type = CertificateType.LEAF
                cert_der = create_leaf_certificate(
                    issuer_private_key,
                    subject_public_key or issuer_private_key.public_key(),
                    issuer_cert,
                    subject_data,
                    validity_days,
                    extensions,
                    None,
                )
        parent_id = issuer_id

    # Parse certificate for metadata
    cert_meta = parse_certificate(cert_der)

    certificate = Certificate(
        type=cert_type,
        parent_id=parent_id,
        key_id=key_id_used,
        serial_number=cert_meta["serial_number"],
        subject_cn=cert_meta["subject"]["CN"],
        not_before=datetime.fromisoformat(cert_meta["not_before"]),
        not_after=datetime.fromisoformat(cert_meta["not_after"]),
        status=CertificateStatus.VALID,
        certificate_der=cert_der,
        meta_data=json.dumps(cert_meta),
    )

    db.add(certificate)
    db.commit()
    db.refresh(certificate)

    return certificate


def import_certificate(
    db: Session,
    cert_pem: str,
    key_pem: Optional[str] = None,
    key_password: Optional[str] = None,
    remember_password: bool = False,
) -> tuple:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_meta = parse_certificate(cert_der)

    key_id = None
    if key_pem:
        from app.services.key_service import import_key

        key = import_key(db, key_pem, key_password, remember_password)
        key_id = key.id

    # Determine certificate type
    cert_type = CertificateType.LEAF
    try:
        bc = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
        if bc.value.ca:
            cert_type = CertificateType.ROOT
    except:
        pass

    # Find parent certificate
    parent_id = None
    issuer = cert.issuer
    if issuer != cert.subject:
        parent = (
            db.query(Certificate)
            .filter(
                Certificate.subject_cn
                == issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                Certificate.is_deleted == False,
            )
            .first()
        )
        if parent:
            parent_id = parent.id
            cert_type = CertificateType.INTERMEDIATE

    certificate = Certificate(
        type=cert_type,
        parent_id=parent_id,
        key_id=key_id,
        serial_number=cert_meta["serial_number"],
        subject_cn=cert_meta["subject"]["CN"],
        not_before=datetime.fromisoformat(cert_meta["not_before"]),
        not_after=datetime.fromisoformat(cert_meta["not_after"]),
        status=CertificateStatus.VALID,
        certificate_der=cert_der,
        meta_data=json.dumps(cert_meta),
    )

    db.add(certificate)
    db.commit()
    db.refresh(certificate)

    return certificate


def revoke_certificate(
    db: Session,
    certificate_id: int,
    reason: str = "unspecified",
    issuer_password: Optional[str] = None,
) -> None:
    from cryptography import x509

    cert = (
        db.query(Certificate)
        .filter(
            Certificate.id == certificate_id,
            Certificate.is_deleted == False,
        )
        .first()
    )
    if not cert:
        raise ValueError("Certificate not found")

    if cert.status == CertificateStatus.REVOKED:
        raise ValueError("Certificate already revoked")

    # Revoke certificate
    cert.status = CertificateStatus.REVOKED
    cert.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # Update meta_data with revocation reason
    cert_meta = parse_certificate(cert.certificate_der)
    cert_meta["revocation_reason"] = reason
    cert.meta_data = json.dumps(cert_meta)

    db.commit()


def export_certificate(
    db: Session,
    certificate_id: int,
    format: str = "pem",
    password: Optional[str] = None,
) -> tuple:
    from cryptography import x509

    cert = (
        db.query(Certificate)
        .filter(
            Certificate.id == certificate_id,
            Certificate.is_deleted == False,
        )
        .first()
    )
    if not cert:
        raise ValueError("Certificate not found")

    loaded_cert = x509.load_der_x509_certificate(cert.certificate_der)
    pem = loaded_cert.public_bytes(serialization.Encoding.PEM)

    if format == "pem":
        return pem, f"cert_{cert.id}.pem", "application/x-pem-file"
    elif format == "der":
        return cert.certificate_der, f"cert_{cert.id}.der", "application/x-x509-ca-cert"
    elif format == "pem-chain":
        chain = get_certificate_chain(db, certificate_id)
        chain_pem = b"".join(
            x509.load_der_x509_certificate(item.certificate_der).public_bytes(
                serialization.Encoding.PEM
            )
            for item in chain
        )
        return chain_pem, f"cert_{cert.id}-chain.pem", "application/x-pem-file"
    elif format == "pem-bundle":
        chain = get_certificate_chain(db, certificate_id)
        chain_pem = b"".join(
            x509.load_der_x509_certificate(item.certificate_der).public_bytes(
                serialization.Encoding.PEM
            )
            for item in chain
        )
        bundle = chain_pem
        if cert.key_id:
            key = db.query(Key).filter(Key.id == cert.key_id, Key.is_deleted == False).first()
            if key:
                key_pem = decrypt_private_key(key.encrypted_pem).encode()
                bundle += key_pem
        return bundle, f"cert_{cert.id}-bundle.pem", "application/x-pem-file"
    elif format == "p12":
        key = None
        if cert.key_id:
            key_record = (
                db.query(Key).filter(Key.id == cert.key_id, Key.is_deleted == False).first()
            )
            if key_record:
                key_pem = decrypt_private_key(key_record.encrypted_pem)
                key = load_pem_private_key(key_pem.encode(), password=None)

        if key is None:
            raise ValueError("Certificate has no available private key for PKCS#12 export")

        if not isinstance(
            key,
            (
                rsa.RSAPrivateKey,
                dsa.DSAPrivateKey,
                ec.EllipticCurvePrivateKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
            ),
        ):
            raise ValueError("Unsupported private key type for PKCS#12 export")

        encryption_algorithm = (
            serialization.BestAvailableEncryption(password.encode())
            if password
            else serialization.NoEncryption()
        )
        p12_data = pkcs12.serialize_key_and_certificates(
            name=(cert.subject_cn or f"cert-{cert.id}").encode(),
            key=cast(PKCS12PrivateKeyTypes, key),
            cert=loaded_cert,
            cas=None,
            encryption_algorithm=encryption_algorithm,
        )
        return p12_data, f"cert_{cert.id}.p12", "application/x-pkcs12"
    else:
        raise ValueError(f"Unsupported format: {format}")


def get_certificate_chain(db: Session, certificate_id: int) -> list:
    chain = []
    cert = (
        db.query(Certificate)
        .filter(
            Certificate.id == certificate_id,
            Certificate.is_deleted == False,
        )
        .first()
    )
    if not cert:
        raise ValueError("Certificate not found")

    chain.append(cert)

    while cert.parent_id:
        cert = (
            db.query(Certificate)
            .filter(
                Certificate.id == cert.parent_id,
                Certificate.is_deleted == False,
            )
            .first()
        )
        if cert:
            chain.append(cert)
        else:
            break

    return chain


def get_certificate_tree(db: Session) -> Dict[str, Any]:
    def build_tree(cert):
        from app.models.certificate import CertificateType

        children = (
            db.query(Certificate)
            .filter(
                Certificate.parent_id == cert.id,
                Certificate.is_deleted == False,
            )
            .all()
        )
        return {
            "id": cert.id,
            "type": cert.type,
            "subject_cn": cert.subject_cn,
            "status": cert.status,
            "children": [build_tree(child) for child in children],
        }

    root_cas = (
        db.query(Certificate)
        .filter(
            Certificate.type == CertificateType.ROOT,
            Certificate.is_deleted == False,
        )
        .all()
    )

    return [build_tree(root) for root in root_cas]


def delete_certificate(db: Session, certificate_id: int, delete_key: bool = False) -> None:
    cert = (
        db.query(Certificate)
        .filter(
            Certificate.id == certificate_id,
            Certificate.is_deleted == False,
        )
        .first()
    )
    if not cert:
        raise ValueError("Certificate not found")

    # Soft delete certificate
    cert.is_deleted = True
    db.commit()

    # Delete associated key if requested
    if delete_key and cert.key_id:
        from app.services.key_service import delete_key as delete_key_service

        delete_key_service(db, cert.key_id)


def list_certificates(
    db: Session,
    page: int = 1,
    per_page: int = 10,
    cert_type: Optional[str] = None,
    status: Optional[str] = None,
    parent_id: Optional[int] = None,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> Dict[str, Any]:
    query = db.query(Certificate).filter(Certificate.is_deleted == False)

    if cert_type:
        query = query.filter(Certificate.type == cert_type)

    if status:
        query = query.filter(Certificate.status == status)

    if parent_id:
        query = query.filter(Certificate.parent_id == parent_id)

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Certificate.subject_cn.ilike(pattern),
                Certificate.meta_data.ilike(pattern),
            )
        )

    sort_column = Certificate.created_at
    if sort_by == "not_after":
        sort_column = Certificate.not_after
    elif sort_by == "subject_cn":
        sort_column = Certificate.subject_cn

    if sort_order == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    total = query.count()
    certificates = query.offset((page - 1) * per_page).limit(per_page).all()

    return {
        "certificates": certificates,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


def validate_certificate_chain(chain: list) -> bool:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    if len(chain) < 2:
        return False

    # Verify each certificate in the chain
    for i in range(len(chain) - 1):
        child = x509.load_der_x509_certificate(chain[i].certificate_der)
        parent = x509.load_der_x509_certificate(chain[i + 1].certificate_der)

        try:
            child.public_key().verify(
                parent.signature,
                parent.tbs_certificate_bytes,
                parent.signature_hash_algorithm,
            )
        except:
            return False

    return True
