import json
from typing import Optional, Dict, Any, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12PrivateKeyTypes
from sqlalchemy.orm import Session

from app.models.key import Key, KeyAlgorithm
from app.models.certificate import Certificate, CertificateType, CertificateStatus
from app.security import (
    decrypt_private_key,
    encrypt_private_key,
    encrypt_key_password,
    calculate_fingerprint,
)
from app.services.crypto_service import (
    generate_key_pair,
    import_private_key,
    parse_private_key_metadata,
)


def generate_key(
    db: Session,
    algorithm: KeyAlgorithm,
    key_size: Optional[int] = None,
    curve: Optional[str] = None,
    password: Optional[str] = None,
    remember_password: bool = False,
) -> Key:
    private_key, public_key = generate_key_pair(algorithm, key_size, curve)

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_str = pem_bytes.decode()

    fingerprint = calculate_fingerprint(pem_bytes)

    encrypted_pem = encrypt_private_key(pem_str, password)

    encrypted_password = None
    if password and remember_password:
        encrypted_password = encrypt_key_password(password)

    key = Key(
        algorithm=algorithm.value,
        fingerprint=fingerprint,
        encrypted_pem=encrypted_pem,
        is_protected=password is not None,
        encrypted_password=encrypted_password,
        meta_data=json.dumps(parse_private_key_metadata(private_key)),
    )

    db.add(key)
    db.commit()
    db.refresh(key)

    return key


def import_key(
    db: Session,
    key_pem: str,
    password: Optional[str] = None,
    remember_password: bool = False,
) -> Key:
    private_key, public_key = import_private_key(key_pem, password)

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fingerprint = calculate_fingerprint(pem_bytes)

    encrypted_pem = encrypt_private_key(key_pem, password)

    encrypted_password = None
    if password and remember_password:
        encrypted_password = encrypt_key_password(password)

    key = Key(
        algorithm=private_key.__class__.__name__.replace("PrivateKey", ""),
        fingerprint=fingerprint,
        encrypted_pem=encrypted_pem,
        is_protected=password is not None,
        encrypted_password=encrypted_password,
        meta_data=json.dumps(parse_private_key_metadata(private_key)),
    )

    db.add(key)
    db.commit()
    db.refresh(key)

    return key


def export_key(
    db: Session,
    key_id: int,
    format: str = "pem",
    password: Optional[str] = None,
) -> tuple:
    key = db.query(Key).filter(Key.id == key_id, Key.is_deleted == False).first()
    if not key:
        raise ValueError("Key not found")

    pem_key = decrypt_private_key(key.encrypted_pem)
    private_key = serialization.load_pem_private_key(pem_key.encode(), password=None)

    if format == "pem":
        return pem_key.encode(), f"key_{key.id}.pem", "application/x-pem-file"
    elif format == "pkcs8":
        pkcs8_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pkcs8_key, f"key_{key.id}.pk8.pem", "application/x-pem-file"
    elif format == "pkcs12":
        if not isinstance(
            private_key,
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
            name=f"key-{key.id}".encode(),
            key=cast(PKCS12PrivateKeyTypes, private_key),
            cert=None,
            cas=None,
            encryption_algorithm=encryption_algorithm,
        )
        return p12_data, f"key_{key.id}.p12", "application/x-pkcs12"
    else:
        raise ValueError(f"Unsupported format: {format}")


def delete_key(db: Session, key_id: int) -> None:
    key = db.query(Key).filter(Key.id == key_id, Key.is_deleted == False).first()
    if not key:
        return

    key.is_deleted = True
    db.commit()


def list_keys(
    db: Session,
    page: int = 1,
    per_page: int = 10,
    algorithm: Optional[str] = None,
) -> Dict[str, Any]:
    query = db.query(Key).filter(Key.is_deleted == False)

    if algorithm:
        query = query.filter(Key.algorithm == algorithm)

    total = query.count()
    keys = query.offset((page - 1) * per_page).limit(per_page).all()

    return {
        "keys": keys,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


def get_key_detail(db: Session, key_id: int) -> Optional[Key]:
    return db.query(Key).filter(Key.id == key_id, Key.is_deleted == False).first()
