import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID

from app.models.key import KeyAlgorithm
from app.security import encrypt_private_key, decrypt_private_key, calculate_fingerprint


_EKU_NAME_TO_OID = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
    "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
}


def _normalize_key_usage(
    values: Optional[Dict[str, Any]], defaults: Dict[str, bool]
) -> Dict[str, bool]:
    result = {
        "digital_signature": False,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False,
    }
    result.update(defaults)
    if values:
        for key in result:
            if key in values:
                result[key] = bool(values[key])
    return result


def _build_extended_key_usage(values: Optional[Any]) -> Optional[x509.ExtendedKeyUsage]:
    if not values:
        return None

    oids = []
    if isinstance(values, dict):
        for name, enabled in values.items():
            if enabled and name in _EKU_NAME_TO_OID:
                oids.append(_EKU_NAME_TO_OID[name])
    elif isinstance(values, list):
        for name in values:
            if isinstance(name, str) and name in _EKU_NAME_TO_OID:
                oids.append(_EKU_NAME_TO_OID[name])

    if not oids:
        return None
    return x509.ExtendedKeyUsage(oids)


def _append_san_entries(san_values: Optional[Dict[str, Any]]) -> list:
    if not san_values:
        return []

    import ipaddress

    entries = []
    for name, value in san_values.items():
        values = value if isinstance(value, list) else [value]
        for item in values:
            if not item:
                continue
            if name == "dns":
                entries.append(x509.DNSName(str(item)))
            elif name == "ip":
                entries.append(x509.IPAddress(ipaddress.ip_address(str(item))))
            elif name == "email":
                entries.append(x509.RFC822Name(str(item)))
            elif name == "uri":
                entries.append(x509.UniformResourceIdentifier(str(item)))
    return entries


def _build_subject_name(subject: Dict[str, str]) -> x509.Name:
    attrs = []
    mapping = [
        ("C", NameOID.COUNTRY_NAME),
        ("ST", NameOID.STATE_OR_PROVINCE_NAME),
        ("L", NameOID.LOCALITY_NAME),
        ("O", NameOID.ORGANIZATION_NAME),
        ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("CN", NameOID.COMMON_NAME),
    ]
    for key, oid in mapping:
        value = subject.get(key)
        if value:
            attrs.append(x509.NameAttribute(oid, value))
    return x509.Name(attrs)


def generate_key_pair(
    algorithm: KeyAlgorithm, key_size: Optional[int] = None, curve: Optional[str] = None
) -> tuple:
    if algorithm == KeyAlgorithm.RSA:
        if not key_size or key_size not in [2048, 4096]:
            key_size = 2048
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
    elif algorithm == KeyAlgorithm.ECDSA:
        curve_name = curve or "P-256"
        if curve_name == "P-256":
            ec_curve = ec.SECP256R1()
        elif curve_name == "P-384":
            ec_curve = ec.SECP384R1()
        else:
            ec_curve = ec.SECP256R1()
        private_key = ec.generate_private_key(curve=ec_curve, backend=default_backend())
    elif algorithm == KeyAlgorithm.EdDSA:
        if key_size == 448:
            private_key = ed448.Ed448PrivateKey.generate()
        else:
            private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    public_key = private_key.public_key()
    return private_key, public_key


def import_private_key(pem_data: str, password: Optional[str] = None) -> tuple:
    try:
        private_key = serialization.load_pem_private_key(
            pem_data.encode(),
            password=password.encode() if password else None,
            backend=default_backend(),
        )
    except ValueError:
        try:
            private_key = serialization.load_pem_private_key(
                pem_data.encode(),
                password=None,
                backend=default_backend(),
            )
        except Exception as e:
            raise ValueError(f"Failed to import private key: {str(e)}")

    public_key = private_key.public_key()
    return private_key, public_key


def parse_private_key_metadata(private_key) -> Dict[str, Any]:
    public_key = private_key.public_key()
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    algorithm = "RSA"
    key_size = None

    if isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = "RSA"
        key_size = private_key.key_size
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm = "ECDSA"
        if isinstance(private_key.curve, ec.SECP256R1):
            key_size = 256
        elif isinstance(private_key.curve, ec.SECP384R1):
            key_size = 384
    elif isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        algorithm = "EdDSA"
        key_size = 256 if isinstance(private_key, ed25519.Ed25519PrivateKey) else 448

    fingerprint = calculate_fingerprint(pem_bytes)

    return {
        "algorithm": algorithm,
        "key_size": key_size,
        "fingerprint": fingerprint,
    }


def create_ca_certificate(
    private_key,
    public_key,
    subject: Dict[str, str],
    validity_days: int = 3650,
    extensions: Optional[Dict[str, Any]] = None,
    parent_key=None,
    parent_cert=None,
) -> bytes:
    subject_name = _build_subject_name(subject)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=validity_days))
    builder = builder.serial_number(x509.random_serial_number())

    if parent_key and parent_cert:
        builder = builder.issuer_name(parent_cert.subject)
    else:
        builder = builder.issuer_name(subject_name)

    builder = builder.public_key(public_key)

    # Basic Constraints
    is_ca = extensions.get("is_ca", True) if extensions else True
    path_length = extensions.get("path_length", None) if extensions else None

    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=path_length),
        critical=True,
    )

    # Key Usage
    key_usage = _normalize_key_usage(
        extensions.get("key_usage") if extensions else None,
        {
            "digital_signature": True,
            "key_cert_sign": True,
            "crl_sign": True,
        },
    )
    builder = builder.add_extension(
        x509.KeyUsage(**key_usage),
        critical=True,
    )

    # Extended Key Usage
    extended_key_usage = _build_extended_key_usage(
        extensions.get("extended_key_usage") if extensions else None
    )
    if extended_key_usage is not None:
        builder = builder.add_extension(extended_key_usage, critical=False)

    # Subject Alternative Name
    san_list = _append_san_entries(extensions.get("san") if extensions else None)
    if san_list:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

    # Sign the certificate
    if parent_key:
        certificate = builder.sign(private_key, hashes.SHA256())
    else:
        certificate = builder.sign(private_key, hashes.SHA256())

    return certificate.public_bytes(serialization.Encoding.DER)


def create_leaf_certificate(
    private_key,
    public_key,
    issuer_cert,
    subject: Dict[str, str],
    validity_days: int = 365,
    extensions: Optional[Dict[str, Any]] = None,
    csr_pem: Optional[str] = None,
) -> bytes:
    if csr_pem:
        csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        public_key = csr.public_key()
        subject_name = csr.subject
        if csr.extensions:
            for ext in csr.extensions:
                builder = x509.CertificateBuilder()
    else:
        subject_name = _build_subject_name(subject)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=validity_days))
    builder = builder.serial_number(x509.random_serial_number())
    if issuer_cert is not None:
        builder = builder.issuer_name(issuer_cert.subject)
    else:
        builder = builder.issuer_name(subject_name)
    builder = builder.public_key(public_key)

    # Basic Constraints
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    # Key Usage
    key_usage = _normalize_key_usage(
        extensions.get("key_usage") if extensions else None,
        {
            "digital_signature": True,
            "key_encipherment": True,
        },
    )
    builder = builder.add_extension(x509.KeyUsage(**key_usage), critical=True)

    # Extended Key Usage
    extended_key_usage = _build_extended_key_usage(
        (extensions.get("extended_key_usage") if extensions else None)
        or {"server_auth": True, "client_auth": True}
    )
    if extended_key_usage is not None:
        builder = builder.add_extension(extended_key_usage, critical=False)

    # Subject Alternative Name
    san_list = _append_san_entries(extensions.get("san") if extensions else None)
    if san_list:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

    certificate = builder.sign(private_key, hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.DER)


def parse_certificate(cert_der: bytes) -> Dict[str, Any]:
    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    subject = cert.subject
    issuer = cert.issuer

    extensions = {}

    for ext in cert.extensions:
        if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
            bc = ext.value
            extensions["basic_constraints"] = {
                "ca": bc.ca,
                "path_length": bc.path_length,
            }
        elif ext.oid == ExtensionOID.KEY_USAGE:
            ku = ext.value
            extensions["key_usage"] = {
                "digital_signature": ku.digital_signature,
                "key_encipherment": ku.key_encipherment,
                "key_cert_sign": ku.key_cert_sign,
                "crl_sign": ku.crl_sign,
                "key_agreement": ku.key_agreement,
                "data_encipherment": ku.data_encipherment,
                "content_commitment": ku.content_commitment,
                "data_encipherment": ku.data_encipherment,
            }
        elif ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
            eku = ext.value
            eku_oids = set(eku)
            extensions["extended_key_usage"] = {
                "server_auth": ExtendedKeyUsageOID.SERVER_AUTH in eku_oids,
                "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH in eku_oids,
                "code_signing": ExtendedKeyUsageOID.CODE_SIGNING in eku_oids,
                "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION in eku_oids,
                "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING in eku_oids,
            }
        elif ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            san = ext.value
            san_list = []
            for name in san.get_values_for_type(x509.DNSName):
                san_list.append({"type": "dns", "value": name})
            for name in san.get_values_for_type(x509.IPAddress):
                san_list.append({"type": "ip", "value": str(name)})
            extensions["san"] = san_list

    return {
        "serial_number": hex(cert.serial_number)[2:].upper(),
        "subject": {
            "CN": subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            else "",
            "O": subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            if subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            else "",
            "OU": subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
            if subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
            else "",
            "C": subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
            if subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
            else "",
            "ST": subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
            if subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
            else "",
            "L": subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
            if subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
            else "",
        },
        "issuer": {
            "CN": issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            else "",
            "O": issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            if issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            else "",
        },
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after.isoformat(),
        "extensions": extensions,
    }


def generate_crl(ca_cert, ca_private_key, revoked_certs: list, crl_number: int = 1) -> bytes:
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(days=7))

    for cert_info in revoked_certs:
        cert = x509.load_der_x509_certificate(cert_info["certificate_der"], default_backend())
        revoked_builder = x509.RevokedCertificateBuilder()
        revoked_builder = revoked_builder.serial_number(cert.serial_number)
        revoked_builder = revoked_builder.revocation_date(now)
        builder = builder.add_revoked_certificate(revoked_builder.build(default_backend()))

    crl = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    return crl.public_bytes(serialization.Encoding.DER)
