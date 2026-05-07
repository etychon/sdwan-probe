"""X.509 parsing and CA type detection."""

from __future__ import annotations

import datetime as dt
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID

from sdwanprobe.models import CertInfo


def _name_attr(cert: x509.Certificate, oid) -> Optional[str]:
    try:
        attrs = cert.subject.get_attributes_for_oid(oid)
        if not attrs:
            return None
        return attrs[0].value
    except Exception:
        return None


def _issuer_attr(cert: x509.Certificate, oid) -> Optional[str]:
    try:
        attrs = cert.issuer.get_attributes_for_oid(oid)
        if not attrs:
            return None
        return attrs[0].value
    except Exception:
        return None


def _public_key_meta(cert: x509.Certificate) -> Tuple[Optional[str], Optional[int]]:
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return "EC", pk.key_size
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA", pk.key_size
    if isinstance(pk, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        name = "Ed25519" if isinstance(pk, ed25519.Ed25519PublicKey) else "Ed448"
        return name, None
    return None, None


def _san_dns_ips(cert: x509.Certificate) -> List[str]:
    out: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for v in ext.value:
            if isinstance(v, x509.DNSName):
                out.append(v.value)
            elif isinstance(v, x509.IPAddress):
                out.append(str(v.value))
    except x509.ExtensionNotFound:
        pass
    return out


def _fingerprint_sha256(cert: x509.Certificate) -> str:
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def _serial_hex(cert: x509.Certificate) -> str:
    sn = cert.serial_number
    h = format(sn, "X")
    # Collapse long serials for display (PRD shows 3AF2...)
    if len(h) > 16:
        return f"{h[:4]}...{h[-4:]}"
    return h


def detect_ca_type(issuer_cn: Optional[str], issuer_o: Optional[str]) -> str:
    icn = (issuer_cn or "").strip()
    io = (issuer_o or "").strip()
    if "Cisco Licensing Root CA" in icn:
        return "Cisco PKI"
    if "Cisco" in io or "Cisco" in icn:
        return "Cisco PKI"
    lo = io.lower()
    if "digicert" in lo or "symantec" in lo:
        return "DigiCert/Symantec (legacy)"
    if icn or io:
        return "Enterprise CA"
    return "—"


def parse_der_certificate(
    der: bytes,
    *,
    trusted: Optional[bool] = None,
    trust_error: Optional[str] = None,
) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    now = dt.datetime.now(dt.timezone.utc)
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    days_remaining: Optional[int] = None
    expired = na < now
    if not expired:
        delta = na - now
        days_remaining = max(0, delta.days)

    sig = cert.signature_algorithm_oid.dotted_string
    pk_type, pk_bits = _public_key_meta(cert)

    san_list = _san_dns_ips(cert)

    return CertInfo(
        subject_cn=_name_attr(cert, NameOID.COMMON_NAME),
        subject_o=_name_attr(cert, NameOID.ORGANIZATION_NAME),
        subject_ou=_name_attr(cert, NameOID.ORGANIZATIONAL_UNIT_NAME),
        subject_c=_name_attr(cert, NameOID.COUNTRY_NAME),
        subject_st=_name_attr(cert, NameOID.STATE_OR_PROVINCE_NAME),
        subject_l=_name_attr(cert, NameOID.LOCALITY_NAME),
        issuer_cn=_issuer_attr(cert, NameOID.COMMON_NAME),
        issuer_o=_issuer_attr(cert, NameOID.ORGANIZATION_NAME),
        serial=_serial_hex(cert),
        fingerprint_sha256=_fingerprint_sha256(cert),
        not_before=nb.strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_after=na.strftime("%Y-%m-%dT%H:%M:%SZ"),
        days_remaining=days_remaining,
        expired=expired,
        trusted=trusted,
        trust_error=trust_error,
        san=san_list,
        signature_algorithm=sig,
        public_key_type=pk_type,
        public_key_bits=pk_bits,
    )


def parse_pem_certificate(
    pem: bytes,
    *,
    trusted: Optional[bool] = None,
    trust_error: Optional[str] = None,
) -> CertInfo:
    cert = x509.load_pem_x509_certificate(pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    return parse_der_certificate(der, trusted=trusted, trust_error=trust_error)
