"""Certificate parsing and CA type detection."""

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sdwanprobe.cert import detect_ca_type, parse_der_certificate


def _self_signed_rsa_cert() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_der_certificate_smoke():
    der = _self_signed_rsa_cert()
    info = parse_der_certificate(der, trusted=False, trust_error="test")
    assert info.subject_cn == "test.example.com"
    assert info.public_key_type == "RSA"
    assert info.public_key_bits == 2048
    assert info.fingerprint_sha256
    assert ":" in info.fingerprint_sha256


def test_detect_ca_type_cisco_issuer():
    assert detect_ca_type("Cisco Licensing Root CA", None) == "Cisco PKI"
    assert detect_ca_type("Some CN", "Cisco Systems, Inc.") == "Cisco PKI"


def test_detect_ca_type_digicert():
    assert detect_ca_type("CN", "DigiCert Inc") == "DigiCert/Symantec (legacy)"


def test_detect_ca_type_enterprise():
    assert detect_ca_type("Internal CA", "Contoso") == "Enterprise CA"
