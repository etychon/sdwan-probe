"""Result dataclasses and enums."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ProbeStatus(str, Enum):
    REACHABLE = "REACHABLE"
    HANDSHAKE_FAILED = "HANDSHAKE_FAILED"
    TIMEOUT = "TIMEOUT"
    REFUSED = "REFUSED"
    DNS_ERROR = "DNS_ERROR"
    OPENSSL_ERROR = "OPENSSL_ERROR"


@dataclass
class CertInfo:
    subject_cn: Optional[str] = None
    subject_o: Optional[str] = None
    subject_ou: Optional[str] = None
    subject_c: Optional[str] = None
    subject_st: Optional[str] = None
    subject_l: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_o: Optional[str] = None
    serial: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_remaining: Optional[int] = None
    expired: Optional[bool] = None
    trusted: Optional[bool] = None
    trust_error: Optional[str] = None
    san: Optional[List[str]] = field(default_factory=list)
    signature_algorithm: Optional[str] = None
    public_key_type: Optional[str] = None
    public_key_bits: Optional[int] = None

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "subject_cn": self.subject_cn,
            "subject_o": self.subject_o,
            "subject_ou": self.subject_ou,
            "subject_c": self.subject_c,
            "subject_st": self.subject_st,
            "subject_l": self.subject_l,
            "issuer_cn": self.issuer_cn,
            "issuer_o": self.issuer_o,
            "serial": self.serial,
            "fingerprint_sha256": self.fingerprint_sha256,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_remaining": self.days_remaining,
            "expired": self.expired,
            "trusted": self.trusted,
            "trust_error": self.trust_error,
            "san": self.san if self.san is not None else None,
            "signature_algorithm": self.signature_algorithm,
            "public_key_type": self.public_key_type,
            "public_key_bits": self.public_key_bits,
        }


@dataclass
class SDWANIdentity:
    cluster_uuid: Optional[str] = None
    node_uuid: Optional[str] = None
    org_name: Optional[str] = None
    ca_type: Optional[str] = None

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "cluster_uuid": self.cluster_uuid,
            "node_uuid": self.node_uuid,
            "org_name": self.org_name,
            "ca_type": self.ca_type,
        }


@dataclass
class TargetSpec:
    """Single probe target."""

    role: str
    host: str
    port: int
    label: Optional[str] = None


@dataclass
class ProbeResult:
    role: str
    host: str
    port: int
    label: Optional[str] = None
    status: ProbeStatus = ProbeStatus.TIMEOUT
    protocol: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    certificate: Optional[CertInfo] = None
    sdwan_identity: Optional[SDWANIdentity] = None
    error: Optional[str] = None
    raw_openssl_stderr: Optional[str] = None

    def to_json_dict(self) -> Dict[str, Any]:
        cert = self.certificate
        ident = self.sdwan_identity
        return {
            "role": self.role,
            "host": self.host,
            "port": self.port,
            "label": self.label,
            "status": self.status.value,
            "protocol": self.protocol,
            "cipher_suite": self.cipher_suite,
            "key_exchange": self.key_exchange,
            "certificate": cert.to_json_dict() if cert else null_cert_dict(),
            "sdwan_identity": ident.to_json_dict() if ident else null_identity_dict(),
            "error": self.error,
        }


def null_cert_dict() -> Dict[str, Any]:
    return {
        "subject_cn": None,
        "subject_o": None,
        "subject_ou": None,
        "subject_c": None,
        "subject_st": None,
        "subject_l": None,
        "issuer_cn": None,
        "issuer_o": None,
        "serial": None,
        "fingerprint_sha256": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "expired": None,
        "trusted": None,
        "trust_error": None,
        "san": None,
        "signature_algorithm": None,
        "public_key_type": None,
        "public_key_bits": None,
    }


def null_identity_dict() -> Dict[str, Any]:
    return {
        "cluster_uuid": None,
        "node_uuid": None,
        "org_name": None,
        "ca_type": None,
    }
