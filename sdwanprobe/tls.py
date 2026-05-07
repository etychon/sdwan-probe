"""TLS probe for vManage (HTTPS) using Python ssl."""

from __future__ import annotations

import socket
import ssl
from typing import Optional, Tuple

from sdwanprobe.cert import detect_ca_type, parse_der_certificate
from sdwanprobe.models import CertInfo, ProbeStatus, SDWANIdentity, TargetSpec


def probe_tls(target: TargetSpec, timeout: int, *, ca_bundle: Optional[str] = None) -> Tuple[
    ProbeStatus,
    Optional[CertInfo],
    Optional[SDWANIdentity],
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[str],
]:
    """
    Returns status, cert, sdwan_identity, protocol, cipher, key_ex, error.
    key_ex: TLS does not always expose temp key via stdlib; may be None.
    """
    try:
        socket.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return (
            ProbeStatus.DNS_ERROR,
            None,
            None,
            None,
            None,
            None,
            "DNS resolution failed",
        )

    if ca_bundle:
        ctx = ssl.create_default_context(cafile=ca_bundle)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target.host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return (
                        ProbeStatus.HANDSHAKE_FAILED,
                        None,
                        None,
                        ssock.version(),
                        None,
                        None,
                        "No peer certificate",
                    )
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else None
                tls_version = ssock.version()

                cert = parse_der_certificate(
                    der,
                    trusted=True if ca_bundle else False,
                    trust_error=None if ca_bundle else "Verification disabled (probe mode)",
                )
                ca = detect_ca_type(cert.issuer_cn, cert.issuer_o)
                ident = SDWANIdentity(
                    cluster_uuid=None,
                    node_uuid=None,
                    org_name=cert.subject_ou,
                    ca_type=ca if ca != "—" else None,
                )
                return (
                    ProbeStatus.REACHABLE,
                    cert,
                    ident,
                    tls_version,
                    cipher_name,
                    None,
                    None,
                )
    except ConnectionRefusedError:
        return (
            ProbeStatus.REFUSED,
            None,
            None,
            None,
            None,
            None,
            "Connection refused",
        )
    except TimeoutError:
        return (
            ProbeStatus.TIMEOUT,
            None,
            None,
            None,
            None,
            None,
            "Probe timed out",
        )
    except ssl.SSLError as e:
        return (
            ProbeStatus.HANDSHAKE_FAILED,
            None,
            None,
            None,
            None,
            None,
            str(e),
        )
    except OSError as e:
        msg = str(e).lower()
        if "timed out" in msg or "timeout" in msg:
            return (
                ProbeStatus.TIMEOUT,
                None,
                None,
                None,
                None,
                None,
                "Probe timed out",
            )
        return (
            ProbeStatus.HANDSHAKE_FAILED,
            None,
            None,
            None,
            None,
            None,
            str(e),
        )
