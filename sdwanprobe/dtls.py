"""DTLS probes via system openssl s_client."""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from typing import List, Optional, Tuple

from sdwanprobe.cert import detect_ca_type, parse_pem_certificate
from sdwanprobe.identity import extract_sdwan_identity
from sdwanprobe.models import CertInfo, ProbeStatus, SDWANIdentity, TargetSpec

OPENSSL_NOT_FOUND = (
    "openssl executable not found in PATH. "
    "Install OpenSSL 1.1.1+ (Linux package openssl, macOS: Xcode CLT or Homebrew)."
)


def openssl_supports_dtls12() -> bool:
    path = shutil.which("openssl")
    if not path:
        return False
    try:
        r = subprocess.run(
            [path, "s_client", "-help"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        text = (r.stdout or b"").decode("utf-8", errors="replace") + (
            r.stderr or b""
        ).decode("utf-8", errors="replace")
        return "-dtls1_2" in text or "dtls1_2" in text
    except (subprocess.SubprocessError, OSError):
        return False


def _resolve_host(host: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
        if not infos:
            return None
        return infos[0][4][0]
    except socket.gaierror:
        return None


def _parse_brief_stderr(stderr: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """protocol, cipher, peer_dn, peer_cn_line, verify_error, server_temp_key."""
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    peer_dn: Optional[str] = None
    peer_cn: Optional[str] = None
    verify_err: Optional[str] = None
    temp_key: Optional[str] = None

    for line in stderr.splitlines():
        ls = line.strip()
        if ls.startswith("Protocol version:"):
            protocol = ls.split(":", 1)[1].strip()
        elif ls.startswith("Ciphersuite:"):
            cipher = ls.split(":", 1)[1].strip()
        elif ls.startswith("Peer certificate:"):
            peer_dn = ls.split(":", 1)[1].strip()
        elif re.match(r"depth=0", ls) and "CN=" in ls:
            peer_cn = ls
        elif "verify error:" in ls or "verify error" in ls:
            # e.g. verify error:num=20:unable to get local issuer certificate
            if "verify error" in ls.lower():
                verify_err = ls
        elif ls.startswith("Server Temp Key:"):
            temp_key = ls.split(":", 1)[1].strip()

    return protocol, cipher, peer_dn, peer_cn, verify_err, temp_key


def _extract_pem_certs(stdout: str) -> List[bytes]:
    blocks: List[bytes] = []
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    idx = 0
    while True:
        i = stdout.find(begin, idx)
        if i < 0:
            break
        j = stdout.find(end, i)
        if j < 0:
            break
        chunk = stdout[i : j + len(end)].encode("ascii", errors="ignore")
        blocks.append(chunk)
        idx = j + len(end)
    return blocks


def _openssl_rejects_dtls12_flag(stderr: str) -> bool:
    low = stderr.lower()
    return ("unknown option" in low and "dtls" in low) or (
        "unrecognized option" in low and "dtls" in low
    )


def _classify_dtls_failure(stderr: str, returncode: int) -> ProbeStatus:
    low = stderr.lower()
    if "connection refused" in low or ("icmp" in low and "unreach" in low):
        return ProbeStatus.REFUSED
    if "name or service not known" in low or "nodename nor servname" in low:
        return ProbeStatus.DNS_ERROR
    if "timed out" in low or "timeout" in low or returncode == 124:  # timeout cmd
        return ProbeStatus.TIMEOUT
    if "connection established" in low:
        return ProbeStatus.HANDSHAKE_FAILED
    if not stderr.strip():
        return ProbeStatus.TIMEOUT
    return ProbeStatus.HANDSHAKE_FAILED


def _brief_error_message(stderr: str, status: ProbeStatus) -> Optional[str]:
    if status == ProbeStatus.DNS_ERROR:
        return "DNS resolution failed"
    if status == ProbeStatus.REFUSED:
        return "Connection refused"
    if status == ProbeStatus.TIMEOUT:
        return "Probe timed out"
    for line in stderr.splitlines():
        s = line.strip()
        if not s:
            continue
        if "verify error" in s.lower():
            return s
    for line in stderr.splitlines():
        s = line.strip()
        if s:
            return s
    return None


def _run_s_client(
    host: str,
    port: int,
    timeout: int,
    extra_args: List[str],
):
    path = shutil.which("openssl")
    if not path:
        raise FileNotFoundError(OPENSSL_NOT_FOUND)
    cmd = [path, "s_client", *extra_args, "-connect", f"{host}:{port}"]
    return subprocess.run(
        cmd,
        input=b"\n",
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def probe_dtls(
    target: TargetSpec,
    timeout: int,
    *,
    prefer_dtls12: bool = True,
    ca_bundle: Optional[str] = None,
) -> Tuple[ProbeStatus, Optional[CertInfo], Optional[SDWANIdentity], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], bytes]:
    """
    Returns status, cert, sdwan_identity, protocol, cipher, key_ex, error, raw_stderr, stdout_bytes.
    """
    if _resolve_host(target.host) is None:
        return (
            ProbeStatus.DNS_ERROR,
            None,
            None,
            None,
            None,
            None,
            "DNS resolution failed",
            None,
            b"",
        )

    use_dtls_12 = bool(prefer_dtls12)

    def brief_cmd_args() -> List[str]:
        args: List[str] = ["-brief"]
        if ca_bundle:
            args.extend(["-verify_return_error", "-CAfile", ca_bundle])
        if use_dtls_12:
            args.insert(0, "-dtls1_2")
        return args

    try:
        r = _run_s_client(target.host, target.port, timeout, brief_cmd_args())
    except FileNotFoundError as e:
        return (
            ProbeStatus.OPENSSL_ERROR,
            None,
            None,
            None,
            None,
            None,
            str(e),
            None,
            b"",
        )
    except subprocess.TimeoutExpired:
        return (
            ProbeStatus.TIMEOUT,
            None,
            None,
            None,
            None,
            None,
            "Probe timed out",
            None,
            b"",
        )

    stderr_text = (r.stderr or b"").decode("utf-8", errors="replace")
    stdout_bytes = r.stdout or b""

    established = "CONNECTION ESTABLISHED" in stderr_text
    if (
        not established
        and use_dtls_12
        and prefer_dtls12
        and _openssl_rejects_dtls12_flag(stderr_text)
    ):
        use_dtls_12 = False
        try:
            r = _run_s_client(target.host, target.port, timeout, brief_cmd_args())
        except subprocess.TimeoutExpired:
            return (
                ProbeStatus.TIMEOUT,
                None,
                None,
                None,
                None,
                None,
                "Probe timed out",
                None,
                b"",
            )
        stderr_text = (r.stderr or b"").decode("utf-8", errors="replace")
        stdout_bytes = r.stdout or b""
        established = "CONNECTION ESTABLISHED" in stderr_text

    if not established:
        st = _classify_dtls_failure(stderr_text, r.returncode)
        return (
            st,
            None,
            None,
            None,
            None,
            None,
            _brief_error_message(stderr_text, st),
            stderr_text,
            stdout_bytes,
        )

    protocol, cipher, _peer_dn, _peer_cn_line, verify_line, temp_key = _parse_brief_stderr(
        stderr_text
    )
    trusted: Optional[bool] = None
    trust_error: Optional[str] = None
    low_full = stderr_text.lower()
    if "verify return code: 0" in low_full:
        trusted = True
        trust_error = None
    elif verify_line or "verify error" in low_full:
        trusted = False
        trust_error = (verify_line or "").strip()
        if not trust_error:
            for line in stderr_text.splitlines():
                if "verify error" in line.lower() or "verify return code" in line.lower():
                    trust_error = line.strip()
                    break
    else:
        trusted = None
        trust_error = None

    def showcerts_cmd_args() -> List[str]:
        args: List[str] = ["-showcerts"]
        if ca_bundle:
            args.extend(["-verify_return_error", "-CAfile", ca_bundle])
        if use_dtls_12:
            args.insert(0, "-dtls1_2")
        return args

    try:
        r2 = _run_s_client(target.host, target.port, timeout, showcerts_cmd_args())
    except subprocess.TimeoutExpired:
        return (
            ProbeStatus.HANDSHAKE_FAILED,
            None,
            None,
            protocol,
            cipher,
            temp_key,
            "Timed out fetching certificate chain",
            stderr_text,
            stdout_bytes,
        )

    stdout2 = (r2.stdout or b"").decode("utf-8", errors="replace")
    stderr2 = (r2.stderr or b"").decode("utf-8", errors="replace")
    combined_err = stderr_text + "\n" + stderr2
    pem_blocks = _extract_pem_certs(stdout2)
    if not pem_blocks:
        return (
            ProbeStatus.HANDSHAKE_FAILED,
            None,
            None,
            protocol,
            cipher,
            temp_key,
            "No peer certificate in openssl output",
            combined_err,
            r2.stdout or b"",
        )

    cert = parse_pem_certificate(pem_blocks[0], trusted=trusted, trust_error=trust_error)
    ca = detect_ca_type(cert.issuer_cn, cert.issuer_o)

    cu, nu, org, inferred_ca = extract_sdwan_identity(
        (r.stdout or b"") + (r2.stdout or b""),
        subject_ou=cert.subject_ou,
        ca_type=ca,
    )
    final_ca = inferred_ca or ca
    ident = SDWANIdentity(
        cluster_uuid=cu,
        node_uuid=nu,
        org_name=org,
        ca_type=None if final_ca in (None, "—") else final_ca,
    )

    return (
        ProbeStatus.REACHABLE,
        cert,
        ident,
        protocol,
        cipher,
        temp_key,
        None,
        combined_err,
        (r.stdout or b"") + (r2.stdout or b""),
    )
