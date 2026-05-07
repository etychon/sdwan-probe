"""Target parsing, config loading, and concurrent probe orchestration."""

from __future__ import annotations

import concurrent.futures
import os
import re
import socket
import shutil
import tempfile
import warnings
from pathlib import Path
from urllib.parse import urlsplit
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from sdwanprobe.dtls import OPENSSL_NOT_FOUND, openssl_supports_dtls12, probe_dtls
from sdwanprobe.models import ProbeResult, ProbeStatus, TargetSpec
from sdwanprobe.tls import probe_tls


def default_port(role: str) -> int:
    r = role.lower()
    if r in ("vbond", "vsmart"):
        return 12346
    if r == "vmanage":
        return 443
    raise ValueError(f"Unknown role: {role!r}")


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_DISCOVERY_PREFIX_RE = re.compile(r"^(vmanage|vbond|vsmart)([-.])(.*)$", re.IGNORECASE)
_ROLE_TOKEN_PREFIX_RE = re.compile(r"^(vmanage|vbond|vsmart):(.*)$", re.IGNORECASE)

# Cisco-published root certificates from https://www.cisco.com/security/pki/
# - Cisco Root CA 2099 (crca2099.pem)
# Note: Cisco Root CA 2048 is SHA-1 self-signed (legacy). We intentionally
# do not bundle it by default to keep verification mode on stronger hashes.
CISCO_CA_BUNDLE_PEM = """
-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIJAZozWHjOFsHBMA0GCSqGSIb3DQEBCwUAMC0xDjAMBgNV
BAoTBUNpc2NvMRswGQYDVQQDExJDaXNjbyBSb290IENBIDIwOTkwIBcNMTYwODA5
MjA1ODI4WhgPMjA5OTA4MDkyMDU4MjhaMC0xDjAMBgNVBAoTBUNpc2NvMRswGQYD
VQQDExJDaXNjbyBSb290IENBIDIwOTkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDTtuM1fg0+9Gflik4axlCK1I2fb3ESCL8+tk8kOXlhfrJ/zlfRbe60
xRP0iUGMKWKBj0IvvWFf4AW/nyzCR8ujTt4a11Eb55SAKXbXYQ7L4YMg+lmZmg/I
v3GJEc3HCYU0BsY8g9LuLMvqwiNmAwM2jWzNq0EPArt/F6RiQKq6Ta3e7VIfDZ7J
65OA2xASA2FrSe9Vj97KpQReDcm6G7cqFH5f+CrdQ4qwAa4zWNyM3kOpUb637DNd
9m+n6WECyc/IUD+2e+yp21kBZIKH7JvDpu2U7NBPfr52mFX8AfCZgkXV69bp+iYf
saH1DvXIfPpNp93zGKUSXxEj4w881t2zAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIB
BjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ4lVcPNCNO86EmILoUkcdBiB2j
WzANBgkqhkiG9w0BAQsFAAOCAQEAjeKZo+4xd05TFtq99nKnWA0J+DmydBOnPMwY
lDrKfBKe2wVu5AJMvRjgJIoY/CHVPaCOWH58UTqfji95eUaryQ/s36RKrBgMMlwr
WNItxE625PHuaN6EjD1WdWiRMZ2hy8F4FCKz5hgUEvN+PUNZwsPnpU6q3Ay0+11T
4TriwCV8kJx3cWu0NvTypYCCXMscSfLFQR13bo+1z6XNm30SecmrxkmQBVMqjCZM
VvAxhxW1iGnYdPRQuNqt0xITzCSERqg3QVVqYnFJUkNVN6j0dmmMVKZh17HgqLnF
PKkmBlNQ9hQcNM3CSzVvEAK0CCEo/NJ/xzZ6WX1/f8Df1eXbFg==
-----END CERTIFICATE-----
""".strip()


def write_cisco_ca_bundle_temp() -> str:
    """Write bundled Cisco roots to a temporary PEM file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tf:
        tf.write(CISCO_CA_BUNDLE_PEM + "\n")
        return tf.name


def _parse_host_port(raw: str, role: str) -> Tuple[str, int]:
    value = raw.strip()
    if not value:
        raise ValueError("Target host cannot be empty")

    # Allow users to pass a full login URL, e.g. https://vmanage.example.com
    if _SCHEME_RE.match(value):
        parsed = urlsplit(value)
        if not parsed.hostname:
            raise ValueError(f"Invalid URL in target {raw!r}")
        return parsed.hostname, parsed.port or default_port(role)

    # Also tolerate accidental path/query fragments after host.
    if "/" in value or "?" in value or "#" in value:
        parsed = urlsplit(f"//{value}")
        if parsed.hostname:
            return parsed.hostname, parsed.port or default_port(role)

    if ":" in value:
        host, port_s = value.rsplit(":", 1)
        if not host:
            raise ValueError(f"Invalid host in target {raw!r}")
        if not port_s.isdigit():
            raise ValueError(f"Invalid port in {raw!r}")
        return host, int(port_s)

    return value, default_port(role)


def _parse_urlish_host(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("Discovery URL/host cannot be empty")

    # Be forgiving if users pass TARGET-like input (e.g. "vmanage:https://host").
    # --discover-from-url expects only URL/host, but stripping role prefix avoids
    # accidental discovery against a literal "vmanage" hostname.
    role_prefixed = _ROLE_TOKEN_PREFIX_RE.match(value)
    if role_prefixed:
        remainder = role_prefixed.group(2).strip()
        if remainder:
            value = remainder

    if _SCHEME_RE.match(value):
        parsed = urlsplit(value)
        if not parsed.hostname:
            raise ValueError(f"Invalid discovery URL: {raw!r}")
        return parsed.hostname
    parsed = urlsplit(f"//{value}")
    if parsed.hostname:
        return parsed.hostname
    raise ValueError(f"Invalid discovery URL/host: {raw!r}")


def _host_resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


def discover_targets_from_url(
    url_or_host: str,
    *,
    resolver: Optional[Callable[[str], bool]] = None,
) -> Tuple[List[TargetSpec], List[str]]:
    """
    Build likely controller targets from a vManage-style URL/hostname.

    Returns:
      (discovered_targets, unresolved_candidates)
    """
    host = _parse_urlish_host(url_or_host)
    check = resolver or _host_resolves

    m = _DISCOVERY_PREFIX_RE.match(host)
    candidates: Dict[str, str] = {}
    if m:
        sep = m.group(2)
        suffix = m.group(3)
        for role in ("vmanage", "vbond", "vsmart"):
            candidates[role] = f"{role}{sep}{suffix}"
    else:
        # If the URL does not follow role-prefixed naming, treat it as vManage only.
        candidates["vmanage"] = host

    specs: List[TargetSpec] = []
    unresolved: List[str] = []
    for role in ("vmanage", "vbond", "vsmart"):
        cand = candidates.get(role)
        if not cand:
            continue
        if check(cand):
            specs.append(TargetSpec(role=role, host=cand, port=default_port(role)))
        else:
            unresolved.append(f"{role}:{cand}")
    return specs, unresolved


def parse_target_token(s: str) -> TargetSpec:
    if ":" not in s:
        raise ValueError(
            f"Invalid target {s!r}; expected <role>:<host>[:<port>] "
            "(role: vbond | vsmart | vmanage)"
        )
    role, target_part = s.split(":", 1)
    role = role.lower()
    if role not in ("vbond", "vsmart", "vmanage"):
        raise ValueError(f"Unknown role in {s!r}; use vbond, vsmart, or vmanage")
    host, port = _parse_host_port(target_part, role)
    return TargetSpec(role=role, host=host, port=port)


def load_config(path: Path) -> Tuple[Optional[str], List[TargetSpec]]:
    try:
        import yaml
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "PyYAML is required for --config. Install with: pip install pyyaml"
        ) from e

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Config root must be a mapping")
    cluster_name = raw.get("cluster_name")
    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, list):
        raise ValueError("Config must contain a 'targets' list")

    specs: List[TargetSpec] = []
    for i, item in enumerate(targets_raw):
        if not isinstance(item, dict):
            raise ValueError(f"targets[{i}] must be a mapping")
        role = str(item["role"]).lower()
        if role not in ("vbond", "vsmart", "vmanage"):
            raise ValueError(f"targets[{i}].role must be vbond, vsmart, or vmanage")
        host_in = str(item["host"])
        host, inferred_port = _parse_host_port(host_in, role)
        port = item.get("port", inferred_port)
        label = item.get("label")
        if isinstance(label, str):
            lab: Optional[str] = label
        elif label is None:
            lab = None
        else:
            lab = str(label)
        specs.append(TargetSpec(role=role, host=host, port=int(port), label=lab))
    cn = str(cluster_name) if cluster_name is not None else None
    return cn, specs


def _probe_one(
    target: TargetSpec,
    timeout: int,
    *,
    prefer_dtls12: bool,
    verbose: bool,
    ca_bundle: Optional[str],
) -> ProbeResult:
    if target.role in ("vbond", "vsmart"):
        (
            status,
            cert,
            ident,
            protocol,
            cipher,
            kex,
            err,
            raw_err,
            _stdout,
        ) = probe_dtls(target, timeout, prefer_dtls12=prefer_dtls12, ca_bundle=ca_bundle)
        return ProbeResult(
            role=target.role,
            host=target.host,
            port=target.port,
            label=target.label,
            status=status,
            protocol=protocol,
            cipher_suite=cipher,
            key_exchange=kex,
            certificate=cert,
            sdwan_identity=ident,
            error=err,
            raw_openssl_stderr=raw_err if verbose else None,
        )

    status, cert, ident, protocol, cipher, kex, err = probe_tls(
        target, timeout, ca_bundle=ca_bundle
    )
    return ProbeResult(
        role=target.role,
        host=target.host,
        port=target.port,
        label=target.label,
        status=status,
        protocol=protocol,
        cipher_suite=cipher,
        key_exchange=kex,
        certificate=cert,
        sdwan_identity=ident,
        error=err,
        raw_openssl_stderr=None,
    )


def ensure_openssl_for_dtls(targets: Iterable[TargetSpec]) -> None:
    needs = any(t.role in ("vbond", "vsmart") for t in targets)
    if not needs:
        return
    if not shutil.which("openssl"):
        raise SystemExit(OPENSSL_NOT_FOUND)


def run_probes(
    targets: List[TargetSpec],
    timeout: int,
    *,
    verbose: bool = False,
    verify_with_cisco_ca: bool = False,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[ProbeResult]:
    """Run all probes concurrently; order of results matches `targets`."""
    ensure_openssl_for_dtls(targets)
    prefer = openssl_supports_dtls12()
    if any(t.role in ("vbond", "vsmart") for t in targets) and not prefer:
        warnings.warn(
            "This openssl may not support -dtls1_2; probing without that flag.",
            UserWarning,
            stacklevel=2,
        )

    ca_bundle: Optional[str] = None
    results: List[Optional[ProbeResult]] = [None] * len(targets)
    try:
        if verify_with_cisco_ca:
            ca_bundle = write_cisco_ca_bundle_temp()

        def work(idx: int, t: TargetSpec) -> Tuple[int, ProbeResult]:
            return idx, _probe_one(
                t, timeout, prefer_dtls12=prefer, verbose=verbose, ca_bundle=ca_bundle
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(targets) or 1)) as ex:
            futs = [ex.submit(work, i, t) for i, t in enumerate(targets)]
            done = 0
            for fut in concurrent.futures.as_completed(futs):
                idx, res = fut.result()
                results[idx] = res
                done += 1
                if progress_callback:
                    progress_callback(done, len(targets))
    finally:
        if ca_bundle:
            try:
                os.unlink(ca_bundle)
            except OSError:
                pass
    return [r for r in results if r is not None]
