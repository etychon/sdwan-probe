"""Best-effort SD-WAN identity extraction from binary DTLS application payload."""

from __future__ import annotations

import re
from typing import List, Optional, Set, Tuple

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def extract_printable_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Sequences of printable ASCII (same spirit as strings(1))."""
    out: List[str] = []
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                out.append(current.decode("ascii", errors="ignore"))
            current = bytearray()
    if len(current) >= min_len:
        out.append(current.decode("ascii", errors="ignore"))
    return out


def _unique_uuids(strings: List[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for s in strings:
        for m in UUID_RE.findall(s):
            key = m.lower()
            if key not in seen:
                seen.add(key)
                ordered.append(m)
    return ordered


def infer_org_from_strings(strings: List[str], subject_ou: Optional[str]) -> Optional[str]:
    """Prefer OU that matches certificate OU or looks like Cisco org id."""
    for s in strings:
        if subject_ou and s == subject_ou:
            return s
    for s in strings:
        if re.fullmatch(r"Cisco\d+", s):
            return s
    if subject_ou:
        return subject_ou
    return None


def extract_sdwan_identity(
    stdout_bytes: bytes,
    *,
    subject_ou: Optional[str] = None,
    ca_type: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Returns (cluster_uuid, node_uuid, org_name, ca_type_overlay).
    ca_type_overlay is only set when we infer Cisco PKI from strings.
    """
    strings = extract_printable_strings(stdout_bytes)
    uuids = _unique_uuids(strings)
    cluster: Optional[str] = None
    node: Optional[str] = None
    if len(uuids) >= 1:
        cluster = uuids[0].lower()
    if len(uuids) >= 2:
        node = uuids[1].lower()
    elif len(uuids) == 1:
        node = None

    org = infer_org_from_strings(strings, subject_ou)

    inferred_ca: Optional[str] = None
    if org and re.fullmatch(r"Cisco\d+", org):
        inferred_ca = "Cisco PKI"
    elif ca_type:
        inferred_ca = ca_type

    return cluster, node, org, inferred_ca
