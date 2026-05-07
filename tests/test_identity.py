"""SD-WAN identity string extraction."""

from sdwanprobe.identity import extract_printable_strings, extract_sdwan_identity


def test_extract_printable_strings():
    data = b"\x00foo\x01barbaz\x00"
    s = extract_printable_strings(data, min_len=3)
    assert "barbaz" in s or "foo" in s


def test_extract_sdwan_identity_uuids():
    payload = b"prefix a83e6648-6a84-4ff2-9489-af97fbb43c94 middle 1fbd07f6-22b4-4263-af69-25074760e40f tail"
    cu, nu, org, ca = extract_sdwan_identity(payload, subject_ou="Cisco12345", ca_type="Cisco PKI")
    assert cu == "a83e6648-6a84-4ff2-9489-af97fbb43c94".lower()
    assert nu == "1fbd07f6-22b4-4263-af69-25074760e40f".lower()
    assert org == "Cisco12345"
    assert ca == "Cisco PKI"
