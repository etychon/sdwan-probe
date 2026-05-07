"""Terminal output helpers."""

from rich.console import Console

from sdwanprobe.models import CertInfo, ProbeResult, ProbeStatus, SDWANIdentity
from sdwanprobe.output import render_probe, render_summary


def test_render_probe_reachable_smoke():
    cert = CertInfo(
        subject_cn="vbond-test.viptela.com",
        subject_o="Cisco Systems, Inc.",
        subject_ou="Cisco12345",
        issuer_cn="Cisco Licensing Root CA",
        serial="ABCD",
        fingerprint_sha256="AA:BB",
        not_before="2023-01-01T00:00:00Z",
        not_after="2030-01-01T00:00:00Z",
        days_remaining=1000,
        expired=False,
        trusted=False,
        trust_error="unable to get local issuer certificate",
        san=[],
        signature_algorithm="1.2.840.113549.1.1.11",
        public_key_type="RSA",
        public_key_bits=2048,
    )
    res = ProbeResult(
        role="vbond",
        host="10.0.0.1",
        port=12346,
        status=ProbeStatus.REACHABLE,
        protocol="DTLSv1.2",
        cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
        key_exchange="ECDH secp521r1 (521 bits)",
        certificate=cert,
        sdwan_identity=SDWANIdentity(
            cluster_uuid="a83e6648-6a84-4ff2-9489-af97fbb43c94",
            node_uuid=None,
            org_name="Cisco12345",
            ca_type="Cisco PKI",
        ),
        error=None,
    )
    c = Console(force_terminal=False, width=80, color_system=None)
    render_probe(c, res)


def test_render_summary_smoke():
    r = ProbeResult(
        role="vmanage",
        host="10.0.0.2",
        port=443,
        status=ProbeStatus.TIMEOUT,
        error="timeout",
    )
    c = Console(force_terminal=False, width=120, color_system=None)
    render_summary(c, [r])
