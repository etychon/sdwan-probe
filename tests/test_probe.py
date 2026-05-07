"""Target token and config parsing."""

import sdwanprobe.probe as probe_mod
from sdwanprobe.models import ProbeStatus, TargetSpec
from sdwanprobe.probe import (
    CISCO_CA_BUNDLE_PEM,
    _probe_one,
    discover_targets_from_url,
    load_config,
    parse_target_token,
)


def test_parse_target_hostname_uses_default_port():
    t = parse_target_token("vmanage:vmanage-acme.sdwan.example.net")
    assert t.role == "vmanage"
    assert t.host == "vmanage-acme.sdwan.example.net"
    assert t.port == 443


def test_parse_target_url_uses_default_port():
    t = parse_target_token("vmanage:https://vmanage-acme.sdwan.example.net")
    assert t.host == "vmanage-acme.sdwan.example.net"
    assert t.port == 443


def test_parse_target_url_with_explicit_port():
    t = parse_target_token("vmanage:https://vmanage-acme.sdwan.example.net:8443/login")
    assert t.host == "vmanage-acme.sdwan.example.net"
    assert t.port == 8443


def test_parse_target_with_path_without_scheme():
    t = parse_target_token("vmanage:vmanage-acme.sdwan.example.net/login")
    assert t.host == "vmanage-acme.sdwan.example.net"
    assert t.port == 443


def test_load_config_allows_url_hosts(tmp_path):
    cfg = tmp_path / "cluster.yaml"
    cfg.write_text(
        """
cluster_name: demo
targets:
  - role: vmanage
    host: https://vmanage-acme.sdwan.example.net
  - role: vbond
    host: vbond.example.com:12346
""".strip(),
        encoding="utf-8",
    )

    cluster_name, targets = load_config(cfg)
    assert cluster_name == "demo"
    assert len(targets) == 2
    assert targets[0].host == "vmanage-acme.sdwan.example.net"
    assert targets[0].port == 443
    assert targets[1].host == "vbond.example.com"
    assert targets[1].port == 12346


def test_discover_targets_from_url_builds_role_candidates():
    resolvable = {
        "vmanage-acme.sdwan.example.net",
        "vbond-acme.sdwan.example.net",
    }
    specs, unresolved = discover_targets_from_url(
        "https://vmanage-acme.sdwan.example.net",
        resolver=lambda host: host in resolvable,
    )
    assert [(s.role, s.host, s.port) for s in specs] == [
        ("vmanage", "vmanage-acme.sdwan.example.net", 443),
        ("vbond", "vbond-acme.sdwan.example.net", 12346),
    ]
    assert unresolved == ["vsmart:vsmart-acme.sdwan.example.net"]


def test_discover_targets_from_non_prefixed_host_is_vmanage_only():
    specs, unresolved = discover_targets_from_url(
        "tenant.example.net",
        resolver=lambda host: host == "tenant.example.net",
    )
    assert len(specs) == 1
    assert specs[0].role == "vmanage"
    assert specs[0].host == "tenant.example.net"
    assert specs[0].port == 443
    assert unresolved == []


def test_cisco_ca_bundle_has_certs():
    assert CISCO_CA_BUNDLE_PEM.count("-----BEGIN CERTIFICATE-----") >= 1


def test_discover_targets_tolerates_role_prefixed_url():
    specs, unresolved = discover_targets_from_url(
        "vmanage:https://vmanage-acme.sdwan.example.net",
        resolver=lambda host: host == "vmanage-acme.sdwan.example.net",
    )
    assert len(specs) == 1
    assert specs[0].role == "vmanage"
    assert specs[0].host == "vmanage-acme.sdwan.example.net"
    assert specs[0].port == 443
    assert unresolved == ["vbond:vbond-acme.sdwan.example.net", "vsmart:vsmart-acme.sdwan.example.net"]


def test_probe_one_vbond_falls_back_to_common_port(monkeypatch):
    def fake_probe_dtls(target, timeout, prefer_dtls12=True, ca_bundle=None):
        if target.port == 23456:
            return (
                ProbeStatus.TIMEOUT,
                None,
                None,
                None,
                None,
                None,
                "Probe timed out",
                "dtls-timeout",
                b"",
            )
        return (
            ProbeStatus.TIMEOUT,
            None,
            None,
            None,
            None,
            None,
            "Probe timed out",
            "dtls-timeout",
            b"",
        )

    def fake_probe_tls(target, timeout, ca_bundle=None):
        if target.port == 23456:
            return (
                ProbeStatus.REACHABLE,
                None,
                None,
                "TLSv1.3",
                "TLS_AES_256_GCM_SHA384",
                None,
                None,
            )
        return (
            ProbeStatus.HANDSHAKE_FAILED,
            None,
            None,
            None,
            None,
            None,
            "certificate verify failed",
        )

    monkeypatch.setattr(probe_mod, "probe_dtls", fake_probe_dtls)
    monkeypatch.setattr(probe_mod, "probe_tls", fake_probe_tls)

    res = _probe_one(
        TargetSpec(role="vbond", host="vbond-acme.sdwan.example.net", port=12346),
        timeout=5,
        prefer_dtls12=True,
        verbose=False,
        ca_bundle=None,
    )
    assert res.status == ProbeStatus.REACHABLE
    assert res.protocol == "TLSv1.3"
    assert res.port == 23456


def test_probe_one_vbond_failure_lists_attempted_ports(monkeypatch):
    def fake_probe_dtls(target, timeout, prefer_dtls12=True, ca_bundle=None):
        return (
            ProbeStatus.TIMEOUT,
            None,
            None,
            None,
            None,
            None,
            "Probe timed out",
            "dtls-timeout",
            b"",
        )

    def fake_probe_tls(target, timeout, ca_bundle=None):
        return (
            ProbeStatus.HANDSHAKE_FAILED,
            None,
            None,
            None,
            None,
            None,
            "certificate verify failed",
        )

    monkeypatch.setattr(probe_mod, "probe_dtls", fake_probe_dtls)
    monkeypatch.setattr(probe_mod, "probe_tls", fake_probe_tls)

    res = _probe_one(
        TargetSpec(role="vbond", host="vbond-acme.sdwan.example.net", port=12346),
        timeout=5,
        prefer_dtls12=True,
        verbose=False,
        ca_bundle=None,
    )
    assert res.status == ProbeStatus.HANDSHAKE_FAILED
    assert res.error is not None
    assert "12346/DTLS" in res.error
    assert "12346/TLS" in res.error
    assert "23456/DTLS" in res.error
    assert "23456/TLS" in res.error
