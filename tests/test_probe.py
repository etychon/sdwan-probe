"""Target token and config parsing."""

from sdwanprobe.probe import (
    CISCO_CA_BUNDLE_PEM,
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
