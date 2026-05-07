# Product Requirements Document — `sdwan-probe`

**Version:** 1.0 — Initial  
**Target audience:** Cursor (AI-assisted implementation)  
**License intent:** MIT, publish on GitHub  

---

## 1. Purpose

`sdwan-probe` is a lightweight, zero-dependency CLI tool that interrogates a running Cisco Catalyst SD-WAN cluster from the outside, using only standard network protocols. It extracts and displays certificate, identity, reachability, and DTLS handshake information for all three controller roles: SD-WAN Manager (vManage), SD-WAN Validator (vBond), and SD-WAN Controller (vSmart).

It requires no Cisco credentials, no API access, and no SD-WAN client software. It works from any Linux or macOS workstation with OpenSSL installed.

---

## 2. Background & Technical Context

Cisco Catalyst SD-WAN controllers use DTLS (UDP) and TLS (TCP) for their control plane. The following ports and protocols apply:

| Controller role | Protocol | Default port | Notes |
|---|---|---|---|
| SD-WAN Validator (vBond) | DTLS (UDP) | 12346 | Sends certificate + application payload on handshake |
| SD-WAN Manager (vManage) | HTTPS (TLS/TCP) | 443 or 8443 | Standard web TLS certificate |
| SD-WAN Controller (vSmart) | DTLS (UDP) | 12346 | Same as vBond |
| Any controller | TLS (TCP) | 23456 | Optional TLS fallback |

During a DTLS handshake with vBond or vSmart, the Cisco controller sends:
- Its X.509 certificate (Cisco PKI or Enterprise CA signed)
- A binary application-layer payload containing the org name (OU field), UUID, and cluster identity info

The tool must use the following proven technique to cleanly probe DTLS without binary garbage on the terminal:

```bash
echo "" | timeout 10 openssl s_client -dtls1_2 -brief \
  -connect <host>:<port> 2>&1 >/dev/null
```

stdout (binary payload) is discarded; stderr (DTLS handshake summary) is captured and parsed.

---

## 3. Goals

- Probe SD-WAN controllers without credentials or proprietary tooling
- Extract and display all available certificate and identity information
- Detect reachability, port state, and DTLS/TLS negotiation outcome
- Work standalone on Linux and macOS with only `openssl` as a system dependency
- Provide clean, colorized, human-readable terminal output
- Be scriptable (machine-readable output mode)

---

## 4. Non-Goals

- No SD-WAN API access or REST calls
- No vManage login or session management
- No configuration changes of any kind
- No support for Windows (not in v1)
- No ongoing monitoring or daemon mode (v1 is one-shot)

---

## 5. Runtime Dependencies

| Dependency | Source | Notes |
|---|---|---|
| Python 3.8+ | System | Standard on Linux/macOS |
| `openssl` CLI | System | Must be OpenSSL 1.1.1+ or LibreSSL 3.x for DTLS support |
| `rich` | PyPI | Terminal color, tables, panels, progress |
| `click` | PyPI | CLI argument parsing |
| `cryptography` | PyPI | X.509 certificate parsing from PEM |

No other third-party dependencies. Installable via `pip install sdwan-probe` or by running `probe.py` directly after `pip install -r requirements.txt`.

---

## 6. Installation

```bash
pip install sdwan-probe          # from PyPI (preferred)
# or
git clone https://github.com/<org>/sdwan-probe
cd sdwan-probe && pip install .
```

Single entry point: `sdwan-probe` (or `python -m sdwanprobe` as fallback).

---

## 7. CLI Interface

### 7.1 Basic usage

```
sdwan-probe [OPTIONS] TARGET [TARGET ...]
```

`TARGET` is `<role>:<host>[:<port>]` where role is one of `vbond`, `vsmart`, `vmanage`.  
Port is optional; defaults apply per role (see section 2).

Examples:

```bash
# Probe a single vBond
sdwan-probe vbond:173.36.209.163

# Probe a full cluster
sdwan-probe vbond:10.0.1.1 vsmart:10.0.1.2 vsmart:10.0.1.3 vmanage:10.0.1.4

# Custom port
sdwan-probe vbond:10.0.1.1:12346 vmanage:10.0.1.4:8443

# Probe all roles from a YAML config file
sdwan-probe --config cluster.yaml

# JSON output (for scripting)
sdwan-probe --json vbond:10.0.1.1

# Increase timeout
sdwan-probe --timeout 15 vbond:10.0.1.1

# Disable color (for piping or logging)
sdwan-probe --no-color vbond:10.0.1.1
```

### 7.2 Options

| Option | Default | Description |
|---|---|---|
| `--config FILE` | — | YAML file defining cluster targets (see section 9) |
| `--timeout SEC` | 10 | Per-probe connection timeout in seconds |
| `--json` | off | Output raw JSON instead of pretty terminal output |
| `--no-color` | off | Disable ANSI color codes (auto-detected if not a TTY) |
| `--verbose` | off | Show raw OpenSSL stderr output for debugging |
| `--version` | — | Print version and exit |

---

## 8. Probe Logic

### 8.1 DTLS probe (vBond, vSmart — UDP 12346)

Implementation uses subprocess to call the system `openssl` binary:

```python
cmd = [
    "openssl", "s_client",
    "-dtls1_2",
    "-brief",
    "-connect", f"{host}:{port}"
]
result = subprocess.run(
    cmd,
    input=b"\n",             # close stdin immediately — prevents hang
    capture_output=True,     # stdout (binary payload) captured but discarded
    timeout=timeout
)
output = result.stderr.decode("utf-8", errors="replace")
```

Parse `output` (stderr) for:
- `CONNECTION ESTABLISHED` → reachable
- `Protocol version:` → DTLS version negotiated
- `Ciphersuite:` → cipher suite
- `Peer certificate:` → raw subject DN
- `depth=0 ...CN=...` → certificate CN
- `verify error:num=...` → certificate trust status
- `Server Temp Key:` → key exchange info

Then re-parse the peer certificate using `openssl s_client` with `-showcerts` to extract the full PEM, then use the `cryptography` library to parse:
- Subject: CN, O, OU, C, ST, L
- Issuer: full chain
- Serial number
- Not Before / Not After (validity window)
- SANs (Subject Alternative Names)
- Signature algorithm
- Public key type and size
- Certificate fingerprint (SHA-256)
- Days until expiry (computed from Not After vs. today)

### 8.2 TLS probe (vManage — TCP 443/8443)

Use Python `ssl` module directly (no subprocess needed):

```python
import ssl, socket
from cryptography import x509

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

with socket.create_connection((host, port), timeout=timeout) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
        der = ssock.getpeercert(binary_form=True)
        cipher = ssock.cipher()
        tls_version = ssock.version()

cert = x509.load_der_x509_certificate(der)
```

Extract same certificate fields as DTLS probe.

### 8.3 Reachability states

Each probe must resolve to exactly one of the following states:

| State | Meaning |
|---|---|
| `REACHABLE` | DTLS/TLS handshake completed, certificate obtained |
| `HANDSHAKE_FAILED` | Port open but handshake failed (wrong protocol, cert error, etc.) |
| `TIMEOUT` | No response within timeout window |
| `REFUSED` | Connection actively refused (TCP RST or ICMP port unreachable) |
| `DNS_ERROR` | Hostname could not be resolved |
| `OPENSSL_ERROR` | Local openssl execution failure |

### 8.4 SD-WAN identity extraction

For vBond/vSmart DTLS responses, the application-layer payload sent after the handshake contains SD-WAN-specific identity strings. Although this payload is binary, it contains readable strings. Use `strings`-style extraction (filter sequences of ≥4 printable ASCII chars) on the stdout bytes to extract:

- Organization name (OU field cross-reference)
- Cluster UUID (format: 8-4-4-4-12 hex)
- Node UUID
- `Cisco12345` or custom OU identifier (confirms Cisco PKI vs Enterprise CA)

These are supplementary — present when available, omitted when not parseable. Do not fail the probe if extraction fails.

---

## 9. Config File Format

```yaml
# cluster.yaml
cluster_name: "MyProvider SD-WAN"
targets:
  - role: vbond
    host: 10.0.1.1
    port: 12346
    label: "vBond Primary"
  - role: vsmart
    host: 10.0.1.2
    label: "vSmart-1"
  - role: vsmart
    host: 10.0.1.3
    label: "vSmart-2"
  - role: vmanage
    host: 10.0.1.4
    label: "vManage"
    port: 8443
```

---

## 10. Terminal Output Specification

### 10.1 Layout

Use `rich` library throughout. Output structure per probe:

```
┌─────────────────────────────────────────────────────────┐
│  vBond  •  173.36.209.163:12346                         │
│  ● REACHABLE                                            │
└─────────────────────────────────────────────────────────┘

  Certificate
  ───────────────────────────────────────────────────────
  Subject CN        vbond-a83e6648-...-1.viptela.com
  Subject O         Cisco Systems, Inc.
  Subject OU        Cisco12345
  Issuer CN         Cisco Licensing Root CA
  Serial            3A:F2:...
  Fingerprint       SHA-256: AB:CD:EF:...

  Validity
  ───────────────────────────────────────────────────────
  Not Before        2023-01-15 08:00:00 UTC
  Not After         2026-01-14 08:00:00 UTC
  Days remaining    ███████████░░░░  267 days  [VALID]

  TLS / DTLS
  ───────────────────────────────────────────────────────
  Protocol          DTLSv1.2
  Cipher suite      ECDHE-RSA-AES256-GCM-SHA384
  Key exchange      ECDH secp521r1 (521 bits)
  Trust             ✗ Untrusted (unable to get local issuer cert)

  SD-WAN Identity
  ───────────────────────────────────────────────────────
  Cluster UUID      a83e6648-6a84-4ff2-9489-af97fbb43c94
  Node UUID         1fbd07f6-22b4-4263-af69-25074760e40f
  Org name (OU)     Cisco12345
  CA type           Cisco PKI
```

### 10.2 Color coding

| Element | Color |
|---|---|
| Role header (vBond / vSmart / vManage) | Bold cyan |
| `REACHABLE` status | Bold green |
| `TIMEOUT` / `REFUSED` status | Bold red |
| `HANDSHAKE_FAILED` status | Bold yellow |
| Section headings | Bold white |
| Certificate field labels | Dim white |
| Certificate field values | White |
| Days remaining bar — > 90 days | Green |
| Days remaining bar — 30–90 days | Yellow |
| Days remaining bar — < 30 days | Red (+ `[EXPIRING SOON]`) |
| Expired | Red bold + `[EXPIRED]` |
| Trust: untrusted (expected for Cisco PKI) | Yellow (not an error) |
| Error states | Red |
| UUID values | Cyan |

### 10.3 Summary table

After all probes complete, print a compact summary table:

```
  Summary
  ┌──────────────┬────────────────────┬───────────┬──────────────┬─────────────┐
  │ Role         │ Host               │ Status    │ Cert expiry  │ CA type     │
  ├──────────────┼────────────────────┼───────────┼──────────────┼─────────────┤
  │ vBond        │ 173.36.209.163     │ ● REACH.  │ 267 days     │ Cisco PKI   │
  │ vSmart       │ 10.0.1.2           │ ● REACH.  │ 267 days     │ Cisco PKI   │
  │ vManage      │ 10.0.1.4           │ ✗ TIMEOUT │ —            │ —           │
  └──────────────┴────────────────────┴───────────┴──────────────┴─────────────┘
```

### 10.4 Progress indication

When probing multiple targets, show a `rich` progress bar while probes run (probes execute concurrently via `concurrent.futures.ThreadPoolExecutor`).

---

## 11. JSON Output Schema

When `--json` is passed, print a single JSON object to stdout. No color, no rich output.

```json
{
  "sdwan_probe_version": "1.0.0",
  "probe_time": "2026-05-06T14:32:00Z",
  "targets": [
    {
      "role": "vbond",
      "host": "173.36.209.163",
      "port": 12346,
      "label": null,
      "status": "REACHABLE",
      "protocol": "DTLSv1.2",
      "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
      "key_exchange": "ECDH secp521r1 521 bits",
      "certificate": {
        "subject_cn": "vbond-a83e6648-6a84-4ff2-9489-af97fbb43c94-1.viptela.com",
        "subject_o": "Cisco Systems, Inc.",
        "subject_ou": "Cisco12345",
        "subject_c": "US",
        "subject_st": "California",
        "subject_l": "San Jose",
        "issuer_cn": "Cisco Licensing Root CA",
        "issuer_o": "Cisco Systems",
        "serial": "3AF2...",
        "fingerprint_sha256": "AB:CD:EF:...",
        "not_before": "2023-01-15T08:00:00Z",
        "not_after": "2026-01-14T08:00:00Z",
        "days_remaining": 267,
        "expired": false,
        "trusted": false,
        "trust_error": "unable to get local issuer certificate",
        "san": [],
        "signature_algorithm": "sha256WithRSAEncryption",
        "public_key_type": "RSA",
        "public_key_bits": 2048
      },
      "sdwan_identity": {
        "cluster_uuid": "a83e6648-6a84-4ff2-9489-af97fbb43c94",
        "node_uuid": "1fbd07f6-22b4-4263-af69-25074760e40f",
        "org_name": "Cisco12345",
        "ca_type": "Cisco PKI"
      },
      "error": null
    }
  ]
}
```

Fields that could not be determined must be `null`, never omitted.

---

## 12. CA Type Detection

Detect the CA type from the certificate issuer chain:

| Issuer pattern | CA type label |
|---|---|
| `Cisco Licensing Root CA` / `Cisco Systems` in issuer O | `Cisco PKI` |
| `DigiCert` / `Symantec` in issuer O | `DigiCert/Symantec (legacy)` |
| Any other issuer | `Enterprise CA` |
| No certificate obtained | `—` |

---

## 13. Project Structure

```
sdwan-probe/
├── sdwanprobe/
│   ├── __init__.py
│   ├── __main__.py          # python -m sdwanprobe entry point
│   ├── cli.py               # click CLI definition
│   ├── probe.py             # probe orchestration, concurrency
│   ├── dtls.py              # DTLS probe via openssl subprocess
│   ├── tls.py               # TLS probe via Python ssl module
│   ├── cert.py              # X.509 parsing using cryptography library
│   ├── identity.py          # SD-WAN identity string extraction
│   ├── output.py            # rich terminal rendering
│   └── models.py            # dataclasses for ProbeResult, CertInfo, etc.
├── tests/
│   ├── test_cert.py
│   ├── test_identity.py
│   └── test_output.py
├── pyproject.toml
├── requirements.txt
├── README.md
└── cluster.yaml.example
```

---

## 14. Error Handling

- If `openssl` is not found in PATH, exit immediately with a clear message and installation hint
- If `openssl` version does not support `-dtls1_2`, warn and attempt without the flag
- Individual probe failures must never crash the tool — record the error state and continue
- Timeout on one target must not delay others (concurrent execution)
- If all probes fail, exit with code 1; if any succeed, exit with code 0

---

## 15. README Requirements

The README must include:

- One-line description
- Prerequisites (Python 3.8+, openssl 1.1.1+)
- Installation (pip and from source)
- Usage examples covering single target, full cluster, config file, JSON output
- Sample terminal screenshot (use an SVG or PNG — do not use asciinema)
- Explanation of the DTLS probe technique and why `2>&1 >/dev/null` is used
- Note that `verify error` on Cisco PKI certs is expected (Cisco root not in system trust store)
- Note on the SD-WAN identity payload extraction (best-effort, not guaranteed)
- Contributing section
- MIT License

---

## 16. Acceptance Criteria

- [ ] `sdwan-probe vbond:173.36.209.163` completes and shows certificate CN, validity, and cluster UUID
- [ ] `sdwan-probe --json vbond:173.36.209.163` outputs valid JSON parseable by `jq`
- [ ] No binary garbage appears in terminal output under any circumstances
- [ ] Concurrent probes complete within `max(individual_timeouts) + 2s`
- [ ] Works on Ubuntu 22.04+, Debian 12+, macOS 13+ with system OpenSSL
- [ ] `pip install sdwan-probe` works cleanly in a fresh virtualenv
- [ ] All cert fields are `null` (not missing) when a probe fails
- [ ] Expired or near-expiry certs are visually distinct from healthy ones
