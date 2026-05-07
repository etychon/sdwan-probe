# sdwan-probe

`sdwan-probe` is a command-line tool that checks reachability and certificate posture of Cisco Catalyst SD-WAN control components from the outside, without API credentials.

It probes:
- `vManage` over TLS (`443` by default)
- `vBond` and `vSmart` over DTLS (`12346` by default)

It is designed for quick operational checks, troubleshooting, and automation pipelines.

## Important Disclaimer

- Author: **Emmanuel Tychon**
- This is a **personal project**.
- This repository is **not endorsed by Cisco**.
- Cisco product names are trademarks of Cisco and used here only for compatibility context.

## What This Tool Does

- Validates basic network reachability and handshake behavior for SD-WAN controllers.
- Extracts and parses peer certificates (subject, issuer, expiry, key size, fingerprint).
- Reports useful SD-WAN identity hints (when available from DTLS payload patterns).
- Supports DNS-based target discovery from a login URL.
- Outputs both human-readable terminal views and machine-readable JSON.

## What This Tool Does Not Do

- It does not log in to your controllers.
- It does not call vManage REST APIs.
- It does not modify controller configuration.
- It does not replace full certificate compliance auditing.

## Who This Is For

- Network and SecOps engineers validating SD-WAN edge/control-plane exposure.
- SRE/platform teams needing a lightweight readiness probe in scripts or CI.
- Anyone troubleshooting control-plane certificate and handshake failures.

## Requirements

- Linux or macOS shell environment
- Python `3.8+`
- OpenSSL `1.1.1+` (or LibreSSL with DTLS client support) available as `openssl`

## Installation (Beginner Friendly)

Many modern Python distributions (Linux and macOS) enforce [PEP 668](https://peps.python.org/pep-0668/), which blocks global `pip install` and shows:
`error: externally-managed-environment`.

If you see that error, use **Option A (`pipx`)** or **Option B (virtual environment)** below.

### Option A (Recommended): Install with pipx

`sdwan-probe` is currently installed from GitHub (not PyPI), so use the Git URL form with `pipx`.

Linux (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
pipx install git+https://github.com/etychon/sdwan-probe.git
```

Linux (Fedora):

```bash
sudo dnf install -y pipx
pipx ensurepath
pipx install git+https://github.com/etychon/sdwan-probe.git
```

macOS (Homebrew):

```bash
brew install pipx
pipx ensurepath
pipx install git+https://github.com/etychon/sdwan-probe.git
```

Then verify:

```bash
sdwan-probe --help
```

If/when the project is published to PyPI, this shorter command will work:

```bash
pipx install sdwan-probe
```

### Option B: Install in a virtual environment (venv)

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install sdwan-probe
```

### Option C: Install from GitHub source (local checkout)

```bash
git clone https://github.com/etychon/sdwan-probe.git
cd sdwan-probe
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
```

For development mode:

```bash
python3 -m pip install -e ".[dev]"
```

## Update to Latest Version

Use the update path that matches how you installed the tool.

### If installed with pipx (GitHub URL)

Check current version:

```bash
sdwan-probe --version
```

Upgrade to latest commit on default branch:

```bash
pipx upgrade sdwan-probe
```

Note: `pipx upgrade` is version-based. If `pyproject.toml` version has not changed, pipx may report "already at latest version" even when new commits exist on GitHub.

To force-refresh from the latest GitHub `main` code:

```bash
pipx install --force git+https://github.com/etychon/sdwan-probe.git@main
```

If needed, reinstall from scratch:

```bash
pipx uninstall sdwan-probe
pipx install git+https://github.com/etychon/sdwan-probe.git
```

### If installed in a virtual environment (venv)

Activate your environment, then upgrade:

```bash
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade git+https://github.com/etychon/sdwan-probe.git
```

### If running from a local git clone

Pull latest changes and reinstall in your virtual environment:

```bash
cd sdwan-probe
git pull --rebase
source .venv/bin/activate
python3 -m pip install -e .
```

### Verify after update

```bash
sdwan-probe --version
sdwan-probe --help
```

## Versioning (for maintainers)

This project uses automatic versioning via `setuptools-scm`.

- Release versions come from git tags (example: `v1.0.2` -> package version `1.0.2`)
- Commits after a tag automatically get dev versions (example: `1.0.3.devN+g<hash>`)

Create and push a new release tag:

```bash
git tag v1.0.2
git push origin v1.0.2
```

## Quick Start

Probe one vBond target:

```bash
sdwan-probe vbond:203.0.113.10
```

Probe a full cluster:

```bash
sdwan-probe vbond:10.0.1.1 vsmart:10.0.1.2 vmanage:10.0.1.4
```

Use hostnames or login URLs:

```bash
sdwan-probe vmanage:vmanage-acme.sdwan.example.net
sdwan-probe vmanage:https://vmanage-acme.sdwan.example.net
```

Discover likely targets from login URL (DNS-based):

```bash
sdwan-probe --discover-from-url https://vmanage-acme.sdwan.example.net
```

JSON output (for scripts):

```bash
sdwan-probe --json --discover-from-url https://vmanage-acme.sdwan.example.net
```

## Target Syntax

Positional target format:

```text
<role>:<host>[:<port>]
```

Allowed roles:
- `vbond`
- `vsmart`
- `vmanage`

Examples:

```bash
sdwan-probe vbond:198.51.100.10
sdwan-probe vmanage:example.com:8443
sdwan-probe vmanage:https://vmanage-acme.sdwan.example.net/login
```

## CLI Reference

### Command

```bash
sdwan-probe [OPTIONS] [TARGET ...]
```

### Options

- `--config FILE`  
  Load targets from YAML file.

- `--discover-from-url URL`  
  Infer probable `vmanage`/`vbond`/`vsmart` hostnames from a vManage-style URL and include DNS-resolvable ones.  
  Pass only the URL/hostname (for example `https://vmanage-acme.sdwan.example.net`), not `vmanage:...`.

- `--timeout INTEGER` (default: `10`)  
  Per-target probe timeout in seconds.

- `--verify-cisco-ca`  
  Attempt certificate-chain verification against bundled Cisco PKI root(s).  
  Best effort only; overlays may use tenant/enterprise chains not in the bundle.

- `--json`  
  Emit JSON payload to stdout.

- `--no-color`  
  Disable ANSI color output.

- `--verbose`  
  Include raw OpenSSL stderr details in output.

- `--version`  
  Print tool version.

- `-h`, `--help`  
  Show help text.

### Exit Codes

- `0`: At least one target was reachable.
- `1`: No target reachable, or command/use error.

## YAML Config File

Example:

```yaml
cluster_name: branch-eu-demo
targets:
  - role: vbond
    host: vbond-acme.sdwan.example.net
  - role: vsmart
    host: vsmart-acme.sdwan.example.net
  - role: vmanage
    host: https://vmanage-acme.sdwan.example.net
```

Run:

```bash
sdwan-probe --config cluster.yaml
```

## Certificate Trust Behavior

Default mode is probe-oriented and permissive for trust-chain collection, because many SD-WAN deployments use private or non-system trust anchors.

If you enable:

```bash
--verify-cisco-ca
```

then chain validation is attempted using bundled Cisco PKI root material. This can still fail when:
- the overlay uses enterprise CA roots,
- intermediates are missing in the presented chain,
- or your deployment uses a different trust anchor set.

## How Discovery from URL Works

Given:

```text
https://vmanage-acme.sdwan.example.net
```

the tool infers:
- `vmanage-acme.sdwan.example.net`
- `vbond-acme.sdwan.example.net`
- `vsmart-acme.sdwan.example.net`

It keeps only DNS-resolvable candidates, then probes them.

## How the Probe Works Internally

- `vManage` uses Python `ssl` for TLS handshake and certificate capture.
- `vBond` / `vSmart` try multiple protocol+port combinations when default controller ports are used:
  - DTLS/UDP on `12346`
  - TLS/TCP on `12346`
  - DTLS/UDP on `23456`
  - TLS/TCP on `23456`
- For DTLS, output parsing is split so binary payload data does not pollute terminal output.
- Certificates are parsed with `cryptography`.
- Identity extraction from DTLS payload is heuristic and best-effort.

## Sample Output

![Example sdwan-probe terminal layout](docs/sample-terminal.svg)

## Troubleshooting

### `command not found: sdwan-probe`

Try:

```bash
python3 -m sdwanprobe --help
```

or reinstall with `python3 -m pip install .`.

### `TIMEOUT` on vManage

- Confirm route/firewall path to TCP `443`.
- Check if source IP is allow-listed.
- Retry with higher timeout: `--timeout 20`.

### `verify error:num=20:unable to get local issuer certificate`

Expected in many environments when trust chain is not fully available locally.
Use probe mode without strict verify or provide your org trust bundle in future enhancements.

### `CERTIFICATE_VERIFY_FAILED` with `self-signed certificate`

This usually means the server is presenting a certificate chain that is not anchored in the bundled Cisco roots (for example enterprise/private CA, SSL interception, or a different certificate path than expected).

Confirm what certificate is actually presented from your network path:

```bash
openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
```

Then compare with expected controller certificates and trust anchors.

### `DNS_ERROR` for discovered targets

The inferred hostname does not resolve publicly from your resolver/view.
Use explicit `TARGET` values if your naming does not follow standard pattern.

## Security and Privacy Notes

- Do not commit internal hostnames, CA bundles, or sensitive diagnostics to public repositories.
- This tool does not require controller credentials.
- No secrets are embedded in source code.

## Contributing

Contributions are welcome. Please:
- keep changes focused,
- add/adjust tests for behavior changes,
- update docs for user-facing flags or outputs.

## License

This project is licensed under the MIT License. See:
- [`LICENSE`](LICENSE)
- [`NOTICE.md`](NOTICE.md)
