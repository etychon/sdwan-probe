"""Rich terminal rendering for probe results."""

from __future__ import annotations

from typing import Iterable, List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from sdwanprobe.models import CertInfo, ProbeResult, ProbeStatus, SDWANIdentity


def _role_title(role: str) -> str:
    m = {"vbond": "vBond", "vsmart": "vSmart", "vmanage": "vManage"}
    return m.get(role.lower(), role)


def _status_style(status: ProbeStatus) -> tuple[str, str]:
    if status == ProbeStatus.REACHABLE:
        return "● " + status.value, "bold green"
    if status in (ProbeStatus.TIMEOUT, ProbeStatus.REFUSED, ProbeStatus.DNS_ERROR, ProbeStatus.OPENSSL_ERROR):
        return "● " + status.value, "bold red"
    if status == ProbeStatus.HANDSHAKE_FAILED:
        return "● " + status.value, "bold yellow"
    return "● " + status.value, "white"


def _days_bar(days: Optional[int], expired: Optional[bool]) -> tuple[Text, str]:
    if expired:
        return Text("[EXPIRED]", style="bold red"), "bold red"
    if days is None:
        return Text("—", style="dim"), "white"
    if days < 0:
        return Text("[EXPIRED]", style="bold red"), "bold red"
    if days < 30:
        bar_style = "red"
        suffix = "  [EXPIRING SOON]"
    elif days <= 90:
        bar_style = "yellow"
        suffix = ""
    else:
        bar_style = "green"
        suffix = ""
    filled = min(15, max(0, int(days / 366 * 15)))
    bar = "█" * filled + "░" * (15 - filled)
    t = Text()
    t.append(bar, style=bar_style)
    t.append(f"  {days} days{suffix}")
    return t, bar_style


def _render_cert_section(cert: CertInfo) -> Table:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="white")
    rows = [
        ("Subject CN", cert.subject_cn),
        ("Subject O", cert.subject_o),
        ("Subject OU", cert.subject_ou),
        ("Issuer CN", cert.issuer_cn),
        ("Serial", cert.serial),
        ("Fingerprint", f"SHA-256: {cert.fingerprint_sha256}" if cert.fingerprint_sha256 else None),
    ]
    for label, val in rows:
        t.add_row(label + " ", val or "—")
    return t


def _render_validity(cert: CertInfo) -> Table:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="white")
    nb = cert.not_before or "—"
    na = cert.not_after or "—"
    t.add_row("Not Before ", nb)
    t.add_row("Not After ", na)
    bar, _style = _days_bar(cert.days_remaining, cert.expired)
    t.add_row("Days remaining ", bar)
    return t


def _render_tls_section(res: ProbeResult) -> Table:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="white")
    t.add_row("Protocol ", res.protocol or "—")
    t.add_row("Cipher suite ", res.cipher_suite or "—")
    t.add_row("Key exchange ", res.key_exchange or "—")
    trust = "—"
    trust_style = "white"
    if res.certificate:
        if res.certificate.trusted is True:
            trust = "✓ Trusted"
            trust_style = "green"
        elif res.certificate.trusted is False:
            trust = "✗ Untrusted"
            if res.certificate.trust_error:
                trust += f" ({res.certificate.trust_error})"
            trust_style = "yellow"
    t.add_row(Text("Trust "), Text(trust, style=trust_style))
    return t


def _render_identity_section(ident: SDWANIdentity) -> Table:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="cyan")
    t.add_row("Cluster UUID ", ident.cluster_uuid or "—")
    t.add_row("Node UUID ", ident.node_uuid or "—")
    t.add_row("Org name (OU) ", ident.org_name or "—")
    t.add_row("CA type ", ident.ca_type or "—")
    return t


def render_probe(console: Console, res: ProbeResult) -> None:
    title = f"{_role_title(res.role)}  •  {res.host}:{res.port}"
    if res.label:
        title += f"  ({res.label})"
    status_txt, status_style = _status_style(res.status)
    header = Text()
    header.append(title + "\n", style="bold cyan")
    header.append(status_txt, style=status_style)
    console.print(Panel(header, box=box.ROUNDED))

    if res.error and res.status != ProbeStatus.REACHABLE:
        console.print(Text(f"  Error: {res.error}", style="red"))
    if res.raw_openssl_stderr:
        console.print(Text(res.raw_openssl_stderr, style="dim"))

    if res.status != ProbeStatus.REACHABLE or not res.certificate:
        console.print()
        return

    cert = res.certificate
    console.print(Text("  Certificate", style="bold white"))
    console.print(Text("  " + "─" * 55, style="dim"))
    console.print(_render_cert_section(cert))

    console.print()
    console.print(Text("  Validity", style="bold white"))
    console.print(Text("  " + "─" * 55, style="dim"))
    console.print(_render_validity(cert))

    console.print()
    console.print(Text("  TLS / DTLS", style="bold white"))
    console.print(Text("  " + "─" * 55, style="dim"))
    console.print(_render_tls_section(res))

    if res.sdwan_identity and (
        res.sdwan_identity.cluster_uuid
        or res.sdwan_identity.node_uuid
        or res.sdwan_identity.org_name
        or res.sdwan_identity.ca_type
    ):
        console.print()
        console.print(Text("  SD-WAN Identity", style="bold white"))
        console.print(Text("  " + "─" * 55, style="dim"))
        console.print(_render_identity_section(res.sdwan_identity))

    console.print()


def _summary_status_cell(res: ProbeResult) -> Text:
    if res.status == ProbeStatus.REACHABLE:
        return Text("● REACH.", style="bold green")
    if res.status == ProbeStatus.TIMEOUT:
        return Text("✗ TIMEOUT", style="bold red")
    if res.status == ProbeStatus.REFUSED:
        return Text("✗ REFUSED", style="bold red")
    if res.status == ProbeStatus.DNS_ERROR:
        return Text("✗ DNS", style="bold red")
    if res.status == ProbeStatus.OPENSSL_ERROR:
        return Text("✗ OPENSSL", style="bold red")
    return Text("⚠ HS FAIL", style="bold yellow")


def _expiry_cell(res: ProbeResult) -> Text:
    c = res.certificate
    if not c or c.days_remaining is None:
        return Text("—", style="dim")
    if c.expired:
        return Text("expired", style="bold red")
    d = c.days_remaining
    if d < 30:
        return Text(f"{d} days", style="red")
    if d <= 90:
        return Text(f"{d} days", style="yellow")
    return Text(f"{d} days", style="green")


def _ca_cell(res: ProbeResult) -> str:
    if res.sdwan_identity and res.sdwan_identity.ca_type:
        return res.sdwan_identity.ca_type
    if res.certificate:
        from sdwanprobe.cert import detect_ca_type

        return detect_ca_type(res.certificate.issuer_cn, res.certificate.issuer_o)
    return "—"


def render_summary(console: Console, results: Iterable[ProbeResult]) -> None:
    console.print(Text("  Summary", style="bold white"))
    table = Table(box=box.ROUNDED, show_edge=True)
    table.add_column("Role", style="cyan")
    table.add_column("Host")
    table.add_column("Status")
    table.add_column("Cert expiry")
    table.add_column("CA type")
    for r in results:
        table.add_row(
            _role_title(r.role),
            r.host,
            _summary_status_cell(r),
            _expiry_cell(r),
            _ca_cell(r),
        )
    console.print(table)


def make_probe_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    )
