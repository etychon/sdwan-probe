"""Click CLI entry point."""

from __future__ import annotations

import json
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console

from sdwanprobe import __version__
from sdwanprobe.models import ProbeStatus, TargetSpec
from sdwanprobe.output import make_probe_progress, render_probe, render_summary
from sdwanprobe.probe import (
    discover_targets_from_url,
    load_config,
    parse_target_token,
    run_probes,
)


@click.command("sdwan-probe", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("targets", nargs=-1)
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="YAML file with cluster targets.",
)
@click.option(
    "--discover-from-url",
    "discover_from_url",
    type=str,
    help="Infer vManage/vBond/vSmart targets from login URL/hostname via DNS.",
)
@click.option("--timeout", default=10, show_default=True, help="Per-probe timeout (seconds).")
@click.option(
    "--verify-cisco-ca",
    is_flag=True,
    help="Verify peer chains against bundled Cisco PKI roots (optional).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON to stdout.")
@click.option("--no-color", is_flag=True, help="Disable ANSI colors.")
@click.option("--verbose", is_flag=True, help="Include raw OpenSSL stderr in output.")
@click.version_option(__version__, "--version")
def cli(
    targets: tuple[str, ...],
    config_file: Optional[Path],
    discover_from_url: Optional[str],
    timeout: int,
    verify_cisco_ca: bool,
    as_json: bool,
    no_color: bool,
    verbose: bool,
) -> None:
    """Probe Cisco Catalyst SD-WAN controllers (vBond / vSmart / vManage) without credentials."""
    specs: List[TargetSpec] = []
    try:
        if config_file is not None:
            _name, cfg_targets = load_config(config_file)
            specs.extend(cfg_targets)
        unresolved_discovery: List[str] = []
        if discover_from_url is not None:
            discovered, unresolved_discovery = discover_targets_from_url(discover_from_url)
            if not discovered:
                raise ValueError(
                    f"No DNS-resolvable SD-WAN targets inferred from {discover_from_url!r}"
                )
            specs.extend(discovered)
        for t in targets:
            specs.append(parse_target_token(t))
    except (ValueError, RuntimeError, KeyError, TypeError) as e:
        raise click.UsageError(str(e)) from e

    if not specs:
        raise click.UsageError(
            "Provide at least one TARGET (role:host[:port]), use --config FILE, "
            "or pass --discover-from-url URL."
        )

    # Keep first occurrence to preserve user-provided ordering.
    deduped: List[TargetSpec] = []
    seen = set()
    for s in specs:
        key = (s.role, s.host, s.port)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(s)
    specs = deduped

    color_system = None if (no_color or as_json) else "standard"
    console = Console(
        force_terminal=not no_color if not as_json else False,
        color_system=color_system,
    )

    if discover_from_url and not as_json:
        discovered_labels = ", ".join(f"{t.role}:{t.host}:{t.port}" for t in specs)
        console.print(f"[cyan]Discovered targets:[/cyan] {discovered_labels}")
        if unresolved_discovery:
            skipped = ", ".join(unresolved_discovery)
            console.print(f"[yellow]Discovery skipped (no DNS):[/yellow] {skipped}")
    if verify_cisco_ca and not as_json:
        console.print("[cyan]Trust mode:[/cyan] verify chains against bundled Cisco roots")

    if as_json:
        results = run_probes(specs, timeout, verbose=verbose, verify_with_cisco_ca=verify_cisco_ca)
        payload = {
            "sdwan_probe_version": __version__,
            "probe_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": [r.to_json_dict() for r in results],
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        with warnings.catch_warnings(record=True) as wrec:
            warnings.simplefilter("always", UserWarning)
            if len(specs) > 1:
                with make_probe_progress() as progress:
                    task_id = progress.add_task("Probing…", total=len(specs))

                    def cb(done: int, total: int) -> None:
                        progress.update(task_id, completed=done)

                    results = run_probes(
                        specs,
                        timeout,
                        verbose=verbose,
                        verify_with_cisco_ca=verify_cisco_ca,
                        progress_callback=cb,
                    )
            else:
                results = run_probes(
                    specs, timeout, verbose=verbose, verify_with_cisco_ca=verify_cisco_ca
                )

            for w in wrec:
                if issubclass(w.category, UserWarning):
                    console.print(f"[yellow]{w.message}[/yellow]")

        for r in results:
            render_probe(console, r)
        render_summary(console, results)

    ok_any = any(r.status == ProbeStatus.REACHABLE for r in results)
    sys.exit(0 if ok_any else 1)
