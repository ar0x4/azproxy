"""
AzProx CLI — dead simple IP rotation through Azure Functions.

Design principle: if the first arg isn't a known subcommand, it's a command
to run through the proxy. Just like proxychains.

    azprox curl https://ifconfig.me          ← proxied command
    azprox python3 spray.py                  ← proxied command
    azprox deploy                            ← subcommand
    azprox nuke                              ← subcommand
"""
from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.table import Table

from azprox import __version__

console = Console()

# ── Known subcommands ──────────────────────────────────────────────────────
# Anything NOT in this set is treated as a command to execute through the proxy.
SUBCOMMANDS = {"init", "deploy", "status", "nuke", "serve", "regions", "version", "help", "--help", "-h"}


def main():
    """
    Entry point. Routes to subcommand handler or proxy-exec mode.

    If argv[1] is a known subcommand → dispatch to handler.
    If argv[1] is anything else → treat entire argv[1:] as a command to proxy.
    """
    if len(sys.argv) < 2 or sys.argv[1] in ("help", "--help", "-h"):
        _print_usage()
        return

    cmd = sys.argv[1]

    if cmd == "version":
        console.print(f"azprox v{__version__}")

    elif cmd == "init":
        _cmd_init(sys.argv[2:])

    elif cmd == "deploy":
        _cmd_deploy(sys.argv[2:])

    elif cmd == "status":
        _cmd_status(sys.argv[2:])

    elif cmd == "nuke":
        _cmd_nuke(sys.argv[2:])

    elif cmd == "serve":
        _cmd_serve(sys.argv[2:])

    elif cmd == "regions":
        _cmd_regions()

    else:
        # Not a subcommand → proxy-exec mode
        _cmd_proxy_exec(sys.argv[1:])


# ── Usage ──────────────────────────────────────────────────────────────────

def _print_usage():
    console.print(f"\n[bold]AzProx[/bold] v{__version__} — Azure Functions IP rotation proxy\n")
    console.print("  [bold]Usage:[/bold]")
    console.print("    azprox <command>                  run command through proxy")
    console.print("    azprox curl https://ifconfig.me   example: curl through rotating IPs")
    console.print("    azprox python3 spray.py           example: any tool, any args")
    console.print()
    console.print("  [bold]Setup:[/bold]")
    console.print("    azprox init                       authenticate to Azure")
    console.print("    azprox deploy                     deploy proxy functions (5 random EU regions)")
    console.print("    azprox deploy -n 10               deploy to 10 regions")
    console.print("    azprox deploy --regions eu        deploy to all EU regions")
    console.print()
    console.print("  [bold]Management:[/bold]")
    console.print("    azprox status                     show deployed endpoints & health")
    console.print("    azprox serve                      start persistent local proxy")
    console.print("    azprox regions                    list available Azure regions")
    console.print("    azprox nuke                       tear down everything")
    console.print("    azprox nuke --force               skip confirmation")
    console.print()


# ── Subcommand handlers ───────────────────────────────────────────────────

def _cmd_init(args: list[str]):
    """Authenticate to Azure (az login, or service-principal flags)."""
    import argparse
    parser = argparse.ArgumentParser(prog="azprox init")
    parser.add_argument("--client-id", help="Service principal client ID")
    parser.add_argument("--secret", help="Service principal secret")
    parser.add_argument("--tenant", help="Azure AD tenant ID")
    parser.add_argument("--subscription", help="Azure subscription ID")
    parsed = parser.parse_args(args)

    from azprox.core.auth import authenticate

    try:
        session = authenticate(
            client_id=parsed.client_id,
            client_secret=parsed.secret,
            tenant_id=parsed.tenant,
            subscription_id=parsed.subscription,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Authentication failed:[/red] {exc}")
        sys.exit(1)

    console.print("[green]✓ Authenticated to Azure[/green]")
    console.print(f"  Subscription: [cyan]{session.subscription_id}[/cyan]")
    if session.tenant_id:
        console.print(f"  Tenant:       [dim]{session.tenant_id}[/dim]")


def _cmd_deploy(args: list[str]):
    """Deploy Function App proxies to the resolved regions."""
    import argparse
    parser = argparse.ArgumentParser(prog="azprox deploy")
    parser.add_argument("-n", "--count", type=int, default=5, help="Number of regions (default: 5)")
    parser.add_argument("--regions", default=None, help="'eu', 'us', 'apac', 'all', or comma-separated list")
    parser.add_argument("--stealth", action="store_true", help="Use bland resource names (default: True)")
    parsed = parser.parse_args(args)

    from azprox.core.config import has_deployment
    from azprox.core.regions import (
        ALL_REGIONS,
        APAC_REGIONS,
        EU_REGIONS,
        US_REGIONS,
        resolve_regions,
    )

    if has_deployment():
        console.print("[yellow]An active deployment already exists.[/yellow] Run [bold]azprox nuke[/bold] first.")
        sys.exit(1)

    arg = parsed.regions
    if arg is None:
        regions = resolve_regions(count=parsed.count)
    else:
        keyword = arg.strip().lower()
        pools = {"eu": EU_REGIONS, "us": US_REGIONS, "apac": APAC_REGIONS, "all": ALL_REGIONS}
        if keyword in pools:
            regions = pools[keyword].copy()
        else:
            regions = resolve_regions(regions_csv=arg)

    if not regions:
        console.print("[red]No regions resolved.[/red]")
        sys.exit(1)

    from azprox.core.deployer import Deployer

    try:
        state = Deployer().deploy(regions)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Deploy failed:[/red] {exc}")
        sys.exit(1)

    active = len(state.active_endpoints)
    console.print(
        f"\n[green]Deployment complete.[/green] {active}/{len(state.endpoints)} endpoints healthy. "
        f"Use: [bold]azprox curl https://ifconfig.me[/bold]"
    )


def _cmd_status(args: list[str]):
    """Health-check every endpoint and print a status table."""
    from azprox.core.config import load_state, save_state

    try:
        state = load_state()
    except FileNotFoundError:
        console.print("[yellow]No active deployment.[/yellow] Run: [bold]azprox deploy[/bold]")
        return

    import asyncio

    from azprox.core.health import check_deployment_health

    console.print("[dim]checking endpoint health...[/dim]")
    try:
        results = asyncio.run(check_deployment_health(state))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Health check failed:[/red] {exc}")
        results = []

    by_url = {r.endpoint.url: r for r in results}

    table = Table(title="AzProx Endpoints")
    table.add_column("Region", style="cyan")
    table.add_column("Endpoint", style="dim")
    table.add_column("Status")
    table.add_column("Outbound IP", style="magenta")
    table.add_column("ms", justify="right", style="dim")

    healthy = 0
    for ep in state.endpoints:
        r = by_url.get(ep.url)
        if r and r.healthy:
            healthy += 1
            status = "[green]healthy[/green]"
            ip = r.outbound_ip
            ms = f"{r.response_time_ms:.0f}"
        elif r:
            status = "[red]unhealthy[/red]"
            ip = r.error[:30]
            ms = f"{r.response_time_ms:.0f}"
        else:
            status = f"[yellow]{ep.status}[/yellow]"
            ip = ""
            ms = ""
        table.add_row(ep.region, ep.url, status, ip, ms)

    console.print(table)
    save_state(state)
    console.print(
        f"\n  [dim]{healthy}/{len(state.endpoints)} healthy | rg: {state.resource_group} "
        f"| key: {state.auth_key[:8]}...[/dim]"
    )


def _cmd_nuke(args: list[str]):
    """Delete the resource group and clear local state (--force skips the prompt)."""
    force = "--force" in args or "-f" in args

    from azprox.core.config import load_state
    try:
        state = load_state()
    except FileNotFoundError:
        console.print("[dim]Nothing to nuke — no active deployment.[/dim]")
        return

    if not force:
        console.print(f"[yellow]This will destroy {len(state.endpoints)} endpoints in [bold]{state.resource_group}[/bold][/yellow]")
        confirm = input("Type 'yes' to confirm: ")
        if confirm.strip().lower() != "yes":
            console.print("[dim]Aborted.[/dim]")
            return

    from azprox.core.deployer import Deployer

    try:
        Deployer().destroy()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Nuke failed:[/red] {exc}")
        sys.exit(1)


def _cmd_serve(args: list[str]):
    """Run a persistent local proxy in the foreground."""
    import argparse
    parser = argparse.ArgumentParser(prog="azprox serve")
    parser.add_argument("-p", "--port", type=int, default=8080)
    parser.add_argument("--random", action="store_true", help="Random endpoint selection")
    parsed = parser.parse_args(args)

    from azprox.core.config import load_state
    from azprox.proxy.server import run_proxy_server

    try:
        state = load_state()
    except FileNotFoundError:
        console.print("[red]No active deployment.[/red] Run: [bold]azprox deploy[/bold]")
        sys.exit(1)

    strategy = "random" if parsed.random else "round-robin"

    run_proxy_server(
        endpoints=state.endpoint_urls,
        auth_key=state.auth_key,
        strategy=strategy,
        port=parsed.port,
    )


def _cmd_regions():
    """List available Azure regions."""
    from azprox.core.regions import EU_REGIONS, US_REGIONS, APAC_REGIONS

    table = Table(title="Available Azure Regions")
    table.add_column("Region", style="cyan")
    table.add_column("Pool", style="dim")

    for r in EU_REGIONS:
        table.add_row(r, "eu")
    for r in US_REGIONS:
        table.add_row(r, "us")
    for r in APAC_REGIONS:
        table.add_row(r, "apac")

    console.print(table)


# ── Proxy-exec mode ───────────────────────────────────────────────────────

def _cmd_proxy_exec(command: list[str]):
    """Run a command with its HTTP(S) traffic routed through the proxy."""
    from azprox.core.config import load_state
    from azprox.proxy.server import exec_with_proxy

    try:
        state = load_state()
    except FileNotFoundError:
        console.print("[red]No active deployment.[/red] Run: [bold]azprox deploy[/bold] first.")
        sys.exit(1)

    if not state.endpoint_urls:
        console.print("[red]No healthy endpoints.[/red] Run: [bold]azprox status[/bold] to check.")
        sys.exit(1)

    exit_code = exec_with_proxy(
        endpoints=state.endpoint_urls,
        auth_key=state.auth_key,
        command=command,
    )
    sys.exit(exit_code)


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
