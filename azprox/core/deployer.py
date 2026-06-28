"""Create and destroy the Azure Function proxy infrastructure (one deployment at a time)."""
from __future__ import annotations

import asyncio
import io
import secrets
import string
import time
import traceback
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests
from rich.console import Console

from azprox.core.auth import AzureSession
from azprox.core.config import (
    CONFIG_DIR,
    DeploymentState,
    EndpointState,
    clear_state,
    load_state,
    save_state,
)
from azprox.core.regions import get_region_short

console = Console()

RG_LOCATION = "westeurope"
HEALTH_TIMEOUT = 420.0
ZIPDEPLOY_RETRIES = 4


def _random_string(length: int, charset: str = string.ascii_lowercase + string.digits) -> str:
    return "".join(secrets.choice(charset) for _ in range(length))


class Deployer:
    def __init__(self):
        self.session: AzureSession | None = None

    def _ensure_auth(self):
        if not self.session:
            self.session = AzureSession.from_config()

    def deploy(self, regions: list[str]) -> DeploymentState:
        self._ensure_auth()
        assert self.session is not None

        auth_key = secrets.token_urlsafe(32)
        run_id = _random_string(8)
        rg_name = f"azp-{run_id}-rg"

        console.print(f"\n[bold]Deploying to {len(regions)} region(s)...[/bold]")
        console.print(f"  Resource group: [cyan]{rg_name}[/cyan]")
        console.print(f"  Auth key:       [dim]{auth_key[:12]}...[/dim]\n")

        console.print(f"  [dim]creating resource group {rg_name}...[/dim]")
        self.session.resource_client().resource_groups.create_or_update(rg_name, {"location": RG_LOCATION})

        endpoints: list[EndpointState] = []
        with ThreadPoolExecutor(max_workers=min(len(regions), 8)) as pool:
            futures = {
                pool.submit(self._deploy_region, region, rg_name, run_id, auth_key): region
                for region in regions
            }
            for fut in as_completed(futures):
                region = futures[fut]
                try:
                    ep = fut.result()
                    endpoints.append(ep)
                    console.print(f"  [green]✓[/green] {region:<20} {ep.url}")
                except Exception as exc:  # noqa: BLE001
                    console.print(f"  [red]✗[/red] {region:<20} {type(exc).__name__}: {exc}")
                    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
                    (CONFIG_DIR / "last-deploy-error.log").write_text(traceback.format_exc())

        if not endpoints:
            raise RuntimeError("All region deployments failed. Resource group left in place for inspection.")

        state = DeploymentState(
            resource_group=rg_name,
            subscription_id=self.session.subscription_id,
            auth_key=auth_key,
            created_at=datetime.now(timezone.utc).isoformat(),
            endpoints=endpoints,
        )
        save_state(state)

        console.print("\n  [dim]running health checks...[/dim]")
        from azprox.core.health import check_deployment_health

        for r in asyncio.run(check_deployment_health(state)):
            tag = "[green]healthy[/green]" if r.healthy else f"[red]unhealthy[/red] ({r.error})"
            ip = f" → {r.outbound_ip}" if r.outbound_ip else ""
            console.print(f"    {r.endpoint.region:<20} {tag}{ip}")
        save_state(state)
        return state

    def _deploy_region(self, region: str, rg_name: str, run_id: str, auth_key: str) -> EndpointState:
        assert self.session is not None
        short = get_region_short(region)
        storage_name = f"azpst{_random_string(12)}"
        plan_name = f"azp-{run_id}-{short}-plan"
        app_name = f"azp-{run_id}-{short}-{_random_string(4)}"

        sc = self.session.storage_client()
        wc = self.session.web_client()

        sc.storage_accounts.begin_create(rg_name, storage_name, {
            "location": region,
            "sku": {"name": "Standard_LRS"},
            "kind": "StorageV2",
            "properties": {"minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": False},
        }).result()
        keys = sc.storage_accounts.list_keys(rg_name, storage_name)
        # SDK model is a Mapping, so `.keys` is the dict method — index it.
        account_key = keys["keys"][0].value
        conn_str = (
            f"DefaultEndpointsProtocol=https;AccountName={storage_name};"
            f"AccountKey={account_key};EndpointSuffix=core.windows.net"
        )

        plan = wc.app_service_plans.begin_create_or_update(rg_name, plan_name, {
            "location": region,
            "kind": "functionapp",
            "sku": {"name": "Y1", "tier": "Dynamic"},
            "properties": {"reserved": True},
        }).result()

        app_settings = [
            {"name": "FUNCTIONS_EXTENSION_VERSION", "value": "~4"},
            {"name": "FUNCTIONS_WORKER_RUNTIME", "value": "python"},
            {"name": "AzureWebJobsStorage", "value": conn_str},
            {"name": "AzureWebJobsFeatureFlags", "value": "EnableWorkerIndexing"},
            {"name": "AZUREPROX_KEY", "value": auth_key},
            {"name": "SCM_DO_BUILD_DURING_DEPLOYMENT", "value": "true"},
            {"name": "ENABLE_ORYX_BUILD", "value": "true"},
            {"name": "APPINSIGHTS_INSTRUMENTATIONKEY", "value": ""},
            {"name": "APPLICATIONINSIGHTS_CONNECTION_STRING", "value": ""},
        ]
        wc.web_apps.begin_create_or_update(rg_name, app_name, {
            "location": region,
            "kind": "functionapp,linux",
            "properties": {
                "serverFarmId": plan.id,
                "reserved": True,
                "httpsOnly": True,
                "siteConfig": {
                    "linuxFxVersion": "Python|3.11",
                    "appSettings": app_settings,
                    "ftpsState": "Disabled",
                    "minTlsVersion": "1.2",
                },
            },
        }).result()

        self._zip_deploy(app_name)
        self._wait_for_health(app_name)

        return EndpointState(
            region=region,
            function_app_name=app_name,
            url=f"https://{app_name}.azurewebsites.net/api/proxy",
            storage_account=storage_name,
            status="active",
        )

    def _zip_deploy(self, app_name: str) -> None:
        assert self.session is not None
        zip_bytes = self._build_zip()
        scm_url = f"https://{app_name}.scm.azurewebsites.net/api/zipdeploy"
        last_err = ""
        for attempt in range(1, ZIPDEPLOY_RETRIES + 1):
            try:
                resp = requests.post(
                    scm_url,
                    headers={
                        "Authorization": f"Bearer {self.session.mgmt_token()}",
                        "Content-Type": "application/zip",
                    },
                    data=zip_bytes,
                    timeout=600,
                )
                if resp.status_code in (200, 202):
                    return
                last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
            except requests.RequestException as exc:
                last_err = f"{type(exc).__name__}: {exc}"
            time.sleep(15 * attempt)  # SCM may not be ready right after app creation
        raise RuntimeError(f"zip deploy failed for {app_name}: {last_err}")

    def _build_zip(self) -> bytes:
        template_dir = Path(__file__).parent.parent / "function_template"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in template_dir.iterdir():
                if f.is_file() and not f.name.startswith("."):
                    zf.write(f, f.name)
        return buf.getvalue()

    def _wait_for_health(self, app_name: str) -> None:
        health_url = f"https://{app_name}.azurewebsites.net/api/health"
        deadline = time.time() + HEALTH_TIMEOUT
        last = ""
        while time.time() < deadline:
            try:
                resp = requests.get(health_url, timeout=20)
                if resp.status_code == 200:
                    return
                last = f"HTTP {resp.status_code}"
            except requests.RequestException as exc:
                last = type(exc).__name__
            time.sleep(10)
        raise RuntimeError(f"{app_name} not healthy within {HEALTH_TIMEOUT:.0f}s (last: {last})")

    def destroy(self) -> None:
        self._ensure_auth()
        assert self.session is not None
        state = load_state()

        console.print(f"[yellow]Deleting resource group [bold]{state.resource_group}[/bold] (cascading)...[/yellow]")
        self.session.resource_client().resource_groups.begin_delete(state.resource_group).wait()
        clear_state()
        console.print("[green]Done. All infrastructure destroyed.[/green]")
