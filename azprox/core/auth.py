"""Azure authentication — az CLI session or service principal."""
from __future__ import annotations

import json
import subprocess
from typing import Optional

from azprox.core.config import AuthConfig, load_auth, save_auth


def _az_account_show() -> dict:
    try:
        out = subprocess.run(
            ["az", "account", "show", "-o", "json"],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
        pass
    return {}


class AzureSession:
    def __init__(self, credential, subscription_id: str, tenant_id: str = ""):
        self.credential = credential
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self._resource_client = None
        self._web_client = None
        self._storage_client = None

    @classmethod
    def from_config(cls) -> "AzureSession":
        auth = load_auth()

        if auth.method == "sp" and auth.client_id and auth.client_secret and auth.tenant_id:
            from azure.identity import ClientSecretCredential

            credential = ClientSecretCredential(
                tenant_id=auth.tenant_id,
                client_id=auth.client_id,
                client_secret=auth.client_secret,
            )
            if not auth.subscription_id:
                raise RuntimeError("Service-principal auth needs a subscription_id. Re-run: azprox init")
            return cls(credential, auth.subscription_id, auth.tenant_id)

        from azure.identity import AzureCliCredential

        sub, tenant = auth.subscription_id, auth.tenant_id
        if not sub or not tenant:
            acct = _az_account_show()
            if not acct:
                raise RuntimeError("Not authenticated. Run `az login` (or `azprox init`) first.")
            sub = sub or acct.get("id", "")
            tenant = tenant or acct.get("tenantId", "")

        return cls(AzureCliCredential(), sub, tenant)

    @classmethod
    def interactive_login(
        cls,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        tenant_id: Optional[str] = None,
        subscription_id: Optional[str] = None,
    ) -> "AzureSession":
        if client_id and client_secret and tenant_id:
            from azure.identity import ClientSecretCredential

            if not subscription_id:
                raise RuntimeError("--subscription is required with service-principal credentials.")
            credential = ClientSecretCredential(
                tenant_id=tenant_id, client_id=client_id, client_secret=client_secret,
            )
            session = cls(credential, subscription_id, tenant_id)
            session.verify()
            save_auth(AuthConfig(
                method="sp", subscription_id=subscription_id,
                client_id=client_id, client_secret=client_secret, tenant_id=tenant_id,
            ))
            return session

        acct = _az_account_show()
        if not acct:
            subprocess.run(["az", "login"], check=True)
            acct = _az_account_show()
            if not acct:
                raise RuntimeError("az login did not produce an active account.")

        sub = subscription_id or acct.get("id", "")
        tenant = tenant_id or acct.get("tenantId", "")
        if subscription_id and subscription_id != acct.get("id"):
            subprocess.run(["az", "account", "set", "--subscription", subscription_id], check=True)

        from azure.identity import AzureCliCredential

        session = cls(AzureCliCredential(), sub, tenant)
        session.verify()
        save_auth(AuthConfig(method="cli", subscription_id=sub, tenant_id=tenant))
        return session

    def verify(self) -> None:
        next(iter(self.resource_client().resource_groups.list()), None)

    def resource_client(self):
        if self._resource_client is None:
            try:
                from azure.mgmt.resource import ResourceManagementClient
            except ImportError:
                # azure-mgmt-resource >= 26 dropped the top-level re-export.
                from azure.mgmt.resource.resources import ResourceManagementClient
            self._resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        return self._resource_client

    def web_client(self):
        if self._web_client is None:
            from azure.mgmt.web import WebSiteManagementClient

            self._web_client = WebSiteManagementClient(self.credential, self.subscription_id)
        return self._web_client

    def storage_client(self):
        if self._storage_client is None:
            from azure.mgmt.storage import StorageManagementClient

            self._storage_client = StorageManagementClient(self.credential, self.subscription_id)
        return self._storage_client

    def mgmt_token(self) -> str:
        return self.credential.get_token("https://management.azure.com/.default").token


def authenticate(**kwargs) -> AzureSession:
    return AzureSession.interactive_login(**kwargs)
