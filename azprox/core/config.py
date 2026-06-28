"""
Config — single deployment state management.

No named deployments, no complexity. One active deployment at a time.

State file: ~/.azprox/state.json
Config file: ~/.azprox/config.json (auth creds)
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path.home() / ".azprox"
STATE_FILE = CONFIG_DIR / "state.json"
CONFIG_FILE = CONFIG_DIR / "config.json"


@dataclass
class EndpointState:
    """Single deployed Azure Function endpoint."""

    region: str
    function_app_name: str
    url: str
    storage_account: str
    status: str = "active"  # active | unhealthy | deploying


@dataclass
class DeploymentState:
    """The one active deployment."""

    resource_group: str
    subscription_id: str
    auth_key: str  # shared secret for function auth
    created_at: str = ""
    endpoints: list[EndpointState] = field(default_factory=list)

    @property
    def active_endpoints(self) -> list[EndpointState]:
        return [e for e in self.endpoints if e.status == "active"]

    @property
    def endpoint_urls(self) -> list[str]:
        return [e.url for e in self.active_endpoints]


@dataclass
class AuthConfig:
    """Stored Azure auth configuration."""

    method: str = "cli"  # "cli" or "sp"
    subscription_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    tenant_id: str = ""


# ── File operations ───────────────────────────────────────────────────────

def ensure_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_state(state: DeploymentState) -> None:
    ensure_dirs()
    data = {
        "resource_group": state.resource_group,
        "subscription_id": state.subscription_id,
        "auth_key": state.auth_key,
        "created_at": state.created_at,
        "endpoints": [asdict(e) for e in state.endpoints],
    }
    STATE_FILE.write_text(json.dumps(data, indent=2))


def load_state() -> DeploymentState:
    """Load active deployment. Raises FileNotFoundError if none."""
    if not STATE_FILE.exists():
        raise FileNotFoundError("No active deployment")
    data = json.loads(STATE_FILE.read_text())
    endpoints = [EndpointState(**e) for e in data.pop("endpoints", [])]
    return DeploymentState(**data, endpoints=endpoints)


def has_deployment() -> bool:
    return STATE_FILE.exists()


def clear_state() -> None:
    if STATE_FILE.exists():
        STATE_FILE.unlink()


def save_auth(auth: AuthConfig) -> None:
    ensure_dirs()
    CONFIG_FILE.write_text(json.dumps(asdict(auth), indent=2))


def load_auth() -> AuthConfig:
    if not CONFIG_FILE.exists():
        return AuthConfig()
    data = json.loads(CONFIG_FILE.read_text())
    return AuthConfig(**data)
