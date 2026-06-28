"""Endpoint health checks — confirm forwarding works and capture the outbound IP."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import httpx

from azprox.core.config import DeploymentState, EndpointState

IP_ECHO_TARGET = "https://api.ipify.org?format=json"


@dataclass
class HealthResult:
    endpoint: EndpointState
    healthy: bool
    response_time_ms: float
    error: str = ""
    outbound_ip: str = ""


def _parse_ip(body: str) -> str:
    body = body.strip()
    try:
        data = json.loads(body)
        for key in ("ip", "origin", "ipAddress"):
            if key in data:
                return str(data[key]).split(",")[0].strip()
    except (json.JSONDecodeError, TypeError):
        pass
    return body.split()[0] if body else ""


async def check_endpoint(
    endpoint: EndpointState,
    auth_key: str,
    timeout: float = 15.0,
    client: httpx.AsyncClient | None = None,
) -> HealthResult:
    headers = {"X-AzureProx-Key": auth_key, "X-AzureProx-Target": IP_ECHO_TARGET}
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=timeout)
    loop = asyncio.get_event_loop()
    start = loop.time()
    try:
        resp = await client.get(endpoint.url, headers=headers)
        elapsed_ms = (loop.time() - start) * 1000.0
        if resp.status_code == 200:
            return HealthResult(endpoint, True, elapsed_ms, outbound_ip=_parse_ip(resp.text))
        return HealthResult(endpoint, False, elapsed_ms, error=f"HTTP {resp.status_code}")
    except httpx.HTTPError as exc:
        return HealthResult(endpoint, False, (loop.time() - start) * 1000.0, error=f"{type(exc).__name__}: {exc}")
    finally:
        if owns_client:
            await client.aclose()


async def check_deployment_health(deployment: DeploymentState, concurrency: int = 10) -> list[HealthResult]:
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=15.0) as client:
        async def _bounded(ep: EndpointState) -> HealthResult:
            async with sem:
                return await check_endpoint(ep, deployment.auth_key, client=client)

        results = await asyncio.gather(*[_bounded(ep) for ep in deployment.endpoints])

    for result in results:
        result.endpoint.status = "active" if result.healthy else "unhealthy"
    return results
