"""
AzureProx — Azure Function HTTP Proxy Relay

This function is deployed to multiple Azure regions. It receives HTTP requests
from the local AzureProx proxy client, strips identifying headers, forwards
the request to the target URL, and returns the response.

Each Function App instance has 6-8 unique outbound IP addresses assigned by
Azure, providing natural IP diversity when deploying across multiple regions.

Azure Functions v2 Python programming model.
"""
import logging
import os

import azure.functions as func
import httpx

app = func.FunctionApp()

# Auth key set during deployment — all requests must include this
AZUREPROX_KEY = os.environ.get("AZUREPROX_KEY", "")

# Headers to strip before forwarding to target
# These would reveal the request is proxied through Azure
STRIP_REQUEST_HEADERS: set[str] = {
    # Azure / App Service headers
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-original-url",
    "x-original-host",
    "x-arr-log-id",
    "x-arr-ssl",
    "x-site-deployment-id",
    "x-azure-clientip",
    "x-azure-fdid",
    "x-azure-ref",
    "x-azure-requestchain",
    "x-azure-socketip",
    "disguised-host",
    "was-default-hostname",
    "x-waws-unencoded-url",
    "x-appservice-proto",
    "x-ms-client-principal",
    "x-ms-client-principal-id",
    "x-ms-client-principal-name",
    "x-ms-client-principal-idp",
    "x-ms-token-aad-access-token",
    "client-ip",
    "max-forwards",
    "via",
}

# Prefix for our control headers (always stripped)
CONTROL_PREFIX = "x-azureprox-"

# Headers to strip from the response (revealing Azure origin)
STRIP_RESPONSE_HEADERS: set[str] = {
    "x-azure-ref",
    "x-azure-requestchain",
    "x-ms-request-id",
    "x-ms-correlation-request-id",
    "x-ms-routing-request-id",
    "x-aspnet-version",
    "x-powered-by",
}

# Response headers that should not be passed through
# (they describe the transfer encoding between us and client, not us and target)
SKIP_RESPONSE_HEADERS: set[str] = {
    "transfer-encoding",
    "content-encoding",
    "content-length",  # will be recalculated
}

logger = logging.getLogger("azureprox")


@app.function_name(name="proxy")
@app.route(
    route="proxy",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    auth_level=func.AuthLevel.ANONYMOUS,  # We handle auth ourselves via X-AzureProx-Key
)
async def proxy_handler(req: func.HttpRequest) -> func.HttpResponse:
    """
    HTTP proxy relay handler.

    Protocol:
    - Caller sets X-AzureProx-Target header with the destination URL
    - Caller sets X-AzureProx-Key header with the shared auth secret
    - All other headers are forwarded to the target (after stripping Azure headers)
    - Target's response is returned to the caller
    """
    # ── 1. Authenticate ──────────────────────────────────────────────
    if AZUREPROX_KEY:
        caller_key = req.headers.get("X-AzureProx-Key", "")
        if caller_key != AZUREPROX_KEY:
            return func.HttpResponse(
                "Unauthorized",
                status_code=401,
            )

    # ── 2. Extract target URL ────────────────────────────────────────
    target = (
        req.headers.get("X-AzureProx-Target")
        or req.params.get("target")
    )
    if not target:
        return func.HttpResponse(
            '{"error": "Missing X-AzureProx-Target header or ?target= param"}',
            status_code=400,
            mimetype="application/json",
        )

    # ── 3. Build clean headers for forwarding ────────────────────────
    forward_headers: dict[str, str] = {}
    for key, value in req.headers.items():
        k_lower = key.lower()

        # Skip our control headers
        if k_lower.startswith(CONTROL_PREFIX):
            continue

        # Skip Azure / proxy-revealing headers
        if k_lower in STRIP_REQUEST_HEADERS:
            continue

        # Skip Host — httpx will set it based on the target URL
        if k_lower == "host":
            continue

        forward_headers[key] = value

    # ── 4. Forward request to target ─────────────────────────────────
    body = req.get_body()

    try:
        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=False,  # Let the caller handle redirects
            verify=True,
        ) as client:
            response = await client.request(
                method=req.method,
                url=target,
                headers=forward_headers,
                content=body if body else None,
            )
    except httpx.TimeoutException:
        return func.HttpResponse(
            '{"error": "Upstream timeout"}',
            status_code=504,
            mimetype="application/json",
        )
    except httpx.RequestError as exc:
        logger.warning(f"Upstream error: {exc}")
        return func.HttpResponse(
            f'{{"error": "Upstream error: {type(exc).__name__}"}}',
            status_code=502,
            mimetype="application/json",
        )

    # ── 5. Build response ────────────────────────────────────────────
    response_headers: dict[str, str] = {}
    for key, value in response.headers.items():
        k_lower = key.lower()

        # Skip transport-level headers
        if k_lower in SKIP_RESPONSE_HEADERS:
            continue

        # Strip Azure-revealing response headers
        if k_lower in STRIP_RESPONSE_HEADERS:
            continue

        response_headers[key] = value

    return func.HttpResponse(
        body=response.content,
        status_code=response.status_code,
        headers=response_headers,
    )


@app.function_name(name="health")
@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Simple health check endpoint — no auth required."""
    return func.HttpResponse(
        '{"status": "ok", "service": "azureprox"}',
        status_code=200,
        mimetype="application/json",
    )
