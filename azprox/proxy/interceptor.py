"""
Interceptor — request rewriting for Azure Function proxy routing.

Takes an incoming HTTP request targeting a real destination and rewrites it
to route through an Azure Function endpoint instead.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class RewrittenRequest:
    """A request rewritten to target an Azure Function endpoint."""

    method: str
    url: str               # Azure Function endpoint URL
    headers: dict[str, str]
    body: bytes


def rewrite_request(
    method: str,
    original_url: str,
    headers: dict[str, str],
    body: bytes,
    function_endpoint: str,
    auth_key: str,
) -> RewrittenRequest:
    """
    Rewrite an HTTP request to route through an Azure Function proxy.

    Original request:
        GET https://target.com/api/users HTTP/1.1
        Host: target.com
        User-Agent: curl/8.0

    Rewritten request:
        GET https://azureprox-xxx-westeurope-func.azurewebsites.net/api/proxy HTTP/1.1
        Host: azureprox-xxx-westeurope-func.azurewebsites.net
        User-Agent: curl/8.0
        X-AzureProx-Target: https://target.com/api/users
        X-AzureProx-Key: <auth_key>

    The Azure Function then:
    1. Reads X-AzureProx-Target to know where to forward
    2. Validates X-AzureProx-Key
    3. Strips proxy headers
    4. Forwards the request with the remaining headers
    """
    rewritten_headers = {}

    # Copy original headers, except Host (will be set by httpx on the function side)
    for key, value in headers.items():
        k_lower = key.lower()
        if k_lower == "host":
            continue
        # Don't forward proxy-specific headers
        if k_lower in ("proxy-connection", "proxy-authorization"):
            continue
        rewritten_headers[key] = value

    # Add our control headers
    rewritten_headers["X-AzureProx-Target"] = original_url
    rewritten_headers["X-AzureProx-Key"] = auth_key

    # Set correct Host for the function endpoint
    parsed = urlparse(function_endpoint)
    rewritten_headers["Host"] = parsed.hostname

    return RewrittenRequest(
        method=method,
        url=function_endpoint,
        headers=rewritten_headers,
        body=body,
    )


def parse_proxy_request_line(line: str) -> tuple[str, str, str]:
    """
    Parse an HTTP proxy request line.

    Proxy requests come in absolute-URI form:
        GET http://target.com/path HTTP/1.1
        CONNECT target.com:443 HTTP/1.1

    Returns (method, url, http_version)
    """
    parts = line.strip().split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"Malformed request line: {line!r}")
    return parts[0], parts[1], parts[2]
