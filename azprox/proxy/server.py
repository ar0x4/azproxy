"""
Local proxy that routes traffic through rotating Azure Function endpoints.

Plain HTTP requests (absolute-URI) are rewritten and forwarded directly. HTTPS
arrives as CONNECT, which we can't rewrite inside the tunnel — so we terminate
TLS locally with a leaf cert signed by a local CA (~/.azprox/ca), read the
decrypted request, and forward it the same way. `exec_with_proxy` points the
child's CA-bundle env vars at that CA so the interception is transparent.
"""
from __future__ import annotations

import asyncio
import logging
import os
import ssl
import subprocess
import threading
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console

from azprox.proxy.interceptor import parse_proxy_request_line, rewrite_request
from azprox.proxy.rotator import EndpointRotator

console = Console()
err_console = Console(stderr=True)
logger = logging.getLogger("azprox.proxy")

CONFIG_DIR = Path.home() / ".azprox"
CA_DIR = CONFIG_DIR / "ca"

# Hop-by-hop headers (RFC 7230) plus framing headers we recompute.
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
}


def _ci_get(headers: dict[str, str], name: str) -> Optional[str]:
    name = name.lower()
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return None


class CAStore:
    """Local CA + per-host leaf certs for HTTPS interception."""

    def __init__(self, directory: Path = CA_DIR):
        self.dir = directory
        self.leaf_dir = directory / "leaf"
        self.ca_cert_path = directory / "ca-cert.pem"
        self.ca_key_path = directory / "ca-key.pem"
        self._ca_cert = None
        self._ca_key = None
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()

    def ensure_ca(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.leaf_dir.mkdir(parents=True, exist_ok=True)
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            self._load_ca()
        else:
            self._generate_ca()

    def _generate_ca(self) -> None:
        import datetime as dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AzProx Local CA")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(key, hashes.SHA256())
        )
        self.ca_key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.ca_key_path.chmod(0o600)
        self._ca_cert, self._ca_key = cert, key

    def _load_ca(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        self._ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)

    def context_for(self, host: str) -> ssl.SSLContext:
        with self._lock:
            if host not in self._contexts:
                cert_path, key_path = self._leaf_for(host)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
                self._contexts[host] = ctx
            return self._contexts[host]

    def _leaf_for(self, host: str) -> tuple[Path, Path]:
        import datetime as dt
        import ipaddress

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        safe = host.replace(":", "_")
        cert_path = self.leaf_dir / f"{safe}-cert.pem"
        key_path = self.leaf_dir / f"{safe}-key.pem"
        if cert_path.exists() and key_path.exists():
            return cert_path, key_path

        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .sign(self._ca_key, hashes.SHA256())
        )
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cert_path, key_path


class ProxyServer:
    def __init__(
        self,
        rotator: EndpointRotator,
        auth_key: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        verbose: bool = False,
        ca: Optional[CAStore] = None,
    ):
        self.rotator = rotator
        self.auth_key = auth_key
        self.host = host
        self.port = port
        self.verbose = verbose
        self.ca = ca or CAStore()
        self.actual_port = port
        self._server: Optional[asyncio.Server] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._stop_event: Optional[asyncio.Event] = None

    @property
    def proxy_url(self) -> str:
        return f"http://{self.host}:{self.actual_port}"

    async def start(self) -> None:
        self.ca.ensure_ca()
        self._client = httpx.AsyncClient(timeout=60.0, verify=True, follow_redirects=False)
        self._stop_event = asyncio.Event()
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.actual_port = self._server.sockets[0].getsockname()[1]

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        if self._client:
            await self._client.aclose()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            req = await self._read_request(reader)
            if req is None:
                return
            method, target, _version, headers, body = req

            if method.upper() == "CONNECT":
                await self._handle_connect(target, reader, writer)
                return

            await self._handle_http_proxy(method, target, headers, body, writer)
            while not writer.is_closing():
                nxt = await self._read_request(reader)
                if nxt is None:
                    break
                m, t, _v, h, b = nxt
                if m.upper() == "CONNECT":
                    break
                await self._handle_http_proxy(m, t, h, b, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("client handler error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _read_request(self, reader: asyncio.StreamReader):
        line = b""
        while line in (b"", b"\r\n", b"\n"):
            try:
                line = await reader.readuntil(b"\r\n")
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
                return None
            if not line:
                return None

        method, target, version = parse_proxy_request_line(line.decode("latin-1"))
        headers = await self._read_headers(reader)
        body = await self._read_body(reader, headers)
        return method, target, version, headers, body

    async def _read_headers(self, reader: asyncio.StreamReader) -> dict[str, str]:
        headers: dict[str, str] = {}
        while True:
            line = await reader.readuntil(b"\r\n")
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("latin-1").rstrip("\r\n")
            if ":" in decoded:
                k, _, v = decoded.partition(":")
                headers[k.strip()] = v.strip()
        return headers

    async def _read_body(self, reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
        if "chunked" in (_ci_get(headers, "transfer-encoding") or "").lower():
            return await self._read_chunked(reader)
        cl = _ci_get(headers, "content-length")
        if cl:
            try:
                n = int(cl)
            except ValueError:
                return b""
            if n > 0:
                return await reader.readexactly(n)
        return b""

    async def _read_chunked(self, reader: asyncio.StreamReader) -> bytes:
        out = bytearray()
        while True:
            size_line = await reader.readuntil(b"\r\n")
            try:
                size = int(size_line.strip().split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                await reader.readuntil(b"\r\n")
                break
            out += await reader.readexactly(size)
            await reader.readexactly(2)
        return bytes(out)

    async def _handle_connect(self, authority: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host, _, port_s = authority.partition(":")
        port = int(port_s) if port_s else 443

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        try:
            treader, twriter = await _upgrade_to_tls(reader, writer, self.ca.context_for(host))
        except (ssl.SSLError, ConnectionError, asyncio.IncompleteReadError) as exc:
            logger.warning("TLS upgrade failed for %s: %s", host, exc)
            return

        authority_host = host if port == 443 else f"{host}:{port}"
        try:
            while True:
                req = await self._read_request(treader)
                if req is None:
                    break
                method, path, _v, headers, body = req
                if method.upper() == "CONNECT":
                    break
                await self._handle_http_proxy(method, f"https://{authority_host}{path}", headers, body, twriter)
                if (_ci_get(headers, "connection") or "").lower() == "close":
                    break
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                twriter.close()
                await twriter.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _handle_http_proxy(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        writer: asyncio.StreamWriter,
    ) -> None:
        assert self._client is not None
        endpoint = await self.rotator.next()
        rewritten = rewrite_request(method, url, headers, body, endpoint, self.auth_key)

        try:
            resp = await self._client.request(
                rewritten.method, rewritten.url,
                headers=rewritten.headers, content=rewritten.body or None,
            )
            self.rotator.report_success(endpoint)
        except httpx.HTTPError as exc:
            self.rotator.report_error(endpoint)
            await self._write_error(writer, 502, f"Bad Gateway: {type(exc).__name__}")
            return

        if self.verbose:
            err_console.print(f"[dim]{method} {url} via {endpoint.split('//')[1].split('.')[0]} → {resp.status_code}[/dim]")
        await self._write_response(writer, resp)

    async def _write_response(self, writer: asyncio.StreamWriter, resp: httpx.Response) -> None:
        body = resp.content
        out = bytearray(f"HTTP/1.1 {resp.status_code} {resp.reason_phrase or ''}\r\n".encode("latin-1"))
        for k, v in resp.headers.items():
            if k.lower() not in _HOP_BY_HOP:
                out += f"{k}: {v}\r\n".encode("latin-1")
        out += f"Content-Length: {len(body)}\r\n".encode("latin-1")
        out += b"Connection: keep-alive\r\n\r\n" + body
        writer.write(out)
        await writer.drain()

    async def _write_error(self, writer: asyncio.StreamWriter, code: int, message: str) -> None:
        body = message.encode("latin-1", "replace")
        out = (
            f"HTTP/1.1 {code} {message}\r\nContent-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n"
        ).encode("latin-1") + body
        try:
            writer.write(out)
            await writer.drain()
        except (ConnectionError, RuntimeError):
            pass


async def _upgrade_to_tls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ctx: ssl.SSLContext,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    loop = asyncio.get_event_loop()
    transport = writer.transport
    protocol = transport.get_protocol()
    new_transport = await loop.start_tls(transport, protocol, ctx, server_side=True)
    # Re-point the existing protocol/writer at the new TLS transport.
    protocol._transport = new_transport  # type: ignore[attr-defined]
    writer._transport = new_transport    # type: ignore[attr-defined]
    return reader, writer


def run_proxy_server(
    endpoints: list[str],
    auth_key: str,
    strategy: str = "round-robin",
    host: str = "127.0.0.1",
    port: int = 8080,
    verbose: bool = False,
) -> None:
    logging.getLogger("asyncio").setLevel(logging.ERROR)
    ca = CAStore()
    ca.ensure_ca()
    rotator = EndpointRotator(endpoints, strategy=strategy, auth_key=auth_key)
    server = ProxyServer(rotator, auth_key, host, port, verbose, ca)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _run() -> None:
        await server.start()
        console.print("\n[green]AzProx proxy started[/green]")
        console.print(f"  HTTP proxy:  {server.proxy_url}")
        console.print(f"  Endpoints:   {len(endpoints)} active")
        console.print(f"  Strategy:    {strategy}")
        console.print(f"  CA bundle:   {ca.ca_cert_path}")
        console.print("\n  Usage:")
        console.print(f"    export HTTP_PROXY={server.proxy_url}")
        console.print(f"    export HTTPS_PROXY={server.proxy_url}")
        console.print(f"    export CURL_CA_BUNDLE={ca.ca_cert_path}")
        console.print("    curl http://ifconfig.me\n")
        console.print("  Press Ctrl+C to stop\n")
        await server.serve_forever()

    try:
        loop.run_until_complete(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down proxy...[/yellow]")
    finally:
        loop.run_until_complete(server.stop())
        loop.close()


def start_proxy_background(
    endpoints: list[str],
    auth_key: str,
    strategy: str = "round-robin",
    host: str = "127.0.0.1",
    port: int = 0,
    verbose: bool = False,
    ca: Optional[CAStore] = None,
) -> tuple[threading.Thread, "ProxyServer"]:
    rotator = EndpointRotator(endpoints, strategy=strategy, auth_key=auth_key)
    server = ProxyServer(rotator, auth_key, host, port, verbose, ca)
    ready = threading.Event()

    def _run() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        server._loop = loop  # type: ignore[attr-defined]

        async def _boot() -> None:
            await server.start()
            ready.set()
            assert server._stop_event is not None
            await server._stop_event.wait()
            await server.stop()

        try:
            loop.run_until_complete(_boot())
        except Exception as exc:  # noqa: BLE001
            logger.warning("proxy loop error: %s", exc)
            ready.set()
        finally:
            loop.close()

    thread = threading.Thread(target=_run, daemon=True, name="azprox-proxy")
    thread.start()
    if not ready.wait(timeout=15):
        raise RuntimeError("Proxy server failed to start within 15s")
    return thread, server


def stop_background(thread: threading.Thread, server: "ProxyServer") -> None:
    loop = getattr(server, "_loop", None)
    if loop and server._stop_event is not None:
        loop.call_soon_threadsafe(server._stop_event.set)
    thread.join(timeout=5)


def exec_with_proxy(
    endpoints: list[str],
    auth_key: str,
    command: list[str],
    strategy: str = "random",
    verbose: bool = False,
) -> int:
    # Default to random: most invocations issue one request, and round-robin
    # would always start at index 0 (same endpoint every time).
    logging.getLogger("asyncio").setLevel(logging.ERROR)
    ca = CAStore()
    ca.ensure_ca()

    thread, server = start_proxy_background(endpoints, auth_key, strategy, verbose=verbose, ca=ca)
    proxy = server.proxy_url
    ca_path = str(ca.ca_cert_path)

    env = os.environ.copy()
    env.update({
        "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
        "http_proxy": proxy, "https_proxy": proxy,
        "ALL_PROXY": proxy, "all_proxy": proxy,
        "NO_PROXY": "localhost,127.0.0.1,::1",
        "no_proxy": "localhost,127.0.0.1,::1",
        # Trust the local MITM CA so HTTPS interception is transparent.
        "CURL_CA_BUNDLE": ca_path,
        "REQUESTS_CA_BUNDLE": ca_path,
        "SSL_CERT_FILE": ca_path,
        "NODE_EXTRA_CA_CERTS": ca_path,
        "GIT_SSL_CAINFO": ca_path,
    })

    err_console.print(f"[dim]azprox: proxying via {len(endpoints)} endpoint(s) on {proxy} ({strategy})[/dim]")

    try:
        return subprocess.run(command, env=env).returncode
    except FileNotFoundError:
        err_console.print(f"[red]command not found:[/red] {command[0]}")
        return 127
    except KeyboardInterrupt:
        return 130
    finally:
        stop_background(thread, server)
