# AzProx

**IP rotation through Azure Functions. Like proxychains, but through the cloud.**

Deploy lightweight HTTP proxy functions across Azure regions. Each Function App
gets several outbound IPs, so prefixing a command with `azprox` routes its
traffic through a rotating pool of Azure IPs.

```bash
azprox curl https://ifconfig.me     # different Azure IP per request
azprox python3 spray.py             # any tool, all HTTP(S) traffic rotated
azprox nuclei -u https://target.com
```

## Install

```bash
git clone <repo> azprox && cd azprox
pip install -e .
```

Requires Python 3.10+ and the Azure CLI (`az`).

## Quickstart

```bash
azprox init                      # use your current `az login` session
azprox deploy                    # 5 random EU regions (~3-5 min, remote build)
azprox status                    # show endpoints + live outbound IPs
azprox curl https://ifconfig.me  # go
azprox nuke                      # tear everything down when done
```

## Commands

| Command | What it does |
|---------|--------------|
| `azprox init` | Authenticate (az CLI session, or `--client-id/--secret/--tenant/--subscription` for a service principal) |
| `azprox deploy` | Deploy proxies. `-n 10`, `--regions eu\|us\|apac\|all`, or `--regions westeurope,uksouth` |
| `azprox status` | Health-check each endpoint, print outbound IP + latency |
| `azprox serve` | Run a persistent local proxy (`-p 8080`, `--random`) |
| `azprox regions` | List available regions |
| `azprox nuke` | Delete the resource group and clear local state (`--force` to skip the prompt) |
| `azprox <anything else>` | Run that command through the proxy |

One active deployment at a time. State lives in `~/.azprox/`.

## How it works

1. `azprox deploy` creates a Function App per region — each a small HTTP relay
   that strips identifying headers and forwards to your target.
2. `azprox <command>` starts a local proxy, sets `HTTP_PROXY`/`HTTPS_PROXY`, and
   runs your command.
3. The local proxy picks an endpoint per request; the function forwards from its
   own Azure outbound IP. The target sees a rotating Azure IP, no proxy headers.

```
your machine            Azure Functions              target
┌──────────┐    ┌───────────────────────────┐    ┌────────┐
│ azprox   │    │ westeurope    (N IPs)      │    │        │
│ curl ... │──► │ northeurope   (N IPs)      │──► │ target │
│          │    │ uksouth       (N IPs)      │    │  .com  │
└──────────┘    └───────────────────────────┘    └────────┘
 HTTP_PROXY       random / round-robin             sees rotating IPs
```

**HTTPS:** an `HTTP_PROXY` can't see inside a `CONNECT` tunnel, so `azprox`
terminates TLS locally with a leaf cert from a local CA (`~/.azprox/ca/`),
rewrites the decrypted request through the rotating function, and re-encrypts the
reply. In `azprox <command>` mode the child's CA-bundle env vars are pointed at
that CA, so curl, requests, httpx, wget, node, and git trust it automatically.
The CA never leaves your machine.

## Cost

Azure Functions Consumption plan: 1M executions/month free (permanent). Typical
engagement volume is effectively free; idle costs nothing.

## OPSEC

Resource names are randomized, App Insights is disabled, and the TLS fingerprint
to targets is Azure's. Use a dedicated subscription and always `azprox nuke`
afterward. See [docs/OPSEC.md](docs/OPSEC.md).

## License

GPL-3.0
