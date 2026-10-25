# hub-net-node

Self-hostable Hub Network rendezvous node. A coordination service, never a
WireGuard peer or application traffic relay. The first release advertises
exactly one role: `rendezvous`. Devices keep presence on it, and it introduces
two devices that hold a hub-signed peer link grant so they can punch a direct
path; application packets then travel directly between them over WireGuard and
never traverse the node. Each device checks the grant itself: the node decides
nothing.

See [`PROTOCOL.md`](PROTOCOL.md) for the wire contract and no-payload
invariant.

## Status

Presence, targeted peer links (grant check, accept gate, probes, link.ready),
invitation bootstrap sessions, candidate exchange,
rate/retention limits, strict no-payload validation, and deployment assets are
implemented. `/healthz` reports protocol capabilities and live session count;
`/rendezvous` serves the WebSocket coordination protocol.

| Task    | Area                                  | Status                                                                                                                                   |
|---------|---------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| HN-400  | Scaffold, config, health, versioning  | Complete: root `hubnetnode` package, `server`, `config`, `health`, `version`, `logging`; `/healthz` + `/rendezvous` wire stub; examples |
| HN-401  | Ticket verification, no registration  | Complete: self-contained Hub SPKI signature, lifetime, purpose, role, identity, network, and node binding validation                    |
| HN-402  | Session lifecycle, candidate exchange | Complete                                                                                                                                 |
| HN-403  | Rate, size, connection, retention     | Complete                                                                                                                                 |
| HN-404  | No-payload forwarding proof           | Complete                                                                                                                                 |
| HN-405  | Container, standalone deployment      | Complete: packaged Linux binary and hardened container pass health, checksum, unprivileged-runtime, and SIGTERM acceptance                |
| HN-406  | Two-NAT integration                   | Complete: isolated nftables NATs, real WireGuard traffic, packet-capture no-relay assertion on Ubuntu amd64                              |
| HN-407  | Sibling-module build repair           | Complete: removed local `replace` directives, consumes published `channel-go`/`hub-service-go v0.1.0`, clean Docker build                 |
| HN-408  | RFC 6455 frame-parser hardening       | Complete: attacker-controlled length can no longer panic or over-allocate; masking/reserved-bit/opcode/control-frame validation enforced |
| HN-412  | Single-use rendezvous tickets         | Complete: post-verification atomic consumption, expiry sweeping, global/source bounds, documented restart and replica boundary           |

## Layout

```
hub-net-node/
├── protocol/      # Hub Network rendezvous wire models, capabilities, envelope validation
├── config/        # Node ID, bind address, state dir, operator-tunable limits
├── logging/       # slog helpers, JSON/text formats, component tagging
├── version/       # Major/minor from protocol constants, link-time build identifier
├── health/        # /healthz JSON snapshot, session counter, liveness
├── server/        # HTTP/WebSocket server, Prepare/Run/Shutdown lifecycle, /rendezvous stub
├── cmd/            # Production hub-net-node command
├── packaging/      # systemd, sysusers, tmpfiles, install/upgrade docs
├── integration/    # Privileged Linux two-NAT direct-traffic proof
├── examples/basic  # Minimal embedding example
└── node.go        # Root hubnetnode package: Agent aggregates server + config + health
```

## Build

```
make test
make integration-linux
sudo make integration-two-nat
make VERSION=1.0.0 package
```

Dependencies resolve from their published Go module versions; no sibling
checkout is required for native builds.

## Release gates

Go version is pinned by `go.mod`. Every change builds, vets, runs race tests,
the checked-in WebSocket fuzz seeds, malformed-frame process survival,
connection-exhaustion tests, `govulncheck`, and Linux standalone/container
health plus SIGTERM smoke checks. Version tags additionally run privileged
two-NAT/NAT-matrix jobs on the `hub-net-privileged` Ubuntu amd64 runner.

Tagged releases are immutable archives with SHA-256 manifests and GitHub
artifact attestations. Release fails on any `govulncheck` finding affecting
called code; unresolved critical/high findings block publication. Container
images must become healthy and exit cleanly on SIGTERM before release.

## Configuration

Production binary accepts flags:

```
./build/hub-net-node \
  -node-id public-1 \
  -listen :1964 \
  -state-dir /var/lib/hub-net-node \
  -log-json
```

The node deliberately uses `admissionPolicy: open`: any self-hosted hub's devices
may present a self-contained signed grant. Signature validation proves grant
integrity only; it is not operator trust or Sybil resistance, and devices never
rely on it.
`-max-connections` (default 8192) and `-max-connections-per-source` (default
256, so many devices behind one NAT fit) therefore bound sockets independently of attacker-rotatable Hub and agent keys.
HTTP headers are capped at 8 KiB and incomplete handshakes expire after 10
seconds. Authenticated UDP observations are capped at 16,384 globally and 256
per source IP, then swept when their link or invitation ends. Private deployments
needing Hub allowlists must add an external admission proxy until a trusted-Hub
policy is implemented.

Behind a TLS-terminating TCP proxy, pass `-proxy-protocol-from` with the
proxy's addresses or CIDRs (comma-separated). Connections from those peers must
begin with a PROXY protocol v1 or v2 header, and the declared client address
feeds admission limits, replay bounds and logs; a headerless connection from a
trusted peer is closed. Connections from other peers keep their own address
and cannot claim another. Without the flag, TCP limits see the proxy address.
v1 `UNKNOWN` and v2 `LOCAL` headers (proxy health checks) keep the proxy's.

Agents send their UDP probe to the port of the node URL they were given, so
UDP must reach the node directly on that port with the client's source address
intact. `-udp-listen` binds UDP separately from `-listen` (default: the same
address), so the node can take UDP 443 while the proxy holds TCP 443 and the
node's TCP listener stays on loopback.

## Container

Build from the `hub-net-node` repository:

```sh
docker build --build-arg VERSION=1.0.0 -t hub-net-node:1.0.0 .
docker run --rm -p 1964:1964/tcp -p 1964:1964/udp \
  -v hub-net-node-state:/var/lib/hub-net-node \
  hub-net-node:1.0.0 --node-id public-1
```

Image runs as non-root UID/GID 65532, includes `/healthz` health check, persists
state in `/var/lib/hub-net-node`, and handles SIGTERM gracefully. Put a TLS
reverse proxy in front of public deployments.

Docker Compose uses the same workspace-root build context:

```sh
docker compose -f hub-net-node/compose.yaml up -d --build
curl --fail http://127.0.0.1:1964/healthz
docker compose -f hub-net-node/compose.yaml down
```

Optional variables: `HUB_NET_NODE_VERSION`, `HUB_NET_NODE_ID`,
`HUB_NET_NODE_BIND`, and `HUB_NET_NODE_PORT`. State remains in the named
`hub-net-node-state` volume when the service is recreated.

Standalone Linux install, upgrade, uninstall, systemd, dedicated-user, and
directory instructions live in [`packaging/linux/README.md`](packaging/linux/README.md).

`Limits` are operator-tunable and documented in `config/config.go`. Defaults
match [`PROTOCOL.md`](PROTOCOL.md): 16 sessions per agent, 16 candidates per
session, 16 KiB per message, 20 messages per second, two-minute session
lifetime, 30-second candidate lifetime. Operators may lower limits; raising
them is a deployment choice that does not change the wire protocol.

## Trust boundary

The node is **not trusted with application data or authorization**. It:

- checks hub-signed peer link grants without prior hub registration, as an
  abuse gate only, and forwards a grant only to the device it names;
- releases no endpoint of either side before the target accepts;
- reports observed UDP endpoints separately from client-declared candidates;
- never treats a candidate as an authorization grant;
- accepts only bounded, typed coordination fields; unknown JSON fields are
  discarded and never forwarded (no-payload invariant, see
  [`protocol/protocol_test.go`](protocol/protocol_test.go)).

Authorization is established by agents against their configured Hub. The node
sees coordination timing and public endpoints only.
