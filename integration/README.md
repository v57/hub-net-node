# Linux acceptance

`linux_acceptance.sh` builds and verifies the release archive, runs its
`linux/amd64` binary unprivileged in a read-only Linux container, builds the
production image, and requires both deployment forms to become healthy and
exit cleanly on SIGTERM. Docker is required:

```sh
make integration-linux
```

The release gate runs this acceptance test before producing artifacts.

## Linux two-NAT integration

`two_nat_no_relay.sh` creates six temporary network namespaces:

```text
agent-a -- NAT A --+
                   +-- public bridge -- rendezvous node
agent-b -- NAT B --+
```

Each agent has a private subnet and independent nftables NAT. WireGuard peers
use the two public NAT endpoints. Both agents contact the real
`hub-net-node` health endpoint, then exchange ICMP application packets over
the overlay.

`tcpdump` runs inside the rendezvous-node namespace. The test requires visible
coordination traffic on TCP and UDP 1964 while rejecting any captured ICMP or
`100.96.0.10`/`100.96.0.20` overlay packet. This proves successful direct
traffic crosses the NAT routers but not the node.

Run on Linux with root, kernel WireGuard, network namespaces, nftables,
tcpdump, curl, and ping:

```sh
sudo make integration-two-nat
```

When `sudo` removes Go from `PATH`, the harness resolves the invoking user's
`~/.local/bin/go`. Set `HUB_NET_GO=/absolute/path/to/go` for other layouts.

All namespaces, processes, keys, captures, and binaries use unique temporary
names and are removed on exit.

## Representative NAT matrix

`nat_matrix.sh` runs the same real WireGuard test with four nftables policies:

- `full-cone`: inbound packets to the advertised mapping may come from any peer.
- `restricted`: inbound packets must come from the contacted peer address.
- `port-restricted`: inbound packets must also come from the contacted peer port.
- `symmetric`: endpoint-dependent source-port mapping makes the rendezvous
  candidate stale. Direct connection must time out with
  `direct_connect_failed`; no relay fallback is attempted.

Run all cases:

```sh
sudo make integration-nat-matrix
```

Linux namespaces provide deterministic NAT-policy coverage on one host. They
cannot reproduce every carrier-grade NAT, firewall, or hairpin behavior.
Cross-provider NAT and mappings whose public endpoint changes across distinct
external hosts require a second external test host. Those cases remain
unsupported in v1 and fail after the configured direct-connect timeout; the
rendezvous node is never used as an application relay.
