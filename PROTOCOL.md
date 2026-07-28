# Hub Network rendezvous protocol v1.0

`hub-net-node` is a coordination service, never a WireGuard peer or application
traffic relay. Version 1 advertises exactly one role: `rendezvous`.

## Negotiation

The server advertises major/minor version, roles, and effective limits. A
different major version is rejected. A client may use a supported minor version
and must ignore unknown optional fields. Initial limits are:

- 16 concurrent sessions per authenticated agent;
- 16 candidates per session;
- 16 KiB per coordination message;
- 20 messages per second per connection;
- two-minute session lifetime; and
- 30-second candidate lifetime.

Operators may lower limits. Raising them is a deployment choice but does not
change the protocol.

## Session lifecycle

1. An agent sends one UDP probe to the node's WebSocket port using the
   `UDPProbe` JSON shape: wire `version` plus a valid, unexpired Hub
   rendezvous `ticket`. The datagram must originate from the same local UDP
   socket/port that WireGuard will use.
2. The node verifies the ticket, records only the datagram source address and
   port until ticket expiry, and acknowledges `version` plus `ticketId`. It
   never returns the observed address to the probing agent.
3. The agent sends `session.open` over WebSocket with that same ticket. A
   missing, expired, or differently bound UDP observation fails with
   `udp_observation_required`.
4. The node creates an opaque, unpredictable session ID and replies with
   `session.opened`.
5. Agents submit bounded `candidate.offer` messages. Each candidate is tied to
   its ticket identity and session and expires after the advertised lifetime.
6. The node returns `candidate.list` coordination data to the matched peer.
   `observedEndpoint` contains the node-measured UDP mapping, is bound to the
   peer `agentKey`, and remains distinct from declared candidates.
7. Either agent may send `session.close`; otherwise expiry removes the session
   and retained endpoints.

## Ticket replay state

After complete signature, purpose, binding, issue-time, expiry, maximum-lifetime,
and clock-skew validation, successful `session.open` atomically consumes its
Hub-scoped `ticketId`. Reuse returns `replay_detected`; reconnect requires a
freshly issued ticket. Consumed IDs remain only until signed ticket expiry.

Replay memory is bounded to 16,384 entries globally and 256 entries per source
IP and swept with other short-lived coordination state. Capacity pressure fails
closed. State is process-local: restart clears it, while the ten-minute maximum
ticket lifetime bounds the remaining replay window. Multi-replica deployments,
or deployments requiring strict cross-restart rejection, MUST provide shared
replay state or deterministically route each ticket to one replay authority.

Authenticated UDP observations use matching bounds: 16,384 globally and 256
per source IP. They are keyed by Hub key plus ticket ID, expire with tickets,
and are swept periodically even when no session consumes them.

For endpoint-dependent NAT, mapping observed toward the node can differ from
mapping toward the peer. Direct checks therefore fail within bounded timeout;
the node provides no relay fallback.

## No-payload invariant

The envelope has no payload, packet, stream, forwarding, destination-port, or
arbitrary byte field. Unknown JSON fields are discarded and are never forwarded.
Only typed ticket, session, candidate, capability, and error fields can be
emitted. Oversized messages and unsupported message types are rejected before
session handling.
# Production release boundary

Release requires pinned-toolchain build/vet/race tests, persistent fuzz seeds,
malformed-frame survival and connection-exhaustion gates, dependency
vulnerability scanning with zero unresolved critical/high findings, Linux
standalone and container health/SIGTERM smoke tests, and privileged Ubuntu
two-NAT/NAT-matrix acceptance. Versioned archives carry SHA-256 manifests and
build provenance.
