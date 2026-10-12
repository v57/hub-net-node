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
- two-minute session lifetime;
- 30-second candidate lifetime; and
- two-minute online inviter registration lease.

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
   peer `key`, and remains distinct from declared candidates.
7. Either agent may send `session.close`; otherwise expiry removes the session
   and retained endpoints.

## Online inviter registry

An agent that can issue compact invitations registers itself so joins are routed
to a currently present inviter. Registration is keyed by the agent's service
public key (the base64 SPKI Ed25519 key that signs its invitations) and proves
possession of the matching private key through a signed challenge.

1. The agent opens a WebSocket to the rendezvous endpoint and sends
   `inviter.register` carrying only its `serviceKey`. The node replies
   `inviter.challenge` with a random `challengeNonce` (16 bytes, unpadded
   base64url).
2. The agent signs the raw nonce bytes under the
   `hub-network/inviter-registration/v1` domain and resends `inviter.register`
   with `serviceKey`, `challengeNonce`, and `challengeSignature`.
3. The node verifies the signature against the raw 32-byte service public key.
   On success it replies `inviter.registered` with a `registrationExpiresAt`
   lease (two minutes by default). The nonce is single-use: it cannot be replayed.
4. While the connection stays open and the lease is live, the inviter is
   considered online. Disconnect or lease expiry drops the registration; the
   agent re-runs the challenge to re-register.

A joiner's `session.open` carrying an invitation is rejected with a
non-retryable `unauthorized` (`inviter offline`) unless the invitation's signing
key is currently registered. This routes joins to a live inviter without the
node relaying any application traffic; the no-payload invariant still holds.

Registration state is in-memory and process-local; a node restart clears it and
inviters re-register. A registration lease is swept on the same cadence as
sessions and UDP observations.

## Invitation bootstrap signaling

The joiner opens its invitation session first in the client-initiated flow.
After the node verifies the compact invitation, confirms the signing inviter is
online, consumes the joiner's replay entry, and opens the joiner session, it
pushes `inviter.bootstrap` to the registered inviter's connection:

- `invitationCode` (the compact code the joiner presented, so the inviter can
  probe and open its own side without retaining invitation state);
- `key` (the joiner's service public key);
- `tokenDigest`, `transactionId`, `tunnelInstanceId`, and `generation` (the
  exact transaction identity the joiner used).

The inviter then runs the same authenticated UDP probe and `session.open`
(invitation form) on its registration connection, offering its declared
`candidate.offer` messages. The node pairs the two sessions in either arrival
order: the first opener may be the inviter or the joiner, and the second must
complete the exact (inviter, joiner) pair for the invitation (same token digest,
transaction, tunnel instance, and generation; a third peer is rejected). When
the second session opens, the node delivers each peer's candidates and observed
endpoint to the other immediately, so both sides learn the match without
waiting for an offer.

The inviter's own `session.open` for an invitation never triggers a second
`inviter.bootstrap` push (the signal is joiner-opened only). The node relays
coordination data only; the direct bootstrap request/response exchange happens
between the joiner and the inviter outside this connection.

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
