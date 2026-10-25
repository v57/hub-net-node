# Hub Network rendezvous protocol

`hub-net-node` is a coordination service, never a WireGuard peer or application
traffic relay. It advertises exactly one role: `rendezvous`.

## Negotiation

The server advertises major/minor version, roles, and effective limits. A
different major version is rejected. A client may use a supported minor version
and must ignore unknown optional fields. Initial limits are:

- 16 concurrent links (and invitation sessions) per device;
- 16 candidates per link;
- 16 KiB per coordination message;
- 20 messages per second per connection;
- one-minute link setup and two-minute session lifetime;
- 30-second candidate lifetime; and
- two-minute presence lease.

Operators may lower limits. Raising them is a deployment choice but does not
change the protocol.

## Trust

The node introduces two devices and helps them find a direct UDP path; it never
decides who may talk. Every grant it checks is checked again, and authoritatively,
by the device it is delivered to: against the hub key that device pinned when it
joined, its own key and its own list of admitted devices. WireGuard keys reach a
device only inside hub-signed grants, never from the node. A compromised node can
withhold or delay introductions, hand out wrong endpoints and see addresses: denial
of service and address exposure, never access.

## Presence

Every device that wants to be reachable keeps one WebSocket to the node and
registers on it. Registration is keyed by the device's service public key (the
base64 SPKI Ed25519 key its hub profile is bound to) and proves possession of the
matching private key through a signed challenge.

1. The device sends `presence.register` carrying only its `serviceKey`. The node
   replies `presence.challenge` with a random `challengeNonce` (16 bytes,
   unpadded base64url).
2. The device signs the raw nonce bytes under the `hub-network/presence/v1`
   domain and resends `presence.register` with `serviceKey`, `challengeNonce`
   and `challengeSignature`.
3. The node verifies the signature against the raw 32-byte public key and replies
   `presence.registered` with a `registrationExpiresAt` lease (two minutes by
   default). The nonce is single-use.
4. The device renews by repeating the challenge on the same connection before
   the lease ends. Disconnect or lease expiry drops the registration
   (`presence.unregistered` when the node can still tell it).

A present device can be the target of links and, when it issued them, of
invitations. Presence state is in-memory; a node restart clears it and devices
register again.

## Peer links

A peer link is one direct WireGuard path between two devices of one hub, named by
a hub-signed `PeerLinkGrant`:

```
{version, grantId, hubKey, hubNetworkId, purpose,
 a: {key, wireGuardKey, member, addresses[]},
 b: {key, wireGuardKey, member, addresses[]},
 aViaB: [cidr], bViaA: [cidr],          routes each side sends through the other
 aToB: [{protocol, port}], bToA: [...], ports each side may open on the other
 issuedAt, expiresAt, signature}
```

signed by `hubKey` under `hub-network/peer-link/v1` over the canonical JSON
without `signature`, lifetime at most 31 days. `purpose` is `hub` (a member and
the hub's machine: the member routes the machine's overlay addresses through it
and may open the hub's port), `gateway` (adds `0.0.0.0/0` and `::/0`) or `share`.

1. Both devices are present. Either side sends `link.open` with the grant; its
   registered `serviceKey` must be `a.key` or `b.key`. The node checks the
   signature against the grant's own `hubKey`, the lifetime and that the other
   side is present (else retryable `peer_offline`). One live link exists per
   (hubKey, grantId): a new open replaces the old one.
2. The node replies `link.opened` with an unpredictable `linkId`, the opener's
   `probeToken` and the target's key as `peerKey`, and pushes `link.incoming`
   to the target with the `linkId`, the `grant`, the opener as `peerKey` and the
   target's own `probeToken`.
3. The target verifies the grant itself and answers `link.accept` or
   `link.reject`. A rejection closes the link (`link.closed` to the opener).
4. Each side sends a `LinkUDPProbe` `{version, linkId, probeToken}` to the node's
   WebSocket port from the same UDP socket WireGuard uses, repeating it every
   second until the link is ready. The node records only the datagram source and
   acknowledges `{version, linkId}`.
5. Each side may send `link.offer` with the `linkId` and up to 16
   `{address, port}` host candidates (LAN, global IPv6).
6. Once the target accepted and both sides were observed, the node pushes
   `link.ready` to both: the `linkId`, the other side as `peerKey`, its
   node-observed endpoint as `observedEndpoint`, its declared `candidates` and a
   `punchAt` time about a second ahead. Later offers push `link.ready` again.
7. At `punchAt` both devices set the other as a WireGuard peer, with the
   endpoint to try, and WireGuard's own handshakes open the NAT mappings from
   both ends. A device tries the observed endpoint, then each candidate, until a
   handshake completes.
8. Either side may send `link.close`. Setup must finish within 60 seconds; a ready
   link record is dropped two minutes after it became ready, since the devices
   hold the path themselves from then on.

No endpoint or candidate of either side is disclosed before the target accepts.
A device may have 16 links at once; a target receives at most 10 link openings a
minute.

## Invitation bootstrap signaling

Invitations are the first-contact credential, for a device that has no grant yet.
The joiner opens its invitation session first. After the node verifies the compact
invitation, confirms the signing inviter is present, consumes the joiner's replay
entry, and opens the joiner session, it pushes `inviter.bootstrap` to the inviter's
presence connection:

- `invitationCode` (the compact code the joiner presented, so the inviter can
  probe and open its own side without retaining invitation state);
- `key` (the joiner's service public key);
- `tokenDigest`, `transactionId`, `tunnelInstanceId`, and `generation` (the
  exact transaction identity the joiner used).

The inviter then runs the same authenticated UDP probe and `session.open`
(invitation form) on its presence connection, offering its declared
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

## Replay state

An invitation can be used once: the joiner's `session.open` atomically consumes a
slot keyed by the invitation's payload digest. Reuse returns `replay_detected`.
Consumed entries stay only until the invitation expires.

Replay memory is bounded to 16,384 entries globally and 256 per source IP and
swept with other short-lived coordination state. Capacity pressure fails closed.
State is process-local: a restart clears it, and the invitation lifetime bounds the
remaining window. Multi-replica deployments MUST share replay state.

Authenticated UDP observations use the same bounds. They are keyed by link and
side (or invitation digest and key), expire with the link or invitation, and are
swept periodically.

For endpoint-dependent NAT, the mapping observed toward the node can differ from
the mapping toward the peer. The direct path then fails within the setup time; the
node provides no relay fallback.

## No-payload invariant

The envelope has no payload, packet, stream, forwarding, destination-port, or
arbitrary byte field. Unknown JSON fields are discarded and are never forwarded.
Only typed presence, grant, link, session, candidate, capability, and error
fields can be emitted. A grant is forwarded only to the device it names. Oversized messages and unsupported message types are rejected before
session handling.
# Production release boundary

Release requires pinned-toolchain build/vet/race tests, persistent fuzz seeds,
malformed-frame survival and connection-exhaustion gates, dependency
vulnerability scanning with zero unresolved critical/high findings, Linux
standalone and container health/SIGTERM smoke tests, and privileged Ubuntu
two-NAT/NAT-matrix acceptance. Versioned archives carry SHA-256 manifests and
build provenance.
