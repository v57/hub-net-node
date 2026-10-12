package server

import (
	"bytes"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/v57/hub-net-node/invitation"
	"github.com/v57/hub-net-node/protocol"
	network "github.com/v57/hub-service-go/protocol"
)

const (
	maxUDPProbeBytes              = 16 * 1024
	defaultUDPObservationCapacity = 16384
	defaultUDPObservationsPerIP   = 256
)

type udpObservation struct {
	endpoint  protocol.ObservedEndpoint
	expiresAt time.Time
	source    string
}

type udpObservations struct {
	mu        sync.Mutex
	entries   map[string]udpObservation
	bySource  map[string]int
	max       int
	perSource int
}

func newUDPObservations() *udpObservations {
	return newUDPObservationsWithLimits(
		defaultUDPObservationCapacity,
		defaultUDPObservationsPerIP,
	)
}

func newUDPObservationsWithLimits(max, perSource int) *udpObservations {
	if max <= 0 || perSource <= 0 {
		panic("server: UDP observation limits must be positive")
	}
	return &udpObservations{
		entries:   make(map[string]udpObservation),
		bySource:  make(map[string]int),
		max:       max,
		perSource: perSource,
	}
}

func udpObservationKey(ticket network.RendezvousTicket) string {
	return ticket.HubKey + "\x00" + ticket.TicketID
}

// invitationObservationKey namespaces UDP observations for compact-invitation
// bootstrap by the exact payload digest and the opener's service key. Unlike
// legacy hub-signed rendezvous tickets, an invitation has no hub key, so the
// cache is keyed directly instead of overloading ticket.HubKey with a
// placeholder.
func invitationObservationKey(digest, agentKey string) string {
	return "invitation:" + digest + "\x00" + agentKey
}

func (o *udpObservations) put(ticket network.RendezvousTicket, address *net.UDPAddr, expiresAt, now time.Time) bool {
	return o.putKey(udpObservationKey(ticket), ticket.Key, address, expiresAt, now)
}

func (o *udpObservations) putKey(key, agentKey string, address *net.UDPAddr, expiresAt, now time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sweepLocked(now)
	source := address.IP.String()
	if existing, ok := o.entries[key]; ok {
		if existing.source != source {
			o.decrementSourceLocked(existing.source)
			if o.bySource[source] >= o.perSource {
				o.bySource[existing.source]++
				return false
			}
			o.bySource[source]++
		}
	} else {
		if len(o.entries) >= o.max || o.bySource[source] >= o.perSource {
			return false
		}
		o.bySource[source]++
	}
	o.entries[key] = udpObservation{
		endpoint: protocol.ObservedEndpoint{
			Version:   network.WireVersion,
			Key:       agentKey,
			Transport: "udp",
			Address:   address.IP.String(),
			Port:      uint16(address.Port),
		},
		expiresAt: expiresAt,
		source:    source,
	}
	return true
}

func (o *udpObservations) get(ticket network.RendezvousTicket, now time.Time) (protocol.ObservedEndpoint, bool) {
	return o.getKey(udpObservationKey(ticket), ticket.Key, now)
}

func (o *udpObservations) getKey(key, agentKey string, now time.Time) (protocol.ObservedEndpoint, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sweepLocked(now)
	value, ok := o.entries[key]
	if !ok || !value.expiresAt.After(now) || value.endpoint.Key != agentKey {
		o.removeLocked(key)
		return protocol.ObservedEndpoint{}, false
	}
	return value.endpoint, true
}

func (o *udpObservations) sweep(now time.Time) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.sweepLocked(now)
}

func (o *udpObservations) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}

func (o *udpObservations) sweepLocked(now time.Time) int {
	removed := 0
	for key, value := range o.entries {
		if !value.expiresAt.After(now) {
			o.removeLocked(key)
			removed++
		}
	}
	return removed
}

func (o *udpObservations) removeLocked(key string) {
	value, ok := o.entries[key]
	if !ok {
		return
	}
	delete(o.entries, key)
	o.decrementSourceLocked(value.source)
}

func (o *udpObservations) decrementSourceLocked(source string) {
	if o.bySource[source] <= 1 {
		delete(o.bySource, source)
	} else {
		o.bySource[source]--
	}
}

func (s *Server) serveUDPObservations(ctxDone <-chan struct{}, conn *net.UDPConn, stopped chan<- struct{}) {
	defer close(stopped)
	buffer := make([]byte, maxUDPProbeBytes+1)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, address, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				select {
				case <-ctxDone:
					return
				default:
					continue
				}
			}
			return
		}
		if n > maxUDPProbeBytes {
			continue
		}
		s.logger.Info("udp datagram received", "from", address.String(), "bytes", n)
		now := time.Now()
		// Compact-invitation probes carry no hub ticket; they are recorded
		// under a digest-scoped observation key and acknowledged with the
		// canonical ticket id the inviter/joiner clients expect.
		if key, ticketID, agentKey, expiresAt, ok := s.verifyInvitationUDPProbe(buffer[:n], now); ok {
			if s.udpObserved.putKey(key, agentKey, address, expiresAt, now) {
				response, _ := json.Marshal(protocol.UDPProbeResponse{
					Version: network.WireVersion, TicketID: ticketID,
				})
				_, _ = conn.WriteToUDP(response, address)
			}
			continue
		}
		ticket, ok := s.verifyUDPProbe(buffer[:n], now)
		if !ok {
			continue
		}
		expiresAt, _ := time.Parse(time.RFC3339Nano, ticket.ExpiresAt)
		if !s.udpObserved.put(ticket, address, expiresAt, now) {
			continue
		}
		response, _ := json.Marshal(protocol.UDPProbeResponse{
			Version: network.WireVersion, TicketID: ticket.TicketID,
		})
		_, _ = conn.WriteToUDP(response, address)
	}
}

func (s *Server) verifyUDPProbe(payload []byte, now time.Time) (network.RendezvousTicket, bool) {
	var ticketProbe protocol.UDPProbe
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ticketProbe) == nil && ticketProbe.Version == network.WireVersion && s.tickets.Verify(ticketProbe.Ticket) == nil {
		return ticketProbe.Ticket, true
	}
	return network.RendezvousTicket{}, false
}

// verifyInvitationUDPProbe authenticates a compact-invitation probe and
// returns the digest-scoped observation key, the opener's service key, and
// the invitation expiry. The opener must know the exact invitation payload
// (verified signature + digest) and identify itself with a service key.
func (s *Server) verifyInvitationUDPProbe(payload []byte, now time.Time) (key, ticketID, agentKey string, expiresAt time.Time, ok bool) {
	var probe protocol.InvitationUDPProbe
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&probe) != nil || probe.Version != network.WireVersion || probe.Key == "" || probe.TransactionID == "" {
		return "", "", "", time.Time{}, false
	}
	verified, err := invitation.VerifyCode(probe.InvitationCode, now)
	if err != nil || invitation.ValidatePeer(verified, probe.Key) != nil || probe.TokenDigest != verified.TokenDigest {
		return "", "", "", time.Time{}, false
	}
	expiresAt, _ = time.Parse(time.RFC3339Nano, verified.ExpiresAt)
	return invitationObservationKey(verified.TokenDigest, probe.Key), verified.TokenDigest + ":" + probe.Key, probe.Key, expiresAt, true
}
