package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/v57/hub-net-node/invitation"
	network "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
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

// invitationObservationKey namespaces UDP observations for compact-invitation
// bootstrap by the exact payload digest and the opener's service key. Unlike
// legacy hub-signed rendezvous tickets, an invitation has no hub key, so the
// cache is keyed directly instead of overloading ticket.HubKey with a
// placeholder.
func invitationObservationKey(digest, agentKey string) string {
	return "invitation:" + digest + "\x00" + agentKey
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
	reply := newReplyConn(conn)
	buffer := make([]byte, maxUDPProbeBytes+1)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, address, local, err := reply.read(buffer)
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
		now := time.Now()
		// A link probe: the side's own token names the link and the side
		if linkID, endpoint, ok := s.verifyLinkUDPProbe(buffer[:n], address); ok {
			if observed, known := s.links.Observe(linkID, endpoint.token, endpoint.endpoint); known {
				response, _ := json.Marshal(protocol.LinkUDPProbeResponse{Version: network.WireVersion, LinkID: linkID})
				_ = reply.write(response, address, local)
				s.pushReadyIfReady(observed)
			}
			continue
		}
		// Compact-invitation probes carry no hub ticket; they are recorded
		// under a digest-scoped observation key and acknowledged with the
		// canonical ticket id the inviter/joiner clients expect.
		if key, ticketID, agentKey, expiresAt, ok := s.verifyInvitationUDPProbe(buffer[:n], now); ok {
			if !s.udpObserved.putKey(key, agentKey, address, expiresAt, now) {
				s.logger.Info("invitation probe not recorded", "from", address.String())
			} else {
				response, _ := json.Marshal(protocol.UDPProbeResponse{
					Version: network.WireVersion, TicketID: ticketID,
				})
				_ = reply.write(response, address, local)
			}
			continue
		}
	}
}

type linkObservation struct {
	token    string
	endpoint network.ObservedEndpoint
}

// verifyLinkUDPProbe reads a link probe; the store decides whether its token is live. The datagram source is the
// observation, never anything the probe claims.
func (s *Server) verifyLinkUDPProbe(payload []byte, address *net.UDPAddr) (string, linkObservation, bool) {
	var probe protocol.LinkUDPProbe
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&probe) != nil || probe.Version != network.WireVersion || probe.LinkID == "" || probe.ProbeToken == "" {
		return "", linkObservation{}, false
	}
	return probe.LinkID, linkObservation{
		token: probe.ProbeToken,
		endpoint: network.ObservedEndpoint{
			Version: network.WireVersion, Transport: "udp", Address: address.IP.String(), Port: uint16(address.Port),
		},
	}, true
}

// verifyInvitationUDPProbe authenticates a compact-invitation probe and
// returns the digest-scoped observation key, the opener's service key, and
// the invitation expiry. The opener must know the exact invitation payload
// (verified signature + digest) and identify itself with a service key.
func (s *Server) verifyInvitationUDPProbe(payload []byte, now time.Time) (key, ticketID, agentKey string, expiresAt time.Time, ok bool) {
	var probe protocol.InvitationUDPProbe
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&probe); err != nil {
		// Not an invitation probe; the caller tries the ticket form next.
		s.logger.Debug("udp payload is not an invitation probe", "err", err.Error())
		return "", "", "", time.Time{}, false
	}
	if probe.Version != network.WireVersion || probe.Key == "" || probe.TransactionID == "" {
		s.logger.Info("invitation probe rejected", "err", "missing version, key or transaction id")
		return "", "", "", time.Time{}, false
	}
	verified, err := invitation.VerifyCode(probe.InvitationCode, now)
	if err == nil {
		err = invitation.ValidatePeer(verified, probe.Key)
	}
	if err == nil && probe.TokenDigest != verified.TokenDigest {
		err = errors.New("token digest does not match the invitation")
	}
	if err != nil {
		s.logger.Info("invitation probe rejected", "err", err.Error())
		return "", "", "", time.Time{}, false
	}
	expiresAt, _ = time.Parse(time.RFC3339Nano, verified.ExpiresAt)
	return invitationObservationKey(verified.TokenDigest, probe.Key), verified.TokenDigest + ":" + probe.Key, probe.Key, expiresAt, true
}
