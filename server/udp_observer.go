package server

import (
	"bytes"
	"encoding/json"
	"net"
	"sync"
	"time"

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

func (o *udpObservations) put(ticket network.RendezvousTicket, address *net.UDPAddr, expiresAt, now time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sweepLocked(now)
	key := udpObservationKey(ticket)
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
			AgentKey:  ticket.AgentKey,
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
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sweepLocked(now)
	key := udpObservationKey(ticket)
	value, ok := o.entries[key]
	if !ok || !value.expiresAt.After(now) || value.endpoint.AgentKey != ticket.AgentKey {
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
		var probe protocol.UDPProbe
		decoder := json.NewDecoder(bytes.NewReader(buffer[:n]))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&probe) != nil || probe.Version != network.WireVersion {
			continue
		}
		if err := s.tickets.Verify(probe.Ticket); err != nil {
			continue
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, probe.Ticket.ExpiresAt)
		if err != nil {
			continue
		}
		if !s.udpObserved.put(probe.Ticket, address, expiresAt, time.Now()) {
			continue
		}
		response, _ := json.Marshal(protocol.UDPProbeResponse{
			Version: network.WireVersion, TicketID: probe.Ticket.TicketID,
		})
		_, _ = conn.WriteToUDP(response, address)
	}
}
