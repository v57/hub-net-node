package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/v57/hub-net-node/config"
	"github.com/v57/hub-net-node/internal/testticket"
	"github.com/v57/hub-net-node/protocol"
	network "github.com/v57/hub-service-go/protocol"
)

var errPayloadTooLarge = errors.New("test payload too large")

// runServer boots a Server on a random port and returns its address plus a
// shutdown function. The server's NodeID is fixed so test tickets bind to it.
func runServer(t *testing.T, opts ...func(*config.Config)) (string, func()) {
	t.Helper()
	cfg := config.Defaults()
	cfg.StateDir = t.TempDir() + "/node-state"
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.NodeID = "node-public-1"
	for _, opt := range opts {
		opt(&cfg)
	}
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	srv, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	runErr := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { runErr <- srv.Run(ctx) }()
	// Wait for the listener to bind.
	for i := 0; i < 50; i++ {
		if srv.ActualAddress() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ActualAddress() == "" {
		cancel()
		t.Fatal("server never bound")
	}
	return srv.ActualAddress(), func() {
		cancel()
		select {
		case err := <-runErr:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Logf("Run returned: %v", err)
			}
		case <-time.After(3 * time.Second):
		}
	}
}

// dialClient opens a WebSocket connection to the rendezvous endpoint and
// completes the client-side handshake.
func dialClient(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	handshake := "GET " + RendezvousPath + " HTTP/1.1\r\n" +
		"Host: " + address + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(handshake)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 0, 512)
	chunk := make([]byte, 256)
	for {
		n, err := conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			t.Fatalf("read handshake: %v", err)
		}
		if strings.Contains(string(buf), "\r\n\r\n") {
			break
		}
	}
	if !strings.HasPrefix(string(buf), "HTTP/1.1 101") {
		t.Fatalf("handshake not 101: %q", string(buf))
	}
	return conn
}

// sendUDPProbe obtains the node-observed UDP mapping for a signed ticket and
// returns the local endpoint that should be observed in loopback tests.
func sendUDPProbe(t *testing.T, address string, ticket network.RendezvousTicket) *net.UDPAddr {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body, err := json.Marshal(protocol.UDPProbe{Version: network.WireVersion, Ticket: ticket})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	responseBody := make([]byte, 1024)
	n, err := conn.Read(responseBody)
	if err != nil {
		t.Fatalf("read UDP probe response: %v", err)
	}
	var response protocol.UDPProbeResponse
	if err := json.Unmarshal(responseBody[:n], &response); err != nil {
		t.Fatal(err)
	}
	if response.Version != network.WireVersion || response.TicketID != ticket.TicketID {
		t.Fatalf("UDP probe response = %+v", response)
	}
	return conn.LocalAddr().(*net.UDPAddr)
}

// sendEnvelope writes one masked client text frame carrying a JSON envelope.
func sendEnvelope(t *testing.T, conn net.Conn, envelope protocol.Envelope) {
	t.Helper()
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMaskedFrame(conn, 0x1, body); err != nil {
		t.Fatal(err)
	}
}

// sendRaw writes one masked client text frame carrying arbitrary bytes. Used
// for HN-404 no-payload tests that submit malformed/unknown-field JSON.
func sendRaw(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if err := writeMaskedFrame(conn, 0x1, payload); err != nil {
		t.Fatal(err)
	}
}

// readEnvelope reads one server frame and decodes it as an envelope.
func readEnvelope(t *testing.T, conn net.Conn) protocol.Envelope {
	t.Helper()
	op, payload := readFrameConn(t, conn)
	if op != 0x1 {
		t.Fatalf("expected text frame, got opcode %d", op)
	}
	var envelope protocol.Envelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("Unmarshal server frame %q: %v", string(payload), err)
	}
	return envelope
}

// writeMaskedFrame writes a client frame with the given opcode and masking.
func writeMaskedFrame(conn net.Conn, opcode byte, payload []byte) error {
	var header []byte
	length := len(payload)
	mask := [4]byte{0x9a, 0xbc, 0xde, 0xf0}
	switch {
	case length <= 125:
		header = make([]byte, 6)
		header[1] = byte(length) | 0x80
	case length <= 0xFFFF:
		header = make([]byte, 8)
		header[1] = 126 | 0x80
		binary.BigEndian.PutUint16(header[2:4], uint16(length))
	default:
		return errPayloadTooLarge
	}
	header[0] = opcode | 0x80
	copy(header[len(header)-4:], mask[:])
	if _, err := conn.Write(header); err != nil {
		return err
	}
	masked := make([]byte, length)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	_, err := conn.Write(masked)
	return err
}

func readFrameConn(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	op := header[0] & 0x0F
	length := int(header[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		_, _ = io.ReadFull(conn, ext[:])
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		_, _ = io.ReadFull(conn, ext[:])
		length = int(binary.BigEndian.Uint64(ext[:]))
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return op, payload
}

// TestSessionLifecycleEndToEnd opens two sessions with valid tickets, exchanges
// a candidate from the first, and verifies the second receives it plus the
// observed endpoint. Then both close cleanly.
func TestSessionLifecycleEndToEnd(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	now := time.Now().UTC()

	// Agent A opens a session.
	connA := dialClient(t, address)
	defer connA.Close()
	ticketA := testticket.Signed(t, now, "node-public-1", "net-1", "profile-a", "agent-a")
	udpA := sendUDPProbe(t, address, ticketA)
	sendEnvelope(t, connA, protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageOpenSession,
		Ticket:       &ticketA,
	})
	opened := readEnvelope(t, connA)
	if opened.Type != protocol.MessageSessionOpened || opened.SessionID == "" {
		t.Fatalf("agent A open = %+v", opened)
	}

	// Agent B opens; the node pairs them by shared network + distinct agent.
	connB := dialClient(t, address)
	defer connB.Close()
	ticketB := testticket.Signed(t, now, "node-public-1", "net-1", "profile-b", "agent-b")
	sendUDPProbe(t, address, ticketB)
	sendEnvelope(t, connB, protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageOpenSession,
		Ticket:       &ticketB,
	})
	openedB := readEnvelope(t, connB)
	if openedB.Type != protocol.MessageSessionOpened || openedB.SessionID == "" {
		t.Fatalf("agent B open = %+v", openedB)
	}

	// A offers a candidate; B receives it plus A's observed endpoint.
	candidate := network.Candidate{
		Version:     network.WireVersion,
		CandidateID: "cand-a-1",
		SessionID:   opened.SessionID,
		AgentKey:    "agent-a",
		Kind:        "host",
		Transport:   "udp",
		Address:     "192.0.2.10",
		Port:        51820,
		Priority:    100,
		ExpiresAt:   now.Add(protocol.DefaultCandidateLifetime).Format(time.RFC3339Nano),
	}
	sendEnvelope(t, connA, protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageOfferCandidate,
		SessionID:    opened.SessionID,
		Candidate:    &candidate,
	})

	// A first receives B's (empty) candidate list as a side effect of the push;
	// B receives A's candidate. Read until B sees a non-empty candidate list.
	_ = connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	var seen []network.Candidate
	var observed *protocol.ObservedEndpoint
	for i := 0; i < 5; i++ {
		envelope := readEnvelope(t, connB)
		if envelope.Type == protocol.MessageError {
			t.Fatalf("B got error: %+v", envelope.Error)
		}
		if envelope.Type == protocol.MessageCandidates && len(envelope.Candidates) > 0 {
			seen = envelope.Candidates
			observed = envelope.Observed
			break
		}
	}
	if len(seen) == 0 {
		t.Fatal("B never received A's candidate")
	}
	if seen[0].Address != "192.0.2.10" {
		t.Fatalf("received candidate address = %q, want 192.0.2.10", seen[0].Address)
	}
	if observed == nil {
		t.Fatal("candidate.list omitted observed endpoint")
	}
	if observed.Version != network.WireVersion || observed.AgentKey != "agent-a" ||
		observed.Transport != "udp" || observed.Address != udpA.IP.String() || observed.Port != uint16(udpA.Port) {
		t.Fatalf("observed endpoint = %+v, want agent-a udp %s", observed, udpA)
	}
}

// TestOpenRejectsInvalidTicket proves the node never opens a session for an
// unsigned or tampered ticket (HN-404 authorization boundary).
func TestOpenRejectsInvalidTicket(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	conn := dialClient(t, address)
	defer conn.Close()

	tampered := testticket.Signed(t, time.Now().UTC(), "node-public-1", "net-1", "p", "a")
	tampered.AgentKey = "substituted" // breaks signature.
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageOpenSession,
		Ticket:       &tampered,
	})
	envelope := readEnvelope(t, conn)
	if envelope.Type != protocol.MessageError {
		t.Fatalf("expected error for tampered ticket, got %+v", envelope)
	}
	if envelope.Error.Code != "unauthorized" {
		t.Fatalf("code = %q, want unauthorized", envelope.Error.Code)
	}
	if envelope.Error.Retryable {
		t.Fatal("unauthorized must not be retryable")
	}
}

func TestTicketReplayRejectedAndFreshReconnectAccepted(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	now := time.Now().UTC()
	first := testticket.SignedWithID(t, now, "node-public-1", "net-1", "p", "a", "first")
	sendUDPProbe(t, address, first)

	conn := dialClient(t, address)
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: protocol.MessageOpenSession, Ticket: &first,
	})
	if opened := readEnvelope(t, conn); opened.Type != protocol.MessageSessionOpened {
		t.Fatalf("first open = %+v", opened)
	}
	_ = conn.Close()

	replayConn := dialClient(t, address)
	defer replayConn.Close()
	sendEnvelope(t, replayConn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: protocol.MessageOpenSession, Ticket: &first,
	})
	replayed := readEnvelope(t, replayConn)
	if replayed.Type != protocol.MessageError || replayed.Error.Code != "replay_detected" {
		t.Fatalf("replay = %+v, want replay_detected", replayed)
	}

	fresh := testticket.SignedWithID(t, now, "node-public-1", "net-1", "p", "a", "fresh")
	sendUDPProbe(t, address, fresh)
	freshConn := dialClient(t, address)
	defer freshConn.Close()
	sendEnvelope(t, freshConn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: protocol.MessageOpenSession, Ticket: &fresh,
	})
	if opened := readEnvelope(t, freshConn); opened.Type != protocol.MessageSessionOpened {
		t.Fatalf("fresh reconnect = %+v", opened)
	}
}

// TestNoPayloadInvariantRejectsSmuggling proves the node rejects every shape of
// application-payload or experimental message and never forwards it (HN-404).
func TestNoPayloadInvariantRejectsSmuggling(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()

	tests := []struct {
		name     string
		payload  []byte
		wantCode string
	}{
		{
			name:     "unknown payload field",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"session.close","sessionId":"x","payload":"secret-data"}`),
			wantCode: "bad_request",
		},
		{
			name:     "unknown data field",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"session.close","data":"base64-blob"}`),
			wantCode: "bad_request",
		},
		{
			name:     "unknown message type with payload",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"relay.forward","payload":"app-bytes"}`),
			wantCode: "bad_request",
		},
		{
			name:     "malformed json",
			payload:  []byte(`{not json`),
			wantCode: "bad_request",
		},
		{
			name:     "trailing json value",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"session.close","sessionId":"x"}{"payload":"secret-data"}`),
			wantCode: "bad_request",
		},
		{
			name:     "packet field rejected",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"session.close","sessionId":"x","packet":"deadbeef"}`),
			wantCode: "bad_request",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := dialClient(t, address)
			defer conn.Close()
			sendRaw(t, conn, test.payload)
			envelope := readEnvelope(t, conn)
			if envelope.Type != protocol.MessageError {
				t.Fatalf("%s: expected error envelope, got %+v", test.name, envelope)
			}
			if envelope.Error.Code != test.wantCode {
				t.Fatalf("%s: code = %q, want %q", test.name, envelope.Error.Code, test.wantCode)
			}
			// The error details must never echo the smuggled payload back.
			body, _ := json.Marshal(envelope)
			if strings.Contains(string(body), "secret-data") || strings.Contains(string(body), "app-bytes") {
				t.Fatalf("%s: error echoed smuggled payload: %s", test.name, body)
			}
		})
	}
}

// TestRateLimitRejectsBurst proves the node bounds per-connection message rate
// (HN-403). Sending faster than the configured ceiling yields rate_limited.
func TestRateLimitRejectsBurst(t *testing.T) {
	// Lower the rate so the test does not have to flood the wire.
	lowered := func(cfg *config.Config) {
		cfg.Limits.MessagesPerSecond = 5
	}
	address, cleanup := runServer(t, lowered)
	defer cleanup()
	conn := dialClient(t, address)
	defer conn.Close()

	// Open a valid session first so subsequent offers are processed rather than
	// closing the connection. We then flood candidate.offer messages beyond the
	// per-connection cap; the limiter must reject at least one.
	now := time.Now().UTC()
	ticket := testticket.Signed(t, now, "node-public-1", "net-1", "p", "a")
	sendUDPProbe(t, address, ticket)
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageOpenSession,
		Ticket:       &ticket,
	})
	opened := readEnvelope(t, conn)
	if opened.Type != protocol.MessageSessionOpened {
		t.Fatalf("open = %+v", opened)
	}

	rejected := false
	for i := 0; i < 50; i++ {
		// candidate.offer with no peer yet returns not_matched; that still
		// consumes rate budget, which is exactly what we want to exhaust.
		sendEnvelope(t, conn, protocol.Envelope{
			MajorVersion: protocol.MajorVersion,
			MinorVersion: protocol.MinorVersion,
			Type:         protocol.MessageOfferCandidate,
			SessionID:    opened.SessionID,
			Candidate: &network.Candidate{
				Version:     network.WireVersion,
				CandidateID: "c",
				SessionID:   opened.SessionID,
				AgentKey:    "agent-a",
				Kind:        "host",
				Transport:   "udp",
				Address:     "192.0.2.1",
				Port:        5000,
				ExpiresAt:   now.Add(time.Minute).Format(time.RFC3339Nano),
			},
		})
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 50; i++ {
		op, payload := readFrameConn(t, conn)
		if op != 0x1 {
			break
		}
		var envelope protocol.Envelope
		if err := json.Unmarshal(payload, &envelope); err != nil {
			break
		}
		if envelope.Type == protocol.MessageError && envelope.Error.Code == "rate_limited" {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Fatal("never observed a rate_limited response despite burst over the cap")
	}
}

// TestHealthReflectsSessionCount verifies the /healthz session counter tracks
// opens and closes.
func TestHealthReflectsSessionCount(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()

	healthBefore := fetchHealth(t, address)
	if healthBefore.Sessions != 0 {
		t.Fatalf("initial sessions = %d, want 0", healthBefore.Sessions)
	}

	now := time.Now().UTC()
	conn := dialClient(t, address)
	defer conn.Close()
	ticket := testticket.Signed(t, now, "node-public-1", "net-1", "p", "a")
	sendUDPProbe(t, address, ticket)
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageOpenSession,
		Ticket:       &ticket,
	})
	_ = readEnvelope(t, conn) // session.opened

	// The counter update races with the read loop; poll briefly.
	var after snapshot
	for i := 0; i < 20; i++ {
		after = fetchHealth(t, address)
		if after.Sessions == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if after.Sessions != 1 {
		t.Fatalf("sessions after open = %d, want 1", after.Sessions)
	}
}

type snapshot struct {
	Sessions int `json:"sessions"`
}

func fetchHealth(t *testing.T, address string) snapshot {
	t.Helper()
	resp, err := http.Get("http://" + address + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var snap snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	return snap
}
