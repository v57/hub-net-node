package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	network "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
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

func sendInvitationUDPProbe(t *testing.T, address string, probe protocol.InvitationUDPProbe) *net.UDPAddr {
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
	body, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	responseBody := make([]byte, 1024)
	if _, err := conn.Read(responseBody); err != nil {
		t.Fatalf("read invitation UDP probe response: %v", err)
	}
	return conn.LocalAddr().(*net.UDPAddr)
}

func signedInvitation(t *testing.T, now time.Time, bindingKind string) (code, digest, invitingAgent string, agentPrivate ed25519.PrivateKey) {
	t.Helper()
	agentPublic, agentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentDER, err := x509.MarshalPKIXPublicKey(agentPublic)
	if err != nil {
		t.Fatal(err)
	}
	var nonce, expires [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(expires[:], uint32(now.Add(7*24*time.Hour).Unix()))
	payload := base64.RawURLEncoding.EncodeToString(agentPublic) + "." + base64.RawURLEncoding.EncodeToString(expires[:]) + "." + base64.RawURLEncoding.EncodeToString(nonce[:])
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(agentPrivate, []byte(payload)))
	digestBytes := sha256.Sum256([]byte(payload))
	invitingAgent = base64.StdEncoding.EncodeToString(agentDER)
	return payload + "/" + signature, base64.RawURLEncoding.EncodeToString(digestBytes[:]), invitingAgent, agentPrivate
}

func signedAppleInvitation(t *testing.T, now time.Time) (code, digest, invitingAgent string, agentPrivate ed25519.PrivateKey) {
	return signedInvitation(t, now, "apple-app")
}

// registerInviter performs the online-inviter registration handshake over a
// fresh connection and returns that connection (kept open so the registration
// stays live). The caller defers conn.Close().
func registerInviter(t *testing.T, address, serviceKey string, privateKey ed25519.PrivateKey) net.Conn {
	t.Helper()
	conn := dialClient(t, address)
	// Request a challenge.
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessagePresenceRegister,
		ServiceKey: serviceKey,
	})
	challenge := readEnvelope(t, conn)
	if challenge.Type != protocol.MessagePresenceChallenge || challenge.ChallengeNonce == "" {
		conn.Close()
		t.Fatalf("inviter.challenge = %+v", challenge)
	}
	// Answer it.
	nonceBytes, err := base64.RawURLEncoding.DecodeString(challenge.ChallengeNonce)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	signature, err := network.SignBytes(network.PurposePresence, nonceBytes, privateKey)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessagePresenceRegister,
		ServiceKey: serviceKey, ChallengeNonce: challenge.ChallengeNonce, ChallengeSignature: signature,
	})
	registered := readEnvelope(t, conn)
	if registered.Type != protocol.MessagePresenceRegistered || registered.RegistrationExpiresAt == "" {
		conn.Close()
		t.Fatalf("inviter.registered = %+v", registered)
	}
	return conn
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

func TestAppleInvitationSessionPinsAuthorizationAndExchangesCandidates(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	now := time.Now().UTC()
	code, digest, invitingAgent, inviterPrivate := signedAppleInvitation(t, now)
	transactionID := "transaction-apple-1"

	// Register the inviter online; a join is only accepted while it is present.
	inviterReg := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer inviterReg.Close()

	open := func(key string) (net.Conn, protocol.Envelope, *net.UDPAddr) {
		t.Helper()
		probe := protocol.InvitationUDPProbe{
			Version: 1, InvitationCode: code, Key: key,
			TokenDigest: digest, TransactionID: transactionID,
			TunnelInstanceID: "tunnel-live", Generation: 7,
		}
		observed := sendInvitationUDPProbe(t, address, probe)
		// The inviter opens its side on its registration connection.
		conn := inviterReg
		if key != invitingAgent {
			conn = dialClient(t, address)
		}
		sendEnvelope(t, conn, protocol.Envelope{
			MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
			InvitationCode: code, Key: key,
			TokenDigest: digest, TransactionID: transactionID,
			TunnelInstance: "tunnel-live", Generation: 7,
		})
		opened := readEnvelope(t, conn)
		if opened.Type != protocol.MessageSessionOpened || opened.SessionID == "" {
			conn.Close()
			t.Fatalf("invitation open = %+v", opened)
		}
		return conn, opened, observed
	}

	inviter, inviterOpened, inviterObserved := open(invitingAgent)
	defer inviter.Close()
	joiner, joinerOpened, _ := open("joiner-wireguard-key")
	defer joiner.Close()

	candidate := network.Candidate{
		Version: 1, CandidateID: "apple-candidate", SessionID: inviterOpened.SessionID,
		Key: invitingAgent, Kind: "host", Transport: "udp",
		Address: "192.0.2.44", Port: 51820, Priority: 100,
		ExpiresAt: now.Add(protocol.DefaultCandidateLifetime).Format(time.RFC3339Nano),
	}
	sendEnvelope(t, inviter, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOfferCandidate,
		SessionID: inviterOpened.SessionID, Candidate: &candidate,
	})
	_ = joiner.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 5; i++ {
		message := readEnvelope(t, joiner)
		if message.Type != protocol.MessageCandidates || len(message.Candidates) == 0 {
			continue
		}
		if message.SessionID != joinerOpened.SessionID || message.Candidates[0].SessionID != joinerOpened.SessionID || message.Candidates[0].Key != invitingAgent {
			t.Fatalf("candidate delivery = %+v", message)
		}
		if message.Observed == nil || message.Observed.Key != invitingAgent ||
			message.Observed.Address != inviterObserved.IP.String() || message.Observed.Port != uint16(inviterObserved.Port) {
			t.Fatalf("inviter observation = %+v, want %s", message.Observed, inviterObserved)
		}
		return
	}
	t.Fatal("joiner never received Apple inviter candidate")
}

func TestMachineInvitationSessionExchangesEquivalentCandidates(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	now := time.Now().UTC()
	code, digest, invitingAgent, inviterPrivate := signedInvitation(t, now, "machine")
	transactionID := "transaction-machine-1"

	inviterReg := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer inviterReg.Close()

	open := func(key string) (net.Conn, protocol.Envelope, *net.UDPAddr) {
		t.Helper()
		probe := protocol.InvitationUDPProbe{
			Version: 1, InvitationCode: code, Key: key,
			TokenDigest: digest, TransactionID: transactionID,
		}
		observed := sendInvitationUDPProbe(t, address, probe)
		// The inviter opens its side on its registration connection.
		conn := inviterReg
		if key != invitingAgent {
			conn = dialClient(t, address)
		}
		sendEnvelope(t, conn, protocol.Envelope{
			MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
			InvitationCode: code, Key: key,
			TokenDigest: digest, TransactionID: transactionID,
		})
		opened := readEnvelope(t, conn)
		if opened.Type != protocol.MessageSessionOpened || opened.SessionID == "" {
			conn.Close()
			t.Fatalf("machine invitation open = %+v", opened)
		}
		return conn, opened, observed
	}

	inviter, inviterOpened, inviterObserved := open(invitingAgent)
	defer inviter.Close()
	joiner, joinerOpened, _ := open("joiner-wireguard-key")
	defer joiner.Close()
	candidate := network.Candidate{
		Version: 1, CandidateID: "machine-candidate", SessionID: inviterOpened.SessionID,
		Key: invitingAgent, Kind: "host", Transport: "udp",
		Address: "192.0.2.45", Port: 51820, Priority: 100,
		ExpiresAt: now.Add(protocol.DefaultCandidateLifetime).Format(time.RFC3339Nano),
	}
	sendEnvelope(t, inviter, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOfferCandidate,
		SessionID: inviterOpened.SessionID, Candidate: &candidate,
	})
	_ = joiner.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 5; i++ {
		message := readEnvelope(t, joiner)
		if message.Type != protocol.MessageCandidates || len(message.Candidates) == 0 {
			continue
		}
		if message.SessionID != joinerOpened.SessionID || message.Candidates[0].SessionID != joinerOpened.SessionID || message.Candidates[0].Key != invitingAgent {
			t.Fatalf("machine candidate delivery = %+v", message)
		}
		if message.Observed == nil || message.Observed.Key != invitingAgent ||
			message.Observed.Address != inviterObserved.IP.String() || message.Observed.Port != uint16(inviterObserved.Port) {
			t.Fatalf("machine inviter observation = %+v, want %s", message.Observed, inviterObserved)
		}
		return
	}
	t.Fatal("joiner never received machine inviter candidate")
}

func TestAppleInvitationRejectsReplayAndCleansDisconnectedState(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	code, digest, invitingAgent, inviterPrivate := signedAppleInvitation(t, time.Now().UTC())
	inviterReg := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer inviterReg.Close()
	probe := protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: "joiner-wireguard-key",
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstanceID: "tunnel-live", Generation: 7,
	}
	sendInvitationUDPProbe(t, address, probe)
	open := protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: "joiner-wireguard-key",
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstance: "tunnel-live", Generation: 7,
	}
	first := dialClient(t, address)
	sendEnvelope(t, first, open)
	if opened := readEnvelope(t, first); opened.Type != protocol.MessageSessionOpened {
		t.Fatalf("first open = %+v", opened)
	}

	replay := dialClient(t, address)
	defer replay.Close()
	sendEnvelope(t, replay, open)
	if rejected := readEnvelope(t, replay); rejected.Type != protocol.MessageError || rejected.Error.Code != "replay_detected" {
		t.Fatalf("replay = %+v, want replay_detected", rejected)
	}
	_ = first.Close()
	for i := 0; i < 50 && fetchHealth(t, address).Sessions != 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if got := fetchHealth(t, address).Sessions; got != 0 {
		t.Fatalf("sessions after disconnect = %d, want 0", got)
	}
}

// TestInvitationIsSingleUseAcrossDistinctJoiners proves one compact
// invitation cannot create a second join after the first joiner opened, even
// when a different joiner key opens from a fresh source. The joiner's open
// consumes a global slot keyed on the exact payload digest, so the second
// joiner is rejected as replay before any session pairing is attempted.
func TestInvitationIsSingleUseAcrossDistinctJoiners(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	code, digest, invitingAgent, inviterPrivate := signedAppleInvitation(t, time.Now().UTC())
	inviterReg := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer inviterReg.Close()
	transactionID := "single-use-transaction"
	probe := func(key string) {
		t.Helper()
		sendInvitationUDPProbe(t, address, protocol.InvitationUDPProbe{
			Version: 1, InvitationCode: code, Key: key,
			TokenDigest: digest, TransactionID: transactionID,
			TunnelInstanceID: "tunnel-live", Generation: 7,
		})
	}
	open := func(key string) net.Conn {
		t.Helper()
		conn := dialClient(t, address)
		sendEnvelope(t, conn, protocol.Envelope{
			MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
			InvitationCode: code, Key: key,
			TokenDigest: digest, TransactionID: transactionID,
			TunnelInstance: "tunnel-live", Generation: 7,
		})
		return conn
	}

	probe("joiner-key")
	first := open("joiner-key")
	defer first.Close()
	if opened := readEnvelope(t, first); opened.Type != protocol.MessageSessionOpened {
		t.Fatalf("first joiner open = %+v, want session.opened", opened)
	}
	// The first joiner's open pushed inviter.bootstrap to the registered
	// inviter; drain it so the paired-open assertion below reads its own
	// response.
	_ = inviterReg.SetReadDeadline(time.Now().Add(2 * time.Second))
	if pending := readEnvelope(t, inviterReg); pending.Type != protocol.MessageBootstrapPending {
		t.Fatalf("registered inviter received %q, want inviter.bootstrap", pending.Type)
	}

	// A different joiner key with the same exact invitation must be rejected
	// as replay even though its per-peer slot is unused.
	probe("joiner-key-2")
	second := open("joiner-key-2")
	defer second.Close()
	if rejected := readEnvelope(t, second); rejected.Type != protocol.MessageError || rejected.Error.Code != "replay_detected" {
		t.Fatalf("second joiner = %+v, want replay_detected", rejected)
	}

	// The inviter's own paired open for the same invitation still succeeds:
	// it is the same single join, not a second one.
	probe(invitingAgent)
	sendEnvelope(t, inviterReg, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: invitingAgent,
		TokenDigest: digest, TransactionID: transactionID,
		TunnelInstance: "tunnel-live", Generation: 7,
	})
	if opened := readEnvelope(t, inviterReg); opened.Type != protocol.MessageSessionOpened {
		t.Fatalf("inviter paired open = %+v, want session.opened", opened)
	}
}

func TestAppleInvitationCloseCancelsSessionState(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	code, digest, invitingAgent, inviterPrivate := signedAppleInvitation(t, time.Now().UTC())
	inviterReg := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer inviterReg.Close()
	probe := protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: "joiner-wireguard-key",
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstanceID: "tunnel-live", Generation: 7,
	}
	sendInvitationUDPProbe(t, address, probe)
	conn := dialClient(t, address)
	defer conn.Close()
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: "joiner-wireguard-key",
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstance: "tunnel-live", Generation: 7,
	})
	opened := readEnvelope(t, conn)
	if opened.Type != protocol.MessageSessionOpened {
		t.Fatalf("open = %+v", opened)
	}
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageCloseSession,
		SessionID: opened.SessionID,
	})
	for i := 0; i < 50 && fetchHealth(t, address).Sessions != 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if got := fetchHealth(t, address).Sessions; got != 0 {
		t.Fatalf("sessions after cancellation = %d, want 0", got)
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
		{
			name:     "Hub RPC field rejected",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"session.close","sessionId":"x","hubRpc":{"method":"hub/header"}}`),
			wantCode: "bad_request",
		},
		{
			name:     "enrollment field rejected",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"session.close","sessionId":"x","enrollment":{"profile":"secret"}}`),
			wantCode: "bad_request",
		},
		{
			name:     "DNS field rejected",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"session.close","sessionId":"x","dns":{"name":"private.hub.invalid"}}`),
			wantCode: "bad_request",
		},
		{
			name:     "application packet field rejected",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"session.close","sessionId":"x","applicationPacket":"deadbeef"}`),
			wantCode: "bad_request",
		},
		{
			name:     "presence.register with smuggled payload",
			payload:  []byte(`{"majorVersion":1,"minorVersion":0,"type":"presence.register","serviceKey":"k","payload":"secret-data"}`),
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

// TestInviterRegistrationAcceptsSignedChallenge proves the full challenge
// handshake returns inviter.registered with a lease expiry.
func TestInviterRegistrationAcceptsSignedChallenge(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	now := time.Now().UTC()
	_, _, invitingAgent, inviterPrivate := signedAppleInvitation(t, now)
	reg := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer reg.Close()
}

// TestJoinRejectsWhenInviterOffline proves an invitation is rejected with a
// non-retryable unauthorized error when no inviter registered its key.
func TestJoinRejectsWhenInviterOffline(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	now := time.Now().UTC()
	code, digest, invitingAgent, _ := signedAppleInvitation(t, now)
	// Deliberately do NOT register the inviter.
	probe := protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: invitingAgent,
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstanceID: "tunnel-live", Generation: 7,
	}
	sendInvitationUDPProbe(t, address, probe)
	conn := dialClient(t, address)
	defer conn.Close()
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: invitingAgent,
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstance: "tunnel-live", Generation: 7,
	})
	rejected := readEnvelope(t, conn)
	if rejected.Type != protocol.MessageError || rejected.Error.Code != "unauthorized" {
		t.Fatalf("offline join = %+v, want unauthorized error", rejected)
	}
	if rejected.Error.Retryable {
		t.Fatalf("offline join retryable = true, want false")
	}
}

// TestJoinAcceptsWhenInviterOnline proves a joiner reaches session.opened once
// the invitation's signing key is registered online.
func TestJoinAcceptsWhenInviterOnline(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	now := time.Now().UTC()
	code, digest, invitingAgent, inviterPrivate := signedAppleInvitation(t, now)
	inviterReg := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer inviterReg.Close()
	probe := protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: "joiner-wireguard-key",
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstanceID: "tunnel-live", Generation: 7,
	}
	sendInvitationUDPProbe(t, address, probe)
	conn := dialClient(t, address)
	defer conn.Close()
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: "joiner-wireguard-key",
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstance: "tunnel-live", Generation: 7,
	})
	opened := readEnvelope(t, conn)
	if opened.Type != protocol.MessageSessionOpened || opened.SessionID == "" {
		t.Fatalf("online join = %+v, want session.opened", opened)
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

// TestRegisteredInviterReceivesBootstrapSignalAndJoinsOnSameConnection proves
// the joiner-first flow: a joiner opens its invitation session, the node
// pushes inviter.bootstrap to the registered inviter's connection, and the
// inviter probes and opens its own side of the paired session on that same
// connection. Both peers then receive each other's candidates and observed
// endpoints without either side waiting for an offer.
func TestRegisteredInviterReceivesBootstrapSignalAndJoinsOnSameConnection(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	now := time.Now().UTC()
	code, digest, invitingAgent, inviterPrivate := signedInvitation(t, now, "machine")
	transactionID := "transaction-join-first"

	inviterReg := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer inviterReg.Close()

	// Joiner opens first: the client pastes the link and initiates.
	joinerProbe := protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: "joiner-key",
		TokenDigest: digest, TransactionID: transactionID,
		TunnelInstanceID: "tunnel-live", Generation: 7,
	}
	joinerObserved := sendInvitationUDPProbe(t, address, joinerProbe)
	joiner := dialClient(t, address)
	defer joiner.Close()
	sendEnvelope(t, joiner, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: "joiner-key",
		TokenDigest: digest, TransactionID: transactionID,
		TunnelInstance: "tunnel-live", Generation: 7,
	})
	joinerOpened := readEnvelope(t, joiner)
	if joinerOpened.Type != protocol.MessageSessionOpened || joinerOpened.SessionID == "" {
		t.Fatalf("joiner open = %+v", joinerOpened)
	}

	// The registered inviter connection must receive the push carrying the
	// joiner's transaction identity and the invitation code.
	_ = inviterReg.SetReadDeadline(time.Now().Add(2 * time.Second))
	pending := readEnvelope(t, inviterReg)
	if pending.Type != protocol.MessageBootstrapPending {
		t.Fatalf("registered inviter received %q, want inviter.bootstrap", pending.Type)
	}
	if pending.InvitationCode != code || pending.TokenDigest != digest ||
		pending.TransactionID != transactionID || pending.Key != "joiner-key" ||
		pending.TunnelInstance != "tunnel-live" || pending.Generation != 7 {
		t.Fatalf("inviter.bootstrap = %+v", pending)
	}

	// The inviter probes and opens its side on the SAME registration
	// connection, using the pushed code.
	inviterProbe := protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: invitingAgent,
		TokenDigest: digest, TransactionID: transactionID,
		TunnelInstanceID: "tunnel-live", Generation: 7,
	}
	inviterObserved := sendInvitationUDPProbe(t, address, inviterProbe)
	sendEnvelope(t, inviterReg, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: invitingAgent,
		TokenDigest: digest, TransactionID: transactionID,
		TunnelInstance: "tunnel-live", Generation: 7,
	})
	inviterOpened := readEnvelope(t, inviterReg)
	if inviterOpened.Type != protocol.MessageSessionOpened || inviterOpened.SessionID == "" {
		t.Fatalf("inviter open on registration connection = %+v", inviterOpened)
	}

	// The joiner learns the inviter's observed endpoint immediately after the
	// pairing, without the inviter having offered a candidate.
	_ = joiner.SetReadDeadline(time.Now().Add(2 * time.Second))
	seenInviter := false
	for i := 0; i < 5 && !seenInviter; i++ {
		message := readEnvelope(t, joiner)
		if message.Type != protocol.MessageCandidates || message.Observed == nil {
			continue
		}
		if message.Observed.Key != invitingAgent {
			t.Fatalf("joiner candidate.list = %+v", message)
		}
		if message.Observed.Address != inviterObserved.IP.String() ||
			message.Observed.Port != uint16(inviterObserved.Port) {
			t.Fatalf("inviter observation = %+v, want %s", message.Observed, inviterObserved)
		}
		seenInviter = true
	}
	if !seenInviter {
		t.Fatal("joiner never received inviter observed endpoint")
	}

	// The inviter receives the joiner's candidates once the joiner offers.
	candidate := network.Candidate{
		Version: 1, CandidateID: "joiner-candidate", SessionID: joinerOpened.SessionID,
		Key: "joiner-key", Kind: "host", Transport: "udp",
		Address: "192.0.2.99", Port: 51820, Priority: 100,
		ExpiresAt: now.Add(protocol.DefaultCandidateLifetime).Format(time.RFC3339Nano),
	}
	sendEnvelope(t, joiner, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOfferCandidate,
		SessionID: joinerOpened.SessionID, Candidate: &candidate,
	})
	_ = inviterReg.SetReadDeadline(time.Now().Add(2 * time.Second))
	seenJoiner := false
	for i := 0; i < 5 && !seenJoiner; i++ {
		message := readEnvelope(t, inviterReg)
		if message.Type != protocol.MessageCandidates || len(message.Candidates) == 0 {
			continue
		}
		if message.SessionID != inviterOpened.SessionID {
			t.Fatalf("inviter candidate.list session = %+v", message)
		}
		if len(message.Candidates) != 1 || message.Candidates[0].Address != "192.0.2.99" ||
			message.Candidates[0].Key != "joiner-key" {
			t.Fatalf("inviter received joiner candidates = %+v", message)
		}
		if message.Observed == nil || message.Observed.Key != "joiner-key" ||
			message.Observed.Address != joinerObserved.IP.String() {
			t.Fatalf("joiner observation = %+v, want %s", message.Observed, joinerObserved)
		}
		seenJoiner = true
	}
	if !seenJoiner {
		t.Fatal("inviter never received joiner candidates")
	}
}

// Holding the invitation code does not make a client the inviter: the inviter
// side must come from the inviter's registration connection.
func TestInviterSideRequiresRegistrationConnection(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	code, digest, invitingAgent, inviterPrivate := signedAppleInvitation(t, time.Now().UTC())
	inviterReg := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer inviterReg.Close()
	sendInvitationUDPProbe(t, address, protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: invitingAgent,
		TokenDigest: digest, TransactionID: "transaction",
	})
	impostor := dialClient(t, address)
	defer impostor.Close()
	sendEnvelope(t, impostor, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: invitingAgent,
		TokenDigest: digest, TransactionID: "transaction",
	})
	if rejected := readEnvelope(t, impostor); rejected.Type != protocol.MessageError || rejected.Error.Code != "unauthorized" {
		t.Fatalf("impostor inviter open = %+v, want unauthorized", rejected)
	}
}

// TestRateLimitRejectsBurst proves the node bounds per-connection message rate. Sending faster than the configured
// ceiling yields rate_limited; every message, even one the node refuses, spends the budget.
func TestRateLimitRejectsBurst(t *testing.T) {
	address, cleanup := runServer(t, func(cfg *config.Config) { cfg.Limits.MessagesPerSecond = 5 })
	defer cleanup()
	conn := dialClient(t, address)
	defer conn.Close()
	for i := 0; i < 50; i++ {
		sendEnvelope(t, conn, protocol.Envelope{
			MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
			Type: protocol.MessageLinkClose, LinkID: "burst",
		})
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 50; i++ {
		envelope := readEnvelope(t, conn)
		if envelope.Type == protocol.MessageError && envelope.Error.Code == "rate_limited" {
			return
		}
	}
	t.Fatal("never observed a rate_limited response despite burst over the cap")
}

// TestHealthReflectsSessionCount verifies the /healthz session counter tracks an invitation session.
func TestHealthReflectsSessionCount(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	if before := fetchHealth(t, address); before.Sessions != 0 {
		t.Fatalf("initial sessions = %d, want 0", before.Sessions)
	}
	now := time.Now().UTC()
	code, digest, invitingAgent, inviterPrivate := signedAppleInvitation(t, now)
	inviter := registerInviter(t, address, invitingAgent, inviterPrivate)
	defer inviter.Close()
	probe := protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: "joiner-key", TokenDigest: digest, TransactionID: "transaction",
	}
	sendInvitationUDPProbe(t, address, probe)
	conn := dialClient(t, address)
	defer conn.Close()
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: "joiner-key", TokenDigest: digest, TransactionID: "transaction",
	})
	if opened := readEnvelope(t, conn); opened.Type != protocol.MessageSessionOpened {
		t.Fatalf("open = %+v", opened)
	}
	var after snapshot
	for i := 0; i < 20; i++ {
		if after = fetchHealth(t, address); after.Sessions == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sessions after open = %d, want 1", after.Sessions)
}
