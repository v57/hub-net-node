package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/v57/hub-net-node/config"
	network "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
)

// invitationFrom signs a fresh invitation with the inviter's key, as the inviter does for every invite.
func invitationFrom(t *testing.T, inviterPrivate ed25519.PrivateKey, now time.Time) (code, digest string) {
	t.Helper()
	var nonce, expires [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(expires[:], uint32(now.Add(7*24*time.Hour).Unix()))
	public := inviterPrivate.Public().(ed25519.PublicKey)
	payload := base64.RawURLEncoding.EncodeToString(public) + "." + base64.RawURLEncoding.EncodeToString(expires[:]) + "." + base64.RawURLEncoding.EncodeToString(nonce[:])
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(inviterPrivate, []byte(payload)))
	sum := sha256.Sum256([]byte(payload))
	return payload + "/" + signature, base64.RawURLEncoding.EncodeToString(sum[:])
}

func newInviterKey(t *testing.T) (spki string, private ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der), private
}

// readUntil reads envelopes until one of the type arrives
func readUntil(t *testing.T, conn net.Conn, messageType protocol.MessageType) protocol.Envelope {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 10; i++ {
		envelope := readEnvelope(t, conn)
		if envelope.Type == messageType {
			return envelope
		}
		if envelope.Type == protocol.MessageError {
			t.Fatalf("waiting for %s: error %+v", messageType, envelope.Error)
		}
	}
	t.Fatalf("never received %s", messageType)
	return protocol.Envelope{}
}

// renewOn re-runs the registration handshake on the inviter's existing connection
func renewOn(t *testing.T, conn net.Conn, serviceKey string, private ed25519.PrivateKey) protocol.Envelope {
	t.Helper()
	sendEnvelope(t, conn, protocol.Envelope{MajorVersion: 1, MinorVersion: 0, Type: protocol.MessagePresenceRegister, RequestID: "renew-1", ServiceKey: serviceKey})
	challenge := readUntil(t, conn, protocol.MessagePresenceChallenge)
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.ChallengeNonce)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := network.SignBytes(network.PurposePresence, nonce, private)
	if err != nil {
		t.Fatal(err)
	}
	sendEnvelope(t, conn, protocol.Envelope{MajorVersion: 1, MinorVersion: 0, Type: protocol.MessagePresenceRegister, RequestID: "renew-2",
		ServiceKey: serviceKey, ChallengeNonce: challenge.ChallengeNonce, ChallengeSignature: signature})
	return readUntil(t, conn, protocol.MessagePresenceRegistered)
}

// invite runs one invitation from the joiner's open to both sides' session.close; renew re-registers on the inviter's
// connection while its bootstrap session is open
func invite(t *testing.T, address string, inviter net.Conn, inviterKey string, inviterPrivate ed25519.PrivateKey, round int, renew bool) {
	t.Helper()
	code, digest := invitationFrom(t, inviterPrivate, time.Now().UTC())
	transaction := fmt.Sprintf("transaction-%d", round)
	joinerKey := fmt.Sprintf("joiner-%d", round)
	sendInvitationUDPProbe(t, address, protocol.InvitationUDPProbe{Version: 1, InvitationCode: code, Key: joinerKey,
		TokenDigest: digest, TransactionID: transaction, TunnelInstanceID: "tunnel", Generation: 1})
	joiner := dialClient(t, address)
	defer joiner.Close()
	sendEnvelope(t, joiner, protocol.Envelope{MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: joinerKey, TokenDigest: digest, TransactionID: transaction, TunnelInstance: "tunnel", Generation: 1})
	if opened := readUntil(t, joiner, protocol.MessageSessionOpened); opened.SessionID == "" {
		t.Fatalf("round %d: joiner session = %+v", round, opened)
	}
	pending := readUntil(t, inviter, protocol.MessageBootstrapPending)
	if pending.TokenDigest != digest {
		t.Fatalf("round %d: push for %s, want %s", round, pending.TokenDigest, digest)
	}
	sendInvitationUDPProbe(t, address, protocol.InvitationUDPProbe{Version: 1, InvitationCode: code, Key: inviterKey,
		TokenDigest: digest, TransactionID: transaction, TunnelInstanceID: "tunnel", Generation: 1})
	sendEnvelope(t, inviter, protocol.Envelope{MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession, RequestID: "open",
		InvitationCode: code, Key: inviterKey, TokenDigest: digest, TransactionID: transaction, TunnelInstance: "tunnel", Generation: 1})
	opened := readUntil(t, inviter, protocol.MessageSessionOpened)
	if opened.SessionID == "" {
		t.Fatalf("round %d: inviter session = %+v", round, opened)
	}
	if renew {
		if registered := renewOn(t, inviter, inviterKey, inviterPrivate); registered.RegistrationExpiresAt == "" {
			t.Fatalf("round %d: renewal = %+v", round, registered)
		}
	}
	sendEnvelope(t, inviter, protocol.Envelope{MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageCloseSession, SessionID: opened.SessionID})
}

// One registration serves invitation after invitation; closing a bootstrap session keeps it, and the inviter may renew
// its lease while a session is open.
func TestOneInviterRegistrationServesSequentialInvites(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	inviterKey, inviterPrivate := newInviterKey(t)
	inviter := registerInviter(t, address, inviterKey, inviterPrivate)
	defer inviter.Close()
	for round := 1; round <= 4; round++ {
		invite(t, address, inviter, inviterKey, inviterPrivate, round, round == 2)
	}
}

// A lease runs out without a renewal (joins fail with inviter offline), and renewals on the same connection keep it.
func TestInviterLeaseNeedsRenewal(t *testing.T) {
	address, cleanup := runServer(t, func(cfg *config.Config) { cfg.RegistrationLease = 2 * time.Second })
	defer cleanup()
	inviterKey, inviterPrivate := newInviterKey(t)
	inviter := registerInviter(t, address, inviterKey, inviterPrivate)
	defer inviter.Close()
	// Renewing every second keeps it online past several leases
	for i := 0; i < 4; i++ {
		time.Sleep(time.Second)
		renewOn(t, inviter, inviterKey, inviterPrivate)
	}
	invite(t, address, inviter, inviterKey, inviterPrivate, 1, false)
	// Without renewals it expires
	time.Sleep(2500 * time.Millisecond)
	code, digest := invitationFrom(t, inviterPrivate, time.Now().UTC())
	sendInvitationUDPProbe(t, address, protocol.InvitationUDPProbe{Version: 1, InvitationCode: code, Key: "late-joiner",
		TokenDigest: digest, TransactionID: "late", TunnelInstanceID: "tunnel", Generation: 1})
	joiner := dialClient(t, address)
	defer joiner.Close()
	sendEnvelope(t, joiner, protocol.Envelope{MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: "late-joiner", TokenDigest: digest, TransactionID: "late", TunnelInstance: "tunnel", Generation: 1})
	_ = joiner.SetReadDeadline(time.Now().Add(3 * time.Second))
	rejected := readEnvelope(t, joiner)
	if rejected.Type != protocol.MessageError || rejected.Error.Code != "unauthorized" || rejected.Error.Message != "inviter offline" {
		t.Fatalf("join after the lease ran out = %+v, want inviter offline", rejected)
	}
}

func TestKeyTagKeepsKeysApart(t *testing.T) {
	first, _ := newInviterKey(t)
	second, _ := newInviterKey(t)
	if keyTag(first) == keyTag(second) || len(keyTag(first)) != 12 {
		t.Fatalf("keyTag(%s) = %s, keyTag(%s) = %s", first, keyTag(first), second, keyTag(second))
	}
}
