package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	network "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
)

type testDevice struct {
	key     string
	private ed25519.PrivateKey
	conn    net.Conn
}

func newKey(t *testing.T) (string, ed25519.PrivateKey) {
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

// presentDevice registers a fresh device's presence and keeps its connection open.
func presentDevice(t *testing.T, address string) testDevice {
	t.Helper()
	key, private := newKey(t)
	conn := registerInviter(t, address, key, private)
	t.Cleanup(func() { conn.Close() })
	return testDevice{key: key, private: private, conn: conn}
}

// signedGrant is a hub-signed hub link between a and b (the hub's machine).
func signedGrant(t *testing.T, hubPrivate ed25519.PrivateKey, hubKey string, a, b testDevice) network.PeerLinkGrant {
	t.Helper()
	now := time.Now().UTC()
	grant := network.PeerLinkGrant{
		Version: network.WireVersion, GrantID: "grant-" + a.key[len(a.key)-8:], HubKey: hubKey, HubNetworkID: "network-1",
		Purpose:  network.PeerLinkPurposeHub,
		A:        network.PeerLinkSide{Key: a.key, WireGuardKey: "wg-a", Member: "device:a", Addresses: []string{"100.96.0.1", "fd48:5542:4e45::1"}},
		B:        network.PeerLinkSide{Key: b.key, WireGuardKey: "wg-b", Member: "device:b", Addresses: []string{"100.96.0.2", "fd48:5542:4e45::2"}},
		AViaB:    []string{"100.96.0.2/32", "fd48:5542:4e45::2/128"},
		BViaA:    []string{"100.96.0.1/32", "fd48:5542:4e45::1/128"},
		AToB:     []network.PeerLinkPort{{Protocol: "tcp", Port: 1997}},
		BToA:     []network.PeerLinkPort{},
		IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339Nano),
	}
	signature, err := network.SignEnvelope(network.PurposePeerLink, grant, hubPrivate)
	if err != nil {
		t.Fatal(err)
	}
	grant.Signature = signature
	return grant
}

func newHub(t *testing.T) (string, ed25519.PrivateKey) { return newKey(t) }

func openLink(t *testing.T, opener testDevice, grant network.PeerLinkGrant) protocol.Envelope {
	t.Helper()
	sendEnvelope(t, opener.conn, protocol.Envelope{
		MajorVersion: 1, Type: protocol.MessageLinkOpen, RequestID: "open", Grant: &grant,
	})
	return readEnvelope(t, opener.conn)
}

// sendLinkProbe sends a link probe from a fresh UDP socket and returns the socket's local address, the endpoint the
// node should observe.
func sendLinkProbe(t *testing.T, address, linkID, token string) *net.UDPAddr {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	body, _ := json.Marshal(protocol.LinkUDPProbe{Version: network.WireVersion, LinkID: linkID, ProbeToken: token})
	if _, err := conn.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatalf("read link probe response: %v", err)
	}
	var ack protocol.LinkUDPProbeResponse
	if err := json.Unmarshal(response[:n], &ack); err != nil || ack.LinkID != linkID {
		t.Fatalf("link probe response = %s", response[:n])
	}
	return conn.LocalAddr().(*net.UDPAddr)
}

// expectNothing fails if the connection receives a frame within the window.
func expectNothing(t *testing.T, conn net.Conn, window time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(window))
	one := make([]byte, 1)
	if n, err := conn.Read(one); err == nil && n > 0 {
		t.Fatalf("unexpected message before accept (first byte %x)", one[0])
	}
	_ = conn.SetReadDeadline(time.Time{})
}

func TestLinkIntroducesTwoPresentDevices(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	hubKey, hubPrivate := newHub(t)
	member, machine := presentDevice(t, address), presentDevice(t, address)
	grant := signedGrant(t, hubPrivate, hubKey, member, machine)

	opened := openLink(t, member, grant)
	if opened.Type != protocol.MessageLinkOpened || opened.LinkID == "" || opened.ProbeToken == "" || opened.PeerKey != machine.key {
		t.Fatalf("link.opened = %+v", opened)
	}
	incoming := readEnvelope(t, machine.conn)
	if incoming.Type != protocol.MessageLinkIncoming || incoming.LinkID != opened.LinkID || incoming.PeerKey != member.key ||
		incoming.Grant == nil || incoming.Grant.Signature != grant.Signature || incoming.ProbeToken == opened.ProbeToken {
		t.Fatalf("link.incoming = %+v", incoming)
	}

	memberUDP := sendLinkProbe(t, address, opened.LinkID, opened.ProbeToken)
	// Observed, but the target hasn't accepted: nothing about either side goes out yet
	expectNothing(t, member.conn, 300*time.Millisecond)
	sendEnvelope(t, machine.conn, protocol.Envelope{MajorVersion: 1, Type: protocol.MessageLinkAccept, LinkID: incoming.LinkID})
	expectNothing(t, machine.conn, 300*time.Millisecond)
	machineUDP := sendLinkProbe(t, address, incoming.LinkID, incoming.ProbeToken)

	toMember, toMachine := readEnvelope(t, member.conn), readEnvelope(t, machine.conn)
	for _, check := range []struct {
		ready    protocol.Envelope
		peer     string
		observed *net.UDPAddr
	}{{toMember, machine.key, machineUDP}, {toMachine, member.key, memberUDP}} {
		if check.ready.Type != protocol.MessageLinkReady || check.ready.PeerKey != check.peer || check.ready.PunchAt == "" ||
			check.ready.Observed == nil || int(check.ready.Observed.Port) != check.observed.Port {
			t.Fatalf("link.ready = %+v, want peer %s observed at %v", check.ready, check.peer, check.observed)
		}
	}

	// A later offer reaches the peer as another link.ready with the candidates
	sendEnvelope(t, member.conn, protocol.Envelope{
		MajorVersion: 1, Type: protocol.MessageLinkOffer, LinkID: opened.LinkID,
		Endpoints: []network.LinkEndpoint{{Address: "192.168.1.18", Port: 51820}},
	})
	again := readEnvelope(t, machine.conn)
	if again.Type != protocol.MessageLinkReady || len(again.Endpoints) != 1 || again.Endpoints[0].Address != "192.168.1.18" {
		t.Fatalf("link.ready after offer = %+v", again)
	}
}

func TestLinkRejectsForgedOrForeignGrants(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	hubKey, hubPrivate := newHub(t)
	member, machine, stranger := presentDevice(t, address), presentDevice(t, address), presentDevice(t, address)

	forged := signedGrant(t, hubPrivate, hubKey, member, machine)
	forged.B.WireGuardKey = "wg-attacker"
	if reply := openLink(t, member, forged); reply.Type != protocol.MessageError || reply.Error.Code != "unauthorized" {
		t.Fatalf("forged grant = %+v", reply)
	}
	// A valid grant between two other devices doesn't let a third one open it
	if reply := openLink(t, stranger, signedGrant(t, hubPrivate, hubKey, member, machine)); reply.Type != protocol.MessageError || reply.Error.Code != "unauthorized" {
		t.Fatalf("grant opened by a stranger = %+v", reply)
	}
	expectNothing(t, machine.conn, 300*time.Millisecond)
}

func TestLinkNeedsPresence(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	hubKey, hubPrivate := newHub(t)
	member := presentDevice(t, address)
	absentKey, absentPrivate := newKey(t)
	absent := testDevice{key: absentKey, private: absentPrivate}
	if reply := openLink(t, member, signedGrant(t, hubPrivate, hubKey, member, absent)); reply.Type != protocol.MessageError || reply.Error.Code != "peer_offline" {
		t.Fatalf("link to an absent device = %+v", reply)
	}
	// A connection that never registered can't open links at all
	unregistered := testDevice{key: member.key, conn: dialClient(t, address)}
	defer unregistered.conn.Close()
	if reply := openLink(t, unregistered, signedGrant(t, hubPrivate, hubKey, member, absent)); reply.Type != protocol.MessageError || reply.Error.Code != "unauthorized" {
		t.Fatalf("link without presence = %+v", reply)
	}
}

func TestLinkRejectionAndPresenceDropCloseIt(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	hubKey, hubPrivate := newHub(t)
	member, machine := presentDevice(t, address), presentDevice(t, address)

	opened := openLink(t, member, signedGrant(t, hubPrivate, hubKey, member, machine))
	incoming := readEnvelope(t, machine.conn)
	sendEnvelope(t, machine.conn, protocol.Envelope{MajorVersion: 1, Type: protocol.MessageLinkReject, LinkID: incoming.LinkID})
	if closed := readEnvelope(t, member.conn); closed.Type != protocol.MessageLinkClosed || closed.LinkID != opened.LinkID || closed.Error.Code != "link_rejected" {
		t.Fatalf("after reject = %+v", closed)
	}

	reopened := openLink(t, member, signedGrant(t, hubPrivate, hubKey, member, machine))
	_ = readEnvelope(t, machine.conn) // link.incoming
	machine.conn.Close()
	if closed := readEnvelope(t, member.conn); closed.Type != protocol.MessageLinkClosed || closed.LinkID != reopened.LinkID || closed.Error.Code != "peer_offline" {
		t.Fatalf("after the target left = %+v", closed)
	}
}

func registerWithTags(t *testing.T, address string, tags []string) testDevice {
	t.Helper()
	key, private := newKey(t)
	conn := dialClient(t, address)
	t.Cleanup(func() { conn.Close() })
	sendEnvelope(t, conn, protocol.Envelope{MajorVersion: 1, Type: protocol.MessagePresenceRegister, RequestID: "c", ServiceKey: key})
	challenge := readEnvelope(t, conn)
	if challenge.MinorVersion != protocol.ChallengeMinorVersion {
		t.Fatalf("challenge says minor %d", challenge.MinorVersion)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.ChallengeNonce)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := network.SignBytes(network.PurposePresence, nonce, private)
	if err != nil {
		t.Fatal(err)
	}
	sendEnvelope(t, conn, protocol.Envelope{
		MajorVersion: 1, Type: protocol.MessagePresenceRegister, RequestID: "r", ServiceKey: key,
		ChallengeNonce: challenge.ChallengeNonce, ChallengeSignature: signature, PresenceTags: tags,
	})
	if reply := readEnvelope(t, conn); reply.Type != protocol.MessagePresenceRegistered || reply.MinorVersion != 0 {
		t.Fatalf("registered = %+v", reply)
	}
	return testDevice{key: key, private: private, conn: conn}
}

func openLinkWithProof(t *testing.T, opener testDevice, grant network.PeerLinkGrant, proof string) protocol.Envelope {
	t.Helper()
	sendEnvelope(t, opener.conn, protocol.Envelope{
		MajorVersion: 1, Type: protocol.MessageLinkOpen, RequestID: "open", Grant: &grant, PresenceProof: proof,
	})
	return readEnvelope(t, opener.conn)
}

// A device with tags and no device at all give the same answer to anyone without the secret, and nothing reaches it.
func TestWithoutThePresenceSecretTheNodeGivesNoAnswer(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	hubKey, hubPrivate := newHub(t)
	secret := []byte("0123456789abcdef0123456789abcdef")

	// The tag is for the target's own key, so register first, then state it
	target := presentDevice(t, address)
	proof := protocol.PresenceProof(secret, target.key)
	sendEnvelope(t, target.conn, protocol.Envelope{MajorVersion: 1, Type: protocol.MessagePresenceTags, PresenceTags: []string{protocol.PresenceTag(proof)}})
	time.Sleep(50 * time.Millisecond)

	absentKey, absentPrivate := newKey(t)
	absent := testDevice{key: absentKey, private: absentPrivate}
	attacker := presentDevice(t, address)
	attackerHub, attackerPrivate := newHub(t)

	answers := map[string]protocol.Envelope{
		"no proof, online":      openLink(t, attacker, signedGrant(t, attackerPrivate, attackerHub, attacker, target)),
		"no proof, offline":     openLink(t, attacker, signedGrant(t, attackerPrivate, attackerHub, attacker, absent)),
		"wrong secret":          openLinkWithProof(t, attacker, signedGrant(t, attackerPrivate, attackerHub, attacker, target), protocol.PresenceProof([]byte("guess"), target.key)),
		"proof for another key": openLinkWithProof(t, attacker, signedGrant(t, attackerPrivate, attackerHub, attacker, target), protocol.PresenceProof(secret, attacker.key)),
		"the tag used as proof": openLinkWithProof(t, attacker, signedGrant(t, attackerPrivate, attackerHub, attacker, target), protocol.PresenceTag(proof)),
		"any proof, offline":    openLinkWithProof(t, attacker, signedGrant(t, attackerPrivate, attackerHub, attacker, absent), proof),
	}
	first, err := json.Marshal(answers["no proof, offline"])
	if err != nil {
		t.Fatal(err)
	}
	for name, answer := range answers {
		if answer.Type != protocol.MessageError || answer.Error.Code != "peer_offline" {
			t.Fatalf("%s = %+v", name, answer)
		}
		body, _ := json.Marshal(answer)
		if string(body) != string(first) {
			t.Fatalf("%s differs from an absent device: %s vs %s", name, body, first)
		}
	}
	expectNothing(t, target.conn, 200*time.Millisecond)

	// All of that used none of the target's budget, and the right proof opens
	member := presentDevice(t, address)
	reply := openLinkWithProof(t, member, signedGrant(t, hubPrivate, hubKey, member, target), proof)
	if reply.Type != protocol.MessageLinkOpened {
		t.Fatalf("with the proof = %+v", reply)
	}
	if incoming := readEnvelope(t, target.conn); incoming.Type != protocol.MessageLinkIncoming {
		t.Fatalf("target got %+v", incoming)
	}
}

func TestPresenceTagsFollowTheConnection(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	hubKey, hubPrivate := newHub(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	first := protocol.PresenceTag(protocol.PresenceProof(secret, "unused"))
	target := registerWithTags(t, address, []string{first})
	proof := protocol.PresenceProof(secret, target.key)
	member := presentDevice(t, address)
	grant := signedGrant(t, hubPrivate, hubKey, member, target)
	if reply := openLinkWithProof(t, member, grant, proof); reply.Type != protocol.MessageError || reply.Error.Code != "peer_offline" {
		t.Fatalf("a tag for another proof = %+v", reply)
	}
	// presence.tags replaces them
	sendEnvelope(t, target.conn, protocol.Envelope{MajorVersion: 1, Type: protocol.MessagePresenceTags, PresenceTags: []string{protocol.PresenceTag(proof)}})
	time.Sleep(50 * time.Millisecond)
	if reply := openLinkWithProof(t, member, grant, proof); reply.Type != protocol.MessageLinkOpened {
		t.Fatalf("after presence.tags = %+v", reply)
	}
	// Someone else's connection can't set them: presence.tags needs a registered connection
	stranger := dialClient(t, address)
	defer stranger.Close()
	sendEnvelope(t, stranger, protocol.Envelope{MajorVersion: 1, Type: protocol.MessagePresenceTags, PresenceTags: []string{"x"}})
	if reply := readEnvelope(t, stranger); reply.Type != protocol.MessageError || reply.Error.Code != "unauthorized" {
		t.Fatalf("presence.tags without presence = %+v", reply)
	}
}

// What an older device does: no tags, no proofs, and it answers as it always did.
func TestADeviceWithoutTagsAnswersAsBefore(t *testing.T) {
	address, cleanup := runServer(t)
	defer cleanup()
	hubKey, hubPrivate := newHub(t)
	target, member := presentDevice(t, address), presentDevice(t, address)
	if reply := openLink(t, member, signedGrant(t, hubPrivate, hubKey, member, target)); reply.Type != protocol.MessageLinkOpened || reply.MinorVersion != 0 {
		t.Fatalf("no tags, no proof = %+v", reply)
	}
}
