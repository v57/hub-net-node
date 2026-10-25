// rendezvous_client is a Linux acceptance-test client. It proves that the
// endpoint installed into WireGuard came from link.ready, not fixture
// knowledge embedded in the network-namespace script.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/v57/hub-net-node/identity"
	network "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
)

func main() {
	var (
		server       = flag.String("server", "", "rendezvous node host:port")
		hubPath      = flag.String("identity", "", "shared hub signing identity")
		devicePath   = flag.String("device", "", "this device's identity (its service key)")
		peerPath     = flag.String("peer-device", "", "the other device's identity (only its public key is used)")
		role         = flag.String("role", "target", "target waits for the link, opener opens it")
		listenPort   = flag.Int("listen-port", 51820, "UDP source port later used by WireGuard")
		output       = flag.String("output", "", "file receiving the peer endpoint from link.ready")
		initIdentity = flag.Bool("init-identity", false, "create the identities if absent, then exit")
	)
	flag.Parse()
	if *hubPath == "" || *devicePath == "" {
		fatal(errors.New("-identity and -device are required"))
	}
	hub, err := identity.Load(*hubPath)
	if err != nil {
		fatal(err)
	}
	device, err := identity.Load(*devicePath)
	if err != nil {
		fatal(err)
	}
	if *initIdentity {
		return
	}
	if *server == "" || *peerPath == "" || *output == "" {
		fatal(errors.New("-server, -peer-device and -output are required"))
	}
	peer, err := identity.Load(*peerPath)
	if err != nil {
		fatal(err)
	}
	if err := run(hub, device, peer, *server, *role == "opener", *listenPort, *output); err != nil {
		fatal(err)
	}
}

// run introduces this device to its peer through the node and writes the peer's node-observed endpoint, the only
// endpoint knowledge the script gets: proof that WireGuard's endpoint came from link.ready.
func run(hub, device, peer *identity.Identity, server string, opener bool, listenPort int, output string) error {
	deviceKey, _ := device.PublicKeyBase64()
	peerKey, _ := peer.PublicKeyBase64()
	conn, reader, err := dialWebSocket(server)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := registerPresence(conn, reader, device, deviceKey); err != nil {
		return err
	}

	var linkID, probeToken string
	if opener {
		grant, err := hubGrant(hub, deviceKey, peerKey)
		if err != nil {
			return err
		}
		// The target registers at about the same time: retry while it isn't present yet
		for attempt := 0; ; attempt++ {
			if err := writeEnvelope(conn, protocol.Envelope{MajorVersion: protocol.MajorVersion, Type: protocol.MessageLinkOpen, Grant: &grant}); err != nil {
				return err
			}
			reply, err := readEnvelope(reader)
			if err != nil {
				return err
			}
			if reply.Type == protocol.MessageLinkOpened {
				linkID, probeToken = reply.LinkID, reply.ProbeToken
				break
			}
			if reply.Type != protocol.MessageError || reply.Error.Code != "peer_offline" || attempt > 50 {
				return fmt.Errorf("link.open: %+v", reply.Error)
			}
			time.Sleep(200 * time.Millisecond)
		}
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		incoming, err := readEnvelope(reader)
		if err != nil {
			return err
		}
		if incoming.Type != protocol.MessageLinkIncoming || incoming.PeerKey != peerKey {
			return fmt.Errorf("expected link.incoming from the peer, got %+v", incoming)
		}
		linkID, probeToken = incoming.LinkID, incoming.ProbeToken
		if err := writeEnvelope(conn, protocol.Envelope{MajorVersion: protocol.MajorVersion, Type: protocol.MessageLinkAccept, LinkID: linkID}); err != nil {
			return err
		}
	}

	// Probe from WireGuard's port until the node pushes link.ready, then release the port for WireGuard
	remote, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: listenPort})
	if err != nil {
		return fmt.Errorf("bind probe port %d: %w", listenPort, err)
	}
	probe, _ := json.Marshal(protocol.LinkUDPProbe{Version: network.WireVersion, LinkID: linkID, ProbeToken: probeToken})
	stop := make(chan struct{})
	go func() {
		for {
			_, _ = udp.WriteToUDP(probe, remote)
			select {
			case <-stop:
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()
	defer func() { close(stop); udp.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		envelope, err := readEnvelope(reader)
		if err != nil {
			return err
		}
		switch envelope.Type {
		case protocol.MessageError, protocol.MessageLinkClosed:
			return fmt.Errorf("link failed: %+v", envelope.Error)
		case protocol.MessageLinkReady:
			observed := envelope.Observed
			if envelope.PeerKey != peerKey || observed == nil || observed.Transport != "udp" || observed.Port == 0 {
				return fmt.Errorf("invalid link.ready: %+v", envelope)
			}
			endpoint := net.JoinHostPort(observed.Address, strconv.Itoa(int(observed.Port)))
			return os.WriteFile(output, []byte(endpoint+"\n"), 0o600)
		}
	}
}

func registerPresence(conn net.Conn, reader io.Reader, device *identity.Identity, deviceKey string) error {
	if err := writeEnvelope(conn, protocol.Envelope{MajorVersion: protocol.MajorVersion, Type: protocol.MessagePresenceRegister, ServiceKey: deviceKey}); err != nil {
		return err
	}
	challenge, err := readEnvelope(reader)
	if err != nil {
		return err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.ChallengeNonce)
	if challenge.Type != protocol.MessagePresenceChallenge || err != nil {
		return fmt.Errorf("presence.challenge: %+v", challenge)
	}
	signature, err := network.SignBytes(network.PurposePresence, nonce, device.PrivateKey())
	if err != nil {
		return err
	}
	if err := writeEnvelope(conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, Type: protocol.MessagePresenceRegister, ServiceKey: deviceKey,
		ChallengeNonce: challenge.ChallengeNonce, ChallengeSignature: signature,
	}); err != nil {
		return err
	}
	registered, err := readEnvelope(reader)
	if err != nil {
		return err
	}
	if registered.Type != protocol.MessagePresenceRegistered {
		return fmt.Errorf("presence.register: %+v", registered.Error)
	}
	return nil
}

// hubGrant is a hub link between the two devices, signed by the shared hub identity.
func hubGrant(hub *identity.Identity, a, b string) (network.PeerLinkGrant, error) {
	hubKey, err := hub.PublicKeyBase64()
	if err != nil {
		return network.PeerLinkGrant{}, err
	}
	now := time.Now().UTC()
	grant := network.PeerLinkGrant{
		Version: network.WireVersion, GrantID: "hn409-" + strconv.FormatInt(now.UnixNano(), 10), HubKey: hubKey,
		HubNetworkID: "hn409-integration", Purpose: network.PeerLinkPurposeHub,
		A:     network.PeerLinkSide{Key: a, WireGuardKey: "wg-" + a[len(a)-8:], Member: "device:a", Addresses: []string{"100.96.0.20"}},
		B:     network.PeerLinkSide{Key: b, WireGuardKey: "wg-" + b[len(b)-8:], Member: "device:b", Addresses: []string{"100.96.0.10"}},
		AViaB: []string{"100.96.0.10/32"}, BViaA: []string{"100.96.0.20/32"},
		AToB: []network.PeerLinkPort{}, BToA: []network.PeerLinkPort{},
		IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	grant.Signature, err = network.SignEnvelope(network.PurposePeerLink, grant, hub.PrivateKey())
	return grant, err
}

func dialWebSocket(address string) (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		conn.Close()
		return nil, nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	request := "GET /rendezvous HTTP/1.1\r\nHost: " + address +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		conn.Close()
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet, URL: &url.URL{}})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, nil, fmt.Errorf("WebSocket status %s", response.Status)
	}
	return conn, reader, nil
}

func writeEnvelope(writer io.Writer, envelope protocol.Envelope) error {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	mask := [4]byte{}
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header := []byte{0x81}
	switch {
	case len(payload) <= 125:
		header = append(header, 0x80|byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(header[2:], uint16(len(payload)))
	default:
		return errors.New("envelope too large")
	}
	header = append(header, mask[:]...)
	masked := bytes.Clone(payload)
	for i := range masked {
		masked[i] ^= mask[i%4]
	}
	_, err = writer.Write(append(header, masked...))
	return err
}

func readEnvelope(reader io.Reader) (protocol.Envelope, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return protocol.Envelope{}, err
	}
	if header[0]&0x0f != 1 || header[1]&0x80 != 0 {
		return protocol.Envelope{}, errors.New("unexpected WebSocket frame")
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return protocol.Envelope{}, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return protocol.Envelope{}, err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if length > protocol.DefaultMaxMessageBytes {
		return protocol.Envelope{}, errors.New("server frame too large")
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return protocol.Envelope{}, err
	}
	var envelope protocol.Envelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return protocol.Envelope{}, err
	}
	return envelope, nil
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "rendezvous client:", strings.TrimSpace(err.Error()))
	os.Exit(1)
}
