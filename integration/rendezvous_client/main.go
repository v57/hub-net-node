// rendezvous_client is a Linux acceptance-test client. It proves that the
// endpoint installed into WireGuard came from candidate.list, not fixture
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

	"github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-service-go/identity"
	network "github.com/v57/hub-service-go/protocol"
)

func main() {
	var (
		server       = flag.String("server", "", "rendezvous node host:port")
		nodeID       = flag.String("node-id", "default", "ticket node binding")
		networkID    = flag.String("network-id", "hn409-integration", "shared Hub network")
		key          = flag.String("key", "", "peer identity binding")
		identityPath = flag.String("identity", "", "shared Hub signing identity")
		listenPort   = flag.Int("listen-port", 51820, "UDP source port later used by WireGuard")
		output       = flag.String("output", "", "file receiving delivered peer endpoint")
		initIdentity = flag.Bool("init-identity", false, "create identity if absent, then exit")
	)
	flag.Parse()
	if *identityPath == "" {
		fatal(errors.New("-identity is required"))
	}
	hub, err := identity.Load(*identityPath)
	if err != nil {
		fatal(err)
	}
	if *initIdentity {
		return
	}
	if *server == "" || *key == "" || *output == "" {
		fatal(errors.New("-server, -key, and -output are required"))
	}
	if err := run(hub, *server, *nodeID, *networkID, *key, *listenPort, *output); err != nil {
		fatal(err)
	}
}

func run(hub *identity.Identity, server, nodeID, networkID, key string, listenPort int, output string) error {
	now := time.Now().UTC()
	hubKey, err := hub.PublicKeyBase64()
	if err != nil {
		return err
	}
	ticket := network.RendezvousTicket{
		Version: network.WireVersion, TicketID: "hn409-" + key + "-" + strconv.FormatInt(now.UnixNano(), 10),
		HubKey: hubKey, HubNetworkID: networkID, Key: key,
		NodeID: nodeID, Roles: []string{"rendezvous"}, SessionPurpose: "peer-connect",
		IssuedAt:  now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	ticket.Signature, err = network.SignEnvelope(network.PurposeRendezvousTicket, ticket, hub.PrivateKey())
	if err != nil {
		return err
	}

	remote, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: listenPort})
	if err != nil {
		return fmt.Errorf("bind probe port %d: %w", listenPort, err)
	}
	body, _ := json.Marshal(protocol.UDPProbe{Version: network.WireVersion, Ticket: ticket})
	if _, err := udp.WriteToUDP(body, remote); err != nil {
		udp.Close()
		return err
	}
	_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 1024)
	n, _, err := udp.ReadFromUDP(reply)
	if err != nil {
		udp.Close()
		return fmt.Errorf("UDP probe response: %w", err)
	}
	var probeResponse protocol.UDPProbeResponse
	if json.Unmarshal(reply[:n], &probeResponse) != nil || probeResponse.TicketID != ticket.TicketID {
		udp.Close()
		return errors.New("invalid UDP probe response")
	}
	// Release port only after node confirms observation. Script starts
	// WireGuard on this same numeric port after both clients finish.
	if err := udp.Close(); err != nil {
		return err
	}

	conn, reader, err := dialWebSocket(server)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := writeEnvelope(conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: protocol.MessageOpenSession, Ticket: &ticket,
	}); err != nil {
		return err
	}
	opened, err := readEnvelope(reader)
	if err != nil {
		return err
	}
	if opened.Type != protocol.MessageSessionOpened || opened.SessionID == "" {
		return fmt.Errorf("session open failed: %+v", opened.Error)
	}
	candidate := network.Candidate{
		Version: network.WireVersion, CandidateID: "host-" + key,
		SessionID: opened.SessionID, Key: key, Kind: "host", Transport: "udp",
		Address: "127.0.0.1", Port: uint16(listenPort), Priority: 1,
		ExpiresAt: time.Now().Add(protocol.DefaultCandidateLifetime).Format(time.RFC3339Nano),
	}
	if err := writeEnvelope(conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: protocol.MessageOfferCandidate, SessionID: opened.SessionID, Candidate: &candidate,
	}); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		envelope, err := readEnvelope(reader)
		if err != nil {
			return err
		}
		if envelope.Type == protocol.MessageError {
			return fmt.Errorf("rendezvous error: %s", envelope.Error.Code)
		}
		if envelope.Type != protocol.MessageCandidates || envelope.Observed == nil {
			continue
		}
		observed := envelope.Observed
		if observed.Transport != "udp" || observed.Key == key || observed.Port == 0 {
			return fmt.Errorf("invalid peer observedEndpoint: %+v", observed)
		}
		endpoint := net.JoinHostPort(observed.Address, strconv.Itoa(int(observed.Port)))
		return os.WriteFile(output, []byte(endpoint+"\n"), 0o600)
	}
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
