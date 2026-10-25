package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/v57/hub-net-node/config"
)

func proxyV2Header(command, family byte, body []byte) []byte {
	header := append([]byte{}, proxyV2Signature...)
	header = append(header, 0x20|command, family, 0, 0)
	binary.BigEndian.PutUint16(header[14:16], uint16(len(body)))
	return append(header, body...)
}

func TestReadProxyHeader(t *testing.T) {
	ipv4Body := []byte{198, 51, 100, 7, 10, 0, 0, 1, 0xd4, 0x31, 0x01, 0xbb}
	ipv6Body := make([]byte, 36)
	copy(ipv6Body, netip.MustParseAddr("2001:db8::7").AsSlice())
	copy(ipv6Body[16:], netip.MustParseAddr("2001:db8::1").AsSlice())
	binary.BigEndian.PutUint16(ipv6Body[32:], 40000)
	binary.BigEndian.PutUint16(ipv6Body[34:], 443)
	withTLV := append(append([]byte{}, ipv4Body...), 0x04, 0x00, 0x02, 'h', 'i')

	tests := []struct {
		name   string
		header []byte
		want   string // empty: header names no client (keep peer address)
		err    bool
	}{
		{name: "v1 tcp4", header: []byte("PROXY TCP4 198.51.100.7 10.0.0.1 54321 443\r\n"), want: "198.51.100.7:54321"},
		{name: "v1 tcp6", header: []byte("PROXY TCP6 2001:db8::7 2001:db8::1 40000 443\r\n"), want: "[2001:db8::7]:40000"},
		{name: "v1 mapped tcp6", header: []byte("PROXY TCP6 ::ffff:198.51.100.7 ::1 40000 443\r\n"), want: "198.51.100.7:40000"},
		{name: "v1 unknown", header: []byte("PROXY UNKNOWN\r\n")},
		{name: "v1 family mismatch", header: []byte("PROXY TCP4 2001:db8::7 10.0.0.1 1 443\r\n"), err: true},
		{name: "v1 port overflow", header: []byte("PROXY TCP4 198.51.100.7 10.0.0.1 65536 443\r\n"), err: true},
		{name: "v1 leading zero port", header: []byte("PROXY TCP4 198.51.100.7 10.0.0.1 0443 443\r\n"), err: true},
		{name: "v1 missing field", header: []byte("PROXY TCP4 198.51.100.7 10.0.0.1 443\r\n"), err: true},
		{name: "v1 bare newline", header: []byte("PROXY TCP4 198.51.100.7 10.0.0.1 1 443\n"), err: true},
		{name: "v1 too long", header: []byte("PROXY TCP4 " + strings.Repeat("1", 120) + "\r\n"), err: true},
		{name: "v2 tcp4", header: proxyV2Header(1, 0x11, ipv4Body), want: "198.51.100.7:54321"},
		{name: "v2 tcp4 with tlv", header: proxyV2Header(1, 0x11, withTLV), want: "198.51.100.7:54321"},
		{name: "v2 tcp6", header: proxyV2Header(1, 0x21, ipv6Body), want: "[2001:db8::7]:40000"},
		{name: "v2 local", header: proxyV2Header(0, 0x00, nil)},
		{name: "v2 short ipv4 block", header: proxyV2Header(1, 0x11, ipv4Body[:8]), err: true},
		{name: "v2 udp family", header: proxyV2Header(1, 0x12, ipv4Body), err: true},
		{name: "v2 unknown command", header: proxyV2Header(2, 0x11, ipv4Body), err: true},
		{name: "v2 oversized", header: proxyV2Header(1, 0x11, make([]byte, proxyV2MaxLength+1)), err: true},
		{name: "plain http", header: []byte("GET /healthz HTTP/1.1\r\n"), err: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := bytes.NewReader(append(append([]byte{}, test.header...), "GET /"...))
			got, err := readProxyHeader(reader)
			if test.err {
				if err == nil {
					t.Fatalf("accepted %q as %v", test.header, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("readProxyHeader: %v", err)
			}
			if test.want == "" {
				if got.IsValid() {
					t.Fatalf("got %v, want no client address", got)
				}
			} else if got.String() != test.want {
				t.Fatalf("got %v, want %s", got, test.want)
			}
			rest, _ := io.ReadAll(reader)
			if string(rest) != "GET /" {
				t.Fatalf("header read consumed application bytes; rest = %q", rest)
			}
		})
	}
}

func TestReadProxyHeaderTruncated(t *testing.T) {
	full := []byte("PROXY TCP4 198.51.100.7 10.0.0.1 54321 443\r\n")
	if _, err := readProxyHeader(bytes.NewReader(full[:20])); !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("truncated v1 err = %v", err)
	}
}

func listenProxyProtocol(t *testing.T, trusted string, timeout time.Duration) (net.Listener, chan error) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	prefixes, err := config.ParseTrustedProxies(trusted)
	if err != nil {
		t.Fatal(err)
	}
	rejected := make(chan error, 8)
	listener := newProxyProtocolListener(inner, prefixes, timeout, 4, func(_ string, err error) { rejected <- err })
	t.Cleanup(func() { _ = listener.Close() })
	return listener, rejected
}

func dialAndWrite(t *testing.T, address string, data string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if data != "" {
		if _, err := conn.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	return conn
}

func acceptWithin(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	case <-time.After(2 * time.Second):
		t.Fatal("no connection accepted")
		return nil
	}
}

func TestProxyProtocolListenerUsesDeclaredClient(t *testing.T) {
	listener, _ := listenProxyProtocol(t, "127.0.0.0/8", time.Second)
	dialAndWrite(t, listener.Addr().String(), "PROXY TCP4 198.51.100.7 10.0.0.1 54321 443\r\nhello")
	conn := acceptWithin(t, listener)
	if got := conn.RemoteAddr().String(); got != "198.51.100.7:54321" {
		t.Fatalf("RemoteAddr = %s", got)
	}
	payload := make([]byte, 5)
	if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "hello" {
		t.Fatalf("payload = %q, %v", payload, err)
	}
}

func TestProxyProtocolListenerRejectsTrustedPeerWithoutHeader(t *testing.T) {
	listener, rejected := listenProxyProtocol(t, "127.0.0.1", time.Second)
	dialAndWrite(t, listener.Addr().String(), "GET /healthz HTTP/1.1\r\n\r\n")
	select {
	case err := <-rejected:
		if !errors.Is(err, errProxyHeader) {
			t.Fatalf("reject err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("headerless trusted connection was not rejected")
	}
}

func TestProxyProtocolListenerPassesUntrustedPeer(t *testing.T) {
	listener, _ := listenProxyProtocol(t, "192.0.2.0/24", time.Second)
	// A client outside the trusted set cannot claim another source.
	dialAndWrite(t, listener.Addr().String(), "PROXY TCP4 198.51.100.7 10.0.0.1 54321 443\r\n")
	conn := acceptWithin(t, listener)
	if got := sourceIPFromAddr(conn.RemoteAddr()); got != "127.0.0.1" {
		t.Fatalf("RemoteAddr = %s, want the TCP peer", conn.RemoteAddr())
	}
}

func TestProxyProtocolListenerSlowPeerDoesNotBlockOthers(t *testing.T) {
	listener, rejected := listenProxyProtocol(t, "127.0.0.0/8", 300*time.Millisecond)
	dialAndWrite(t, listener.Addr().String(), "PROXY TCP4 ")
	dialAndWrite(t, listener.Addr().String(), "PROXY TCP4 198.51.100.8 10.0.0.1 1000 443\r\n")
	conn := acceptWithin(t, listener)
	if got := conn.RemoteAddr().String(); got != "198.51.100.8:1000" {
		t.Fatalf("RemoteAddr = %s", got)
	}
	select {
	case err := <-rejected:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("slow peer err = %v, want timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow header was not timed out")
	}
}

// TestServerAdmitsByProxiedSource runs the full listener stack: per-source
// admission counts the declared clients, not the proxy they share.
func TestServerAdmitsByProxiedSource(t *testing.T) {
	address, stop := runServer(t, func(cfg *config.Config) {
		cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
		cfg.MaxConnectionsPerSource = 1
	})
	defer stop()

	health := func(header string) (int, error) {
		conn := dialAndWrite(t, address, header+"GET "+HealthPath+" HTTP/1.1\r\nHost: net.v57.dev\r\n\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return 0, err
		}
		_ = response.Body.Close()
		return response.StatusCode, nil
	}
	// Both connections stay open (keep-alive): one per declared source fits.
	for _, client := range []string{"198.51.100.1", "198.51.100.2"} {
		status, err := health("PROXY TCP4 " + client + " 127.0.0.1 40000 443\r\n")
		if err != nil || status != http.StatusOK {
			t.Fatalf("health via %s = %d, %v", client, status, err)
		}
	}
	if _, err := health("PROXY TCP4 198.51.100.1 127.0.0.1 40001 443\r\n"); err == nil {
		t.Fatal("second connection from the same declared source was admitted")
	}
	if _, err := health(""); err == nil {
		t.Fatal("headerless connection from the trusted proxy was served")
	}
}

func TestServerBindsSeparateUDPAddress(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	udpAddress := probe.LocalAddr().String()
	_ = probe.Close()
	_, stop := runServer(t, func(cfg *config.Config) { cfg.UDPListenAddress = udpAddress })
	defer stop()
	// The node owns the port now; binding it again fails.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.ListenPacket("udp", udpAddress)
		if err != nil {
			return
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("UDP %s was not bound by the node", udpAddress)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
