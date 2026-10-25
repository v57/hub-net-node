package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PROXY protocol (HAProxy v1 text and v2 binary) carries the client address
// across a TLS-terminating TCP proxy, so admission limits, replay bounds and
// logs see the client instead of the proxy. Only connections from configured
// trusted prefixes are parsed, and they must start with a header: a trusted
// proxy that forwarded client bytes without one would otherwise let any
// client claim an arbitrary source. Other sources keep their own address.

const (
	proxyV1MaxLength = 107
	// proxyV2MaxLength bounds the address block plus TLVs. Real proxies send
	// at most a few hundred bytes; anything larger is refused unread.
	proxyV2MaxLength = 1024
)

var (
	proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")
	errProxyHeader   = errors.New("proxy protocol: invalid header")
)

// proxyProtocolListener resolves PROXY headers off the accept loop so a slow
// trusted peer cannot stall other connections. Pending header reads are
// bounded by maxPending and each one by timeout.
type proxyProtocolListener struct {
	net.Listener
	trusted  []netip.Prefix
	timeout  time.Duration
	pending  chan struct{}
	results  chan acceptResult
	done     chan struct{}
	once     sync.Once
	onReject func(source string, err error)
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func newProxyProtocolListener(inner net.Listener, trusted []netip.Prefix, timeout time.Duration, maxPending int, onReject func(string, error)) net.Listener {
	l := &proxyProtocolListener{
		Listener: inner, trusted: trusted, timeout: timeout,
		pending: make(chan struct{}, maxPending), results: make(chan acceptResult),
		done: make(chan struct{}), onReject: onReject,
	}
	go l.acceptLoop()
	return l
}

func (l *proxyProtocolListener) acceptLoop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			l.deliver(acceptResult{err: err})
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				continue
			}
			return
		}
		if !l.isTrusted(conn.RemoteAddr()) {
			if !l.deliver(acceptResult{conn: conn}) {
				_ = conn.Close()
				return
			}
			continue
		}
		select {
		case l.pending <- struct{}{}:
		case <-l.done:
			_ = conn.Close()
			return
		}
		go l.resolve(conn)
	}
}

func (l *proxyProtocolListener) resolve(conn net.Conn) {
	defer func() { <-l.pending }()
	_ = conn.SetReadDeadline(time.Now().Add(l.timeout))
	source, err := readProxyHeader(conn)
	if err == nil {
		err = conn.SetReadDeadline(time.Time{})
	}
	if err != nil {
		_ = conn.Close()
		if l.onReject != nil {
			l.onReject(sourceIPFromAddr(conn.RemoteAddr()), err)
		}
		return
	}
	if source.IsValid() {
		conn = &proxiedConn{Conn: conn, remote: net.TCPAddrFromAddrPort(source)}
	}
	if !l.deliver(acceptResult{conn: conn}) {
		_ = conn.Close()
	}
}

func (l *proxyProtocolListener) deliver(result acceptResult) bool {
	select {
	case l.results <- result:
		return true
	case <-l.done:
		return false
	}
}

func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	select {
	case result := <-l.results:
		return result.conn, result.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *proxyProtocolListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

func (l *proxyProtocolListener) isTrusted(address net.Addr) bool {
	addrPort, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return false
	}
	ip := addrPort.Addr().Unmap()
	for _, prefix := range l.trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// proxiedConn reports the client address the trusted proxy declared.
type proxiedConn struct {
	net.Conn
	remote net.Addr
}

func (c *proxiedConn) RemoteAddr() net.Addr { return c.remote }

// readProxyHeader consumes exactly one PROXY header and nothing after it. It
// returns the declared client address, or an invalid AddrPort for v1
// UNKNOWN and v2 LOCAL headers (proxy health checks), which keep the
// connection's own address.
func readProxyHeader(r io.Reader) (netip.AddrPort, error) {
	start := make([]byte, 5)
	if _, err := io.ReadFull(r, start); err != nil {
		return netip.AddrPort{}, err
	}
	switch {
	case string(start) == "PROXY":
		return readProxyV1(r, start)
	case bytes.Equal(start, proxyV2Signature[:5]):
		return readProxyV2(r, start)
	default:
		return netip.AddrPort{}, fmt.Errorf("%w: missing from trusted source", errProxyHeader)
	}
}

func readProxyV1(r io.Reader, start []byte) (netip.AddrPort, error) {
	line := append(make([]byte, 0, proxyV1MaxLength), start...)
	one := make([]byte, 1)
	for !bytes.HasSuffix(line, []byte("\r\n")) {
		if len(line) == proxyV1MaxLength {
			return netip.AddrPort{}, fmt.Errorf("%w: v1 line too long", errProxyHeader)
		}
		if _, err := io.ReadFull(r, one); err != nil {
			return netip.AddrPort{}, err
		}
		line = append(line, one[0])
	}
	fields := strings.Split(string(line[:len(line)-2]), " ")
	if len(fields) >= 2 && fields[1] == "UNKNOWN" {
		return netip.AddrPort{}, nil
	}
	if len(fields) != 6 || (fields[1] != "TCP4" && fields[1] != "TCP6") {
		return netip.AddrPort{}, fmt.Errorf("%w: v1 fields", errProxyHeader)
	}
	ip, err := netip.ParseAddr(fields[2])
	if err != nil || ip.Zone() != "" || ip.Is4() != (fields[1] == "TCP4") {
		return netip.AddrPort{}, fmt.Errorf("%w: v1 source address", errProxyHeader)
	}
	if _, err := netip.ParseAddr(fields[3]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: v1 destination address", errProxyHeader)
	}
	port, err := parseProxyPort(fields[4])
	if err != nil {
		return netip.AddrPort{}, err
	}
	if _, err := parseProxyPort(fields[5]); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip.Unmap(), port), nil
}

// parseProxyPort accepts the v1 grammar: decimal, no sign, no leading zero.
func parseProxyPort(value string) (uint16, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') || strings.ContainsAny(value, "+-") {
		return 0, fmt.Errorf("%w: v1 port", errProxyHeader)
	}
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: v1 port", errProxyHeader)
	}
	return uint16(port), nil
}

func readProxyV2(r io.Reader, start []byte) (netip.AddrPort, error) {
	header := make([]byte, 16)
	copy(header, start)
	if _, err := io.ReadFull(r, header[5:]); err != nil {
		return netip.AddrPort{}, err
	}
	if !bytes.Equal(header[:12], proxyV2Signature) || header[12]>>4 != 2 {
		return netip.AddrPort{}, fmt.Errorf("%w: v2 signature or version", errProxyHeader)
	}
	length := int(binary.BigEndian.Uint16(header[14:16]))
	if length > proxyV2MaxLength {
		return netip.AddrPort{}, fmt.Errorf("%w: v2 length %d", errProxyHeader, length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return netip.AddrPort{}, err
	}
	switch command := header[12] & 0x0f; command {
	case 0x0: // LOCAL: the proxy's own connection, e.g. a health check.
		return netip.AddrPort{}, nil
	case 0x1: // PROXY
	default:
		return netip.AddrPort{}, fmt.Errorf("%w: v2 command %d", errProxyHeader, command)
	}
	switch header[13] {
	case 0x11: // TCP over IPv4: src(4) dst(4) srcport(2) dstport(2)
		if length < 12 {
			return netip.AddrPort{}, fmt.Errorf("%w: v2 IPv4 block", errProxyHeader)
		}
		ip := netip.AddrFrom4([4]byte(body[0:4]))
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(body[8:10])), nil
	case 0x21: // TCP over IPv6: src(16) dst(16) srcport(2) dstport(2)
		if length < 36 {
			return netip.AddrPort{}, fmt.Errorf("%w: v2 IPv6 block", errProxyHeader)
		}
		ip := netip.AddrFrom16([16]byte(body[0:16])).Unmap()
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(body[32:34])), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("%w: v2 family 0x%02x", errProxyHeader, header[13])
	}
}
