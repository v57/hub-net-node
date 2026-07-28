package server

import (
	"net"
	"sync"
)

// newListener opens a TCP listener on the configured address. Kept in its own
// file so HN-402 can add per-platform listener options (TLS, socket options
// for observed-endpoint reporting) without touching the server lifecycle.
func newListener(address string) (net.Listener, error) {
	return net.Listen("tcp", address)
}

// admissionListener bounds sockets before HTTP parsing or authentication.
// Source IP remains effective when clients rotate self-generated identities.
type admissionListener struct {
	net.Listener
	maxTotal, maxPerSource int
	mu                     sync.Mutex
	total                  int
	bySource               map[string]int
	onReject               func(source string)
}

func newAdmissionListener(inner net.Listener, maxTotal, maxPerSource int, onReject func(string)) net.Listener {
	return &admissionListener{
		Listener: inner, maxTotal: maxTotal, maxPerSource: maxPerSource,
		bySource: make(map[string]int), onReject: onReject,
	}
}

func (l *admissionListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		source := sourceIPFromAddr(conn.RemoteAddr())
		l.mu.Lock()
		allowed := l.total < l.maxTotal && l.bySource[source] < l.maxPerSource
		if allowed {
			l.total++
			l.bySource[source]++
		}
		l.mu.Unlock()
		if allowed {
			return &admissionConn{Conn: conn, release: func() { l.release(source) }}, nil
		}
		_ = conn.Close()
		if l.onReject != nil {
			l.onReject(source)
		}
	}
}

func (l *admissionListener) release(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total > 0 {
		l.total--
	}
	if l.bySource[source] <= 1 {
		delete(l.bySource, source)
	} else {
		l.bySource[source]--
	}
}

type admissionConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *admissionConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func sourceIPFromAddr(address net.Addr) string {
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return address.String()
	}
	return host
}
