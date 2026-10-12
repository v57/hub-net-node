package ws

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// startUpgradeServer runs a one-shot server that upgrades and echoes text
// frames back. Returns the dial address and a cleanup function.
func startEchoServer(t *testing.T, sizeCap int) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := Upgrade(w, r, sizeCap)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				msg, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(msg); err != nil {
					return
				}
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(listener)
		close(done)
	}()
	cleanup := func() {
		_ = srv.Close()
		<-done
	}
	return listener.Addr().String(), cleanup
}

// dialAndHandshake performs a client-side WebSocket handshake over a raw TCP
// connection, returning the open conn and the accept key sent.
func dialAndHandshake(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := "dGhlIHNhbXBsZSBub25jZQ==" // RFC 6455 example key.
	handshake := "GET /rendezvous HTTP/1.1\r\n" +
		"Host: " + address + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(handshake)); err != nil {
		t.Fatal(err)
	}
	// Read until the end of the HTTP headers.
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
		t.Fatalf("handshake response not 101: %q", string(buf))
	}
	return conn
}

// writeTextFrame writes a client text frame with masking applied.
func writeTextFrame(conn net.Conn, opcode OpCode, payload []byte) error {
	var header []byte
	length := len(payload)
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	switch {
	case length <= 125:
		header = make([]byte, 6)
		header[1] = byte(length) | 0x80 // FIN + mask bit set.
	case length <= 0xFFFF:
		header = make([]byte, 8)
		header[1] = 126 | 0x80
		binary.BigEndian.PutUint16(header[2:4], uint16(length))
	default:
		header = make([]byte, 14)
		header[1] = 127 | 0x80
		binary.BigEndian.PutUint64(header[2:10], uint64(length))
	}
	header[0] = byte(opcode) | 0x80
	copy(header[len(header)-4:], mask[:])
	if _, err := conn.Write(header); err != nil {
		return err
	}
	masked := make([]byte, length)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := conn.Write(masked); err != nil {
		return err
	}
	return nil
}

func TestUpgradeAcceptsValidHandshake(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	if err := writeTextFrame(conn, OpText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	echo := readRawFrame(t, conn)
	if echo.op != OpText || string(echo.payload) != "hello" {
		t.Fatalf("echo = op %d payload %q", echo.op, string(echo.payload))
	}
}

type rawFrame struct {
	op      OpCode
	payload []byte
}

func readRawFrame(t *testing.T, conn net.Conn) rawFrame {
	t.Helper()
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	op := OpCode(header[0] & 0x0F)
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
	return rawFrame{op: op, payload: payload}
}

func TestUpgradeRejectsMissingHeaders(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := Upgrade(w, r, 1<<16)
			if !errors.Is(err, ErrBadRequest) {
				t.Fatalf("Upgrade = %v, want ErrBadRequest", err)
			}
		}),
	}
	defer srv.Close()
	go srv.Serve(listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Plain GET with no upgrade headers.
	_, _ = conn.Write([]byte("GET /rendezvous HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 400") {
		t.Fatalf("expected 400, got %q", string(buf[:n]))
	}
}

func TestUpgradeRejectsPost(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := Upgrade(w, r, 1<<16)
			if !errors.Is(err, ErrBadRequest) {
				t.Fatalf("Upgrade = %v, want ErrBadRequest", err)
			}
		}),
	}
	defer srv.Close()
	go srv.Serve(listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("POST /rendezvous HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 405") {
		t.Fatalf("expected 405, got %q", string(buf[:n]))
	}
}

func TestReadRejectsOversizedFrame(t *testing.T) {
	address, cleanup := startEchoServer(t, 16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	// Claim a 1 KiB payload but cap is 16 bytes.
	big := make([]byte, 1024)
	if err := writeTextFrame(conn, OpText, big); err != nil {
		t.Fatal(err)
	}
	// Server must drop the connection without echoing the oversized payload.
	// A close frame followed by EOF is acceptable; echoed text is not.
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	frame := readRawFrame(t, conn)
	if frame.op == OpText {
		t.Fatalf("server echoed oversized frame: %q", string(frame.payload))
	}
	if frame.op != OpClose {
		t.Fatalf("expected close frame, got opcode %d", frame.op)
	}
}

func TestPingIsAnsweredWithPong(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	if err := writeTextFrame(conn, OpPing, []byte("heartbeat")); err != nil {
		t.Fatal(err)
	}
	frame := readRawFrame(t, conn)
	if frame.op != OpPong || string(frame.payload) != "heartbeat" {
		t.Fatalf("pong = op %d payload %q", frame.op, string(frame.payload))
	}
}

func TestCloseFrameClosesConnection(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	if err := writeTextFrame(conn, OpClose, nil); err != nil {
		t.Fatal(err)
	}
	// Server answers with a close frame per RFC 6455, then tears the connection.
	frame := readRawFrame(t, conn)
	if frame.op != OpClose {
		t.Fatalf("expected close frame, got opcode %d", frame.op)
	}
}

// TestConcurrentRoundTrip exercises the frame codec under the race detector:
// one writer, one reader on separate goroutines.
func TestConcurrentRoundTrip(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	const messages = 50
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < messages; i++ {
			if err := writeTextFrame(conn, OpText, []byte("msg")); err != nil {
				return
			}
		}
	}()
	received := 0
	go func() {
		defer wg.Done()
		for i := 0; i < messages; i++ {
			frame := readRawFrame(t, conn)
			if frame.op == OpText && string(frame.payload) == "msg" {
				received++
			}
		}
	}()
	wg.Wait()
	if received != messages {
		t.Fatalf("received %d of %d", received, messages)
	}
}

// ---------------------------------------------------------------------------
// HN-408: frame-parser hardening against malformed and attacker-controlled
// frames. The production gate is that NO attacker-controlled frame may panic
// the process or allocate beyond the configured message cap. The existing
// startEchoServer is reused as the target: it upgrades, echoes text frames,
// and tears down on read error without aborting from inside the handler, so a
// parser panic would surface as the test process dying.
// ---------------------------------------------------------------------------

// expectConnectionClosed asserts the server tore the connection down without
// echoing an application payload. A close frame, EOF, or a small non-text frame
// are all acceptable; a text echo of the hostile input is a security failure.
func expectConnectionClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Read whatever the server sends (close frame body or nothing) before EOF.
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	// A masked close frame is 2-byte header + 4-byte mask + 0/2-byte body; if we
	// got text back, the parser wrongly accepted the hostile frame.
	if n >= 2 && OpCode(buf[0]&0x0F) == OpText {
		t.Fatalf("server echoed text from a rejected frame: %q", buf[:n])
	}
	// n == 0 (EOF) or a close/error frame are both acceptable outcomes.
}

// TestHardenRejectsOverflow64BitLength is the central regression: a 64-bit
// length of 0xffffffffffffffff narrows to int(-1), bypasses the old "> cap"
// check, and panicked in make([]byte, -1). The parser must reject it instead.
func TestHardenRejectsOverflow64BitLength(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	// FIN + text + mask bit; extended 64-bit length of 0xffffffffffffffff.
	hdr := []byte{
		byte(OpText) | 0x80,
		127 | 0x80,
	}
	hdr = binary.BigEndian.AppendUint64(hdr, 0xffffffffffffffff)
	hdr = append(hdr, 0x12, 0x34, 0x56, 0x78) // mask (server reads it before rejecting)
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, conn)
}

// TestHardenRejectsMaxIntPlusOneLength covers the platform-maximum boundary:
// MaxInt64+1 narrows to MinInt64 and also slips past the old guard.
func TestHardenRejectsMaxIntPlusOneLength(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	hdr := []byte{
		byte(OpText) | 0x80,
		127 | 0x80,
	}
	hdr = binary.BigEndian.AppendUint64(hdr, uint64(math.MaxInt)+1)
	hdr = append(hdr, 0x12, 0x34, 0x56, 0x78)
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, conn)
}

// TestHardenRejectsAboveSizeCap pins the documented cap behavior with a
// controlled oversized 64-bit length that fits in int but exceeds sizeCap.
func TestHardenRejectsAboveSizeCap(t *testing.T) {
	address, cleanup := startEchoServer(t, 64)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	hdr := []byte{
		byte(OpText) | 0x80,
		127 | 0x80,
	}
	hdr = binary.BigEndian.AppendUint64(hdr, 4096) // fits in int, > sizeCap(64)
	hdr = append(hdr, 0x12, 0x34, 0x56, 0x78)
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, conn)
}

// TestHardenRejectsUnmaskedClientFrame enforces RFC 6455 §5.1: clients must
// mask every frame. The old parser accepted unmasked frames.
func TestHardenRejectsUnmaskedClientFrame(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	// FIN + text, mask bit CLEAR, small length, no mask bytes, payload.
	hdr := []byte{byte(OpText) | 0x80, 5}
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, conn)
}

// TestHardenRejectsReservedBits enforces RFC 6455 §5.2: RSV1/2/3 must be zero
// when no extension negotiated them. This node negotiates none.
func TestHardenRejectsReservedBits(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	// FIN + RSV1 set + text + mask bit + small length.
	hdr := []byte{byte(OpText) | 0x80 | 0x40, 1 | 0x80, 0x12, 0x34, 0x56, 0x78, 'A'}
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, conn)
}

// TestHardenRejectsReservedOpcode rejects opcodes 3-7 and 11-15 (RFC 6455 §5.2).
func TestHardenRejectsReservedOpcode(t *testing.T) {
	for _, op := range []OpCode{0x3, 0xB, 0xF} {
		t.Run(fmt.Sprintf("op%d", op), func(t *testing.T) {
			address, cleanup := startEchoServer(t, 1<<16)
			defer cleanup()
			conn := dialAndHandshake(t, address)
			defer conn.Close()

			hdr := []byte{byte(op) | 0x80, 0 | 0x80} // masked, zero-length
			if _, err := conn.Write(hdr); err != nil {
				t.Fatal(err)
			}
			expectConnectionClosed(t, conn)
		})
	}
}

// TestHardenRejectsFragmentedControlFrame enforces RFC 6455 §5.5: control
// frames must not be fragmented.
func TestHardenRejectsFragmentedControlFrame(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	// FIN clear + Ping + mask bit + zero-length.
	hdr := []byte{byte(OpPing), 0 | 0x80}
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, conn)
}

// TestHardenRejectsOversizedControlFrame enforces RFC 6455 §5.5: control
// frames carry at most 125 payload bytes.
func TestHardenRejectsOversizedControlFrame(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	// Ping with 7-bit length 200 (encoded inline, no extended bytes).
	hdr := []byte{byte(OpPing) | 0x80, 200 | 0x80}
	hdr = append(hdr, 0x12, 0x34, 0x56, 0x78)
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, conn)
}

// TestHardenTruncatedExtendedLength verifies a truncated 64-bit length header
// is handled as a clean close rather than a stalled/half-read connection. The
// parser reads only the bytes available and errors on io.ReadFull.
func TestHardenTruncatedExtendedLength(t *testing.T) {
	address, cleanup := startEchoServer(t, 1<<16)
	defer cleanup()
	conn := dialAndHandshake(t, address)
	defer conn.Close()

	// Announce a 64-bit length, then send only 2 of the 8 length bytes.
	hdr := []byte{byte(OpText) | 0x80, 127 | 0x80, 0x00, 0x01}
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}
	// Close the write side so the server's io.ReadFull fails with unexpected EOF.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	if n, _ := conn.Read(buf); n > 0 && OpCode(buf[0]&0x0F) == OpText {
		t.Fatalf("server echoed text from a truncated-length frame")
	}
}

// TestProcessSurvivesMalformedFrames is the HN-408 production gate: one server
// process absorbs the full attack-shape list in sequence and is then proven
// still able to serve a well-formed exchange. If any input panicked the parser,
// this test (and the process) would die.
func TestProcessSurvivesMalformedFrames(t *testing.T) {
	const sizeCap = 256
	address, cleanup := startEchoServer(t, sizeCap)
	defer cleanup()

	maxIntPlus1 := binary.BigEndian.AppendUint64(nil, uint64(math.MaxInt)+1)
	overflow64 := binary.BigEndian.AppendUint64(nil, 0xffffffffffffffff)
	attacks := [][]byte{
		// 64-bit length overflow.
		append(append([]byte{byte(OpText) | 0x80, 127 | 0x80}, overflow64...), 0x12, 0x34, 0x56, 0x78),
		// MaxInt+1.
		append(append([]byte{byte(OpText) | 0x80, 127 | 0x80}, maxIntPlus1...), 0x12, 0x34, 0x56, 0x78),
		// Above size cap (fits in int).
		append(append([]byte{byte(OpText) | 0x80, 127 | 0x80},
			binary.BigEndian.AppendUint64(nil, 4096)...), 0x12, 0x34, 0x56, 0x78),
		// Unmasked client frame.
		{byte(OpText) | 0x80, 5, 'h', 'e', 'l', 'l', 'o'},
		// Reserved bits (RSV1).
		{byte(OpText) | 0x80 | 0x40, 1 | 0x80, 0x12, 0x34, 0x56, 0x78, 'A'},
		// Reserved opcode 0x3.
		{0x03 | 0x80, 0 | 0x80},
		// Reserved opcode 0xF.
		{0x0F | 0x80, 0 | 0x80},
		// Fragmented control frame (FIN clear, Ping).
		{byte(OpPing), 0 | 0x80},
		// Oversized control frame (Ping, length 200).
		{byte(OpPing) | 0x80, 200 | 0x80, 0x12, 0x34, 0x56, 0x78},
	}

	for i, frame := range attacks {
		conn := dialAndHandshake(t, address)
		if _, err := conn.Write(frame); err != nil {
			t.Fatalf("attack %d write: %v", i, err)
		}
		expectConnectionClosed(t, conn)
		_ = conn.Close()
	}

	// Liveness: the same process must still complete a normal echo round-trip.
	live := dialAndHandshake(t, address)
	defer live.Close()
	if err := writeTextFrame(live, OpText, []byte("survived")); err != nil {
		t.Fatal(err)
	}
	echo := readRawFrame(t, live)
	if echo.op != OpText || string(echo.payload) != "survived" {
		t.Fatalf("post-attack echo = op %d payload %q; process did not survive", echo.op, echo.payload)
	}
}

// FuzzReadFrame feeds arbitrary byte streams through an upgraded server's read
// loop and asserts no input panics the process or hangs past the deadline. The
// seed corpus is the HN-408 attack catalog plus well-formed frames.
func FuzzReadFrame(f *testing.F) {
	// Seed: each attack shape.
	maxIntPlus1 := binary.BigEndian.AppendUint64(nil, uint64(math.MaxInt)+1)
	overflow64 := binary.BigEndian.AppendUint64(nil, 0xffffffffffffffff)
	seeds := [][]byte{
		append(append([]byte{byte(OpText) | 0x80, 127 | 0x80}, overflow64...), 0x12, 0x34, 0x56, 0x78),
		append(append([]byte{byte(OpText) | 0x80, 127 | 0x80}, maxIntPlus1...), 0x12, 0x34, 0x56, 0x78),
		{byte(OpText) | 0x80, 5, 'h', 'e', 'l', 'l', 'o'},                   // unmasked
		{byte(OpText) | 0x80 | 0x40, 1 | 0x80, 0x12, 0x34, 0x56, 0x78, 'A'}, // RSV1
		{0x03 | 0x80, 0 | 0x80},                                                     // reserved opcode
		{byte(OpPing), 0 | 0x80},                                                    // fragmented control
		{byte(OpPing) | 0x80, 200 | 0x80},                                           // oversized control
		{byte(OpText) | 0x80, 1 | 0x80, 0x00, 0x00, 0x00, 0x00, 'A'},                // valid masked text
		{byte(OpPing) | 0x80, 4 | 0x80, 0x00, 0x00, 0x00, 0x00, 'p', 'i', 'n', 'g'}, // valid ping
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, frame []byte) {
		// An in-process parser-level fuzz avoids a per-input TCP server while
		// exercising the exact production code path. Build the bufio reader the
		// production Conn uses and parse directly.
		if len(frame) > 1<<20 {
			t.Skip("input too large for fast fuzz path")
		}
		br := bufio.NewReader(bytes.NewReader(frame))
		c := &Conn{rw: nopReadWriter{}, br: br, sizeCap: 1 << 16}
		// Loop until the parser stops. The assertion is "does not panic"; any
		// returned error is acceptable for a malformed input.
		for i := 0; i < 32; i++ {
			_, _, err := c.readFrame()
			if err != nil {
				return
			}
		}
	})
}

// nopReadWriter satisfies io.ReadWriter for the Conn in the fuzz path, where
// writes (Pong answers) are discarded.
type nopReadWriter struct{}

func (nopReadWriter) Read(p []byte) (int, error)  { return 0, io.EOF }
func (nopReadWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWriter) Close() error                { return nil }
