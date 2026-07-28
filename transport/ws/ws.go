// Package ws implements the minimal RFC 6455 WebSocket transport that the
// hub-net-node rendezvous endpoint needs.
//
// The rendezvous protocol exchanges short JSON envelopes over a single
// connection. This package therefore supports only text frames (no binary,
// no fragmentation), enforces client masking, auto-answers Ping with Pong,
// and rejects any frame larger than the configured size limit before it is
// decoded. It is stdlib-only on purpose: the node keeps a zero external-
// dependency posture, and channel-go's internal/wsraw demonstrates the same
// hand-rolled handshake is viable.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"time"
)

// RFC 6455 magic GUID combined with the client key to form the accept value.
const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// OpCode for a WebSocket frame. Only OpText, OpPing, and OpClose are handled;
// the rendezvous protocol rejects binary and fragmentation.
type OpCode byte

const (
	OpContinuation OpCode = 0x0
	OpText         OpCode = 0x1
	OpBinary       OpCode = 0x2
	OpClose        OpCode = 0x8
	OpPing         OpCode = 0x9
	OpPong         OpCode = 0xA
)

const (
	defaultReadLimit = 1 << 20 // 1 MiB fallback cap when none configured.
	expectedVersion  = "13"
)

// Sentinels surfaced to callers.
var (
	ErrBadRequest       = errors.New("ws: invalid upgrade request")
	ErrSize             = errors.New("ws: message exceeds size limit")
	ErrUnsupportedFrame = errors.New("ws: unsupported frame")
	ErrProtocol         = errors.New("ws: protocol error")
	ErrClosed           = errors.New("ws: connection closed")
)

// Conn is a server-side WebSocket connection wrapping a hijacked net.Conn.
// It is not safe for concurrent use; the rendezvous handler serializes reads
// and writes on one goroutine.
type Conn struct {
	rw       io.ReadWriter
	br       *bufio.Reader
	sizeCap  int
	writeBuf []byte
}

// Upgrade completes the WebSocket handshake on a hijackable ResponseWriter.
// maxMessageBytes caps inbound frame size; the caller passes the node's
// protocol.MaxMessageBytes so oversized envelopes are rejected before decode.
func Upgrade(writer http.ResponseWriter, request *http.Request, maxMessageBytes int) (*Conn, error) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", "GET")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return nil, ErrBadRequest
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	version := request.Header.Get("Sec-WebSocket-Version")
	upgrade := request.Header.Get("Upgrade")
	connection := request.Header.Get("Connection")
	if key == "" || version != expectedVersion ||
		!headerContains(upgrade, "websocket") || !headerContains(connection, "upgrade") {
		http.Error(writer, "missing websocket upgrade headers", http.StatusBadRequest)
		return nil, ErrBadRequest
	}

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "hijack unsupported", http.StatusInternalServerError)
		return nil, ErrBadRequest
	}
	netConn, brw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("ws: hijack: %w", err)
	}

	accept := acceptKey(key)
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(response); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("ws: write handshake: %w", err)
	}
	if err := brw.Flush(); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("ws: flush handshake: %w", err)
	}
	sizeCap := maxMessageBytes
	if sizeCap <= 0 {
		sizeCap = defaultReadLimit
	}
	return &Conn{
		rw:      netConn,
		br:      brw.Reader,
		sizeCap: sizeCap,
	}, nil
}

// SetDeadline applies read/write deadlines to the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error {
	type deadliner interface{ SetDeadline(time.Time) error }
	if d, ok := c.rw.(deadliner); ok {
		return d.SetDeadline(t)
	}
	return nil
}

// ReadMessage reads one complete text message and returns its payload. Ping
// frames are answered with Pong; Close frames terminate the read loop. Binary
// and fragmented frames are rejected.
func (c *Conn) ReadMessage() ([]byte, error) {
	for {
		op, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch op {
		case OpText:
			return payload, nil
		case OpPing:
			if err := c.writeFrame(OpPong, payload); err != nil {
				return nil, err
			}
		case OpPong:
			// Heartbeat acknowledgement; no action.
		case OpClose:
			_ = c.writeFrame(OpClose, nil)
			return nil, ErrClosed
		case OpBinary, OpContinuation:
			return nil, fmt.Errorf("%w: opcode %d", ErrUnsupportedFrame, op)
		default:
			return nil, fmt.Errorf("%w: opcode %d", ErrUnsupportedFrame, op)
		}
	}
}

// WriteMessage sends one text frame.
func (c *Conn) WriteMessage(payload []byte) error {
	return c.writeFrame(OpText, payload)
}

// Close sends a close frame and closes the underlying connection.
func (c *Conn) Close() error {
	_ = c.writeFrame(OpClose, nil)
	type closer interface{ Close() error }
	if c, ok := c.rw.(closer); ok {
		return c.Close()
	}
	return nil
}

// Underlying exposes the wrapped connection for callers that need the remote
// address (the node records request.RemoteAddr as the observed endpoint).
func (c *Conn) Underlying() net.Conn {
	if conn, ok := c.rw.(net.Conn); ok {
		return conn
	}
	return nil
}

// readFrame parses one WebSocket frame and applies every validation that keeps
// an attacker-controlled client from crashing the process. The length field is
// the critical path: a 64-bit length of 0xffffffffffffffff narrows to int(-1)
// on a 64-bit platform, bypasses a naive "> cap" check, and panics in make. To
// prevent that, the declared length is held as uint64 and rejected before any
// narrowing or allocation when it exceeds either the configured size cap or the
// platform's maximum int. The same pre-allocation gate covers the 7/16-bit
// encodings. Masking is mandatory on client frames (RFC 6455 §5.1), reserved
// bits must be clear (§5.2), opcodes are constrained (§5.2), and control frames
// must be unfragmented with at most 125 payload bytes (§5.5). Every violation
// returns a typed sentinel so the caller can emit a close frame and tear down
// rather than panic.
func (c *Conn) readFrame() (OpCode, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.br, header); err != nil {
		return 0, nil, err
	}
	fin := header[0]&0x80 != 0
	rsv := header[0]&0x70 != 0
	op := OpCode(header[0] & 0x0F)
	masked := header[1]&0x80 != 0
	declared := uint64(header[1] & 0x7F)

	// Reserved bits RSV1/RSV2/RSV3 MUST be zero unless an extension negotiated
	// during the handshake defined them. This node negotiates no extensions.
	if rsv {
		return 0, nil, fmt.Errorf("%w: reserved bits set", ErrProtocol)
	}
	if !validOpcode(op) {
		return 0, nil, fmt.Errorf("%w: opcode %d", ErrUnsupportedFrame, op)
	}
	// Clients MUST mask every frame (RFC 6455 §5.1). The server never receives
	// unmasked client traffic in a compliant exchange; accepting it would let a
	// peer inject bytes that bypass the masking invariant.
	if !masked {
		return 0, nil, fmt.Errorf("%w: client frame unmasked", ErrProtocol)
	}

	switch declared {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		declared = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		declared = binary.BigEndian.Uint64(ext[:])
	}
	// Control frames (op >= 8) MUST carry at most 125 payload bytes and MUST NOT
	// be fragmented (RFC 6455 §5.5). Reject before allocation so an oversized
	// control frame never reserves memory.
	isControl := op >= 0x8
	if isControl {
		if !fin {
			return 0, nil, fmt.Errorf("%w: fragmented control frame", ErrProtocol)
		}
		if declared > 125 {
			return 0, nil, fmt.Errorf("%w: control frame payload %d > 125", ErrProtocol, declared)
		}
	}
	// The size cap and the platform int maximum are both upper bounds the parser
	// must enforce before narrowing or allocating. The int maximum matters on
	// 32-bit builds (max int is ~2 GiB) and on 64-bit builds for the 64-bit
	// length encoding (max uint64 overflows int to -1). Reject either boundary
	// here, returning ErrSize so the caller closes without panicking.
	if declared > uint64(c.sizeCap) {
		return 0, nil, fmt.Errorf("%w: %d bytes", ErrSize, declared)
	}
	if declared > uint64(math.MaxInt) {
		// math.MaxInt caps allocation below the Go runtime's slice limit on
		// every supported platform; unreachable after the sizeCap check when
		// sizeCap <= MaxInt, but kept as a defense-in-depth gate.
		return 0, nil, fmt.Errorf("%w: length %d exceeds platform maximum", ErrSize, declared)
	}

	var mask [4]byte
	// masked is always true here (validated above); read the 4 mask bytes.
	if _, err := io.ReadFull(c.br, mask[:]); err != nil {
		return 0, nil, err
	}

	length := int(declared) // safe: declared <= sizeCap <= MaxInt
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	if !fin {
		return 0, nil, fmt.Errorf("%w: fragmentation", ErrUnsupportedFrame)
	}
	return op, payload, nil
}

// validOpcode reports whether op is one of the data/control opcodes this node
// accepts for further, type-specific handling. Reserved opcodes (3-7, 11-15)
// and the unused opcode 0xF are rejected (RFC 6455 §5.2). OpBinary and
// OpContinuation pass validation here but are rejected later by ReadMessage as
// unsupported for the text-only rendezvous protocol.
func validOpcode(op OpCode) bool {
	switch op {
	case OpText, OpBinary, OpContinuation, OpClose, OpPing, OpPong:
		return true
	default:
		return false
	}
}

func (c *Conn) writeFrame(op OpCode, payload []byte) error {
	// Server frames are unmasked; length encodes into 7/16/64 bits.
	var header []byte
	length := len(payload)
	switch {
	case length <= 125:
		header = make([]byte, 2)
		header[1] = byte(length)
	case length <= 0xFFFF:
		header = make([]byte, 4)
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(length))
	default:
		header = make([]byte, 10)
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(length))
	}
	header[0] = byte(op) | 0x80 // FIN bit set.

	if _, err := c.rw.Write(header); err != nil {
		return err
	}
	if length > 0 {
		if _, err := c.rw.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// acceptKey computes the Sec-WebSocket-Accept value per RFC 6455 §1.3.
func acceptKey(key string) string {
	hash := sha1.New()
	hash.Write([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

// headerContains reports whether a comma-separated header value contains a
// token, case-insensitive. WebSocket upgrade headers are free-form lists.
func headerContains(value, token string) bool {
	remaining := value
	for {
		// Split on commas; trim spaces; compare case-insensitively.
		i := indexOfByte(remaining, ',')
		var part string
		if i < 0 {
			part = remaining
			remaining = ""
		} else {
			part = remaining[:i]
			remaining = remaining[i+1:]
		}
		part = trimSpace(part)
		if equalFold(part, token) {
			return true
		}
		if i < 0 {
			return false
		}
	}
}

func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ac, bc := a[i], b[i]
		if 'A' <= ac && ac <= 'Z' {
			ac += 'a' - 'A'
		}
		if 'A' <= bc && bc <= 'Z' {
			bc += 'a' - 'A'
		}
		if ac != bc {
			return false
		}
	}
	return true
}
