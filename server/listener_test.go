package server

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestAdmissionListenerBoundsIncompleteConnections(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	rejected := make(chan struct{}, 8)
	limited := newAdmissionListener(inner, 2, 2, func(string) { rejected <- struct{}{} })
	defer limited.Close()

	var accepted []net.Conn
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, conn)
			mu.Unlock()
		}
	}()
	var clients []net.Conn
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, conn)
	}
	defer func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
	}()
	select {
	case <-rejected:
	case <-time.After(time.Second):
		t.Fatal("third source connection was not rejected")
	}
	// Release one admitted socket, then supply a fourth connection so Accept
	// can return after skipping the rejected third socket.
	mu.Lock()
	if len(accepted) == 0 {
		mu.Unlock()
		t.Fatal("no admitted connection")
	}
	_ = accepted[0].Close()
	mu.Unlock()
	conn, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clients = append(clients, conn)
	<-done
	mu.Lock()
	for _, conn := range accepted {
		_ = conn.Close()
	}
	mu.Unlock()
}

func TestSourceIPDoesNotUsePort(t *testing.T) {
	if got := sourceIPFromAddr(&net.TCPAddr{IP: net.ParseIP("192.0.2.4"), Port: 1234}); got != "192.0.2.4" {
		t.Fatalf("sourceIP = %q", got)
	}
}
