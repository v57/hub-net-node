package server

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// replyConn answers each datagram from the address it was sent to.
//
// A node bound to a wildcard address on a multi-homed host (Docker bridges,
// several interfaces, IPv4 and IPv6) would otherwise reply from whatever
// source address the route to the client picks. Clients probe with connected
// UDP sockets and drop a reply that comes from another address, so the probe
// times out. Reading the destination of each datagram (IP_PKTINFO /
// IPV6_PKTINFO) and sending the reply from it avoids that. Platforms without
// packet info fall back to plain replies.
type replyConn struct {
	conn *net.UDPConn
	v6   *ipv6.PacketConn
	v4   *ipv4.PacketConn
	// send4 writes IPv4 replies with IP_PKTINFO. On a dual-stack socket the
	// IPv6 packet info cannot carry an IPv4 source (x/net drops it), while
	// Linux accepts IP_PKTINFO for an IPv4 destination on that socket.
	send4 *ipv4.PacketConn
}

func newReplyConn(conn *net.UDPConn) *replyConn {
	reply := &replyConn{conn: conn}
	local, _ := conn.LocalAddr().(*net.UDPAddr)
	if local == nil || !local.IP.IsUnspecified() {
		// A socket bound to one address already replies from it.
		return reply
	}
	if v6 := ipv6.NewPacketConn(conn); v6.SetControlMessage(ipv6.FlagDst, true) == nil {
		reply.v6 = v6
		reply.send4 = ipv4.NewPacketConn(conn)
	} else if v4 := ipv4.NewPacketConn(conn); v4.SetControlMessage(ipv4.FlagDst, true) == nil {
		reply.v4 = v4
		reply.send4 = v4
	}
	return reply
}

// read returns one datagram, its sender and the local address it was sent to
// (nil when unknown).
func (r *replyConn) read(buffer []byte) (int, *net.UDPAddr, net.IP, error) {
	switch {
	case r.v6 != nil:
		n, cm, source, err := r.v6.ReadFrom(buffer)
		return n, udpAddr(source), dst6(cm), err
	case r.v4 != nil:
		n, cm, source, err := r.v4.ReadFrom(buffer)
		return n, udpAddr(source), dst4(cm), err
	default:
		n, source, err := r.conn.ReadFromUDP(buffer)
		return n, source, nil, err
	}
}

// write replies to destination from local, the address the request reached.
func (r *replyConn) write(payload []byte, destination *net.UDPAddr, local net.IP) error {
	if local != nil {
		var err error
		switch {
		case local.To4() != nil && r.send4 != nil && destination.IP.To4() != nil:
			target := &net.UDPAddr{IP: destination.IP.To4(), Port: destination.Port}
			_, err = r.send4.WriteTo(payload, &ipv4.ControlMessage{Src: local.To4()}, target)
		case local.To4() == nil && r.v6 != nil:
			_, err = r.v6.WriteTo(payload, &ipv6.ControlMessage{Src: local}, destination)
		default:
			err = net.ErrClosed
		}
		if err == nil {
			return nil
		}
	}
	_, err := r.conn.WriteToUDP(payload, destination)
	return err
}

func udpAddr(address net.Addr) *net.UDPAddr {
	udp, _ := address.(*net.UDPAddr)
	return udp
}

func dst6(cm *ipv6.ControlMessage) net.IP {
	if cm == nil {
		return nil
	}
	return cm.Dst
}

func dst4(cm *ipv4.ControlMessage) net.IP {
	if cm == nil {
		return nil
	}
	return cm.Dst
}
