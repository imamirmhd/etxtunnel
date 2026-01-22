package protocols

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/etxtunnel/etxtunnel/spoofing"
)

// TCPOverICMP implements TCP tunneling over ICMP
type TCPOverICMP struct {
	conn         *icmp.PacketConn
	spoofedIP    string
	connections  map[string]*ICMPTunnelConn
	virtualIface string // Name of virtual interface if created
	mu           sync.RWMutex
}

// ICMPTunnelConn represents an ICMP-based tunnel connection
type ICMPTunnelConn struct {
	id           string
	remoteAddr   net.Addr
	lastActivity time.Time
	seqNum       uint16
}

// NewTCPOverICMP creates a new TCP over ICMP protocol handler
func NewTCPOverICMP(spoofedIP string) *TCPOverICMP {
	return &TCPOverICMP{
		spoofedIP:   spoofedIP,
		connections: make(map[string]*ICMPTunnelConn),
	}
}

// Connect establishes a connection to the server
func (t *TCPOverICMP) Connect(ctx context.Context, serverAddr string, authToken string) (net.Conn, error) {
	// ICMP operates at Layer 3, so we use IP address directly
	ip := net.ParseIP(serverAddr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", serverAddr)
	}

	// If spoofing is enabled, ensure the IP exists on the system
	if t.spoofedIP != "" {
		exists, err := spoofing.IPExistsOnSystem(t.spoofedIP)
		if err != nil {
			return nil, fmt.Errorf("failed to check if IP exists: %w", err)
		}
		
		if !exists {
			// Create virtual interface for the spoofed IP
			ifaceName, err := spoofing.CreateVirtualInterface(t.spoofedIP)
			if err != nil {
				return nil, fmt.Errorf("failed to create virtual interface for %s: %w", t.spoofedIP, err)
			}
			t.mu.Lock()
			t.virtualIface = ifaceName
			t.mu.Unlock()
		}
	}

	// Create ICMP connection - bind to spoofed IP if available
	bindAddr := "0.0.0.0"
	if t.spoofedIP != "" {
		bindAddr = t.spoofedIP
	}
	conn, err := icmp.ListenPacket("ip4:icmp", bindAddr)
	if err != nil {
		// Clean up virtual interface if we created it
		if t.virtualIface != "" {
			spoofing.DeleteVirtualInterface(t.virtualIface)
			t.virtualIface = ""
		}
		return nil, fmt.Errorf("failed to listen ICMP: %w", err)
	}

	t.conn = conn

	// Send authentication in ICMP echo request
	authData := []byte(authToken)
	if err := t.sendEcho(ip, 1, authData); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send auth: %w", err)
	}

	// Create tunnel connection
	tunnelConn := &ICMPTunnelConn{
		id:           fmt.Sprintf("%s-%d", ip.String(), time.Now().UnixNano()),
		remoteAddr:   &net.IPAddr{IP: ip},
		lastActivity: time.Now(),
		seqNum:       1,
	}

	t.mu.Lock()
	t.connections[tunnelConn.id] = tunnelConn
	t.mu.Unlock()

	return &ICMPConnWrapper{
		conn:       conn,
		tunnelConn: tunnelConn,
		protocol:   t,
		remoteIP:   ip,
	}, nil
}

// Listen starts listening for incoming ICMP connections
func (t *TCPOverICMP) Listen(ctx context.Context, listenAddr string) (net.Listener, error) {
	// If spoofing is enabled, ensure the IP exists on the system
	if t.spoofedIP != "" {
		exists, err := spoofing.IPExistsOnSystem(t.spoofedIP)
		if err != nil {
			return nil, fmt.Errorf("failed to check if IP exists: %w", err)
		}
		
		if !exists {
			// Create virtual interface for the spoofed IP
			ifaceName, err := spoofing.CreateVirtualInterface(t.spoofedIP)
			if err != nil {
				return nil, fmt.Errorf("failed to create virtual interface for %s: %w", t.spoofedIP, err)
			}
			t.mu.Lock()
			t.virtualIface = ifaceName
			t.mu.Unlock()
		}
	}

	// Bind to spoofed IP if available
	bindAddr := "0.0.0.0"
	if t.spoofedIP != "" {
		bindAddr = t.spoofedIP
	}
	conn, err := icmp.ListenPacket("ip4:icmp", bindAddr)
	if err != nil {
		// Clean up virtual interface if we created it
		if t.virtualIface != "" {
			spoofing.DeleteVirtualInterface(t.virtualIface)
			t.virtualIface = ""
		}
		return nil, fmt.Errorf("failed to listen ICMP: %w", err)
	}

	t.conn = conn

	return &ICMPListener{
		conn:     conn,
		protocol: t,
		ctx:      ctx,
	}, nil
}

// SendData sends data through the ICMP tunnel
func (t *TCPOverICMP) SendData(conn net.Conn, data []byte) error {
	icmpConn, ok := conn.(*ICMPConnWrapper)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	return t.sendEcho(icmpConn.remoteIP, icmpConn.tunnelConn.seqNum, data)
}

// ReceiveData receives data from the ICMP tunnel
func (t *TCPOverICMP) ReceiveData(conn net.Conn) ([]byte, error) {
	icmpConn, ok := conn.(*ICMPConnWrapper)
	if !ok {
		return nil, fmt.Errorf("invalid connection type")
	}

	buffer := make([]byte, 1500)
	n, _, err := icmpConn.conn.ReadFrom(buffer)
	if err != nil {
		return nil, err
	}

	// Parse ICMP message
	msg, err := icmp.ParseMessage(1, buffer[:n])
	if err != nil {
		return nil, err
	}

	// Extract data from echo reply
	if echo, ok := msg.Body.(*icmp.Echo); ok {
		return echo.Data, nil
	}

	return nil, fmt.Errorf("unexpected ICMP message type")
}

// sendEcho sends an ICMP echo request with data
func (t *TCPOverICMP) sendEcho(dst net.IP, seq uint16, data []byte) error {
	// Create ICMP echo message
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  int(seq),
			Data: data,
		},
	}

	packet, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	dstAddr := &net.IPAddr{IP: dst}
	_, err = t.conn.WriteTo(packet, dstAddr)
	return err
}

// Close closes the protocol
func (t *TCPOverICMP) Close() error {
	var err error
	if t.conn != nil {
		err = t.conn.Close()
		t.conn = nil
	}
	
	// Clean up virtual interface if we created one
	t.mu.Lock()
	ifaceName := t.virtualIface
	t.virtualIface = ""
	t.mu.Unlock()
	
	if ifaceName != "" {
		if delErr := spoofing.DeleteVirtualInterface(ifaceName); delErr != nil {
			if err == nil {
				err = delErr
			}
		}
	}
	
	return err
}

// ICMPConnWrapper wraps ICMP connection to implement net.Conn
type ICMPConnWrapper struct {
	conn       *icmp.PacketConn
	tunnelConn *ICMPTunnelConn
	protocol   *TCPOverICMP
	remoteIP   net.IP
}

func (i *ICMPConnWrapper) Read(b []byte) (int, error) {
	data, err := i.protocol.ReceiveData(i)
	if err != nil {
		return 0, err
	}
	copy(b, data)
	return len(data), nil
}

func (i *ICMPConnWrapper) Write(b []byte) (int, error) {
	if err := i.protocol.SendData(i, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (i *ICMPConnWrapper) Close() error {
	i.protocol.mu.Lock()
	delete(i.protocol.connections, i.tunnelConn.id)
	i.protocol.mu.Unlock()
	return i.conn.Close()
}

func (i *ICMPConnWrapper) LocalAddr() net.Addr {
	return i.conn.LocalAddr()
}

func (i *ICMPConnWrapper) RemoteAddr() net.Addr {
	return i.tunnelConn.remoteAddr
}

func (i *ICMPConnWrapper) SetDeadline(t time.Time) error {
	return i.conn.SetDeadline(t)
}

func (i *ICMPConnWrapper) SetReadDeadline(t time.Time) error {
	return i.conn.SetReadDeadline(t)
}

func (i *ICMPConnWrapper) SetWriteDeadline(t time.Time) error {
	return i.conn.SetWriteDeadline(t)
}

// ICMPListener implements net.Listener for ICMP
type ICMPListener struct {
	conn     *icmp.PacketConn
	protocol *TCPOverICMP
	ctx      context.Context
}

func (l *ICMPListener) Accept() (net.Conn, error) {
	buffer := make([]byte, 1500)
	n, addr, err := l.conn.ReadFrom(buffer)
	if err != nil {
		return nil, err
	}

	// Parse ICMP message
	msg, err := icmp.ParseMessage(1, buffer[:n])
	if err != nil {
		return nil, err
	}

	// Only accept echo requests
	if msg.Type != ipv4.ICMPTypeEcho {
		return l.Accept() // Try again
	}

	// Get source IP
	ipAddr, ok := addr.(*net.IPAddr)
	if !ok {
		return l.Accept() // Try again
	}

	// Create tunnel connection
	tunnelConn := &ICMPTunnelConn{
		id:           fmt.Sprintf("%s-%d", ipAddr.String(), time.Now().UnixNano()),
		remoteAddr:   ipAddr,
		lastActivity: time.Now(),
	}

	l.protocol.mu.Lock()
	l.protocol.connections[tunnelConn.id] = tunnelConn
	l.protocol.mu.Unlock()

	return &ICMPConnWrapper{
		conn:       l.conn,
		tunnelConn: tunnelConn,
		protocol:   l.protocol,
		remoteIP:   ipAddr.IP,
	}, nil
}

func (l *ICMPListener) Close() error {
	return l.conn.Close()
}

func (l *ICMPListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
