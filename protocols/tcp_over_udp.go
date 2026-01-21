package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/etxtunnel/etxtunnel/spoofing"
)

// TCPOverUDP implements TCP tunneling over UDP
type TCPOverUDP struct {
	conn         *net.UDPConn
	spoofedIP    string
	spoofedPort  int
	connections  map[string]*UDPTunnelConn
	mu           sync.RWMutex
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// UDPTunnelConn represents a UDP-based tunnel connection
type UDPTunnelConn struct {
	id           string
	remoteAddr   *net.UDPAddr
	localAddr    *net.UDPAddr
	lastActivity time.Time
	seqNum       uint32
	ackNum       uint32
	mu           sync.Mutex
}

// NewTCPOverUDP creates a new TCP over UDP protocol handler
func NewTCPOverUDP(spoofedIP string, spoofedPort int) *TCPOverUDP {
	return &TCPOverUDP{
		spoofedIP:    spoofedIP,
		spoofedPort:  spoofedPort,
		connections:  make(map[string]*UDPTunnelConn),
		readTimeout:  30 * time.Second,
		writeTimeout: 30 * time.Second,
	}
}

// Connect establishes a connection to the server
func (t *TCPOverUDP) Connect(ctx context.Context, serverAddr string, authToken string) (net.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	// Create UDP connection
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP: %w", err)
	}

	// Send authentication
	authData := []byte(authToken)
	if err := t.sendPacket(conn, addr, 0, 0, authData); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send auth: %w", err)
	}

	// Create tunnel connection
	tunnelConn := &UDPTunnelConn{
		id:           fmt.Sprintf("%s-%d", addr.String(), time.Now().UnixNano()),
		remoteAddr:   addr,
		lastActivity: time.Now(),
		seqNum:       1,
		ackNum:       0,
	}

	t.mu.Lock()
	t.connections[tunnelConn.id] = tunnelConn
	t.mu.Unlock()

	return &UDPConnWrapper{
		conn:       conn,
		tunnelConn: tunnelConn,
		protocol:   t,
	}, nil
}

// Listen starts listening for incoming UDP connections
func (t *TCPOverUDP) Listen(ctx context.Context, listenAddr string) (net.Listener, error) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen UDP: %w", err)
	}

	t.conn = conn

	return &UDPListener{
		conn:     conn,
		protocol: t,
		ctx:      ctx,
	}, nil
}

// SendData sends data through the UDP tunnel
func (t *TCPOverUDP) SendData(conn net.Conn, data []byte) error {
	udpConn, ok := conn.(*UDPConnWrapper)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	return t.sendPacket(udpConn.conn, udpConn.tunnelConn.remoteAddr, 
		udpConn.tunnelConn.seqNum, udpConn.tunnelConn.ackNum, data)
}

// ReceiveData receives data from the UDP tunnel
func (t *TCPOverUDP) ReceiveData(conn net.Conn) ([]byte, error) {
	udpConn, ok := conn.(*UDPConnWrapper)
	if !ok {
		return nil, fmt.Errorf("invalid connection type")
	}

	buffer := make([]byte, 65507) // Max UDP packet size
	n, err := udpConn.conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	// Parse packet (simplified - would need proper protocol parsing)
	return buffer[:n], nil
}

// sendPacket sends a packet with sequence and acknowledgment numbers
func (t *TCPOverUDP) sendPacket(conn *net.UDPConn, addr *net.UDPAddr, seq, ack uint32, data []byte) error {
	// Create packet with header: seq(4) + ack(4) + data
	packet := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(packet[0:4], seq)
	binary.BigEndian.PutUint32(packet[4:8], ack)
	copy(packet[8:], data)

	// Use spoofing if configured
	if t.spoofedIP != "" {
		spoofedAddr := net.ParseIP(t.spoofedIP)
		if spoofedAddr != nil {
			// Use spoofing for sending
			return spoofing.SpoofUDP(t.spoofedIP, addr.IP.String(), 
				t.spoofedPort, addr.Port, packet)
		}
	}

	_, err := conn.WriteToUDP(packet, addr)
	return err
}

// Close closes the protocol
func (t *TCPOverUDP) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// UDPConnWrapper wraps UDP connection to implement net.Conn
type UDPConnWrapper struct {
	conn       *net.UDPConn
	tunnelConn *UDPTunnelConn
	protocol   *TCPOverUDP
}

func (u *UDPConnWrapper) Read(b []byte) (int, error) {
	data, err := u.protocol.ReceiveData(u)
	if err != nil {
		return 0, err
	}
	copy(b, data)
	return len(data), nil
}

func (u *UDPConnWrapper) Write(b []byte) (int, error) {
	if err := u.protocol.SendData(u, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (u *UDPConnWrapper) Close() error {
	u.protocol.mu.Lock()
	delete(u.protocol.connections, u.tunnelConn.id)
	u.protocol.mu.Unlock()
	return u.conn.Close()
}

func (u *UDPConnWrapper) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}

func (u *UDPConnWrapper) RemoteAddr() net.Addr {
	return u.conn.RemoteAddr()
}

func (u *UDPConnWrapper) SetDeadline(t time.Time) error {
	return u.conn.SetDeadline(t)
}

func (u *UDPConnWrapper) SetReadDeadline(t time.Time) error {
	return u.conn.SetReadDeadline(t)
}

func (u *UDPConnWrapper) SetWriteDeadline(t time.Time) error {
	return u.conn.SetWriteDeadline(t)
}

// UDPListener implements net.Listener for UDP
type UDPListener struct {
	conn     *net.UDPConn
	protocol *TCPOverUDP
	ctx      context.Context
}

func (l *UDPListener) Accept() (net.Conn, error) {
	buffer := make([]byte, 65507)
	_, addr, err := l.conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	// Create tunnel connection
	tunnelConn := &UDPTunnelConn{
		id:           fmt.Sprintf("%s-%d", addr.String(), time.Now().UnixNano()),
		remoteAddr:   addr,
		localAddr:    l.conn.LocalAddr().(*net.UDPAddr),
		lastActivity: time.Now(),
	}

	l.protocol.mu.Lock()
	l.protocol.connections[tunnelConn.id] = tunnelConn
	l.protocol.mu.Unlock()

	// Create connection wrapper
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	return &UDPConnWrapper{
		conn:       conn,
		tunnelConn: tunnelConn,
		protocol:   l.protocol,
	}, nil
}

func (l *UDPListener) Close() error {
	return l.conn.Close()
}

func (l *UDPListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
