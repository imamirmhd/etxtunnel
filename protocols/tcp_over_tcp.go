package protocols

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// TCPOverTCP implements TCP tunneling over TCP
type TCPOverTCP struct {
	spoofedIP   string
	connections map[string]*TCPTunnelConn
	mu          sync.RWMutex
}

// TCPTunnelConn represents a TCP-based tunnel connection
type TCPTunnelConn struct {
	id           string
	conn         net.Conn
	lastActivity time.Time
}

// NewTCPOverTCP creates a new TCP over TCP protocol handler
func NewTCPOverTCP(spoofedIP string) *TCPOverTCP {
	return &TCPOverTCP{
		spoofedIP:   spoofedIP,
		connections: make(map[string]*TCPTunnelConn),
	}
}

// Connect establishes a connection to the server
func (t *TCPOverTCP) Connect(ctx context.Context, serverAddr string, authToken string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	// If spoofing is configured, we'd need to use raw sockets
	// For now, use standard TCP connection
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	// Send authentication
	if _, err := conn.Write([]byte(authToken)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send auth: %w", err)
	}

	// Create tunnel connection
	tunnelConn := &TCPTunnelConn{
		id:           fmt.Sprintf("%s-%d", serverAddr, time.Now().UnixNano()),
		conn:         conn,
		lastActivity: time.Now(),
	}

	t.mu.Lock()
	t.connections[tunnelConn.id] = tunnelConn
	t.mu.Unlock()

	return conn, nil
}

// Listen starts listening for incoming TCP connections
func (t *TCPOverTCP) Listen(ctx context.Context, listenAddr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen TCP: %w", err)
	}

	return &TCPListener{
		listener: listener,
		protocol: t,
		ctx:      ctx,
	}, nil
}

// SendData sends data through the TCP tunnel
func (t *TCPOverTCP) SendData(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	return err
}

// ReceiveData receives data from the TCP tunnel
func (t *TCPOverTCP) ReceiveData(conn net.Conn) ([]byte, error) {
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
}

// Close closes the protocol
func (t *TCPOverTCP) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var errs []error
	for _, tunnelConn := range t.connections {
		if err := tunnelConn.conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	t.connections = make(map[string]*TCPTunnelConn)

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// TCPListener implements net.Listener for TCP
type TCPListener struct {
	listener net.Listener
	protocol *TCPOverTCP
	ctx      context.Context
}

func (l *TCPListener) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}

	// Create tunnel connection
	tunnelConn := &TCPTunnelConn{
		id:           fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano()),
		conn:         conn,
		lastActivity: time.Now(),
	}

	l.protocol.mu.Lock()
	l.protocol.connections[tunnelConn.id] = tunnelConn
	l.protocol.mu.Unlock()

	return conn, nil
}

func (l *TCPListener) Close() error {
	return l.listener.Close()
}

func (l *TCPListener) Addr() net.Addr {
	return l.listener.Addr()
}
