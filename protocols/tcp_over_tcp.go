package protocols

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/etxtunnel/etxtunnel/spoofing"
)

// TCPOverTCP implements TCP tunneling over TCP
type TCPOverTCP struct {
	spoofedIP    string
	connections  map[string]*TCPTunnelConn
	virtualIface string // Name of virtual interface if created
	mu           sync.RWMutex
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

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	// Bind to spoofed IP if available
	if t.spoofedIP != "" {
		localIP := net.ParseIP(t.spoofedIP)
		if localIP != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: localIP, Port: 0}
		}
	}

	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		// Clean up virtual interface if we created it
		if t.virtualIface != "" {
			spoofing.DeleteVirtualInterface(t.virtualIface)
			t.virtualIface = ""
		}
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

	// Parse listen address and replace with spoofed IP if needed
	actualListenAddr := listenAddr
	if t.spoofedIP != "" {
		// Extract port from listenAddr
		_, port, err := net.SplitHostPort(listenAddr)
		if err == nil {
			actualListenAddr = net.JoinHostPort(t.spoofedIP, port)
		}
	}

	listener, err := net.Listen("tcp", actualListenAddr)
	if err != nil {
		// Clean up virtual interface if we created it
		if t.virtualIface != "" {
			spoofing.DeleteVirtualInterface(t.virtualIface)
			t.virtualIface = ""
		}
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

	// Clean up virtual interface if we created one
	ifaceName := t.virtualIface
	t.virtualIface = ""
	t.mu.Unlock()
	
	if ifaceName != "" {
		if err := spoofing.DeleteVirtualInterface(ifaceName); err != nil {
			errs = append(errs, err)
		}
	}
	t.mu.Lock()

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
