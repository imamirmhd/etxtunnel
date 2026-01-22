package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/etxtunnel/etxtunnel/spoofing"
)

// TCPOverUDP implements TCP tunneling over UDP
type TCPOverUDP struct {
	conn            *net.UDPConn
	spoofedIP       string
	spoofedPort     int
	connections     map[string]*UDPTunnelConn // By connection ID
	addrConnMap     map[string]*UDPConnWrapper // By client address for connection reuse
	virtualIface    string                     // Name of virtual interface if created
	mu              sync.RWMutex
	readTimeout     time.Duration
	writeTimeout    time.Duration
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
		addrConnMap:  make(map[string]*UDPConnWrapper),
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

	// Create UDP connection
	// Bind to the spoofed IP if it exists (now it should exist after creating virtual interface)
	var localAddr *net.UDPAddr
	actualPort := t.spoofedPort
	
	if t.spoofedIP != "" {
		// Bind to the spoofed IP address
		localIP := net.ParseIP(t.spoofedIP)
		if localIP == nil {
			return nil, fmt.Errorf("invalid spoofed IP address: %s", t.spoofedIP)
		}
		// If port is 0, use a random port from ephemeral range (49152-65535)
		if actualPort == 0 {
			actualPort = 49152 + rand.Intn(65535-49152+1)
		}
		localAddr = &net.UDPAddr{IP: localIP, Port: actualPort}
	} else if actualPort != 0 {
		// Only bind to specific port if not spoofing and port is specified
		localAddr = &net.UDPAddr{IP: nil, Port: actualPort}
	} else {
		// Let system choose port
		localAddr = nil
	}
	
	conn, err := net.DialUDP("udp", localAddr, addr)
	if err != nil {
		// Clean up virtual interface if we created it
		if t.virtualIface != "" {
			spoofing.DeleteVirtualInterface(t.virtualIface)
			t.virtualIface = ""
		}
		return nil, fmt.Errorf("failed to dial UDP: %w", err)
	}

	// Get the actual local port assigned (in case system assigned different port)
	localUDPAddr := conn.LocalAddr().(*net.UDPAddr)
	if localUDPAddr != nil && localUDPAddr.Port != 0 {
		actualPort = localUDPAddr.Port
	} else if actualPort == 0 {
		// If still 0, generate a random ephemeral port
		actualPort = 49152 + rand.Intn(65535-49152+1)
	}
	
	// Update spoofedPort to remember the actual port used
	t.spoofedPort = actualPort

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
		conn:         conn,
		listenConn:   nil, // Client side doesn't have a listening connection
		tunnelConn:   tunnelConn,
		protocol:     t,
		isServerSide: false, // This is a client-side connection
	}, nil
}

// Listen starts listening for incoming UDP connections
func (t *TCPOverUDP) Listen(ctx context.Context, listenAddr string) (net.Listener, error) {
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

	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		// Clean up virtual interface if we created it
		if t.virtualIface != "" {
			spoofing.DeleteVirtualInterface(t.virtualIface)
			t.virtualIface = ""
		}
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

	// For server side, use listening connection to maintain correct source port
	// For client side, use the dialed connection
	connToUse := udpConn.conn
	if udpConn.isServerSide && udpConn.listenConn != nil {
		connToUse = udpConn.listenConn
	}

	return t.sendPacket(connToUse, udpConn.tunnelConn.remoteAddr, 
		udpConn.tunnelConn.seqNum, udpConn.tunnelConn.ackNum, data)
}

// ReceiveData receives data from the UDP tunnel
func (t *TCPOverUDP) ReceiveData(conn net.Conn) ([]byte, error) {
	udpConn, ok := conn.(*UDPConnWrapper)
	if !ok {
		return nil, fmt.Errorf("invalid connection type")
	}

	// For server side, read from listening connection
	// For client side, read from dialed connection
	connToRead := udpConn.conn
	if udpConn.isServerSide && udpConn.listenConn != nil {
		connToRead = udpConn.listenConn
	}

	buffer := make([]byte, 65507) // Max UDP packet size
	n, addr, err := connToRead.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	// Verify this packet is from the expected remote address
	if udpConn.tunnelConn.remoteAddr != nil {
		if addr.IP.String() != udpConn.tunnelConn.remoteAddr.IP.String() {
			// Packet from different source, ignore or handle accordingly
			return t.ReceiveData(conn) // Try again
		}
	}

	// Parse packet header (seq + ack = 8 bytes) and extract payload
	var packetData []byte
	if n >= 8 {
		// Skip header (seq + ack), extract payload
		packetData = buffer[8:n]
	} else {
		// No header, use entire packet
		packetData = buffer[:n]
	}

	return packetData, nil
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
			// Get actual source port from connection
			srcPort := 0
			localAddr := conn.LocalAddr()
			if udpAddr, ok := localAddr.(*net.UDPAddr); ok && udpAddr != nil {
				srcPort = udpAddr.Port
			}
			// If port is 0 or not available, use stored spoofedPort or random ephemeral port
			if srcPort == 0 {
				srcPort = t.spoofedPort
				if srcPort == 0 {
					// Generate random ephemeral port and remember it
					srcPort = 49152 + rand.Intn(65535-49152+1)
					t.spoofedPort = srcPort
				}
			}
			// Use spoofing for sending (requires root)
			return spoofing.SpoofUDP(t.spoofedIP, addr.IP.String(), 
				srcPort, addr.Port, packet)
		}
	}

	// Normal UDP send (no spoofing)
	_, err := conn.WriteToUDP(packet, addr)
	return err
}

// Close closes the protocol
func (t *TCPOverUDP) Close() error {
	var err error
	if t.conn != nil {
		err = t.conn.Close()
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

// UDPConnWrapper wraps UDP connection to implement net.Conn
type UDPConnWrapper struct {
	conn         *net.UDPConn
	listenConn   *net.UDPConn // Listening connection (for server side)
	tunnelConn   *UDPTunnelConn
	protocol     *TCPOverUDP
	buffer       []byte // Buffer for initial packet data
	bufferPos    int    // Current position in buffer
	isServerSide bool   // True if this is a server-side connection
	mu           sync.Mutex
}

func (u *UDPConnWrapper) Read(b []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	// First, return any buffered data
	if u.bufferPos < len(u.buffer) {
		n := copy(b, u.buffer[u.bufferPos:])
		u.bufferPos += n
		if u.bufferPos >= len(u.buffer) {
			u.buffer = nil // Clear buffer after reading
			u.bufferPos = 0
		}
		return n, nil
	}

	// Then read from the connection
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
	// Remove from address map
	if u.tunnelConn.remoteAddr != nil {
		delete(u.protocol.addrConnMap, u.tunnelConn.remoteAddr.String())
	}
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
	n, addr, err := l.conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	addrKey := addr.String()

	// Check if we already have a connection for this address
	l.protocol.mu.RLock()
	existingConn, exists := l.protocol.addrConnMap[addrKey]
	l.protocol.mu.RUnlock()

	if exists {
		// Existing connection - append data to its buffer
		existingConn.mu.Lock()
		// Parse packet header if present
		var packetData []byte
		if n >= 8 {
			packetData = buffer[8:n]
		} else {
			packetData = buffer[:n]
		}
		// Append to existing buffer
		existingConn.buffer = append(existingConn.buffer, packetData...)
		existingConn.mu.Unlock()
		// Return nil to indicate this is not a new connection
		// The server will handle this differently
		return nil, fmt.Errorf("existing connection")
	}

	// Parse packet header (seq + ack = 8 bytes) and extract data
	var packetData []byte
	if n >= 8 {
		// Skip header (seq + ack), extract payload
		packetData = buffer[8:n]
	} else {
		// No header, use entire packet
		packetData = buffer[:n]
	}

	// Create tunnel connection
	tunnelConn := &UDPTunnelConn{
		id:           fmt.Sprintf("%s-%d", addr.String(), time.Now().UnixNano()),
		remoteAddr:   addr,
		localAddr:    l.conn.LocalAddr().(*net.UDPAddr),
		lastActivity: time.Now(),
	}

	// For server side, we'll use the listening connection to send responses
	// This ensures the source port matches the listening port
	// We still create a dialed connection for client compatibility, but won't use it for sending
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	wrapper := &UDPConnWrapper{
		conn:         conn,
		listenConn:   l.conn, // Store reference to listening connection
		tunnelConn:   tunnelConn,
		protocol:     l.protocol,
		buffer:       packetData, // Store initial packet data
		bufferPos:    0,
		isServerSide: true, // This is a server-side connection
	}

	// Store in connection maps
	l.protocol.mu.Lock()
	l.protocol.connections[tunnelConn.id] = tunnelConn
	l.protocol.addrConnMap[addrKey] = wrapper
	l.protocol.mu.Unlock()

	return wrapper, nil
}

func (l *UDPListener) Close() error {
	return l.conn.Close()
}

func (l *UDPListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
