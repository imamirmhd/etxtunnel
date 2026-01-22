package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/etxtunnel/etxtunnel/spoofing"
)

// TCPOverIP implements TCP tunneling over raw IP
type TCPOverIP struct {
	fd           int
	spoofedIP    string
	connections  map[string]*IPTunnelConn
	virtualIface string // Name of virtual interface if created
	mu           sync.RWMutex
}

// IPTunnelConn represents an IP-based tunnel connection
type IPTunnelConn struct {
	id           string
	remoteIP     net.IP
	lastActivity time.Time
	seqNum       uint32
	ackNum       uint32
	srcPort      int // Source port for this connection
}

// NewTCPOverIP creates a new TCP over IP protocol handler
func NewTCPOverIP(spoofedIP string) *TCPOverIP {
	return &TCPOverIP{
		spoofedIP:   spoofedIP,
		connections: make(map[string]*IPTunnelConn),
	}
}

// Connect establishes a connection to the server
func (t *TCPOverIP) Connect(ctx context.Context, serverAddr string, authToken string) (net.Conn, error) {
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

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		// Clean up virtual interface if we created it
		if t.virtualIface != "" {
			spoofing.DeleteVirtualInterface(t.virtualIface)
			t.virtualIface = ""
		}
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}

	// Set IP_HDRINCL
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	t.fd = fd

	// Generate a random ephemeral source port (49152-65535)
	srcPort := 49152 + rand.Intn(65535-49152+1)
	
	// Create tunnel connection
	tunnelConn := &IPTunnelConn{
		id:           fmt.Sprintf("%s-%d", ip.String(), time.Now().UnixNano()),
		remoteIP:     ip,
		lastActivity: time.Now(),
		seqNum:       1,
		ackNum:       0,
		srcPort:      srcPort,
	}

	t.mu.Lock()
	t.connections[tunnelConn.id] = tunnelConn
	t.mu.Unlock()

	// Send authentication
	authData := []byte(authToken)
	if err := t.sendPacket(ip, tunnelConn.seqNum, tunnelConn.ackNum, authData, tunnelConn.srcPort); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to send auth: %w", err)
	}

	return &IPConnWrapper{
		fd:         fd,
		tunnelConn: tunnelConn,
		protocol:   t,
		remoteIP:   ip,
	}, nil
}

// Listen starts listening for incoming IP connections
func (t *TCPOverIP) Listen(ctx context.Context, listenAddr string) (net.Listener, error) {
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

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		// Clean up virtual interface if we created it
		if t.virtualIface != "" {
			spoofing.DeleteVirtualInterface(t.virtualIface)
			t.virtualIface = ""
		}
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}

	// Set IP_HDRINCL
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	t.fd = fd

	return &IPListener{
		fd:       fd,
		protocol: t,
		ctx:      ctx,
	}, nil
}

// SendData sends data through the IP tunnel
func (t *TCPOverIP) SendData(conn net.Conn, data []byte) error {
	ipConn, ok := conn.(*IPConnWrapper)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	return t.sendPacket(ipConn.remoteIP, ipConn.tunnelConn.seqNum, 
		ipConn.tunnelConn.ackNum, data, ipConn.tunnelConn.srcPort)
}

// ReceiveData receives data from the IP tunnel
func (t *TCPOverIP) ReceiveData(conn net.Conn) ([]byte, error) {
	ipConn, ok := conn.(*IPConnWrapper)
	if !ok {
		return nil, fmt.Errorf("invalid connection type")
	}

	buffer := make([]byte, 65535)
	n, err := syscall.Read(ipConn.fd, buffer)
	if err != nil {
		return nil, err
	}

	// Parse IP header (simplified)
	if n < 20 {
		return nil, fmt.Errorf("packet too short")
	}

	// Extract TCP payload (skip IP header)
	ipHeaderLen := int((buffer[0] & 0x0F) * 4)
	if n < ipHeaderLen+20 {
		return nil, fmt.Errorf("packet too short for TCP")
	}

	tcpHeaderLen := int((buffer[ipHeaderLen+12] >> 4) * 4)
	payloadStart := ipHeaderLen + tcpHeaderLen

	if n < payloadStart {
		return nil, fmt.Errorf("packet too short for payload")
	}

	return buffer[payloadStart:n], nil
}

// sendPacket sends a raw IP packet with TCP data
func (t *TCPOverIP) sendPacket(dst net.IP, seq, ack uint32, data []byte, srcPort int) error {
	// This is a simplified implementation
	// Full implementation would construct proper IP and TCP headers
	packet := make([]byte, 20+20+len(data)) // IP header + TCP header + data

	// IP header (simplified)
	packet[0] = 0x45 // Version 4, IHL 5
	packet[1] = 0x00 // TOS
	totalLen := len(packet)
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen & 0xff)
	packet[6] = 0x40 // Don't fragment
	packet[8] = 0x40 // TTL
	packet[9] = 0x06 // TCP protocol

	srcIP := net.ParseIP(t.spoofedIP)
	if srcIP == nil {
		srcIP = net.IPv4(127, 0, 0, 1)
	}

	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dst.To4())

	// TCP header (simplified)
	// Use provided source port, or random ephemeral port if 0
	if srcPort == 0 {
		srcPort = 49152 + rand.Intn(65535-49152+1)
	}
	packet[20] = byte(srcPort >> 8)  // Source port (high)
	packet[21] = byte(srcPort & 0xff) // Source port (low)
	packet[22] = 0x00                 // Dest port (high) - will be set based on connection
	packet[23] = 0x00                 // Dest port (low) - will be set based on connection
	binary.BigEndian.PutUint32(packet[24:28], seq)
	binary.BigEndian.PutUint32(packet[28:32], ack)
	packet[32] = 0x50 // Data offset
	packet[33] = 0x10 // Flags (ACK)
	packet[34] = 0x00 // Window
	packet[35] = 0x00
	packet[36] = 0x00 // Checksum
	packet[37] = 0x00

	// Data
	copy(packet[40:], data)

	// Send packet
	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{},
	}
	copy(addr.Addr[:], dst.To4())

	return syscall.Sendto(t.fd, packet, 0, &addr)
}

// Close closes the protocol
func (t *TCPOverIP) Close() error {
	var err error
	if t.fd != 0 {
		err = syscall.Close(t.fd)
		t.fd = 0
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

// IPConnWrapper wraps raw IP socket to implement net.Conn
type IPConnWrapper struct {
	fd         int
	tunnelConn *IPTunnelConn
	protocol   *TCPOverIP
	remoteIP   net.IP
}

func (i *IPConnWrapper) Read(b []byte) (int, error) {
	data, err := i.protocol.ReceiveData(i)
	if err != nil {
		return 0, err
	}
	copy(b, data)
	return len(data), nil
}

func (i *IPConnWrapper) Write(b []byte) (int, error) {
	if err := i.protocol.SendData(i, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (i *IPConnWrapper) Close() error {
	i.protocol.mu.Lock()
	delete(i.protocol.connections, i.tunnelConn.id)
	i.protocol.mu.Unlock()
	return syscall.Close(i.fd)
}

func (i *IPConnWrapper) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(0, 0, 0, 0)}
}

func (i *IPConnWrapper) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: i.remoteIP}
}

func (i *IPConnWrapper) SetDeadline(t time.Time) error {
	return nil // Raw sockets don't support deadlines easily
}

func (i *IPConnWrapper) SetReadDeadline(t time.Time) error {
	return nil
}

func (i *IPConnWrapper) SetWriteDeadline(t time.Time) error {
	return nil
}

// IPListener implements net.Listener for raw IP
type IPListener struct {
	fd       int
	protocol *TCPOverIP
	ctx      context.Context
}

func (l *IPListener) Accept() (net.Conn, error) {
	buffer := make([]byte, 65535)
	n, err := syscall.Read(l.fd, buffer)
	if err != nil {
		return nil, err
	}

	// Parse IP header
	if n < 20 {
		return l.Accept() // Try again
	}

	srcIP := net.IP(buffer[12:16])
	_ = net.IP(buffer[16:20]) // dstIP

	// Generate a random ephemeral source port (49152-65535)
	srcPort := 49152 + rand.Intn(65535-49152+1)
	
	// Create tunnel connection
	tunnelConn := &IPTunnelConn{
		id:           fmt.Sprintf("%s-%d", srcIP.String(), time.Now().UnixNano()),
		remoteIP:     srcIP,
		lastActivity: time.Now(),
		srcPort:      srcPort,
	}

	l.protocol.mu.Lock()
	l.protocol.connections[tunnelConn.id] = tunnelConn
	l.protocol.mu.Unlock()

	return &IPConnWrapper{
		fd:         l.fd,
		tunnelConn: tunnelConn,
		protocol:   l.protocol,
		remoteIP:   srcIP,
	}, nil
}

func (l *IPListener) Close() error {
	return syscall.Close(l.fd)
}

func (l *IPListener) Addr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(0, 0, 0, 0)}
}
