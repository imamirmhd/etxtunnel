package protocols

import (
	"context"
	"encoding/base32"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/etxtunnel/etxtunnel/spoofing"
	"github.com/miekg/dns"
)

// TCPOverDNS implements TCP tunneling over DNS
type TCPOverDNS struct {
	dnsServer    string
	dnsDomain    string
	spoofedIP    string
	connections  map[string]*DNSTunnelConn
	virtualIface string // Name of virtual interface if created
	mu           sync.RWMutex
	client       *dns.Client
}

// DNSTunnelConn represents a DNS-based tunnel connection
type DNSTunnelConn struct {
	id           string
	remoteAddr   string
	lastActivity time.Time
	seqNum       uint16
	chunks       map[uint16][]byte
}

// NewTCPOverDNS creates a new TCP over DNS protocol handler
func NewTCPOverDNS(dnsServer, dnsDomain, spoofedIP string) *TCPOverDNS {
	return &TCPOverDNS{
		dnsServer:   dnsServer,
		dnsDomain:   dnsDomain,
		spoofedIP:   spoofedIP,
		connections: make(map[string]*DNSTunnelConn),
		client:      &dns.Client{Timeout: 5 * time.Second},
	}
}

// Connect establishes a connection to the server
func (t *TCPOverDNS) Connect(ctx context.Context, serverAddr string, authToken string) (net.Conn, error) {
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

	// DNS tunneling uses DNS queries to send data
	// The server address is the DNS server IP
	if t.dnsServer == "" {
		t.dnsServer = serverAddr
	}

	// Create tunnel connection
	tunnelConn := &DNSTunnelConn{
		id:           fmt.Sprintf("dns-%d", time.Now().UnixNano()),
		remoteAddr:   t.dnsServer,
		lastActivity: time.Now(),
		seqNum:       1,
		chunks:       make(map[uint16][]byte),
	}

	t.mu.Lock()
	t.connections[tunnelConn.id] = tunnelConn
	t.mu.Unlock()

	// Send authentication
	authData := []byte(authToken)
	if err := t.sendData(tunnelConn, authData); err != nil {
		// Clean up virtual interface if we created it
		if t.virtualIface != "" {
			spoofing.DeleteVirtualInterface(t.virtualIface)
			t.virtualIface = ""
		}
		return nil, fmt.Errorf("failed to send auth: %w", err)
	}

	return &DNSConnWrapper{
		tunnelConn: tunnelConn,
		protocol:   t,
	}, nil
}

// Listen starts listening for incoming DNS connections
func (t *TCPOverDNS) Listen(ctx context.Context, listenAddr string) (net.Listener, error) {
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

	// Parse listen address to potentially override with spoofed IP
	actualListenAddr := listenAddr
	if t.spoofedIP != "" {
		// Extract port from listenAddr
		_, port, err := net.SplitHostPort(listenAddr)
		if err == nil && port != "" {
			actualListenAddr = net.JoinHostPort(t.spoofedIP, port)
		}
	}

	// DNS server listener
	server := &dns.Server{
		Addr:    actualListenAddr,
		Net:     "udp",
		Handler: dns.HandlerFunc(t.handleDNSRequest),
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			// Handle error
		}
	}()

	return &DNSListener{
		server:   server,
		protocol: t,
		ctx:      ctx,
	}, nil
}

// SendData sends data through the DNS tunnel
func (t *TCPOverDNS) SendData(conn net.Conn, data []byte) error {
	dnsConn, ok := conn.(*DNSConnWrapper)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	return t.sendData(dnsConn.tunnelConn, data)
}

// ReceiveData receives data from the DNS tunnel
func (t *TCPOverDNS) ReceiveData(conn net.Conn) ([]byte, error) {
	_, ok := conn.(*DNSConnWrapper)
	if !ok {
		return nil, fmt.Errorf("invalid connection type")
	}

	// Wait for data to be received via DNS responses
	// This is a simplified implementation
	time.Sleep(100 * time.Millisecond)
	return []byte{}, nil
}

// sendData sends data via DNS queries
func (t *TCPOverDNS) sendData(tunnelConn *DNSTunnelConn, data []byte) error {
	// Encode data in base32 for DNS compatibility
	encoded := base32.StdEncoding.EncodeToString(data)

	// Split into chunks that fit in DNS labels (max 63 chars per label)
	chunkSize := 50 // Leave room for sequence numbers
	chunks := make([]string, 0)

	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunk := encoded[i:end]
		chunks = append(chunks, chunk)
	}

	// Send each chunk as a DNS query
	for i, chunk := range chunks {
		seq := uint16(i)
		queryName := fmt.Sprintf("%04x.%s.%s", seq, chunk, t.dnsDomain)

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(queryName), dns.TypeTXT)

		// Send DNS query
		_, _, err := t.client.Exchange(msg, t.dnsServer+":53")
		if err != nil {
			return fmt.Errorf("failed to send DNS query: %w", err)
		}

		tunnelConn.seqNum++
	}

	return nil
}

// handleDNSRequest handles incoming DNS requests
func (t *TCPOverDNS) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// Extract data from DNS query
	if len(r.Question) > 0 {
		qname := r.Question[0].Name
		parts := strings.Split(qname, ".")

		if len(parts) >= 3 {
			// Extract sequence number and data
			_ = parts[0] // seqStr
			dataStr := strings.Join(parts[1:len(parts)-2], ".")

			// Decode data
			decoded, err := base32.StdEncoding.DecodeString(dataStr)
			if err == nil {
				// Process received data
				_ = decoded
			}
		}

		// Send response
		txt := new(dns.TXT)
		txt.Hdr = dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		}
		txt.Txt = []string{"ok"}
		msg.Answer = append(msg.Answer, txt)
	}

	w.WriteMsg(msg)
}

// Close closes the protocol
func (t *TCPOverDNS) Close() error {
	// Clean up virtual interface if we created one
	t.mu.Lock()
	ifaceName := t.virtualIface
	t.virtualIface = ""
	t.mu.Unlock()
	
	if ifaceName != "" {
		return spoofing.DeleteVirtualInterface(ifaceName)
	}
	
	return nil
}

// DNSConnWrapper wraps DNS connection to implement net.Conn
type DNSConnWrapper struct {
	tunnelConn *DNSTunnelConn
	protocol   *TCPOverDNS
	buffer     []byte
	mu         sync.Mutex
}

func (d *DNSConnWrapper) Read(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.buffer) == 0 {
		data, err := d.protocol.ReceiveData(d)
		if err != nil {
			return 0, err
		}
		d.buffer = data
	}

	n := copy(b, d.buffer)
	d.buffer = d.buffer[n:]
	return n, nil
}

func (d *DNSConnWrapper) Write(b []byte) (int, error) {
	if err := d.protocol.SendData(d, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (d *DNSConnWrapper) Close() error {
	d.protocol.mu.Lock()
	delete(d.protocol.connections, d.tunnelConn.id)
	d.protocol.mu.Unlock()
	return nil
}

func (d *DNSConnWrapper) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (d *DNSConnWrapper) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(d.tunnelConn.remoteAddr), Port: 53}
}

func (d *DNSConnWrapper) SetDeadline(t time.Time) error {
	return nil
}

func (d *DNSConnWrapper) SetReadDeadline(t time.Time) error {
	return nil
}

func (d *DNSConnWrapper) SetWriteDeadline(t time.Time) error {
	return nil
}

// DNSListener implements net.Listener for DNS
type DNSListener struct {
	server   *dns.Server
	protocol *TCPOverDNS
	ctx      context.Context
}

func (l *DNSListener) Accept() (net.Conn, error) {
	// DNS connections are handled via DNS queries
	// This is a placeholder - actual implementation would queue connections
	select {
	case <-l.ctx.Done():
		return nil, l.ctx.Err()
	default:
		// Wait for DNS query to create connection
		time.Sleep(100 * time.Millisecond)
		return &DNSConnWrapper{
			tunnelConn: &DNSTunnelConn{
				id:           fmt.Sprintf("dns-%d", time.Now().UnixNano()),
				lastActivity: time.Now(),
			},
			protocol: l.protocol,
		}, nil
	}
}

func (l *DNSListener) Close() error {
	return l.server.Shutdown()
}

func (l *DNSListener) Addr() net.Addr {
	if l.server.Listener != nil {
		return l.server.Listener.Addr()
	}
	return &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 53}
}
