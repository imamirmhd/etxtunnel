package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/etxtunnel/etxtunnel/config"
	"github.com/etxtunnel/etxtunnel/logger"
	"github.com/etxtunnel/etxtunnel/protocols"
	"github.com/etxtunnel/etxtunnel/utils"
)

// Server represents the tunneling server
type Server struct {
	config      *config.ServerProtocolConfig
	logger      *logger.TunnelLogger
	protocol    protocols.Protocol
	listener    net.Listener
	connections map[string]*ServerConnection
	clients     map[string]*config.ClientInfo // Map by auth token for quick lookup
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// ServerConnection represents a server-side connection
type ServerConnection struct {
	ID              string
	ClientConn      net.Conn
	ForwardConn     net.Conn
	BytesSent       int64
	BytesReceived   int64
	CreatedAt       time.Time
	ClientIP        string
	ClientInfo      *config.ClientInfo
	mu              sync.Mutex
}

// NewServer creates a new server instance
func NewServer(cfg *config.ServerProtocolConfig, log *logger.TunnelLogger) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Build client lookup map by auth token
	clients := make(map[string]*config.ClientInfo)
	for i := range cfg.Clients {
		client := &cfg.Clients[i]
		clients[client.AuthToken] = client
		log.Info("Registered client: %s (real: %s, fake: %s)", 
			client.AuthToken[:min(8, len(client.AuthToken))]+"...", 
			client.RealIP, client.FakeIP)
	}

	// Use first client's fake IP for protocol initialization (for backward compatibility)
	// In practice, protocols may need to handle multiple source IPs differently
	var fakeIP string
	if len(cfg.Clients) > 0 {
		fakeIP = cfg.Clients[0].FakeIP
	} else {
		fakeIP = cfg.ClientFakeIP // Fallback for backward compatibility
	}

	// Create protocol based on configuration
	var protocol protocols.Protocol
	switch cfg.Protocol {
	case config.TCPOverUDP:
		protocol = protocols.NewTCPOverUDP(fakeIP, cfg.Port)
	case config.TCPOverICMP:
		protocol = protocols.NewTCPOverICMP(fakeIP)
	case config.TCPOverIP:
		protocol = protocols.NewTCPOverIP(fakeIP)
	case config.TCPOverTCP:
		protocol = protocols.NewTCPOverTCP(fakeIP)
	case config.TCPOverDNS:
		protocol = protocols.NewTCPOverDNS(cfg.DNSServer, cfg.DNSDomain, fakeIP)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	server := &Server{
		config:      cfg,
		logger:      log,
		protocol:    protocol,
		connections: make(map[string]*ServerConnection),
		clients:     clients,
		ctx:         ctx,
		cancel:      cancel,
	}

	log.Info("Server initialized with %d client(s)", len(clients))
	return server, nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Start starts the server
func (s *Server) Start() error {
	// Start listening for client connections
	listenAddr := fmt.Sprintf(":%d", s.config.Port)
	
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	listener, err := s.protocol.Listen(ctx, listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.listener = listener
	s.logger.Info("Server started, listening on %s (protocol: %s)", listenAddr, s.config.Protocol)

	// Accept connections
	go s.acceptLoop()

	return nil
}

// acceptLoop accepts incoming client connections
func (s *Server) acceptLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				s.logger.Error("Failed to accept connection: %v", err)
				continue
			}

			// Handle connection
			go s.handleConnection(conn)
		}
	}
}

// handleConnection handles a new client connection
func (s *Server) handleConnection(clientConn net.Conn) {
	connID := utils.GenerateConnectionID("server")
	
	// Get client IP
	clientIP := s.getClientIP(clientConn)
	s.logger.Info("New connection: %s from %s", connID, clientIP)

	// Read authentication token
	authBuffer := make([]byte, 256)
	n, err := clientConn.Read(authBuffer)
	if err != nil {
		s.logger.Error("Failed to read auth token: %v", err)
		clientConn.Close()
		return
	}

	receivedToken := string(authBuffer[:n])
	receivedToken = trimToken(receivedToken) // Remove any trailing whitespace/newlines

	// Look up client by auth token
	s.mu.RLock()
	clientInfo, found := s.clients[receivedToken]
	s.mu.RUnlock()

	if !found {
		s.logger.Error("Invalid authentication token from %s (token: %s...)", 
			clientIP, receivedToken[:min(8, len(receivedToken))])
		clientConn.Close()
		return
	}

	// Verify client IP matches expected (real or fake IP)
	if clientIP != clientInfo.RealIP && clientIP != clientInfo.FakeIP {
		s.logger.Warning("Connection from unexpected IP: %s (expected: %s or %s for client)", 
			clientIP, clientInfo.RealIP, clientInfo.FakeIP)
		// Continue anyway for flexibility, but log the warning
	}

	s.logger.Info("Authenticated client: %s (real: %s, fake: %s)", 
		clientInfo.RealIP, clientInfo.RealIP, clientInfo.FakeIP)

	// Determine forward destination (per-client override or default)
	forwardIP := clientInfo.ForwardDestinationIP
	forwardPort := clientInfo.ForwardDestinationPort
	if forwardIP == "" {
		forwardIP = s.config.ForwardDestinationIP
	}
	if forwardPort == 0 {
		forwardPort = s.config.ForwardDestinationPort
	}

	// Connect to forward destination
	forwardAddr := fmt.Sprintf("%s:%d", forwardIP, forwardPort)
	forwardConn, err := net.DialTimeout("tcp", forwardAddr, 30*time.Second)
	if err != nil {
		s.logger.Error("Failed to connect to forward destination %s: %v", forwardAddr, err)
		clientConn.Close()
		return
	}

	s.logger.Debug("Forwarding to: %s", forwardAddr)

	// Create connection tracking
	serverConn := &ServerConnection{
		ID:          connID,
		ClientConn:  clientConn,
		ForwardConn: forwardConn,
		CreatedAt:   time.Now(),
		ClientIP:    clientIP,
		ClientInfo:  clientInfo,
	}

	s.mu.Lock()
	s.connections[connID] = serverConn
	s.mu.Unlock()

	s.logger.UpdateConnection(connID, "active", 0, 0)

	// Forward data between connections
	s.forwardConnection(serverConn)

	// Cleanup
	s.mu.Lock()
	delete(s.connections, connID)
	s.mu.Unlock()

	s.logger.RemoveConnection(connID)
	clientConn.Close()
	forwardConn.Close()
}

// trimToken removes whitespace and newlines from token
func trimToken(token string) string {
	// Remove common whitespace characters
	token = strings.TrimSpace(token)
	token = strings.Trim(token, "\n\r\t")
	return token
}

// forwardConnection forwards data between client and forward destination
func (s *Server) forwardConnection(conn *ServerConnection) {
	errChan := make(chan error, 2)

	// Forward from client to forward destination
	go func() {
		written, err := io.Copy(conn.ForwardConn, conn.ClientConn)
		conn.mu.Lock()
		conn.BytesSent = written
		conn.mu.Unlock()
		s.logger.UpdateStats(written, 0, 0, 0)
		s.logger.UpdateConnection(conn.ID, "active", written, conn.BytesReceived)
		errChan <- err
	}()

	// Forward from forward destination to client
	go func() {
		written, err := io.Copy(conn.ClientConn, conn.ForwardConn)
		conn.mu.Lock()
		conn.BytesReceived = written
		conn.mu.Unlock()
		s.logger.UpdateStats(0, written, 0, 0)
		s.logger.UpdateConnection(conn.ID, "active", conn.BytesSent, written)
		errChan <- err
	}()

	// Wait for one direction to finish
	select {
	case err := <-errChan:
		if err != nil && err != io.EOF {
			s.logger.Error("Connection error: %v", err)
		}
	case <-s.ctx.Done():
		return
	}
}

// getClientIP extracts the client IP from the connection
func (s *Server) getClientIP(conn net.Conn) string {
	remoteAddr := conn.RemoteAddr()
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		return udpAddr.IP.String()
	}
	if ipAddr, ok := remoteAddr.(*net.IPAddr); ok {
		return ipAddr.IP.String()
	}
	return remoteAddr.String()
}

// Stop stops the server
func (s *Server) Stop() error {
	s.cancel()

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return err
		}
	}

	// Close all connections
	s.mu.Lock()
	for _, conn := range s.connections {
		conn.ClientConn.Close()
		conn.ForwardConn.Close()
	}
	s.mu.Unlock()

	if s.protocol != nil {
		s.protocol.Close()
	}

	s.logger.Info("Server stopped")
	return nil
}

// GetConnections returns current connections
func (s *Server) GetConnections() map[string]*ServerConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*ServerConnection)
	for k, v := range s.connections {
		result[k] = v
	}
	return result
}
