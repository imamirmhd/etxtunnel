package server

import (
	"context"
	"fmt"
	"io"
	"net"
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
	mu              sync.Mutex
}

// NewServer creates a new server instance
func NewServer(cfg *config.ServerProtocolConfig, log *logger.TunnelLogger) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create protocol based on configuration
	var protocol protocols.Protocol
	switch cfg.Protocol {
	case config.TCPOverUDP:
		protocol = protocols.NewTCPOverUDP(cfg.ClientFakeIP, cfg.Port)
	case config.TCPOverICMP:
		protocol = protocols.NewTCPOverICMP(cfg.ClientFakeIP)
	case config.TCPOverIP:
		protocol = protocols.NewTCPOverIP(cfg.ClientFakeIP)
	case config.TCPOverTCP:
		protocol = protocols.NewTCPOverTCP(cfg.ClientFakeIP)
	case config.TCPOverDNS:
		protocol = protocols.NewTCPOverDNS(cfg.DNSServer, cfg.DNSDomain, cfg.ClientFakeIP)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	server := &Server{
		config:      cfg,
		logger:      log,
		protocol:    protocol,
		connections: make(map[string]*ServerConnection),
		ctx:         ctx,
		cancel:      cancel,
	}

	return server, nil
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

	// Verify client IP matches expected
	if clientIP != s.config.ClientRealIP && clientIP != s.config.ClientFakeIP {
		s.logger.Warning("Connection from unexpected IP: %s (expected: %s or %s)", 
			clientIP, s.config.ClientRealIP, s.config.ClientFakeIP)
		// Continue anyway for flexibility
	}

	// Read authentication token
	authBuffer := make([]byte, 256)
	n, err := clientConn.Read(authBuffer)
	if err != nil {
		s.logger.Error("Failed to read auth token: %v", err)
		clientConn.Close()
		return
	}

	receivedToken := string(authBuffer[:n])
	if !utils.VerifyAuthToken(s.config.AuthToken, receivedToken) {
		s.logger.Error("Invalid authentication token from %s", clientIP)
		clientConn.Close()
		return
	}

	// Connect to forward destination
	forwardAddr := fmt.Sprintf("%s:%d", s.config.ForwardDestinationIP, s.config.ForwardDestinationPort)
	forwardConn, err := net.DialTimeout("tcp", forwardAddr, 30*time.Second)
	if err != nil {
		s.logger.Error("Failed to connect to forward destination: %v", err)
		clientConn.Close()
		return
	}

	// Create connection tracking
	serverConn := &ServerConnection{
		ID:          connID,
		ClientConn:  clientConn,
		ForwardConn: forwardConn,
		CreatedAt:   time.Now(),
		ClientIP:    clientIP,
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
