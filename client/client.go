package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/etxtunnel/etxtunnel/config"
	"github.com/etxtunnel/etxtunnel/loadbalancer"
	"github.com/etxtunnel/etxtunnel/logger"
	"github.com/etxtunnel/etxtunnel/protocols"
	"github.com/etxtunnel/etxtunnel/utils"
)

// Client represents the tunneling client
type Client struct {
	config         *config.ClientConfig
	logger         *logger.TunnelLogger
	loadBalancer   *loadbalancer.LoadBalancer
	listener       net.Listener
	connections    map[string]*ClientConnection
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	keepaliveTicker *time.Ticker
}

// ClientConnection represents a client-side connection
type ClientConnection struct {
	ID           string
	LocalConn    net.Conn
	RemoteConn   net.Conn
	Server       *config.ServerConfig
	Protocol     protocols.Protocol
	BytesSent    int64
	BytesReceived int64
	CreatedAt    time.Time
	mu           sync.Mutex
}

// NewClient creates a new client instance
func NewClient(cfg *config.ClientConfig, log *logger.TunnelLogger) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	// Validate configuration
	if len(cfg.Servers) == 0 {
		log.Warning("No servers configured in client config")
	} else {
		log.Info("Loaded %d server(s) from configuration", len(cfg.Servers))
		for i, srv := range cfg.Servers {
			log.Debug("Server %d: %s:%d (source: %s)", i+1, srv.RealIP, srv.Port, srv.SourceAddress)
		}
	}

	lb := loadbalancer.NewLoadBalancer(cfg.Servers, cfg.LoadBalanceAlgorithm)

	client := &Client{
		config:       cfg,
		logger:       log,
		loadBalancer: lb,
		connections:  make(map[string]*ClientConnection),
		ctx:          ctx,
		cancel:       cancel,
	}

	return client
}

// Start starts the client
func (c *Client) Start() error {
	// Start listening for user connections
	listenAddr := fmt.Sprintf("%s:%d", c.config.ListenIP, c.config.ListenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	c.listener = listener
	c.logger.Info("Client started, listening on %s", listenAddr)

	// Start keepalive ticker
	if len(c.config.Servers) > 0 {
		// Use the minimum keepalive interval from all servers
		minInterval := c.config.Servers[0].KeepaliveInterval
		for _, srv := range c.config.Servers {
			if srv.KeepaliveInterval < minInterval {
				minInterval = srv.KeepaliveInterval
			}
		}
		c.keepaliveTicker = time.NewTicker(time.Duration(minInterval) * time.Second)
		go c.keepaliveLoop()
	}

	// Accept connections
	go c.acceptLoop()

	return nil
}

// acceptLoop accepts incoming user connections
func (c *Client) acceptLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			conn, err := c.listener.Accept()
			if err != nil {
				c.logger.Error("Failed to accept connection: %v", err)
				continue
			}

			// Check if IP is blocked
			remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
			if utils.IsIPBlocked(remoteAddr.IP.String(), c.config.BlockedRanges) {
				c.logger.Warning("Blocked connection from %s", remoteAddr.IP.String())
				conn.Close()
				continue
			}

			// Handle connection
			go c.handleConnection(conn)
		}
	}
}

// handleConnection handles a new user connection
func (c *Client) handleConnection(localConn net.Conn) {
	connID := utils.GenerateConnectionID("client")
	c.logger.Info("New connection: %s from %s", connID, localConn.RemoteAddr())

	// Select server using load balancer
	server := c.loadBalancer.GetServer(connID)
	if server == nil {
		c.logger.Error("No servers available - check your configuration file")
		c.logger.Error("Expected at least one server in 'servers' section of config")
		localConn.Close()
		return
	}
	
	c.logger.Debug("Selected server: %s:%d", server.RealIP, server.Port)

	// Create protocol based on server configuration
	// For now, we'll use TCP over UDP as default
	// In a full implementation, this would be configurable
	protocol := protocols.NewTCPOverUDP(server.SourceAddress, 0)

	// Connect to server
	serverAddr := fmt.Sprintf("%s:%d", server.RealIP, server.Port)
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	remoteConn, err := protocol.Connect(ctx, serverAddr, server.AuthToken)
	if err != nil {
		c.logger.Error("Failed to connect to server: %v", err)
		localConn.Close()
		c.loadBalancer.ReleaseConnection(server)
		return
	}

	// Create connection tracking
	clientConn := &ClientConnection{
		ID:          connID,
		LocalConn:   localConn,
		RemoteConn:  remoteConn,
		Server:      server,
		Protocol:    protocol,
		CreatedAt:   time.Now(),
	}

	c.mu.Lock()
	c.connections[connID] = clientConn
	c.mu.Unlock()

	c.logger.UpdateConnection(connID, "active", 0, 0)

	// Forward data between connections
	c.forwardConnection(clientConn)

	// Cleanup
	c.mu.Lock()
	delete(c.connections, connID)
	c.mu.Unlock()

	c.loadBalancer.ReleaseConnection(server)
	c.logger.RemoveConnection(connID)
	localConn.Close()
	remoteConn.Close()
}

// forwardConnection forwards data between local and remote connections
func (c *Client) forwardConnection(conn *ClientConnection) {
	errChan := make(chan error, 2)

	// Forward from local to remote
	go func() {
		written, err := io.Copy(conn.RemoteConn, conn.LocalConn)
		conn.mu.Lock()
		conn.BytesSent = written
		conn.mu.Unlock()
		c.logger.UpdateStats(written, 0, 0, 0)
		c.logger.UpdateConnection(conn.ID, "active", written, conn.BytesReceived)
		errChan <- err
	}()

	// Forward from remote to local
	go func() {
		written, err := io.Copy(conn.LocalConn, conn.RemoteConn)
		conn.mu.Lock()
		conn.BytesReceived = written
		conn.mu.Unlock()
		c.logger.UpdateStats(0, written, 0, 0)
		c.logger.UpdateConnection(conn.ID, "active", conn.BytesSent, written)
		errChan <- err
	}()

	// Wait for one direction to finish
	select {
	case err := <-errChan:
		if err != nil && err != io.EOF {
			c.logger.Error("Connection error: %v", err)
		}
	case <-c.ctx.Done():
		return
	}
}

// keepaliveLoop sends keepalive packets to servers
func (c *Client) keepaliveLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.keepaliveTicker.C:
			c.mu.RLock()
			activeConnections := make([]*ClientConnection, 0, len(c.connections))
			for _, conn := range c.connections {
				activeConnections = append(activeConnections, conn)
			}
			c.mu.RUnlock()

			// Send keepalive to each active connection's server
			for _, conn := range activeConnections {
				// Send keepalive packet (simplified)
				keepaliveData := []byte("KEEPALIVE")
				if _, err := conn.RemoteConn.Write(keepaliveData); err != nil {
					c.logger.Debug("Keepalive failed for connection %s: %v", conn.ID, err)
				}
			}
		}
	}
}

// Stop stops the client
func (c *Client) Stop() error {
	c.cancel()

	if c.keepaliveTicker != nil {
		c.keepaliveTicker.Stop()
	}

	if c.listener != nil {
		if err := c.listener.Close(); err != nil {
			return err
		}
	}

	// Close all connections
	c.mu.Lock()
	for _, conn := range c.connections {
		conn.LocalConn.Close()
		conn.RemoteConn.Close()
	}
	c.mu.Unlock()

	c.logger.Info("Client stopped")
	return nil
}

// GetConnections returns current connections
func (c *Client) GetConnections() map[string]*ClientConnection {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*ClientConnection)
	for k, v := range c.connections {
		result[k] = v
	}
	return result
}
