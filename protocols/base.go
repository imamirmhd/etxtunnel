package protocols

import (
	"context"
	"io"
	"net"
)

// Protocol defines the interface for all tunneling protocols
type Protocol interface {
	// Connect establishes a connection to the server
	Connect(ctx context.Context, serverAddr string, authToken string) (net.Conn, error)
	
	// Listen starts listening for incoming connections
	Listen(ctx context.Context, listenAddr string) (net.Listener, error)
	
	// SendData sends data through the tunnel
	SendData(conn net.Conn, data []byte) error
	
	// ReceiveData receives data from the tunnel
	ReceiveData(conn net.Conn) ([]byte, error)
	
	// Close closes the protocol connection
	Close() error
}

// TunnelConnection represents a tunneled connection
type TunnelConnection struct {
	ID           string
	LocalConn    net.Conn
	RemoteConn   net.Conn
	Protocol     Protocol
	BytesSent    int64
	BytesReceived int64
}

// Forward forwards data between local and remote connections
func (tc *TunnelConnection) Forward(ctx context.Context) error {
	errChan := make(chan error, 2)

	// Forward from local to remote
	go func() {
		_, err := io.Copy(tc.RemoteConn, tc.LocalConn)
		errChan <- err
	}()

	// Forward from remote to local
	go func() {
		_, err := io.Copy(tc.LocalConn, tc.RemoteConn)
		errChan <- err
	}()

	// Wait for one direction to finish
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close closes both connections
func (tc *TunnelConnection) Close() error {
	var errs []error
	if tc.LocalConn != nil {
		if err := tc.LocalConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if tc.RemoteConn != nil {
		if err := tc.RemoteConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
