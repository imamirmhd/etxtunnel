package spoofing

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// RawSocket represents a raw socket for packet spoofing
type RawSocket struct {
	fd   int
	addr syscall.Sockaddr
}

// NewRawSocket creates a new raw socket for IP spoofing
func NewRawSocket(protocol int) (*RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protocol)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}

	// Set socket options
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	return &RawSocket{fd: fd}, nil
}

// Close closes the raw socket
func (rs *RawSocket) Close() error {
	return syscall.Close(rs.fd)
}

// SendPacket sends a spoofed packet
func (rs *RawSocket) SendPacket(data []byte, destAddr *net.IPAddr) error {
	addr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{},
	}

	copy(addr.Addr[:], destAddr.IP.To4())

	if err := syscall.Sendto(rs.fd, data, 0, addr); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	return nil
}

// CreateSpoofedUDPPacket creates a UDP packet with spoofed source IP
func CreateSpoofedUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, data []byte) ([]byte, error) {
	// This is a simplified version - full implementation would use gopacket
	// For now, we'll use a basic approach
	packet := make([]byte, 20+8+len(data)) // IP header + UDP header + data

	// IP header (simplified)
	packet[0] = 0x45 // Version 4, IHL 5
	packet[1] = 0x00 // TOS
	// Length will be set later
	packet[4] = 0x00
	packet[5] = 0x00
	packet[6] = 0x40 // Don't fragment
	packet[7] = 0x00
	packet[8] = 0x40 // TTL
	packet[9] = 0x11 // UDP protocol

	// Source and destination IPs
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())

	// UDP header
	packet[20] = byte(srcPort >> 8)
	packet[21] = byte(srcPort & 0xff)
	packet[22] = byte(dstPort >> 8)
	packet[23] = byte(dstPort & 0xff)

	udpLen := 8 + len(data)
	packet[24] = byte(udpLen >> 8)
	packet[25] = byte(udpLen & 0xff)
	packet[26] = 0x00 // Checksum (simplified)
	packet[27] = 0x00

	// Data
	copy(packet[28:], data)

	// Set IP total length
	totalLen := len(packet)
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen & 0xff)

	return packet, nil
}

// SpoofUDP sends a UDP packet with spoofed source IP
func SpoofUDP(srcIP, dstIP string, srcPort, dstPort int, data []byte) error {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	if src == nil || dst == nil {
		return fmt.Errorf("invalid IP address")
	}

	packet, err := CreateSpoofedUDPPacket(src, dst, srcPort, dstPort, data)
	if err != nil {
		return err
	}

	sock, err := NewRawSocket(syscall.IPPROTO_UDP)
	if err != nil {
		return err
	}
	defer sock.Close()

	dstAddr := &net.IPAddr{IP: dst}
	return sock.SendPacket(packet, dstAddr)
}

// BindSocket binds a socket to a specific source IP
func BindSocket(network, address string, sourceIP string) (net.Conn, error) {
	// This is a placeholder - actual implementation would use SO_BINDTODEVICE
	// or bind to specific interface
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	// Note: Setting source IP requires root privileges and raw sockets
	// This is a simplified approach
	return conn, nil
}

// GetInterfaceIP gets the IP address of a network interface
func GetInterfaceIP(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP, nil
			}
		}
	}

	return nil, fmt.Errorf("no IPv4 address found for interface %s", ifaceName)
}

// unused function to avoid unused import warning
var _ = unsafe.Sizeof(0)
