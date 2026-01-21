package utils

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// IsIPBlocked checks if an IP address is in any blocked range
func IsIPBlocked(ip string, blockedRanges []string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return true // Invalid IP is considered blocked
	}

	for _, rangeStr := range blockedRanges {
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			// Try as single IP
			if blockedIP := net.ParseIP(rangeStr); blockedIP != nil {
				if ipAddr.Equal(blockedIP) {
					return true
				}
			}
			continue
		}

		if network.Contains(ipAddr) {
			return true
		}
	}

	return false
}

// VerifyAuthToken verifies authentication token using constant-time comparison
func VerifyAuthToken(token, receivedToken string) bool {
	return hmac.Equal([]byte(token), []byte(receivedToken))
}

// GenerateConnectionID generates a unique connection ID
func GenerateConnectionID(prefix string) string {
	timestamp := time.Now().UnixNano()
	data := fmt.Sprintf("%s%d", prefix, timestamp)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ParseAddress parses address string (IP:port) into IP and port
func ParseAddress(address string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}

	port := 0
	if portStr != "" {
		_, err := fmt.Sscanf(portStr, "%d", &port)
		if err != nil {
			return "", 0, err
		}
	}

	return host, port, nil
}

// FormatAddress formats IP and port into address string
func FormatAddress(ip string, port int) string {
	return net.JoinHostPort(ip, fmt.Sprintf("%d", port))
}

// HashToken creates a hash of the token for secure storage
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// ValidateIP validates if a string is a valid IP address
func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ValidatePort validates if a port number is in valid range
func ValidatePort(port int) bool {
	return port > 0 && port <= 65535
}

// NormalizeCIDR normalizes a CIDR string
func NormalizeCIDR(cidr string) (string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		if ip := net.ParseIP(cidr); ip != nil {
			if ip.To4() != nil {
				return fmt.Sprintf("%s/32", ip.String()), nil
			}
			return fmt.Sprintf("%s/128", ip.String()), nil
		}
		return "", err
	}
	return network.String(), nil
}

// GetLocalIP gets the local IP address
func GetLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// ResolveHostname resolves a hostname to IP address
func ResolveHostname(hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP found for hostname: %s", hostname)
	}
	return ips[0].String(), nil
}

// IsIPv4 checks if an IP address is IPv4
func IsIPv4(ip string) bool {
	ipAddr := net.ParseIP(ip)
	return ipAddr != nil && ipAddr.To4() != nil
}

// IsIPv6 checks if an IP address is IPv6
func IsIPv6(ip string) bool {
	ipAddr := net.ParseIP(ip)
	return ipAddr != nil && ipAddr.To16() != nil && ipAddr.To4() == nil
}

// ExtractDomain extracts domain from DNS query
func ExtractDomain(query string) string {
	// Remove common prefixes
	query = strings.TrimPrefix(query, "_tcp.")
	query = strings.TrimPrefix(query, "_udp.")
	return strings.TrimSuffix(query, ".")
}
