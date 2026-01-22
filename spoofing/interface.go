package spoofing

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// IPExistsOnSystem checks if an IP address exists on any network interface
func IPExistsOnSystem(ip string) (bool, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(ipAddr) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// CreateVirtualInterface creates a dummy network interface and assigns the IP to it
func CreateVirtualInterface(ip string) (string, error) {
	// Generate a unique interface name
	// Linux interface names can only contain: a-z, A-Z, 0-9, _, :
	// Replace dots with underscores (not hyphens, as hyphens are invalid)
	ifaceName := fmt.Sprintf("etxtunnel_%s", strings.ReplaceAll(ip, ".", "_"))

	// Check if interface already exists
	if _, err := net.InterfaceByName(ifaceName); err == nil {
		// Interface exists, check if IP is already assigned
		iface, _ := net.InterfaceByName(ifaceName)
		addrs, err := iface.Addrs()
		if err == nil {
			ipAddr := net.ParseIP(ip)
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ipnet.IP.Equal(ipAddr) {
						// IP already assigned to this interface
						return ifaceName, nil
					}
				}
			}
		}
		// Interface exists but IP not assigned, add it
		cmd := exec.Command("ip", "addr", "add", ip+"/32", "dev", ifaceName)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("failed to add IP to existing interface: %w (output: %s)", err, string(output))
		}
		return ifaceName, nil
	}

	// Try to load dummy module if not already loaded
	cmd := exec.Command("modprobe", "dummy")
	cmd.Run() // Ignore errors - module might already be loaded or not available

	// Create dummy interface
	cmd = exec.Command("ip", "link", "add", "name", ifaceName, "type", "dummy")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's a permission error
		if strings.Contains(string(output), "Operation not permitted") || strings.Contains(string(output), "Permission denied") {
			return "", fmt.Errorf("failed to create dummy interface: permission denied (need root/sudo): %w (output: %s)", err, string(output))
		}
		// Check if dummy type is not supported
		if strings.Contains(string(output), "does not support") || strings.Contains(string(output), "Unknown device type") {
			return "", fmt.Errorf("failed to create dummy interface: dummy interface type not supported. Try: sudo modprobe dummy: %w (output: %s)", err, string(output))
		}
		return "", fmt.Errorf("failed to create dummy interface: %w (output: %s)", err, string(output))
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", ifaceName, "up")
	output, err = cmd.CombinedOutput()
	if err != nil {
		// Try to clean up on error
		exec.Command("ip", "link", "delete", ifaceName).Run()
		return "", fmt.Errorf("failed to bring interface up: %w (output: %s)", err, string(output))
	}

	// Assign IP to interface
	cmd = exec.Command("ip", "addr", "add", ip+"/32", "dev", ifaceName)
	output, err = cmd.CombinedOutput()
	if err != nil {
		// Try to clean up on error
		exec.Command("ip", "link", "delete", ifaceName).Run()
		// Check if IP is already assigned (might happen in race conditions)
		if strings.Contains(string(output), "File exists") || strings.Contains(string(output), "already assigned") {
			// IP already assigned, that's okay
			return ifaceName, nil
		}
		return "", fmt.Errorf("failed to assign IP to interface: %w (output: %s)", err, string(output))
	}

	return ifaceName, nil
}

// DeleteVirtualInterface deletes a virtual network interface
func DeleteVirtualInterface(ifaceName string) error {
	// Check if interface exists
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		// Interface doesn't exist, consider it already deleted
		return nil
	}

	// Bring interface down first
	cmd := exec.Command("ip", "link", "set", ifaceName, "down")
	cmd.Run() // Ignore errors

	// Delete the interface
	cmd = exec.Command("ip", "link", "delete", ifaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := string(output)
		// Check if it's because interface doesn't exist
		if strings.Contains(outputStr, "Cannot find device") || strings.Contains(outputStr, "does not exist") {
			return nil
		}
		return fmt.Errorf("failed to delete interface %s: %w (output: %s)", ifaceName, err, outputStr)
	}

	_ = iface // Use iface to avoid unused variable warning
	return nil
}

// GetInterfaceNameForIP gets the interface name that has the given IP
func GetInterfaceNameForIP(ip string) (string, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(ipAddr) {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("IP %s not found on any interface", ip)
}
