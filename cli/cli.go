package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/etxtunnel/etxtunnel/logger"
)

// InteractiveCLI provides an interactive command-line interface
type InteractiveCLI struct {
	logger *logger.TunnelLogger
	reader *bufio.Reader
	running bool
}

// NewInteractiveCLI creates a new interactive CLI
func NewInteractiveCLI(log *logger.TunnelLogger) *InteractiveCLI {
	return &InteractiveCLI{
		logger: log,
		reader: bufio.NewReader(os.Stdin),
		running: true,
	}
}

// Start starts the interactive CLI
func (cli *InteractiveCLI) Start() {
	cli.printWelcome()
	cli.printHelp()

	go cli.statusLoop()

	for cli.running {
		fmt.Print("etxtunnel> ")
		line, err := cli.reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := strings.ToLower(parts[0])
		args := parts[1:]

		cli.handleCommand(command, args)
	}
}

// handleCommand handles a command
func (cli *InteractiveCLI) handleCommand(cmd string, args []string) {
	switch cmd {
	case "help", "h":
		cli.printHelp()
	case "status", "s":
		cli.printStatus()
	case "connections", "conn", "c":
		cli.printConnections()
	case "stats", "stat":
		cli.printStats()
	case "logs", "l":
		cli.printLogs(args)
	case "clear", "cls":
		fmt.Print("\033[2J\033[H") // Clear screen
	case "quit", "exit", "q":
		cli.running = false
		fmt.Println("Exiting...")
	default:
		fmt.Printf("Unknown command: %s. Type 'help' for available commands.\n", cmd)
	}
}

// printWelcome prints welcome message
func (cli *InteractiveCLI) printWelcome() {
	fmt.Println("========================================")
	fmt.Println("   ETXTunnel Interactive Interface")
	fmt.Println("========================================")
	fmt.Println()
}

// printHelp prints help message
func (cli *InteractiveCLI) printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  help, h              - Show this help message")
	fmt.Println("  status, s             - Show current status")
	fmt.Println("  connections, conn, c  - Show active connections")
	fmt.Println("  stats, stat           - Show statistics")
	fmt.Println("  logs, l [count]       - Show recent logs (default: 10)")
	fmt.Println("  clear, cls            - Clear screen")
	fmt.Println("  quit, exit, q         - Exit the application")
	fmt.Println()
}

// printStatus prints current status
func (cli *InteractiveCLI) printStatus() {
	stats := cli.logger.GetStats()
	connections := cli.logger.GetConnections()

	fmt.Println("\n=== Status ===")
	fmt.Printf("Total Connections: %d\n", stats.TotalConnections)
	fmt.Printf("Active Connections: %d\n", stats.ActiveConnections)
	fmt.Printf("Bytes Sent: %s\n", formatBytes(stats.BytesSent))
	fmt.Printf("Bytes Received: %s\n", formatBytes(stats.BytesReceived))
	fmt.Printf("Packets Sent: %d\n", stats.PacketsSent)
	fmt.Printf("Packets Received: %d\n", stats.PacketsReceived)
	fmt.Printf("Errors: %d\n", stats.Errors)
	fmt.Printf("Current Connections: %d\n", len(connections))
	fmt.Println()
}

// printConnections prints active connections
func (cli *InteractiveCLI) printConnections() {
	connections := cli.logger.GetConnections()

	if len(connections) == 0 {
		fmt.Println("No active connections")
		return
	}

	fmt.Println("\n=== Active Connections ===")
	fmt.Printf("%-20s %-15s %-15s %-20s %-20s\n", "ID", "Status", "Created", "Bytes Sent", "Bytes Received")
	fmt.Println(strings.Repeat("-", 90))

	for _, conn := range connections {
		fmt.Printf("%-20s %-15s %-15s %-20s %-20s\n",
			truncate(conn.ID, 20),
			conn.Status,
			conn.CreatedAt.Format("15:04:05"),
			formatBytes(conn.BytesSent),
			formatBytes(conn.BytesReceived))
	}
	fmt.Println()
}

// printStats prints statistics
func (cli *InteractiveCLI) printStats() {
	stats := cli.logger.GetStats()

	fmt.Println("\n=== Statistics ===")
	fmt.Printf("Total Connections: %d\n", stats.TotalConnections)
	fmt.Printf("Active Connections: %d\n", stats.ActiveConnections)
	fmt.Printf("Total Bytes Sent: %s\n", formatBytes(stats.BytesSent))
	fmt.Printf("Total Bytes Received: %s\n", formatBytes(stats.BytesReceived))
	fmt.Printf("Total Packets Sent: %d\n", stats.PacketsSent)
	fmt.Printf("Total Packets Received: %d\n", stats.PacketsReceived)
	fmt.Printf("Total Errors: %d\n", stats.Errors)
	fmt.Println()
}

// printLogs prints recent logs
func (cli *InteractiveCLI) printLogs(args []string) {
	count := 10
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			count = n
		}
	}

	logs := cli.logger.GetRecentLogs(count)

	if len(logs) == 0 {
		fmt.Println("No logs available")
		return
	}

	fmt.Printf("\n=== Recent Logs (last %d) ===\n", count)
	for _, log := range logs {
		levelStr := ""
		switch log.Level {
		case logger.DEBUG:
			levelStr = "DEBUG"
		case logger.INFO:
			levelStr = "INFO"
		case logger.WARNING:
			levelStr = "WARN"
		case logger.ERROR:
			levelStr = "ERROR"
		}

		fmt.Printf("[%s] %s: %s\n",
			log.Timestamp.Format("15:04:05"),
			levelStr,
			log.Message)
	}
	fmt.Println()
}

// statusLoop periodically updates and displays status
func (cli *InteractiveCLI) statusLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for cli.running {
		select {
		case <-ticker.C:
			// Status updates could be displayed here if needed
		}
	}
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// truncate truncates a string to specified length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
