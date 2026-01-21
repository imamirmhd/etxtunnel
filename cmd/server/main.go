package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/etxtunnel/etxtunnel/cli"
	"github.com/etxtunnel/etxtunnel/config"
	"github.com/etxtunnel/etxtunnel/logger"
	"github.com/etxtunnel/etxtunnel/server"
	"github.com/spf13/cobra"
)

var (
	configPath  string
	interactive bool
)

var rootCmd = &cobra.Command{
	Use:   "etxtunnel-server",
	Short: "ETXTunnel Server - High-performance network tunneling server",
	Long: `ETXTunnel Server is a high-performance network tunneling server that supports
multiple tunneling protocols including TCP over UDP, ICMP, IP, TCP, and DNS.`,
	RunE: runServer,
}

func init() {
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "server.yaml", "Path to server configuration file")
	rootCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Enable interactive mode")
}

func runServer(cmd *cobra.Command, args []string) error {
	// Allow config file as positional argument if not provided via flag
	if configPath == "server.yaml" && len(args) > 0 {
		configPath = args[0]
	}
	
	// Load configuration
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create logger
	log := logger.NewLogger(logger.INFO)

	// Create and start server
	srv, err := server.NewServer(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer srv.Stop()

	// Start interactive interface if requested
	if interactive {
		interactiveCLI := cli.NewInteractiveCLI(log)
		go interactiveCLI.Start()
	}

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutting down...")
	return nil
}


func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
