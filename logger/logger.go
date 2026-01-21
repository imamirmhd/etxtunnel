package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// LogLevel represents logging levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
)

// ConnectionStatus represents connection status
type ConnectionStatus struct {
	ID          string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	BytesSent   int64
	BytesReceived int64
}

// Statistics tracks application statistics
type Statistics struct {
	TotalConnections  int64
	ActiveConnections int
	BytesSent         int64
	BytesReceived     int64
	PacketsSent       int64
	PacketsReceived   int64
	Errors            int64
}

// TunnelLogger provides centralized logging and status tracking
type TunnelLogger struct {
	logger     *log.Logger
	level      LogLevel
	mu         sync.RWMutex
	connections map[string]*ConnectionStatus
	stats      Statistics
	recentLogs  []LogEntry
	maxLogs    int
}

// LogEntry represents a log entry
type LogEntry struct {
	Level     LogLevel
	Timestamp time.Time
	Message   string
}

// NewLogger creates a new logger instance
func NewLogger(level LogLevel) *TunnelLogger {
	return &TunnelLogger{
		logger:     log.New(os.Stdout, "", log.LstdFlags),
		level:      level,
		connections: make(map[string]*ConnectionStatus),
		recentLogs:  make([]LogEntry, 0),
		maxLogs:    100,
	}
}

// logMessage logs a message at the specified level
func (l *TunnelLogger) logMessage(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	message := fmt.Sprintf(format, args...)
	prefix := ""
	switch level {
	case DEBUG:
		prefix = "[DEBUG]"
	case INFO:
		prefix = "[INFO]"
	case WARNING:
		prefix = "[WARNING]"
	case ERROR:
		prefix = "[ERROR]"
	}

	l.logger.Printf("%s %s", prefix, message)

	// Store in recent logs
	l.mu.Lock()
	entry := LogEntry{
		Level:     level,
		Timestamp: time.Now(),
		Message:   message,
	}
	l.recentLogs = append(l.recentLogs, entry)
	if len(l.recentLogs) > l.maxLogs {
		l.recentLogs = l.recentLogs[1:]
	}
	l.mu.Unlock()
}

// Debug logs a debug message
func (l *TunnelLogger) Debug(format string, args ...interface{}) {
	l.logMessage(DEBUG, format, args...)
}

// Info logs an info message
func (l *TunnelLogger) Info(format string, args ...interface{}) {
	l.logMessage(INFO, format, args...)
}

// Warning logs a warning message
func (l *TunnelLogger) Warning(format string, args ...interface{}) {
	l.logMessage(WARNING, format, args...)
}

// Error logs an error message
func (l *TunnelLogger) Error(format string, args ...interface{}) {
	l.logMessage(ERROR, format, args...)
	l.mu.Lock()
	l.stats.Errors++
	l.mu.Unlock()
}

// UpdateConnection updates or creates a connection status
func (l *TunnelLogger) UpdateConnection(connID, status string, bytesSent, bytesReceived int64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	conn, exists := l.connections[connID]
	if !exists {
		conn = &ConnectionStatus{
			ID:        connID,
			Status:    status,
			CreatedAt: time.Now(),
		}
		l.connections[connID] = conn
		l.stats.TotalConnections++
	}

	conn.Status = status
	conn.UpdatedAt = time.Now()
	conn.BytesSent = bytesSent
	conn.BytesReceived = bytesReceived

	// Update active connections count
	active := 0
	for _, c := range l.connections {
		if c.Status == "active" {
			active++
		}
	}
	l.stats.ActiveConnections = active
}

// RemoveConnection removes a connection from tracking
func (l *TunnelLogger) RemoveConnection(connID string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.connections, connID)

	// Update active connections count
	active := 0
	for _, c := range l.connections {
		if c.Status == "active" {
			active++
		}
	}
	l.stats.ActiveConnections = active
}

// UpdateStats updates statistics
func (l *TunnelLogger) UpdateStats(bytesSent, bytesReceived, packetsSent, packetsReceived int64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.stats.BytesSent += bytesSent
	l.stats.BytesReceived += bytesReceived
	l.stats.PacketsSent += packetsSent
	l.stats.PacketsReceived += packetsReceived
}

// GetStats returns a copy of current statistics
func (l *TunnelLogger) GetStats() Statistics {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.stats
}

// GetConnections returns a copy of current connections
func (l *TunnelLogger) GetConnections() map[string]*ConnectionStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make(map[string]*ConnectionStatus)
	for k, v := range l.connections {
		conn := *v
		result[k] = &conn
	}
	return result
}

// GetRecentLogs returns recent log entries
func (l *TunnelLogger) GetRecentLogs(count int) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if count > len(l.recentLogs) {
		count = len(l.recentLogs)
	}

	start := len(l.recentLogs) - count
	if start < 0 {
		start = 0
	}

	result := make([]LogEntry, count)
	copy(result, l.recentLogs[start:])
	return result
}
