package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// EventType represents the type of log event
type EventType string

const (
	EventLoopDetected     EventType = "loop_detected"
	EventBroadcastStorm   EventType = "broadcast_storm"
	EventDuplicateMAC     EventType = "duplicate_mac"
	EventTopologyChange   EventType = "topology_change"
	EventMultipleRoots    EventType = "multiple_roots"
	EventDeviceDiscovered EventType = "device_discovered"
	EventSessionStart     EventType = "session_start"
	EventSessionEnd       EventType = "session_end"
)

// Severity levels for events
type Severity int

const (
	SeverityInfo     Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

// String returns a human-readable severity
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// LogEvent represents a single log entry
type LogEvent struct {
	Timestamp time.Time   `json:"timestamp"`
	EventType EventType   `json:"eventType"`
	Severity  Severity    `json:"severity"`
	Message   string      `json:"message"`
	Details   interface{} `json:"details,omitempty"`
}

// LoopDetails contains detailed loop information for logging
type LoopDetails struct {
	MACAddress      string   `json:"macAddress"`
	VendorName      string   `json:"vendorName"`
	InterfaceName   string   `json:"interfaceName"`
	PacketCount     int      `json:"packetCount"`
	ConfidenceScore float64  `json:"confidenceScore"`
	Evidence        []string `json:"evidence"`
}

// BroadcastStormDetails contains broadcast storm information
type BroadcastStormDetails struct {
	InterfaceName    string `json:"interfaceName"`
	PacketsPerSecond int    `json:"packetsPerSecond"`
	Threshold        int    `json:"threshold"`
}

// DuplicateMACDetails contains duplicate MAC information
type DuplicateMACDetails struct {
	MACAddress string   `json:"macAddress"`
	VendorName string   `json:"vendorName"`
	Interfaces []string `json:"interfaces"`
	TimeWindow string   `json:"timeWindow"`
}

// SessionSummary contains end-of-session statistics
type SessionSummary struct {
	Duration         time.Duration `json:"duration"`
	DevicesDetected  int           `json:"devicesDetected"`
	LoopsDetected    int           `json:"loopsDetected"`
	BroadcastStorms  int           `json:"broadcastStorms"`
	DuplicateMACs    int           `json:"duplicateMACs"`
	TopologyChanges  int           `json:"topologyChanges"`
	PacketsProcessed int64         `json:"packetsProcessed"`
}

// Logger handles event logging
type Logger struct {
	file     *os.File
	enabled  bool
	jsonMode bool
	mutex    sync.Mutex
	events   []LogEvent
}

// NewLogger creates a new logger
func NewLogger(filePath string, jsonMode bool) (*Logger, error) {
	logger := &Logger{
		enabled:  filePath != "",
		jsonMode: jsonMode,
		events:   make([]LogEvent, 0),
	}

	if filePath != "" {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logger.file = file
	}

	return logger, nil
}

// Log records an event
func (l *Logger) Log(eventType EventType, severity Severity, message string, details interface{}) {
	event := LogEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		Severity:  severity,
		Message:   message,
		Details:   details,
	}

	l.mutex.Lock()
	l.events = append(l.events, event)
	l.mutex.Unlock()

	if l.enabled && l.file != nil {
		l.writeEvent(event)
	}
}

// LogLoop logs a loop detection event
func (l *Logger) LogLoop(severity Severity, macAddress, vendorName, interfaceName string, packetCount int, confidence float64, evidence []string) {
	details := LoopDetails{
		MACAddress:      macAddress,
		VendorName:      vendorName,
		InterfaceName:   interfaceName,
		PacketCount:     packetCount,
		ConfidenceScore: confidence,
		Evidence:        evidence,
	}
	l.Log(EventLoopDetected, severity, fmt.Sprintf("Loop detected from %s (%s)", macAddress, vendorName), details)
}

// LogBroadcastStorm logs a broadcast storm event
func (l *Logger) LogBroadcastStorm(interfaceName string, pps, threshold int) {
	details := BroadcastStormDetails{
		InterfaceName:    interfaceName,
		PacketsPerSecond: pps,
		Threshold:        threshold,
	}
	l.Log(EventBroadcastStorm, SeverityCritical, fmt.Sprintf("Broadcast storm on %s: %d pps", interfaceName, pps), details)
}

// LogDuplicateMAC logs a duplicate MAC detection event
func (l *Logger) LogDuplicateMAC(macAddress, vendorName string, interfaces []string, timeWindow time.Duration) {
	details := DuplicateMACDetails{
		MACAddress: macAddress,
		VendorName: vendorName,
		Interfaces: interfaces,
		TimeWindow: timeWindow.String(),
	}
	l.Log(EventDuplicateMAC, SeverityHigh, fmt.Sprintf("MAC %s seen on multiple interfaces: %v", macAddress, interfaces), details)
}

// LogTopologyChange logs an STP topology change
func (l *Logger) LogTopologyChange(bridgeID, interfaceName string) {
	l.Log(EventTopologyChange, SeverityMedium, fmt.Sprintf("STP Topology Change from %s on %s", bridgeID, interfaceName), nil)
}

// LogSessionStart logs the start of a monitoring session
func (l *Logger) LogSessionStart() {
	l.Log(EventSessionStart, SeverityInfo, "SpanScan monitoring session started", nil)
}

// LogSessionEnd logs the end of a session with summary
func (l *Logger) LogSessionEnd(summary SessionSummary) {
	l.Log(EventSessionEnd, SeverityInfo, fmt.Sprintf("Session ended after %s", summary.Duration), summary)
}

// GetEvents returns all logged events
func (l *Logger) GetEvents() []LogEvent {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	events := make([]LogEvent, len(l.events))
	copy(events, l.events)
	return events
}

// GetEventsBySeverity returns events at or above the given severity
func (l *Logger) GetEventsBySeverity(minSeverity Severity) []LogEvent {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	filtered := make([]LogEvent, 0)
	for _, event := range l.events {
		if event.Severity >= minSeverity {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// writeEvent writes a single event to the log file
func (l *Logger) writeEvent(event LogEvent) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.jsonMode {
		data, err := json.Marshal(event)
		if err == nil {
			l.file.Write(data)
			l.file.WriteString("\n")
		}
	} else {
		line := fmt.Sprintf("[%s] [%s] %s: %s\n",
			event.Timestamp.Format("2006-01-02 15:04:05"),
			event.Severity.String(),
			event.EventType,
			event.Message,
		)
		l.file.WriteString(line)
	}
}

// ExportToFile exports all events to a file
func (l *Logger) ExportToFile(path string) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	data, err := json.MarshalIndent(l.events, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
