package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config holds all configurable parameters for SpanScan
type Config struct {
	// Detection thresholds
	PacketCountThreshold    int           `json:"packetCountThreshold"`    // Packets per sampling period to trigger loop detection
	BroadcastStormThreshold int           `json:"broadcastStormThreshold"` // Broadcast packets per second to trigger storm alert
	SamplingPeriod          time.Duration `json:"samplingPeriod"`          // Time window for packet counting
	DuplicateMACWindow      time.Duration `json:"duplicateMACWindow"`      // Time window to detect same MAC on multiple interfaces

	// BPF Filter - allows custom packet filtering
	BPFFilter string `json:"bpfFilter"`

	// Logging configuration
	LogFile    string `json:"logFile"`    // Path to log file (empty = no logging)
	JSONOutput bool   `json:"jsonOutput"` // Output in JSON format

	// UI options
	EnableBell bool `json:"enableBell"` // Play terminal bell on critical alerts
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		PacketCountThreshold:    100,
		BroadcastStormThreshold: 500,
		SamplingPeriod:          10 * time.Second,
		DuplicateMACWindow:      2 * time.Second,
		BPFFilter:               "", // Empty = capture all traffic
		LogFile:                 "",
		JSONOutput:              false,
		EnableBell:              true,
	}
}

// LoadFromFile loads configuration from a JSON file
func LoadFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Custom unmarshaler for duration fields
	type configAlias struct {
		PacketCountThreshold    int    `json:"packetCountThreshold"`
		BroadcastStormThreshold int    `json:"broadcastStormThreshold"`
		SamplingPeriodSec       int    `json:"samplingPeriodSec"`
		DuplicateMACWindowSec   int    `json:"duplicateMACWindowSec"`
		BPFFilter               string `json:"bpfFilter"`
		LogFile                 string `json:"logFile"`
		JSONOutput              bool   `json:"jsonOutput"`
		EnableBell              bool   `json:"enableBell"`
	}

	var raw configAlias
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	if raw.PacketCountThreshold > 0 {
		cfg.PacketCountThreshold = raw.PacketCountThreshold
	}
	if raw.BroadcastStormThreshold > 0 {
		cfg.BroadcastStormThreshold = raw.BroadcastStormThreshold
	}
	if raw.SamplingPeriodSec > 0 {
		cfg.SamplingPeriod = time.Duration(raw.SamplingPeriodSec) * time.Second
	}
	if raw.DuplicateMACWindowSec > 0 {
		cfg.DuplicateMACWindow = time.Duration(raw.DuplicateMACWindowSec) * time.Second
	}
	if raw.BPFFilter != "" {
		cfg.BPFFilter = raw.BPFFilter
	}
	cfg.LogFile = raw.LogFile
	cfg.JSONOutput = raw.JSONOutput
	cfg.EnableBell = raw.EnableBell

	return cfg, nil
}

// SaveToFile saves the configuration to a JSON file
func (c *Config) SaveToFile(path string) error {
	type configAlias struct {
		PacketCountThreshold    int    `json:"packetCountThreshold"`
		BroadcastStormThreshold int    `json:"broadcastStormThreshold"`
		SamplingPeriodSec       int    `json:"samplingPeriodSec"`
		DuplicateMACWindowSec   int    `json:"duplicateMACWindowSec"`
		BPFFilter               string `json:"bpfFilter"`
		LogFile                 string `json:"logFile"`
		JSONOutput              bool   `json:"jsonOutput"`
		EnableBell              bool   `json:"enableBell"`
	}

	raw := configAlias{
		PacketCountThreshold:    c.PacketCountThreshold,
		BroadcastStormThreshold: c.BroadcastStormThreshold,
		SamplingPeriodSec:       int(c.SamplingPeriod.Seconds()),
		DuplicateMACWindowSec:   int(c.DuplicateMACWindow.Seconds()),
		BPFFilter:               c.BPFFilter,
		LogFile:                 c.LogFile,
		JSONOutput:              c.JSONOutput,
		EnableBell:              c.EnableBell,
	}

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
