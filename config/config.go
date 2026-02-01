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
	PollInterval            time.Duration `json:"pollInterval"`            // Interval between SNMP polls
	DuplicateMACWindow      time.Duration `json:"duplicateMACWindow"`      // Time window to detect same MAC on multiple interfaces

	// SNMP Configuration
	Targets []SNMPTargetConfig `json:"targets"`

	// Logging configuration
	LogFile    string `json:"logFile"`    // Path to log file (empty = no logging)
	JSONOutput bool   `json:"jsonOutput"` // Output in JSON format

	// UI options
	EnableBell bool `json:"enableBell"` // Play terminal bell on critical alerts
}

// SNMPVersion enum
type SNMPVersion string

const (
	SNMPVersion1  SNMPVersion = "v1"
	SNMPVersion2c SNMPVersion = "v2c"
	SNMPVersion3  SNMPVersion = "v3"
)

// SNMPTargetConfig holds configuration for a single SNMP target
type SNMPTargetConfig struct {
	Address   string      `json:"address"`
	Version   SNMPVersion `json:"version"`
	Community string      `json:"community,omitempty"` // v1, v2c

	// v3 specific
	Username      string `json:"username,omitempty"`
	SecurityLevel string `json:"securityLevel,omitempty"` // NoAuthNoPriv, AuthNoPriv, AuthPriv
	AuthProto     string `json:"authProto,omitempty"`     // MD5, SHA
	AuthPass      string `json:"authPass,omitempty"`
	PrivProto     string `json:"privProto,omitempty"` // DES, AES
	PrivPass      string `json:"privPass,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		PacketCountThreshold:    100,
		BroadcastStormThreshold: 500,
		PollInterval:            10 * time.Second,
		DuplicateMACWindow:      2 * time.Second,
		Targets:                 []SNMPTargetConfig{},
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
		PacketCountThreshold    int                `json:"packetCountThreshold"`
		BroadcastStormThreshold int                `json:"broadcastStormThreshold"`
		PollIntervalSec         int                `json:"pollIntervalSec"`
		DuplicateMACWindowSec   int                `json:"duplicateMACWindowSec"`
		Targets                 []SNMPTargetConfig `json:"targets"`
		// Legacy fields for backward compatibility
		SNMPTargets   []string `json:"snmpTargets"`
		SNMPCommunity string   `json:"snmpCommunity"`

		LogFile    string `json:"logFile"`
		JSONOutput bool   `json:"jsonOutput"`
		EnableBell bool   `json:"enableBell"`
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
	if raw.PollIntervalSec > 0 {
		cfg.PollInterval = time.Duration(raw.PollIntervalSec) * time.Second
	}
	if raw.DuplicateMACWindowSec > 0 {
		cfg.DuplicateMACWindow = time.Duration(raw.DuplicateMACWindowSec) * time.Second
	}

	// Migration legacy config if present
	if len(raw.Targets) > 0 {
		cfg.Targets = raw.Targets
	} else if len(raw.SNMPTargets) > 0 {
		// Migrate legacy simple config to new struct
		community := raw.SNMPCommunity
		if community == "" {
			community = "public"
		}
		for _, target := range raw.SNMPTargets {
			cfg.Targets = append(cfg.Targets, SNMPTargetConfig{
				Address:   target,
				Version:   SNMPVersion2c,
				Community: community,
			})
		}
	}

	cfg.LogFile = raw.LogFile
	cfg.JSONOutput = raw.JSONOutput
	cfg.EnableBell = raw.EnableBell

	return cfg, nil
}

// SaveToFile saves the configuration to a JSON file
func (c *Config) SaveToFile(path string) error {
	type configAlias struct {
		PacketCountThreshold    int                `json:"packetCountThreshold"`
		BroadcastStormThreshold int                `json:"broadcastStormThreshold"`
		PollIntervalSec         int                `json:"pollIntervalSec"`
		DuplicateMACWindowSec   int                `json:"duplicateMACWindowSec"`
		Targets                 []SNMPTargetConfig `json:"targets"`
		LogFile                 string             `json:"logFile"`
		JSONOutput              bool               `json:"jsonOutput"`
		EnableBell              bool               `json:"enableBell"`
	}

	raw := configAlias{
		PacketCountThreshold:    c.PacketCountThreshold,
		BroadcastStormThreshold: c.BroadcastStormThreshold,
		PollIntervalSec:         int(c.PollInterval.Seconds()),
		DuplicateMACWindowSec:   int(c.DuplicateMACWindow.Seconds()),
		Targets:                 c.Targets,
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
