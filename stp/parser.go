package stp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BPDUType represents the type of BPDU
type BPDUType uint8

const (
	BPDUTypeConfiguration BPDUType = 0x00
	BPDUTypeTCN           BPDUType = 0x80 // Topology Change Notification
	BPDUTypeRST           BPDUType = 0x02 // Rapid Spanning Tree
	BPDUTypeMST           BPDUType = 0x03 // Multiple Spanning Tree
)

// STP multicast destination MAC addresses
var (
	STPMulticastMAC  = net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00}
	PVSTMulticastMAC = net.HardwareAddr{0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD}
)

// BridgeID represents an STP Bridge Identifier
type BridgeID struct {
	Priority   uint16
	SystemID   net.HardwareAddr
	SystemIDEx uint16 // Extended system ID (VLAN ID for PVST+)
}

// String returns a human-readable bridge ID
func (b BridgeID) String() string {
	return fmt.Sprintf("%d/%s", b.Priority, b.SystemID.String())
}

// BPDUFlags represents the flags in a BPDU
type BPDUFlags struct {
	TopologyChange    bool
	Proposal          bool
	PortRole          PortRole
	Learning          bool
	Forwarding        bool
	Agreement         bool
	TopologyChangeAck bool
}

// PortRole represents the STP port role
type PortRole uint8

const (
	PortRoleUnknown    PortRole = 0
	PortRoleAlternate  PortRole = 1
	PortRoleRoot       PortRole = 2
	PortRoleDesignated PortRole = 3
)

// String returns a human-readable port role
func (p PortRole) String() string {
	switch p {
	case PortRoleAlternate:
		return "Alternate/Backup"
	case PortRoleRoot:
		return "Root"
	case PortRoleDesignated:
		return "Designated"
	default:
		return "Unknown"
	}
}

// BPDUInfo contains parsed BPDU information
type BPDUInfo struct {
	ProtocolID      uint16
	ProtocolVersion uint8
	BPDUType        BPDUType
	Flags           BPDUFlags

	RootBridgeID   BridgeID
	RootPathCost   uint32
	SenderBridgeID BridgeID
	PortID         uint16

	MessageAge   time.Duration
	MaxAge       time.Duration
	HelloTime    time.Duration
	ForwardDelay time.Duration

	// Derived/computed fields
	IsTopologyChange bool
	SourceMAC        net.HardwareAddr
	DestMAC          net.HardwareAddr
	InterfaceName    string
	CaptureTime      time.Time
}

// BPDUTypeString returns a human-readable BPDU type
func (b *BPDUInfo) BPDUTypeString() string {
	switch b.BPDUType {
	case BPDUTypeConfiguration:
		return "Configuration"
	case BPDUTypeTCN:
		return "Topology Change Notification"
	case BPDUTypeRST:
		return "Rapid Spanning Tree"
	case BPDUTypeMST:
		return "Multiple Spanning Tree"
	default:
		return fmt.Sprintf("Unknown (0x%02X)", b.BPDUType)
	}
}

// Parser handles STP/BPDU packet parsing
type Parser struct {
	bpduHistory  []BPDUInfo
	rootBridges  map[string]BridgeID // Track root bridges seen
	tcnCount     int                 // Topology change notifications count
	lastTCNTime  time.Time
	historyLimit int
}

// NewParser creates a new STP parser
func NewParser() *Parser {
	return &Parser{
		bpduHistory:  make([]BPDUInfo, 0, 1000),
		rootBridges:  make(map[string]BridgeID),
		historyLimit: 1000,
	}
}

// ParsePacket attempts to parse an STP/BPDU packet
func (p *Parser) ParsePacket(packet gopacket.Packet, interfaceName string) (*BPDUInfo, error) {
	// Get Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, fmt.Errorf("no ethernet layer")
	}
	eth := ethLayer.(*layers.Ethernet)

	// Check if this is an STP packet (destination MAC)
	if !isSTPPacket(eth.DstMAC) {
		return nil, fmt.Errorf("not an STP packet")
	}

	// Get LLC layer (STP uses 802.2 LLC)
	llcLayer := packet.Layer(layers.LayerTypeLLC)
	if llcLayer == nil {
		return nil, fmt.Errorf("no LLC layer")
	}

	// Get the payload after LLC
	payload := llcLayer.LayerPayload()
	if len(payload) < 4 {
		return nil, fmt.Errorf("payload too short for BPDU")
	}

	bpdu := &BPDUInfo{
		SourceMAC:     eth.SrcMAC,
		DestMAC:       eth.DstMAC,
		InterfaceName: interfaceName,
		CaptureTime:   time.Now(),
	}

	// Parse BPDU header
	bpdu.ProtocolID = binary.BigEndian.Uint16(payload[0:2])
	bpdu.ProtocolVersion = payload[2]
	bpdu.BPDUType = BPDUType(payload[3])

	// TCN BPDUs are only 4 bytes
	if bpdu.BPDUType == BPDUTypeTCN {
		bpdu.IsTopologyChange = true
		p.recordTCN()
		p.addToHistory(*bpdu)
		return bpdu, nil
	}

	// Configuration BPDU needs at least 35 bytes
	if len(payload) < 35 {
		return nil, fmt.Errorf("payload too short for configuration BPDU")
	}

	// Parse flags
	flags := payload[4]
	bpdu.Flags = parseFlags(flags)
	bpdu.IsTopologyChange = bpdu.Flags.TopologyChange || bpdu.Flags.TopologyChangeAck

	// Parse Root Bridge ID (8 bytes)
	bpdu.RootBridgeID = parseBridgeID(payload[5:13])

	// Parse Root Path Cost (4 bytes)
	bpdu.RootPathCost = binary.BigEndian.Uint32(payload[13:17])

	// Parse Sender Bridge ID (8 bytes)
	bpdu.SenderBridgeID = parseBridgeID(payload[17:25])

	// Parse Port ID (2 bytes)
	bpdu.PortID = binary.BigEndian.Uint16(payload[25:27])

	// Parse timers (stored in 1/256 second units)
	bpdu.MessageAge = parseSTPTime(payload[27:29])
	bpdu.MaxAge = parseSTPTime(payload[29:31])
	bpdu.HelloTime = parseSTPTime(payload[31:33])
	bpdu.ForwardDelay = parseSTPTime(payload[33:35])

	// Track root bridges
	p.trackRootBridge(bpdu.RootBridgeID)

	if bpdu.IsTopologyChange {
		p.recordTCN()
	}

	p.addToHistory(*bpdu)
	return bpdu, nil
}

// GetRootBridges returns all root bridges seen
func (p *Parser) GetRootBridges() []BridgeID {
	bridges := make([]BridgeID, 0, len(p.rootBridges))
	for _, bridge := range p.rootBridges {
		bridges = append(bridges, bridge)
	}
	return bridges
}

// GetTCNCount returns the number of topology change notifications
func (p *Parser) GetTCNCount() int {
	return p.tcnCount
}

// GetRecentBPDUs returns the most recent BPDUs
func (p *Parser) GetRecentBPDUs(count int) []BPDUInfo {
	if count > len(p.bpduHistory) {
		count = len(p.bpduHistory)
	}
	start := len(p.bpduHistory) - count
	return p.bpduHistory[start:]
}

// HasMultipleRoots returns true if multiple root bridges are detected (bad!)
func (p *Parser) HasMultipleRoots() bool {
	return len(p.rootBridges) > 1
}

// GetBPDURate returns BPDUs per second over the last sampling period
func (p *Parser) GetBPDURate(window time.Duration) float64 {
	cutoff := time.Now().Add(-window)
	count := 0
	for i := len(p.bpduHistory) - 1; i >= 0; i-- {
		if p.bpduHistory[i].CaptureTime.Before(cutoff) {
			break
		}
		count++
	}
	return float64(count) / window.Seconds()
}

// Helper functions

func isSTPPacket(mac net.HardwareAddr) bool {
	// Standard STP multicast
	if mac.String() == STPMulticastMAC.String() {
		return true
	}
	// PVST+ multicast
	if mac.String() == PVSTMulticastMAC.String() {
		return true
	}
	return false
}

func parseFlags(b byte) BPDUFlags {
	return BPDUFlags{
		TopologyChange:    b&0x01 != 0,
		Proposal:          b&0x02 != 0,
		PortRole:          PortRole((b >> 2) & 0x03),
		Learning:          b&0x10 != 0,
		Forwarding:        b&0x20 != 0,
		Agreement:         b&0x40 != 0,
		TopologyChangeAck: b&0x80 != 0,
	}
}

func parseBridgeID(data []byte) BridgeID {
	priority := binary.BigEndian.Uint16(data[0:2])
	mac := make(net.HardwareAddr, 6)
	copy(mac, data[2:8])

	return BridgeID{
		Priority:   priority & 0xF000, // Upper 4 bits
		SystemIDEx: priority & 0x0FFF, // Lower 12 bits (VLAN ID)
		SystemID:   mac,
	}
}

func parseSTPTime(data []byte) time.Duration {
	// STP times are in 1/256 second units
	raw := binary.BigEndian.Uint16(data)
	return time.Duration(raw) * time.Second / 256
}

func (p *Parser) addToHistory(bpdu BPDUInfo) {
	p.bpduHistory = append(p.bpduHistory, bpdu)
	// Trim history if needed
	if len(p.bpduHistory) > p.historyLimit {
		p.bpduHistory = p.bpduHistory[len(p.bpduHistory)-p.historyLimit:]
	}
}

func (p *Parser) trackRootBridge(bridge BridgeID) {
	key := bridge.String()
	p.rootBridges[key] = bridge
}

func (p *Parser) recordTCN() {
	p.tcnCount++
	p.lastTCNTime = time.Now()
}

// Reset clears all parser state
func (p *Parser) Reset() {
	p.bpduHistory = make([]BPDUInfo, 0, p.historyLimit)
	p.rootBridges = make(map[string]BridgeID)
	p.tcnCount = 0
}
