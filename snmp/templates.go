package snmp

import (
	"strings"

	"github.com/gosnmp/gosnmp"
)

// VendorID identifies supported switch vendors
type VendorID string

const (
	VendorGeneric  VendorID = "generic"
	VendorCisco    VendorID = "cisco"
	VendorJuniper  VendorID = "juniper"
	VendorHP       VendorID = "hp"
	VendorArista   VendorID = "arista"
	VendorUbiquiti VendorID = "ubiquiti"
)

// Template defines vendor-specific SNMP behavior
type Template struct {
	ID                  VendorID
	Name                string
	VLANPollingStrategy VLANStrategy
	InterfaceNameOID    string // OID to use for interface names (ifDescr, ifName, ifAlias)
	BroadcastStormOID   string // OID for broadcast packets (ifInNUcastPkts usually)
	LoopDetectOID       string // Specific vendor OID for loop detection status (if any)
}

// VLANStrategy defines how to poll per-VLAN data (like MAC tables)
type VLANStrategy int

const (
	StrategyStandard          VLANStrategy = iota // No special handling, just poll standard MIBs
	StrategyCommunityIndexing                     // Cisco styles: community@vlan
	StrategyContext                               // SNMPv3 Context (Juniper/others)
	StrategyQBridge                               // Q-BRIDGE-MIB (dot1qTpFdbTable)
)

// GetTemplate creates a Template based on system description
func GetTemplate(sysDescr string, sysObjectID string) Template {
	sysDescr = strings.ToLower(sysDescr)

	if strings.Contains(sysDescr, "cisco") || strings.Contains(sysDescr, "ios") || strings.Contains(sysDescr, "nx-os") {
		return Template{
			ID:                  VendorCisco,
			Name:                "Cisco Systems",
			VLANPollingStrategy: StrategyCommunityIndexing,
			InterfaceNameOID:    ".1.3.6.1.2.1.31.1.1.1.1", // ifName
			BroadcastStormOID:   ".1.3.6.1.2.1.2.2.1.12",   // ifInNUcastPkts
		}
	}

	if strings.Contains(sysDescr, "juniper") || strings.Contains(sysDescr, "junso") {
		return Template{
			ID:                  VendorJuniper,
			Name:                "Juniper Networks",
			VLANPollingStrategy: StrategyQBridge, // Often supports Q-BRIDGE-MIB
			InterfaceNameOID:    ".1.3.6.1.2.1.31.1.1.1.1",
			BroadcastStormOID:   ".1.3.6.1.2.1.2.2.1.12",
		}
	}

	if strings.Contains(sysDescr, "procurve") || strings.Contains(sysDescr, "hp") || strings.Contains(sysDescr, "aruba") {
		return Template{
			ID:                  VendorHP,
			Name:                "HP/Aruba",
			VLANPollingStrategy: StrategyQBridge,
			InterfaceNameOID:    ".1.3.6.1.2.1.2.2.1.2", // ifDescr often better on older ProCurve
			BroadcastStormOID:   ".1.3.6.1.2.1.2.2.1.12",
		}
	}

	if strings.Contains(sysDescr, "arista") {
		return Template{
			ID:                  VendorArista,
			Name:                "Arista Networks",
			VLANPollingStrategy: StrategyStandard, // Arista often exposes all in standard or uses BRIDGE-MIB
			InterfaceNameOID:    ".1.3.6.1.2.1.31.1.1.1.1",
			BroadcastStormOID:   ".1.3.6.1.2.1.2.2.1.12",
		}
	}

	if strings.Contains(sysDescr, "ubiquiti") || strings.Contains(sysDescr, "edgeswitch") || strings.Contains(sysDescr, "unifi") {
		return Template{
			ID:                  VendorUbiquiti,
			Name:                "Ubiquiti",
			VLANPollingStrategy: StrategyStandard,
			InterfaceNameOID:    ".1.3.6.1.2.1.2.2.1.2",
			BroadcastStormOID:   ".1.3.6.1.2.1.2.2.1.12",
		}
	}

	// Default Generic
	return Template{
		ID:                  VendorGeneric,
		Name:                "Generic SNMP Device",
		VLANPollingStrategy: StrategyStandard,
		InterfaceNameOID:    ".1.3.6.1.2.1.2.2.1.2", // ifDescr
		BroadcastStormOID:   ".1.3.6.1.2.1.2.2.1.12",
	}
}

// Helper to check for Q-BRIDGE-MIB support
func CheckQBridgeSupport(client *gosnmp.GoSNMP) bool {
	// Try to walk a Q-BRIDGE-OID
	// .1.3.6.1.2.1.17.7.1.2.2 (dot1qTpFdbTable)
	result, err := client.Get([]string{".1.3.6.1.2.1.17.7.1.2.2"})
	// Rough check, in reality we'd Walk
	return err == nil && result != nil
}
