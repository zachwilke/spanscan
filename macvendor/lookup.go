package macvendor

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DeviceType represents the type of network device
type DeviceType string

const (
	DeviceTypeSwitch      DeviceType = "Switch"
	DeviceTypeRouter      DeviceType = "Router"
	DeviceTypeAccessPoint DeviceType = "Access Point"
	DeviceTypeFirewall    DeviceType = "Firewall"
	DeviceTypeEndDevice   DeviceType = "End Device"
	DeviceTypeVirtual     DeviceType = "Virtual"
	DeviceTypeIoT         DeviceType = "IoT Device"
	DeviceTypeUnknown     DeviceType = "Unknown"
)

// VendorInfo contains information about a MAC address vendor
type VendorInfo struct {
	Vendor      string
	Company     string
	Address     string
	CountryCode string
	DeviceType  DeviceType
}

// LookupService handles MAC address vendor lookups
type LookupService struct {
	cache      map[string]VendorInfo
	apiKey     string
	mutex      sync.RWMutex
	httpClient *http.Client
}

// NewLookupService creates a new MAC vendor lookup service
func NewLookupService() *LookupService {
	return &LookupService{
		cache: make(map[string]VendorInfo),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Lookup returns vendor information for a MAC address
func (s *LookupService) Lookup(macAddress net.HardwareAddr) VendorInfo {
	if macAddress == nil || len(macAddress) < 3 {
		return VendorInfo{Vendor: "Unknown", DeviceType: DeviceTypeUnknown}
	}

	// Normalize MAC to the first 3 bytes (OUI)
	oui := strings.ToUpper(fmt.Sprintf("%02X:%02X:%02X", macAddress[0], macAddress[1], macAddress[2]))

	// Check cache first
	s.mutex.RLock()
	if info, exists := s.cache[oui]; exists {
		s.mutex.RUnlock()
		return info
	}
	s.mutex.RUnlock()

	// Use local database first, then try online lookup
	vendorInfo := s.lookupLocal(oui)
	if vendorInfo.Vendor == "" {
		vendorInfo = s.lookupOnline(oui)
	}

	// Cache the result
	s.mutex.Lock()
	s.cache[oui] = vendorInfo
	s.mutex.Unlock()

	return vendorInfo
}

// lookupLocal checks local database of common MAC vendors
func (s *LookupService) lookupLocal(oui string) VendorInfo {
	// Comprehensive networking equipment vendors database
	vendors := map[string]VendorInfo{
		// Cisco
		"00:00:0C": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:01:42": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:03:6B": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:04:9A": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:0E:38": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:0E:D6": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:0F:23": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:0F:34": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:11:BB": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:11:92": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:12:7F": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:12:17": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:13:10": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:13:7F": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:13:C4": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:14:69": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:14:A8": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:14:F1": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:14:F2": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:1A:A1": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:1B:0D": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:1D:45": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},
		"00:1E:7A": {Vendor: "Cisco", Company: "Cisco Systems, Inc.", DeviceType: DeviceTypeSwitch},

		// Cisco Meraki
		"00:25:9C": {Vendor: "Cisco-Meraki", Company: "Cisco Meraki", DeviceType: DeviceTypeSwitch},
		"00:18:0A": {Vendor: "Cisco-Meraki", Company: "Cisco Meraki", DeviceType: DeviceTypeSwitch},
		"88:15:44": {Vendor: "Cisco-Meraki", Company: "Cisco Meraki", DeviceType: DeviceTypeSwitch},
		"AC:17:C8": {Vendor: "Cisco-Meraki", Company: "Cisco Meraki", DeviceType: DeviceTypeAccessPoint},

		// Juniper Networks
		"00:1A:A2": {Vendor: "Juniper", Company: "Juniper Networks", DeviceType: DeviceTypeSwitch},
		"00:10:DB": {Vendor: "Juniper", Company: "Juniper Networks", DeviceType: DeviceTypeRouter},
		"00:12:1E": {Vendor: "Juniper", Company: "Juniper Networks", DeviceType: DeviceTypeRouter},
		"00:14:F6": {Vendor: "Juniper", Company: "Juniper Networks", DeviceType: DeviceTypeRouter},
		"00:17:CB": {Vendor: "Juniper", Company: "Juniper Networks", DeviceType: DeviceTypeRouter},
		"00:19:E2": {Vendor: "Juniper", Company: "Juniper Networks", DeviceType: DeviceTypeRouter},
		"00:21:59": {Vendor: "Juniper", Company: "Juniper Networks", DeviceType: DeviceTypeSwitch},
		"00:23:9C": {Vendor: "Juniper", Company: "Juniper Networks", DeviceType: DeviceTypeSwitch},

		// HP / Aruba
		"00:1B:21": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeSwitch},
		"00:0F:61": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeSwitch},
		"00:0B:86": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeAccessPoint},
		"00:1A:1E": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeSwitch},
		"00:24:A8": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeSwitch},
		"00:25:B3": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeSwitch},
		"00:30:C1": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeSwitch},
		"24:BE:05": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeAccessPoint},
		"40:E3:D6": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeAccessPoint},
		"6C:C2:17": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks", DeviceType: DeviceTypeAccessPoint},

		// Dell
		"00:1E:C9": {Vendor: "Dell", Company: "Dell Inc.", DeviceType: DeviceTypeSwitch},
		"00:14:22": {Vendor: "Dell", Company: "Dell Inc.", DeviceType: DeviceTypeSwitch},
		"00:12:3F": {Vendor: "Dell", Company: "Dell Inc.", DeviceType: DeviceTypeSwitch},
		"00:06:5B": {Vendor: "Dell", Company: "Dell Inc.", DeviceType: DeviceTypeEndDevice},
		"00:08:74": {Vendor: "Dell", Company: "Dell Inc.", DeviceType: DeviceTypeEndDevice},
		"00:0B:DB": {Vendor: "Dell", Company: "Dell Inc.", DeviceType: DeviceTypeEndDevice},
		"00:0D:56": {Vendor: "Dell", Company: "Dell Inc.", DeviceType: DeviceTypeEndDevice},
		"00:0F:1F": {Vendor: "Dell", Company: "Dell Inc.", DeviceType: DeviceTypeEndDevice},

		// Ubiquiti
		"00:27:22": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeAccessPoint},
		"04:18:D6": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeAccessPoint},
		"18:E8:29": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeAccessPoint},
		"24:A4:3C": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeSwitch},
		"44:D9:E7": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeAccessPoint},
		"68:72:51": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeAccessPoint},
		"74:83:C2": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeSwitch},
		"78:8A:20": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeAccessPoint},
		"80:2A:A8": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeAccessPoint},
		"DC:9F:DB": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeAccessPoint},
		"FC:EC:DA": {Vendor: "Ubiquiti", Company: "Ubiquiti Networks", DeviceType: DeviceTypeAccessPoint},

		// MikroTik
		"00:0C:42": {Vendor: "MikroTik", Company: "MikroTik", DeviceType: DeviceTypeRouter},
		"4C:5E:0C": {Vendor: "MikroTik", Company: "MikroTik", DeviceType: DeviceTypeRouter},
		"64:D1:54": {Vendor: "MikroTik", Company: "MikroTik", DeviceType: DeviceTypeRouter},
		"6C:3B:6B": {Vendor: "MikroTik", Company: "MikroTik", DeviceType: DeviceTypeRouter},
		"B8:69:F4": {Vendor: "MikroTik", Company: "MikroTik", DeviceType: DeviceTypeRouter},
		"D4:01:29": {Vendor: "MikroTik", Company: "MikroTik", DeviceType: DeviceTypeRouter},
		"DC:2C:6E": {Vendor: "MikroTik", Company: "MikroTik", DeviceType: DeviceTypeRouter},
		"E4:8D:8C": {Vendor: "MikroTik", Company: "MikroTik", DeviceType: DeviceTypeRouter},

		// Netgear
		"00:14:6C": {Vendor: "Netgear", Company: "Netgear Inc.", DeviceType: DeviceTypeSwitch},
		"00:0F:B5": {Vendor: "Netgear", Company: "Netgear Inc.", DeviceType: DeviceTypeSwitch},
		"00:09:5B": {Vendor: "Netgear", Company: "Netgear Inc.", DeviceType: DeviceTypeSwitch},
		"00:18:4D": {Vendor: "Netgear", Company: "Netgear Inc.", DeviceType: DeviceTypeSwitch},
		"00:1B:2F": {Vendor: "Netgear", Company: "Netgear Inc.", DeviceType: DeviceTypeSwitch},
		"00:1E:2A": {Vendor: "Netgear", Company: "Netgear Inc.", DeviceType: DeviceTypeSwitch},
		"00:22:3F": {Vendor: "Netgear", Company: "Netgear Inc.", DeviceType: DeviceTypeSwitch},
		"00:24:B2": {Vendor: "Netgear", Company: "Netgear Inc.", DeviceType: DeviceTypeSwitch},
		"00:26:F2": {Vendor: "Netgear", Company: "Netgear Inc.", DeviceType: DeviceTypeSwitch},

		// TP-Link
		"00:1D:0F": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeSwitch},
		"10:FE:ED": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeRouter},
		"14:CC:20": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeRouter},
		"30:B5:C2": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeSwitch},
		"50:C7:BF": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeRouter},
		"54:C8:0F": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeSwitch},
		"60:E3:27": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeAccessPoint},
		"90:F6:52": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeRouter},
		"B0:BE:76": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeRouter},
		"F4:F2:6D": {Vendor: "TP-Link", Company: "TP-Link Technologies", DeviceType: DeviceTypeRouter},

		// Extreme Networks
		"00:01:30": {Vendor: "Extreme", Company: "Extreme Networks", DeviceType: DeviceTypeSwitch},
		"00:04:96": {Vendor: "Extreme", Company: "Extreme Networks", DeviceType: DeviceTypeSwitch},
		"00:0F:DB": {Vendor: "Extreme", Company: "Extreme Networks", DeviceType: DeviceTypeSwitch},
		"00:11:D8": {Vendor: "Extreme", Company: "Extreme Networks", DeviceType: DeviceTypeSwitch},
		"5C:0E:8B": {Vendor: "Extreme", Company: "Extreme Networks", DeviceType: DeviceTypeSwitch},
		"B4:C7:99": {Vendor: "Extreme", Company: "Extreme Networks", DeviceType: DeviceTypeSwitch},

		// Fortinet
		"00:09:0F": {Vendor: "Fortinet", Company: "Fortinet Inc.", DeviceType: DeviceTypeFirewall},
		"00:1E:4F": {Vendor: "Fortinet", Company: "Fortinet Inc.", DeviceType: DeviceTypeFirewall},
		"08:5B:0E": {Vendor: "Fortinet", Company: "Fortinet Inc.", DeviceType: DeviceTypeFirewall},
		"70:4C:A5": {Vendor: "Fortinet", Company: "Fortinet Inc.", DeviceType: DeviceTypeFirewall},
		"90:6C:AC": {Vendor: "Fortinet", Company: "Fortinet Inc.", DeviceType: DeviceTypeFirewall},

		// Palo Alto Networks
		"00:1B:17": {Vendor: "Palo Alto", Company: "Palo Alto Networks", DeviceType: DeviceTypeFirewall},
		"00:86:9C": {Vendor: "Palo Alto", Company: "Palo Alto Networks", DeviceType: DeviceTypeFirewall},
		"08:66:1F": {Vendor: "Palo Alto", Company: "Palo Alto Networks", DeviceType: DeviceTypeFirewall},
		"78:6D:94": {Vendor: "Palo Alto", Company: "Palo Alto Networks", DeviceType: DeviceTypeFirewall},

		// VMware
		"00:0C:29": {Vendor: "VMware", Company: "VMware, Inc.", DeviceType: DeviceTypeVirtual},
		"00:50:56": {Vendor: "VMware", Company: "VMware, Inc.", DeviceType: DeviceTypeVirtual},
		"00:05:69": {Vendor: "VMware", Company: "VMware, Inc.", DeviceType: DeviceTypeVirtual},
		"00:1C:14": {Vendor: "VMware", Company: "VMware, Inc.", DeviceType: DeviceTypeVirtual},

		// Apple
		"00:1B:63": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"00:1F:F3": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"00:25:00": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"00:26:BB": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"00:3E:E1": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"04:0C:CE": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"14:5A:05": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"28:CF:DA": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"3C:06:30": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"54:4E:90": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"78:4F:43": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"A8:5C:2C": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},
		"DC:56:E7": {Vendor: "Apple", Company: "Apple Inc.", DeviceType: DeviceTypeEndDevice},

		// Intel
		"00:18:DE": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:1F:3B": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:1C:C0": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:1E:64": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:1E:67": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:21:5D": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:22:FA": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:24:D6": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:26:C6": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:26:C7": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},
		"00:27:10": {Vendor: "Intel", Company: "Intel Corporate", DeviceType: DeviceTypeEndDevice},

		// Common IoT / ICS vendors
		"00:1A:F1": {Vendor: "Embedded Sys", Company: "Embedded Systems", DeviceType: DeviceTypeIoT},
		"00:60:35": {Vendor: "Dallas Semi", Company: "Dallas Semiconductor", DeviceType: DeviceTypeIoT},
		"00:80:A3": {Vendor: "Allen-Bradley", Company: "Rockwell Automation", DeviceType: DeviceTypeIoT},
		"00:0D:8D": {Vendor: "Siemens", Company: "Siemens AG", DeviceType: DeviceTypeIoT},
		"00:1F:16": {Vendor: "Wago", Company: "Wago Kontakttechnik", DeviceType: DeviceTypeIoT},
		"00:01:05": {Vendor: "Schneider", Company: "Schneider Electric", DeviceType: DeviceTypeIoT},
		"00:80:F4": {Vendor: "Schneider", Company: "Schneider Electric", DeviceType: DeviceTypeIoT},
		"00:20:4A": {Vendor: "Prosoft", Company: "Prosoft Technology", DeviceType: DeviceTypeIoT},

		// Raspberry Pi (common loop sources in DIY networks)
		"B8:27:EB": {Vendor: "Raspberry Pi", Company: "Raspberry Pi Foundation", DeviceType: DeviceTypeIoT},
		"DC:A6:32": {Vendor: "Raspberry Pi", Company: "Raspberry Pi Foundation", DeviceType: DeviceTypeIoT},
		"E4:5F:01": {Vendor: "Raspberry Pi", Company: "Raspberry Pi Foundation", DeviceType: DeviceTypeIoT},

		// D-Link
		"00:0F:3D": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:13:46": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:15:E9": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:17:9A": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:18:E7": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:19:5B": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:1B:11": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:1C:F0": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:1E:58": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:21:91": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},
		"00:22:B0": {Vendor: "D-Link", Company: "D-Link Corporation", DeviceType: DeviceTypeSwitch},

		// Brocade (now part of Broadcom)
		"00:04:80": {Vendor: "Brocade", Company: "Brocade Communications", DeviceType: DeviceTypeSwitch},
		"00:05:1E": {Vendor: "Brocade", Company: "Brocade Communications", DeviceType: DeviceTypeSwitch},
		"00:05:33": {Vendor: "Brocade", Company: "Brocade Communications", DeviceType: DeviceTypeSwitch},
		"00:60:69": {Vendor: "Brocade", Company: "Brocade Communications", DeviceType: DeviceTypeSwitch},

		// 3Com (legacy)
		"00:0A:04": {Vendor: "3Com", Company: "3Com Corporation", DeviceType: DeviceTypeSwitch},
		"00:10:4B": {Vendor: "3Com", Company: "3Com Corporation", DeviceType: DeviceTypeSwitch},
		"00:50:04": {Vendor: "3Com", Company: "3Com Corporation", DeviceType: DeviceTypeSwitch},

		// Special multicast/broadcast addresses
		"01:00:5E": {Vendor: "Multicast", Company: "IPv4 Multicast", DeviceType: DeviceTypeUnknown},
		"33:33:00": {Vendor: "Multicast", Company: "IPv6 Multicast", DeviceType: DeviceTypeUnknown},
		"01:80:C2": {Vendor: "STP/802.1D", Company: "IEEE 802.1D Bridge", DeviceType: DeviceTypeUnknown},
		"01:00:0C": {Vendor: "CDP/PVST", Company: "Cisco Discovery Protocol", DeviceType: DeviceTypeUnknown},
	}

	// Normalize OUI format for lookup
	normalizedOUI := strings.ReplaceAll(oui, "-", ":")
	normalizedOUI = strings.ToUpper(normalizedOUI)

	if info, found := vendors[normalizedOUI]; found {
		return info
	}

	return VendorInfo{}
}

// lookupOnline tries to get vendor information from online API
func (s *LookupService) lookupOnline(oui string) VendorInfo {
	// API URL for MacAddress.io - requires API key to use
	// We'll use a fallback for now - for production you would set an API key
	url := fmt.Sprintf("https://api.macvendors.com/%s", strings.ReplaceAll(oui, ":", "-"))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return VendorInfo{Vendor: "Unknown", DeviceType: DeviceTypeUnknown}
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return VendorInfo{Vendor: "Unknown", DeviceType: DeviceTypeUnknown}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return VendorInfo{Vendor: "Unknown", DeviceType: DeviceTypeUnknown}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return VendorInfo{Vendor: "Unknown", DeviceType: DeviceTypeUnknown}
	}

	// The API returns just the vendor name as plain text
	vendorName := strings.TrimSpace(string(body))
	if vendorName != "" {
		return VendorInfo{
			Vendor:     vendorName,
			Company:    vendorName,
			DeviceType: DeviceTypeUnknown,
		}
	}

	return VendorInfo{Vendor: "Unknown", DeviceType: DeviceTypeUnknown}
}

// GetVendorName returns a simple vendor name for a MAC address
func (s *LookupService) GetVendorName(macAddress net.HardwareAddr) string {
	info := s.Lookup(macAddress)
	if info.Vendor == "" || info.Vendor == "Unknown" {
		return "Unknown"
	}
	return info.Vendor
}

// GetDeviceType returns the likely device type for a MAC address
func (s *LookupService) GetDeviceType(macAddress net.HardwareAddr) DeviceType {
	info := s.Lookup(macAddress)
	return info.DeviceType
}

// IsNetworkEquipment returns true if the MAC belongs to known network equipment
func (s *LookupService) IsNetworkEquipment(macAddress net.HardwareAddr) bool {
	info := s.Lookup(macAddress)
	switch info.DeviceType {
	case DeviceTypeSwitch, DeviceTypeRouter, DeviceTypeAccessPoint, DeviceTypeFirewall:
		return true
	default:
		return false
	}
}
