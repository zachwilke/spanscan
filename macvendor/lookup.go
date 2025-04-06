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

// VendorInfo contains information about a MAC address vendor
type VendorInfo struct {
	Vendor      string
	Company     string
	Address     string
	CountryCode string
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
		return VendorInfo{Vendor: "Unknown"}
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
	// Common networking equipment vendors
	vendors := map[string]VendorInfo{
		"00:00:0C": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:01:42": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:03:6B": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:04:9A": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:0E:38": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:0E:D6": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:0F:23": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:0F:34": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:11:BB": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:11:92": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:12:7F": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:12:17": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:13:10": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:13:7F": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:13:C4": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:14:69": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:14:A8": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:14:F1": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},
		"00:14:F2": {Vendor: "Cisco", Company: "Cisco Systems, Inc."},

		"00:1A:A1": {Vendor: "Juniper", Company: "Juniper Networks"},
		"00:10:DB": {Vendor: "Juniper", Company: "Juniper Networks"},
		"00:12:1E": {Vendor: "Juniper", Company: "Juniper Networks"},
		"00:14:F6": {Vendor: "Juniper", Company: "Juniper Networks"},
		"00:17:CB": {Vendor: "Juniper", Company: "Juniper Networks"},
		"00:19:E2": {Vendor: "Juniper", Company: "Juniper Networks"},

		"00:0C:29": {Vendor: "VMware", Company: "VMware, Inc."},
		"00:50:56": {Vendor: "VMware", Company: "VMware, Inc."},
		"00:05:69": {Vendor: "VMware", Company: "VMware, Inc."},

		"00:1B:21": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks"},
		"00:0F:61": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks"},
		"00:0B:86": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks"},
		"00:1A:1E": {Vendor: "HP/Aruba", Company: "HP/Aruba Networks"},

		"00:25:9C": {Vendor: "Cisco-Meraki", Company: "Cisco Meraki"},
		"00:18:0A": {Vendor: "Cisco-Meraki", Company: "Cisco Meraki"},

		"00:1E:C9": {Vendor: "Dell", Company: "Dell Inc."},
		"00:14:22": {Vendor: "Dell", Company: "Dell Inc."},
		"00:12:3F": {Vendor: "Dell", Company: "Dell Inc."},

		"00:14:6C": {Vendor: "Netgear", Company: "Netgear Inc."},
		"00:0F:B5": {Vendor: "Netgear", Company: "Netgear Inc."},

		"00:1B:63": {Vendor: "Apple", Company: "Apple Inc."},
		"00:1F:F3": {Vendor: "Apple", Company: "Apple Inc."},
		"00:25:00": {Vendor: "Apple", Company: "Apple Inc."},
		"00:26:BB": {Vendor: "Apple", Company: "Apple Inc."},

		"00:18:DE": {Vendor: "Intel", Company: "Intel Corporate"},
		"00:1F:3B": {Vendor: "Intel", Company: "Intel Corporate"},

		"00:0D:B3": {Vendor: "SDN", Company: "Software Defined Network"},
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
		return VendorInfo{Vendor: "Unknown"}
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return VendorInfo{Vendor: "Unknown"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return VendorInfo{Vendor: "Unknown"}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return VendorInfo{Vendor: "Unknown"}
	}

	// The API returns just the vendor name as plain text
	vendorName := strings.TrimSpace(string(body))
	if vendorName != "" {
		return VendorInfo{
			Vendor:  vendorName,
			Company: vendorName,
		}
	}

	return VendorInfo{Vendor: "Unknown"}
}

// GetVendorName returns a simple vendor name for a MAC address
func (s *LookupService) GetVendorName(macAddress net.HardwareAddr) string {
	info := s.Lookup(macAddress)
	if info.Vendor == "" || info.Vendor == "Unknown" {
		return "Unknown"
	}
	return info.Vendor
}
