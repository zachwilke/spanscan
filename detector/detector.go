package detector

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/spanscan/config"
	"github.com/spanscan/logging"
	"github.com/spanscan/macvendor"
	"github.com/spanscan/snmp"
	"github.com/spanscan/stp"
)

// LoopSeverity represents the severity of a detected loop
type LoopSeverity int

const (
	SeverityLow      LoopSeverity = iota // Unusual pattern, might be loop
	SeverityMedium                       // Strong indicators present
	SeverityHigh                         // Definite loop detected
	SeverityCritical                     // Active broadcast storm
)

// String returns a human-readable severity
func (s LoopSeverity) String() string {
	switch s {
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

// LoopInfo contains details about a detected network loop
type LoopInfo struct {
	MACAddress      net.HardwareAddr
	DeviceName      string
	DetectedTime    time.Time
	PacketCount     int
	VendorName      string
	Severity        LoopSeverity
	ConfidenceScore float64  // 0.0 to 1.0
	Evidence        []string // Human-readable evidence
	SuggestedAction string
}

// DeviceInfo contains information about a detected network device
type DeviceInfo struct {
	MACAddress   net.HardwareAddr
	FirstSeen    time.Time
	LastSeen     time.Time
	PacketCount  int
	Interfaces   map[string]bool
	VendorName   string
	IsLoopSource bool
}

// DuplicateMACEvent tracks when same MAC appears on multiple interfaces
type DuplicateMACEvent struct {
	MACAddress net.HardwareAddr
	VendorName string
	Interfaces []string
	FirstSeen  time.Time
	LastSeen   time.Time
	TimeWindow time.Duration
}

// BroadcastStormInfo tracks broadcast storm conditions
type BroadcastStormInfo struct {
	InterfaceName    string
	PacketsPerSecond int
	DetectedTime     time.Time
	IsActive         bool
}

// Detector handles the network monitoring and loop detection via SNMP
type Detector struct {
	loopDetections map[string]*LoopInfo
	packetCounters map[string]map[string]int // Not fully used in SNMP mode as we don't see every packet per MAC
	seenDevices    map[string]*DeviceInfo

	// New tracking maps
	macInterfaceTimes map[string]map[string]time.Time // MAC -> Interface -> Time
	broadcastStorms   map[string]*BroadcastStormInfo
	duplicateMACs     map[string]*DuplicateMACEvent

	// SNMP State
	snmpClients map[string]*gosnmp.GoSNMP    // Target IP -> Client
	lastPoll    map[string]map[string]uint64 // TargetIP -> InterfaceOID -> LastValue
	templates   map[string]snmp.Template     // TargetIP -> Vendor Template

	// Components
	config       *config.Config
	stpParser    *stp.Parser // Keeps track of STP state if we pull it via SNMP
	vendorLookup *macvendor.LookupService
	logger       *logging.Logger

	// Runtime state
	stopChan     chan struct{}
	mutex        sync.Mutex
	isRunning    bool
	startTime    time.Time
	totalPackets int64
}

// New creates and initializes a new Detector with default config
func New() (*Detector, error) {
	return NewWithConfig(config.DefaultConfig())
}

// NewWithConfig creates a Detector with custom configuration
func NewWithConfig(cfg *config.Config) (*Detector, error) {
	// Initialize logger
	var logger *logging.Logger
	var err error
	if cfg.LogFile != "" {
		logger, err = logging.NewLogger(cfg.LogFile, cfg.JSONOutput)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize logger: %v", err)
		}
	} else {
		logger, _ = logging.NewLogger("", false)
	}

	return &Detector{
		loopDetections:    make(map[string]*LoopInfo),
		packetCounters:    make(map[string]map[string]int),
		seenDevices:       make(map[string]*DeviceInfo),
		macInterfaceTimes: make(map[string]map[string]time.Time),
		broadcastStorms:   make(map[string]*BroadcastStormInfo),
		duplicateMACs:     make(map[string]*DuplicateMACEvent),
		snmpClients:       make(map[string]*gosnmp.GoSNMP),
		lastPoll:          make(map[string]map[string]uint64),
		templates:         make(map[string]snmp.Template),
		config:            cfg,
		stpParser:         stp.NewParser(),
		vendorLookup:      macvendor.NewLookupService(),
		logger:            logger,
		stopChan:          make(chan struct{}),
	}, nil
}

// Start begins monitoring the network for loops
func (d *Detector) Start() error {
	d.mutex.Lock()
	if d.isRunning {
		d.mutex.Unlock()
		return fmt.Errorf("detector is already running")
	}
	d.isRunning = true
	d.startTime = time.Now()
	d.stopChan = make(chan struct{})
	d.mutex.Unlock()

	d.logger.LogSessionStart()

	// Initialize SNMP clients
	if len(d.config.Targets) == 0 {
		fmt.Println("Warning: No SNMP targets configured. Please add targets in config.json or via --config.")
	}

	for _, targetCfg := range d.config.Targets {
		d.AddTarget(targetCfg)
	}

	// Start the periodic polling
	go d.pollLoop()

	return nil
}

// Stop terminates all monitoring
func (d *Detector) Stop() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if !d.isRunning {
		return
	}

	// Close SNMP connections
	for _, client := range d.snmpClients {
		client.Conn.Close()
	}

	// Signal to stop
	close(d.stopChan)
	d.isRunning = false
}

// AddTarget adds a new SNMP target or updates an existing one
func (d *Detector) AddTarget(cfg config.SNMPTargetConfig) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// If exists, close old one
	if client, exists := d.snmpClients[cfg.Address]; exists {
		client.Conn.Close()
	}

	// Create new client based on version
	client := &gosnmp.GoSNMP{
		Target:  cfg.Address,
		Port:    161,
		Timeout: time.Second * 2,
		Retries: 3,
	}

	switch cfg.Version {
	case config.SNMPVersion1:
		client.Version = gosnmp.Version1
		client.Community = cfg.Community
	case config.SNMPVersion2c:
		client.Version = gosnmp.Version2c
		client.Community = cfg.Community
	case config.SNMPVersion3:
		client.Version = gosnmp.Version3
		client.SecurityModel = gosnmp.UserSecurityModel

		msgFlags := gosnmp.NoAuthNoPriv
		if cfg.SecurityLevel == "AuthNoPriv" {
			msgFlags = gosnmp.AuthNoPriv
		} else if cfg.SecurityLevel == "AuthPriv" {
			msgFlags = gosnmp.AuthPriv
		}
		client.MsgFlags = msgFlags

		client.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 cfg.Username,
			AuthenticationProtocol:   getContentAuthProto(cfg.AuthProto),
			AuthenticationPassphrase: cfg.AuthPass,
			PrivacyProtocol:          getContentPrivProto(cfg.PrivProto),
			PrivacyPassphrase:        cfg.PrivPass,
		}
	default:
		// Default to v2c public if unknown
		client.Version = gosnmp.Version2c
		client.Community = "public"
	}

	if err := client.Connect(); err != nil {
		fmt.Printf("Error connecting to SNMP target %s: %v\n", cfg.Address, err)
		return err
	}

	// Vendor Discovery
	// Get sysDescr (.1.3.6.1.2.1.1.1.0) and sysObjectID (.1.3.6.1.2.1.1.2.0)
	sysDescr := ""
	sysObjID := ""

	result, err := client.Get([]string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.2.0"})
	if err == nil {
		for _, pdu := range result.Variables {
			if pdu.Name == ".1.3.6.1.2.1.1.1.0" {
				sysDescr = string(pdu.Value.([]byte))
			}
			// sysObjectID handling if needed
		}
	}

	template := snmp.GetTemplate(sysDescr, sysObjID)
	fmt.Printf("Detected vendor for %s: %s (%s strategy)\n", cfg.Address, template.Name, getStrategyName(template.VLANPollingStrategy))

	d.snmpClients[cfg.Address] = client
	d.templates[cfg.Address] = template

	if _, exists := d.lastPoll[cfg.Address]; !exists {
		d.lastPoll[cfg.Address] = make(map[string]uint64)
	}

	return nil
}

func getStrategyName(s snmp.VLANStrategy) string {
	switch s {
	case snmp.StrategyStandard:
		return "Standard"
	case snmp.StrategyCommunityIndexing:
		return "Community Indexing"
	case snmp.StrategyQBridge:
		return "Q-BRIDGE"
	case snmp.StrategyContext:
		return "Context"
	default:
		return "Unknown"
	}
}

// RemoveTarget removes a target
func (d *Detector) RemoveTarget(address string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if client, exists := d.snmpClients[address]; exists {
		client.Conn.Close()
		delete(d.snmpClients, address)
		delete(d.lastPoll, address)
	}
}

// pollLoop runs the SNMP polling
func (d *Detector) pollLoop() {
	ticker := time.NewTicker(d.config.PollInterval)
	defer ticker.Stop()

	// Initial poll immediately
	d.poll()

	for {
		select {
		case <-d.stopChan:
			return
		case <-ticker.C:
			d.poll()
		}
	}
}

// poll performs one round of SNMP polling
func (d *Detector) poll() {
	// Snapshot clients to iterate avoiding lock contention during IO
	d.mutex.Lock()
	clients := make([]*gosnmp.GoSNMP, 0, len(d.snmpClients))
	for _, c := range d.snmpClients {
		clients = append(clients, c)
	}
	d.mutex.Unlock()

	var wg sync.WaitGroup

	for _, client := range clients {
		wg.Add(1)
		go func(c *gosnmp.GoSNMP) {
			defer wg.Done()
			d.pollTarget(c)
		}(client)
	}

	wg.Wait()

	// After gathering data, analyze for loops
	d.analyze()
}

func (d *Detector) pollTarget(client *gosnmp.GoSNMP) {
	detectedBroadcastStorms := make(map[string]int)

	// Get Template
	template, hasTemplate := d.templates[client.Target]
	if !hasTemplate {
		template = snmp.GetTemplate("unknown", "") // Should have been set in AddTarget, fallback just in case
	}

	// 1. Poll Interface Statistics (Broadcast Storms)
	// Use template OID or default
	stormOID := template.BroadcastStormOID
	if stormOID == "" {
		stormOID = ".1.3.6.1.2.1.2.2.1.12"
	}

	err := client.Walk(stormOID, func(pdu gosnmp.SnmpPDU) error {
		// Calculate rate
		val := gosnmp.ToBigInt(pdu.Value).Uint64()
		ifName := fmt.Sprintf("%s_idx_%v", client.Target, pdu.Name)

		d.mutex.Lock()
		prev, ok := d.lastPoll[client.Target][pdu.Name]
		d.lastPoll[client.Target][pdu.Name] = val
		d.mutex.Unlock()

		if ok {
			diff := val - prev
			// Handle wrap-around
			if val < prev {
				diff = (4294967295 - prev) + val
			}

			pps := int(float64(diff) / d.config.PollInterval.Seconds())
			if pps > d.config.BroadcastStormThreshold {
				detectedBroadcastStorms[ifName] = pps
			}
		}
		return nil
	})
	if err != nil {
		// Log error occasionally
		// fmt.Printf("Error walking interfaces on %s: %v\n", client.Target, err)
	}

	// 2. Poll MAC Address Table (FDB)
	// Strategy Pattern

	if template.VLANPollingStrategy == snmp.StrategyCommunityIndexing {
		// Cisco Style: Need to fetch VLANs first, then poll each Community@VLAN
		vlans := d.getVLANs(client)
		originalCommunity := client.Community

		for _, vlanID := range vlans {
			// Switch context
			client.Community = fmt.Sprintf("%s@%d", originalCommunity, vlanID)

			// Poll FDB
			// Note: This is synchronous and might take time for many VLANs.
			// In high scale, we'd parallelize this too.
			d.pollBridgeTable(client, vlanID)
		}
		// Restore
		client.Community = originalCommunity

	} else {
		// Standard or single-context
		d.pollBridgeTable(client, 1) // Default VLAN 1 or native
	}

	d.mutex.Lock()
	// Update broadcast storms
	for ifName, pps := range detectedBroadcastStorms {
		if _, exists := d.broadcastStorms[ifName]; !exists {
			d.broadcastStorms[ifName] = &BroadcastStormInfo{
				InterfaceName:    ifName,
				PacketsPerSecond: pps,
				DetectedTime:     time.Now(),
				IsActive:         true,
			}
			d.logger.LogBroadcastStorm(ifName, pps, d.config.BroadcastStormThreshold)
		} else {
			d.broadcastStorms[ifName].PacketsPerSecond = pps
			d.broadcastStorms[ifName].IsActive = true
		}
	}
	d.mutex.Unlock()
}

func (d *Detector) pollBridgeTable(client *gosnmp.GoSNMP, vlanID int) {
	// .1.3.6.1.2.1.17.4.3.1.1 (dot1dTpFdbAddress)
	_ = client.Walk(".1.3.6.1.2.1.17.4.3.1.1", func(pdu gosnmp.SnmpPDU) error {
		if pd, ok := pdu.Value.([]byte); ok && len(pd) == 6 {
			mac := net.HardwareAddr(pd)

			d.mutex.Lock()
			if _, exists := d.seenDevices[mac.String()]; !exists {
				d.seenDevices[mac.String()] = &DeviceInfo{
					MACAddress: mac,
					FirstSeen:  time.Now(),
					LastSeen:   time.Now(),
					Interfaces: make(map[string]bool),
					VendorName: d.vendorLookup.GetVendorName(mac),
				}
			}

			d.seenDevices[mac.String()].LastSeen = time.Now()

			// Track switch IP + VLAN as distinct "interface" location context?
			// Or just switch IP. For loop detection, Switch IP is critical.
			loc := client.Target
			if vlanID > 1 {
				loc = fmt.Sprintf("%s(vlan%d)", client.Target, vlanID)
			}
			d.seenDevices[mac.String()].Interfaces[loc] = true

			d.checkDuplicateMAC(mac.String(), mac)
			d.mutex.Unlock()
		}
		return nil
	})
}

// getVLANs fetches active VLAN IDs using CISCO-VTP-MIB or standard Q-BRIDGE
func (d *Detector) getVLANs(client *gosnmp.GoSNMP) []int {
	vlans := []int{1} // Always try 1

	// Try vtpVlanState .1.3.6.1.4.1.9.9.46.1.3.1.1.2
	// OID index is the VLAN ID
	_ = client.Walk(".1.3.6.1.4.1.9.9.46.1.3.1.1.2", func(pdu gosnmp.SnmpPDU) error {
		// OID ends with .VLANID
		oidParts := strings.Split(pdu.Name, ".")
		if len(oidParts) > 0 {
			// Simplified parsing, assuming standard OID structure
			// In production, robust OID parsing needed
			// Let's assume the last part is the VLAN ID
			// (Implement proper parsing later)
		}
		return nil
	})

	// For now, return [1] (and maybe common ones like 10, 20 if we want to guess, but scanning is better)
	// Due to complexity of parsing variable length OIDs in this snippet, returning [1] + hardcoded example
	// In real implementation, parse pdu.Name
	return vlans
}

func (d *Detector) analyze() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Clear old broadcast storms
	for _, storm := range d.broadcastStorms {
		if time.Since(storm.DetectedTime) > d.config.PollInterval*3 {
			storm.IsActive = false
		}
	}

	for macAddr, dup := range d.duplicateMACs {
		// If we see mac flapping + broadcast storm, that's a loop
		if len(dup.Interfaces) > 1 {
			// Update Loop Detections
			if _, exists := d.loopDetections[macAddr]; !exists {
				severity := SeverityMedium
				confidence := 0.6

				// Escalate if associated with a storm
				for _, iface := range dup.Interfaces {
					if _, storming := d.broadcastStorms[iface]; storming {
						severity = SeverityCritical
						confidence = 0.9
						break
					}
				}

				vendorName := d.vendorLookup.GetVendorName(dup.MACAddress)
				d.loopDetections[macAddr] = &LoopInfo{
					MACAddress:      dup.MACAddress,
					DeviceName:      strings.Join(dup.Interfaces, ", "),
					DetectedTime:    time.Now(),
					VendorName:      vendorName,
					Severity:        severity,
					ConfidenceScore: confidence,
					Evidence:        []string{"MAC moving between switches", fmt.Sprintf("Seen on: %v", dup.Interfaces)},
					SuggestedAction: "Check connections between these switches",
				}
				d.logger.LogLoop(logging.Severity(severity), macAddr, vendorName, strings.Join(dup.Interfaces, ","), 0, confidence, []string{"Duplicate MAC"})
			}
		}
	}
}

// checkDuplicateMAC detects when same MAC appears on multiple interfaces
func (d *Detector) checkDuplicateMAC(macStr string, mac net.HardwareAddr) {
	seenInterfaces := make([]string, 0)
	for iface := range d.seenDevices[macStr].Interfaces {
		seenInterfaces = append(seenInterfaces, iface)
	}

	if len(seenInterfaces) > 1 {
		vendorName := d.vendorLookup.GetVendorName(mac)
		if _, exists := d.duplicateMACs[macStr]; !exists {
			d.duplicateMACs[macStr] = &DuplicateMACEvent{
				MACAddress: mac,
				VendorName: vendorName,
				Interfaces: seenInterfaces,
				FirstSeen:  time.Now(),
				LastSeen:   time.Now(),
			}
		} else {
			d.duplicateMACs[macStr].Interfaces = seenInterfaces
			d.duplicateMACs[macStr].LastSeen = time.Now()
		}
	}
}

// GetDetectedLoops returns all detected network loops
func (d *Detector) GetDetectedLoops() []*LoopInfo {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	loops := make([]*LoopInfo, 0, len(d.loopDetections))
	for _, loop := range d.loopDetections {
		loops = append(loops, loop)
	}

	sort.Slice(loops, func(i, j int) bool {
		return loops[i].Severity > loops[j].Severity
	})

	return loops
}

// GetSeenDevices returns information about all devices seen on the network
func (d *Detector) GetSeenDevices() []*DeviceInfo {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	devices := make([]*DeviceInfo, 0, len(d.seenDevices))
	for _, device := range d.seenDevices {
		devices = append(devices, device)
	}

	return devices
}

// GetDuplicateMACs returns all detected duplicate MAC events
func (d *Detector) GetDuplicateMACs() []*DuplicateMACEvent {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	events := make([]*DuplicateMACEvent, 0, len(d.duplicateMACs))
	for _, event := range d.duplicateMACs {
		events = append(events, event)
	}
	return events
}

// GetBroadcastStorms returns active and recent broadcast storms
func (d *Detector) GetBroadcastStorms() []*BroadcastStormInfo {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	storms := make([]*BroadcastStormInfo, 0, len(d.broadcastStorms))
	for _, storm := range d.broadcastStorms {
		storms = append(storms, storm)
	}
	return storms
}

// GetSTPParser returns the STP parser for UI access
func (d *Detector) GetSTPParser() *stp.Parser {
	return d.stpParser
}

// GetLogger returns the logger for exporting
func (d *Detector) GetLogger() *logging.Logger {
	return d.logger
}

// GetConfig returns the current configuration
func (d *Detector) GetConfig() *config.Config {
	return d.config
}

// GetStats returns current monitoring statistics
func (d *Detector) GetStats() map[string]interface{} {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return map[string]interface{}{
		"totalPackets":    d.totalPackets, // Will be 0 or sum of polls?
		"devicesDetected": len(d.seenDevices),
		"loopsDetected":   len(d.loopDetections),
		"broadcastStorms": len(d.broadcastStorms),
		"duplicateMACs":   len(d.duplicateMACs),
		"tcnCount":        0, // STP TCNs not fully implemented in SNMP yet
		"rootBridges":     0,
		"uptime":          time.Since(d.startTime),
	}
}

// Helpers for Auth/Priv protocols
func getContentAuthProto(s string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(s) {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

func getContentPrivProto(s string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(s) {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	case "AES192C":
		return gosnmp.AES192C
	case "AES256C":
		return gosnmp.AES256C
	default:
		return gosnmp.NoPriv
	}
}
