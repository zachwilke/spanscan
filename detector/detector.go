package detector

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spanscan/config"
	"github.com/spanscan/logging"
	"github.com/spanscan/macvendor"
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

// LoopOriginAnalysis provides detailed loop origin information
type LoopOriginAnalysis struct {
	SuspectedOrigin  *LoopInfo
	ConfidenceScore  float64
	Evidence         []string
	RelatedDevices   []net.HardwareAddr
	SuggestedActions []string
}

// Detector handles the network monitoring and loop detection
type Detector struct {
	devices        []pcap.Interface
	handles        map[string]*pcap.Handle
	loopDetections map[string]*LoopInfo
	packetCounters map[string]map[string]int
	seenDevices    map[string]*DeviceInfo

	// New tracking maps
	macInterfaceTimes map[string]map[string]time.Time // MAC -> Interface -> Time
	broadcastCounters map[string]int                  // Interface -> broadcast packet count
	broadcastStorms   map[string]*BroadcastStormInfo
	duplicateMACs     map[string]*DuplicateMACEvent

	// Baseline tracking for rate-of-change detection
	baselineRates map[string]float64 // Interface -> baseline packets/second

	// Components
	config       *config.Config
	stpParser    *stp.Parser
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
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("error finding network devices: %v", err)
	}

	if len(devices) == 0 {
		return nil, fmt.Errorf("no suitable devices found")
	}

	// Initialize logger
	var logger *logging.Logger
	if cfg.LogFile != "" {
		logger, err = logging.NewLogger(cfg.LogFile, cfg.JSONOutput)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize logger: %v", err)
		}
	} else {
		logger, _ = logging.NewLogger("", false)
	}

	return &Detector{
		devices:           devices,
		handles:           make(map[string]*pcap.Handle),
		loopDetections:    make(map[string]*LoopInfo),
		packetCounters:    make(map[string]map[string]int),
		seenDevices:       make(map[string]*DeviceInfo),
		macInterfaceTimes: make(map[string]map[string]time.Time),
		broadcastCounters: make(map[string]int),
		broadcastStorms:   make(map[string]*BroadcastStormInfo),
		duplicateMACs:     make(map[string]*DuplicateMACEvent),
		baselineRates:     make(map[string]float64),
		config:            cfg,
		stpParser:         stp.NewParser(),
		vendorLookup:      macvendor.NewLookupService(),
		logger:            logger,
		stopChan:          make(chan struct{}),
	}, nil
}

// GetConfig returns the current configuration
func (d *Detector) GetConfig() *config.Config {
	return d.config
}

// GetDevices returns the list of network interfaces being monitored
func (d *Detector) GetDevices() []pcap.Interface {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.devices
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

	// Open handles for each interface
	for _, device := range d.devices {
		if err := d.monitorInterface(device); err != nil {
			// Log but continue - some interfaces may not be accessible
			fmt.Printf("Warning: Could not monitor %s: %v\n", device.Name, err)
		}
	}

	// Start the periodic analysis
	go d.periodicAnalysis()

	<-d.stopChan
	return nil
}

// Stop terminates all monitoring
func (d *Detector) Stop() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if !d.isRunning {
		return
	}

	// Log session end
	d.logger.LogSessionEnd(logging.SessionSummary{
		Duration:         time.Since(d.startTime),
		DevicesDetected:  len(d.seenDevices),
		LoopsDetected:    len(d.loopDetections),
		BroadcastStorms:  len(d.broadcastStorms),
		DuplicateMACs:    len(d.duplicateMACs),
		TopologyChanges:  d.stpParser.GetTCNCount(),
		PacketsProcessed: d.totalPackets,
	})

	// Close all pcap handles
	for _, handle := range d.handles {
		handle.Close()
	}
	d.handles = make(map[string]*pcap.Handle)

	// Signal to stop
	close(d.stopChan)
	d.isRunning = false
}

// monitorInterface sets up packet capture for a specific interface
func (d *Detector) monitorInterface(device pcap.Interface) error {
	// Skip loopback interfaces
	if device.Name == "lo" || device.Name == "\\Device\\NPF_Loopback" {
		return nil
	}

	// Open the device for capturing
	handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening device %s: %v", device.Name, err)
	}

	// Set BPF filter if configured
	if d.config.BPFFilter != "" {
		if err := handle.SetBPFFilter(d.config.BPFFilter); err != nil {
			handle.Close()
			return fmt.Errorf("error setting BPF filter on %s: %v", device.Name, err)
		}
	}

	d.handles[device.Name] = handle
	d.packetCounters[device.Name] = make(map[string]int)
	d.broadcastCounters[device.Name] = 0

	// Start packet processing
	go d.processPackets(device.Name, handle)

	return nil
}

// processPackets handles the packet processing for a specific interface
func (d *Detector) processPackets(deviceName string, handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-d.stopChan:
			return
		case packet := <-packetSource.Packets():
			d.analyzePacket(deviceName, packet)
		}
	}
}

// analyzePacket examines each packet for signs of network loops
func (d *Detector) analyzePacket(deviceName string, packet gopacket.Packet) {
	// Extract MAC address from Ethernet layer
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}

	ethernet, _ := ethernetLayer.(*layers.Ethernet)
	srcMAC := ethernet.SrcMAC.String()
	dstMAC := ethernet.DstMAC.String()
	now := time.Now()

	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.totalPackets++

	// Track broadcast packets
	if dstMAC == "ff:ff:ff:ff:ff:ff" {
		d.broadcastCounters[deviceName]++
	}

	// Track this device
	if _, exists := d.seenDevices[srcMAC]; !exists {
		d.seenDevices[srcMAC] = &DeviceInfo{
			MACAddress:  ethernet.SrcMAC,
			FirstSeen:   now,
			LastSeen:    now,
			PacketCount: 0,
			Interfaces:  make(map[string]bool),
			VendorName:  d.vendorLookup.GetVendorName(ethernet.SrcMAC),
		}
		d.logger.Log(logging.EventDeviceDiscovered, logging.SeverityInfo,
			fmt.Sprintf("New device: %s (%s)", srcMAC, d.seenDevices[srcMAC].VendorName), nil)
	}

	// Update device info
	d.seenDevices[srcMAC].LastSeen = now
	d.seenDevices[srcMAC].PacketCount++

	// Track which interface this MAC was seen on
	prevIfaceCount := len(d.seenDevices[srcMAC].Interfaces)
	d.seenDevices[srcMAC].Interfaces[deviceName] = true
	newIfaceCount := len(d.seenDevices[srcMAC].Interfaces)

	// Track MAC-interface timing for duplicate detection
	if _, exists := d.macInterfaceTimes[srcMAC]; !exists {
		d.macInterfaceTimes[srcMAC] = make(map[string]time.Time)
	}
	d.macInterfaceTimes[srcMAC][deviceName] = now

	// Check for duplicate MAC on multiple interfaces (strong loop indicator)
	if newIfaceCount > prevIfaceCount && newIfaceCount >= 2 {
		d.checkDuplicateMAC(srcMAC, ethernet.SrcMAC)
	}

	// Update packet counter for loop detection
	d.packetCounters[deviceName][srcMAC]++

	// Try to parse as STP/BPDU packet
	bpdu, err := d.stpParser.ParsePacket(packet, deviceName)
	if err == nil && bpdu != nil {
		// Successfully parsed STP packet
		if bpdu.IsTopologyChange {
			d.logger.LogTopologyChange(bpdu.SenderBridgeID.String(), deviceName)
		}
	}
}

// checkDuplicateMAC detects when same MAC appears on multiple interfaces
func (d *Detector) checkDuplicateMAC(macStr string, mac net.HardwareAddr) {
	ifaceTimes := d.macInterfaceTimes[macStr]

	// Find the time window
	var earliest, latest time.Time
	interfaces := make([]string, 0)

	for iface, t := range ifaceTimes {
		interfaces = append(interfaces, iface)
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
		if latest.IsZero() || t.After(latest) {
			latest = t
		}
	}

	timeWindow := latest.Sub(earliest)

	// If MAC appeared on multiple interfaces within the duplicate window, it's suspicious
	if len(interfaces) >= 2 && timeWindow <= d.config.DuplicateMACWindow {
		vendorName := d.vendorLookup.GetVendorName(mac)

		if _, exists := d.duplicateMACs[macStr]; !exists {
			d.duplicateMACs[macStr] = &DuplicateMACEvent{
				MACAddress: mac,
				VendorName: vendorName,
				Interfaces: interfaces,
				FirstSeen:  earliest,
				LastSeen:   latest,
				TimeWindow: timeWindow,
			}

			d.logger.LogDuplicateMAC(macStr, vendorName, interfaces, timeWindow)

			// This is a high-confidence loop indicator
			fmt.Printf("\n⚠️  [DUPLICATE MAC] %s (%s) seen on %d interfaces within %v\n",
				macStr, vendorName, len(interfaces), timeWindow)
		} else {
			// Update existing
			d.duplicateMACs[macStr].Interfaces = interfaces
			d.duplicateMACs[macStr].LastSeen = latest
		}
	}
}

// periodicAnalysis runs regular checks to identify loops
func (d *Detector) periodicAnalysis() {
	ticker := time.NewTicker(d.config.SamplingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopChan:
			return
		case <-ticker.C:
			d.detectLoops()
			d.detectBroadcastStorms()
			d.checkSTPIssues()
		}
	}
}

// detectLoops analyzes current packet statistics to identify loops
func (d *Detector) detectLoops() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Clear previous loop detections that haven't been seen recently
	for macAddr, info := range d.loopDetections {
		if time.Since(info.DetectedTime) > d.config.SamplingPeriod*3 {
			delete(d.loopDetections, macAddr)
			// Also clear loop source flag on device
			if device, exists := d.seenDevices[macAddr]; exists {
				device.IsLoopSource = false
			}
		}
	}

	// Check for unusually high packet counts that indicate loops
	for deviceName, counters := range d.packetCounters {
		for macAddr, count := range counters {
			if count > d.config.PacketCountThreshold {
				mac, _ := net.ParseMAC(macAddr)
				vendorName := d.vendorLookup.GetVendorName(mac)

				// Calculate severity and confidence
				severity, confidence, evidence := d.calculateLoopSeverity(macAddr, deviceName, count)

				// Record or update loop information
				if _, exists := d.loopDetections[macAddr]; !exists {
					d.loopDetections[macAddr] = &LoopInfo{
						MACAddress:      mac,
						DeviceName:      deviceName,
						DetectedTime:    time.Now(),
						PacketCount:     count,
						VendorName:      vendorName,
						Severity:        severity,
						ConfidenceScore: confidence,
						Evidence:        evidence,
						SuggestedAction: d.getSuggestedAction(severity, vendorName),
					}

					// Mark device as loop source
					if device, exists := d.seenDevices[macAddr]; exists {
						device.IsLoopSource = true
					}

					// Log and report
					d.logger.LogLoop(logging.Severity(severity), macAddr, vendorName, deviceName, count, confidence, evidence)

					// Report the loop
					fmt.Printf("\n🔴 [LOOP DETECTED - %s] MAC: %s (%s), Interface: %s, Count: %d\n",
						severity.String(), macAddr, vendorName, deviceName, count)
					fmt.Printf("   Confidence: %.0f%% | Evidence: %v\n", confidence*100, evidence)
				} else {
					// Update existing detection
					d.loopDetections[macAddr].PacketCount = count
					d.loopDetections[macAddr].DetectedTime = time.Now()
					d.loopDetections[macAddr].Severity = severity
					d.loopDetections[macAddr].ConfidenceScore = confidence
				}
			}
		}

		// Reset counters for the next period
		d.packetCounters[deviceName] = make(map[string]int)
	}
}

// calculateLoopSeverity determines severity and confidence based on multiple factors
func (d *Detector) calculateLoopSeverity(macAddr, deviceName string, packetCount int) (LoopSeverity, float64, []string) {
	var severity LoopSeverity
	var confidence float64
	evidence := make([]string, 0)

	// Base confidence from packet count
	ratio := float64(packetCount) / float64(d.config.PacketCountThreshold)
	confidence = min(ratio/10.0, 0.5) // Up to 50% from packet count
	evidence = append(evidence, fmt.Sprintf("High packet rate: %d packets", packetCount))

	// Check for duplicate MAC (adds significant confidence)
	if dupEvent, exists := d.duplicateMACs[macAddr]; exists {
		confidence += 0.3
		evidence = append(evidence, fmt.Sprintf("MAC on %d interfaces", len(dupEvent.Interfaces)))
		severity = SeverityHigh
	}

	// Check for broadcast storm on this interface
	if storm, exists := d.broadcastStorms[deviceName]; exists && storm.IsActive {
		confidence += 0.2
		evidence = append(evidence, "Broadcast storm active")
		severity = SeverityCritical
	}

	// Check STP issues
	if d.stpParser.HasMultipleRoots() {
		confidence += 0.1
		evidence = append(evidence, "Multiple STP roots detected")
		if severity < SeverityMedium {
			severity = SeverityMedium
		}
	}

	// Determine severity based on confidence if not already set
	if severity == 0 {
		switch {
		case confidence >= 0.8:
			severity = SeverityHigh
		case confidence >= 0.5:
			severity = SeverityMedium
		default:
			severity = SeverityLow
		}
	}

	confidence = min(confidence, 1.0)

	return severity, confidence, evidence
}

// getSuggestedAction returns remediation advice based on severity and vendor
func (d *Detector) getSuggestedAction(severity LoopSeverity, vendorName string) string {
	switch severity {
	case SeverityCritical:
		return "URGENT: Disconnect the device immediately to stop the broadcast storm"
	case SeverityHigh:
		return "Trace the cable from this device and check for accidental port looping"
	case SeverityMedium:
		if vendorName == "Cisco" || vendorName == "HP/Aruba" || vendorName == "Juniper" {
			return "Check STP configuration on this switch - may need portfast or bpduguard"
		}
		return "Investigate device and check for misconfigured spanning tree"
	default:
		return "Monitor device for continued activity"
	}
}

// detectBroadcastStorms checks for broadcast storm conditions
func (d *Detector) detectBroadcastStorms() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	samplingSeconds := d.config.SamplingPeriod.Seconds()

	for deviceName, count := range d.broadcastCounters {
		pps := int(float64(count) / samplingSeconds)

		if pps > d.config.BroadcastStormThreshold {
			if _, exists := d.broadcastStorms[deviceName]; !exists {
				d.broadcastStorms[deviceName] = &BroadcastStormInfo{
					InterfaceName:    deviceName,
					PacketsPerSecond: pps,
					DetectedTime:     time.Now(),
					IsActive:         true,
				}
				d.logger.LogBroadcastStorm(deviceName, pps, d.config.BroadcastStormThreshold)
				fmt.Printf("\n🔥 [BROADCAST STORM] Interface: %s, Rate: %d pps (threshold: %d)\n",
					deviceName, pps, d.config.BroadcastStormThreshold)
			} else {
				d.broadcastStorms[deviceName].PacketsPerSecond = pps
				d.broadcastStorms[deviceName].IsActive = true
			}
		} else if storm, exists := d.broadcastStorms[deviceName]; exists && storm.IsActive {
			// Storm has subsided
			storm.IsActive = false
			fmt.Printf("\n✅ [STORM CLEARED] Interface: %s\n", deviceName)
		}

		// Reset counter
		d.broadcastCounters[deviceName] = 0
	}
}

// checkSTPIssues analyzes STP data for problems
func (d *Detector) checkSTPIssues() {
	if d.stpParser.HasMultipleRoots() {
		roots := d.stpParser.GetRootBridges()
		d.logger.Log(logging.EventMultipleRoots, logging.SeverityHigh,
			fmt.Sprintf("Multiple root bridges detected: %d", len(roots)), nil)
	}

	// Check BPDU rate
	bpduRate := d.stpParser.GetBPDURate(d.config.SamplingPeriod)
	if bpduRate > 50 {
		fmt.Printf("\n⚠️  [STP WARNING] High BPDU rate: %.1f/sec (normal is ~0.5/sec)\n", bpduRate)
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

	// Sort by severity (highest first)
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

// GetLoopOriginAnalysis provides detailed analysis of suspected loop origin
func (d *Detector) GetLoopOriginAnalysis() *LoopOriginAnalysis {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if len(d.loopDetections) == 0 {
		return nil
	}

	// Find the most likely loop origin
	var mostLikely *LoopInfo
	var highestConfidence float64

	for _, loop := range d.loopDetections {
		if loop.ConfidenceScore > highestConfidence {
			highestConfidence = loop.ConfidenceScore
			mostLikely = loop
		}
	}

	if mostLikely == nil {
		return nil
	}

	// Gather related devices (same interface)
	relatedDevices := make([]net.HardwareAddr, 0)
	for _, device := range d.seenDevices {
		if device.Interfaces[mostLikely.DeviceName] {
			relatedDevices = append(relatedDevices, device.MACAddress)
		}
	}

	// Build suggested actions
	actions := []string{
		mostLikely.SuggestedAction,
		fmt.Sprintf("Check physical connections on interface %s", mostLikely.DeviceName),
	}

	if mostLikely.VendorName != "Unknown" {
		actions = append(actions, fmt.Sprintf("Device is a %s - consult vendor documentation", mostLikely.VendorName))
	}

	return &LoopOriginAnalysis{
		SuspectedOrigin:  mostLikely,
		ConfidenceScore:  highestConfidence,
		Evidence:         mostLikely.Evidence,
		RelatedDevices:   relatedDevices,
		SuggestedActions: actions,
	}
}

// GetStats returns current monitoring statistics
func (d *Detector) GetStats() map[string]interface{} {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return map[string]interface{}{
		"totalPackets":    d.totalPackets,
		"devicesDetected": len(d.seenDevices),
		"loopsDetected":   len(d.loopDetections),
		"broadcastStorms": len(d.broadcastStorms),
		"duplicateMACs":   len(d.duplicateMACs),
		"tcnCount":        d.stpParser.GetTCNCount(),
		"rootBridges":     len(d.stpParser.GetRootBridges()),
		"uptime":          time.Since(d.startTime),
	}
}

// helper
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
