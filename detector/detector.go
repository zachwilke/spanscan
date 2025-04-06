package detector

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spanscan/macvendor"
)

// LoopInfo contains details about a detected network loop
type LoopInfo struct {
	MACAddress   net.HardwareAddr
	DeviceName   string
	DetectedTime time.Time
	PacketCount  int
	VendorName   string
}

// DeviceInfo contains information about a detected network device
type DeviceInfo struct {
	MACAddress  net.HardwareAddr
	FirstSeen   time.Time
	LastSeen    time.Time
	PacketCount int
	Interfaces  map[string]bool
	VendorName  string
}

// Detector handles the network monitoring and loop detection
type Detector struct {
	devices        []pcap.Interface
	handles        map[string]*pcap.Handle
	loopDetections map[string]*LoopInfo
	packetCounters map[string]map[string]int
	seenDevices    map[string]*DeviceInfo
	bpfFilter      string
	samplingPeriod time.Duration
	loopThreshold  int
	stopChan       chan struct{}
	mutex          sync.Mutex
	isRunning      bool
	vendorLookup   *macvendor.LookupService
}

// New creates and initializes a new Detector
func New() (*Detector, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("error finding network devices: %v", err)
	}

	return &Detector{
		devices:        devices,
		handles:        make(map[string]*pcap.Handle),
		loopDetections: make(map[string]*LoopInfo),
		packetCounters: make(map[string]map[string]int),
		seenDevices:    make(map[string]*DeviceInfo),
		bpfFilter:      "ether proto 0x8809 or ether dst 01:80:c2:00:00:00", // STP and BPDU packets
		samplingPeriod: 10 * time.Second,
		loopThreshold:  100, // Threshold for detecting loops
		stopChan:       make(chan struct{}),
		vendorLookup:   macvendor.NewLookupService(),
	}, nil
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
	d.mutex.Unlock()

	// Open handles for each interface
	for _, device := range d.devices {
		if err := d.monitorInterface(device); err != nil {
			d.Stop()
			return err
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

	// Set BPF filter for STP packets
	if err := handle.SetBPFFilter(d.bpfFilter); err != nil {
		handle.Close()
		return fmt.Errorf("error setting BPF filter on %s: %v", device.Name, err)
	}

	d.handles[device.Name] = handle
	d.packetCounters[device.Name] = make(map[string]int)

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

	// Update packet counter for this MAC on this interface
	d.mutex.Lock()

	// Track this device
	if _, exists := d.seenDevices[srcMAC]; !exists {
		d.seenDevices[srcMAC] = &DeviceInfo{
			MACAddress:  ethernet.SrcMAC,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			PacketCount: 0,
			Interfaces:  make(map[string]bool),
			VendorName:  d.vendorLookup.GetVendorName(ethernet.SrcMAC),
		}
	}

	// Update device info
	d.seenDevices[srcMAC].LastSeen = time.Now()
	d.seenDevices[srcMAC].PacketCount++
	d.seenDevices[srcMAC].Interfaces[deviceName] = true

	// Update packet counter for loop detection
	d.packetCounters[deviceName][srcMAC]++

	d.mutex.Unlock()
}

// periodicAnalysis runs regular checks to identify loops
func (d *Detector) periodicAnalysis() {
	ticker := time.NewTicker(d.samplingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopChan:
			return
		case <-ticker.C:
			d.detectLoops()
		}
	}
}

// detectLoops analyzes current packet statistics to identify loops
func (d *Detector) detectLoops() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Clear previous loop detections that haven't been seen recently
	for macAddr, info := range d.loopDetections {
		if time.Since(info.DetectedTime) > d.samplingPeriod*2 {
			delete(d.loopDetections, macAddr)
		}
	}

	// Check for unusually high packet counts that indicate loops
	for deviceName, counters := range d.packetCounters {
		for macAddr, count := range counters {
			if count > d.loopThreshold {
				mac, _ := net.ParseMAC(macAddr)
				vendorName := d.vendorLookup.GetVendorName(mac)

				// Record or update loop information
				if _, exists := d.loopDetections[macAddr]; !exists {
					d.loopDetections[macAddr] = &LoopInfo{
						MACAddress:   mac,
						DeviceName:   deviceName,
						DetectedTime: time.Now(),
						PacketCount:  count,
						VendorName:   vendorName,
					}

					// Report the loop
					fmt.Printf("\n[LOOP DETECTED] MAC: %s (%s), Interface: %s, Count: %d\n",
						macAddr, vendorName, deviceName, count)
				} else {
					// Update existing detection
					d.loopDetections[macAddr].PacketCount = count
					d.loopDetections[macAddr].DetectedTime = time.Now()
				}
			}
		}

		// Reset counters for the next period
		d.packetCounters[deviceName] = make(map[string]int)
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
