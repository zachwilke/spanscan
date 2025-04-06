package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spanscan/detector"
)

// Terminal handles the terminal user interface for the application
type Terminal struct {
	detector *detector.Detector
}

// New creates a new Terminal UI instance
func New(detector *detector.Detector) *Terminal {
	return &Terminal{
		detector: detector,
	}
}

// DisplayLoops shows the currently detected loops
func (t *Terminal) DisplayLoops() {
	loops := t.detector.GetDetectedLoops()

	if len(loops) == 0 {
		fmt.Println("\nNo network loops detected.")
		return
	}

	fmt.Println("\n======= DETECTED NETWORK LOOPS =======")
	fmt.Println("MAC Address            Vendor         Interface       Time                 Packets")
	fmt.Println("--------------------------------------------------------------------------------")

	for _, loop := range loops {
		fmt.Printf("%-22s %-14s %-15s %-20s %d\n",
			loop.MACAddress.String(),
			truncateString(loop.VendorName, 12),
			formatInterfaceName(loop.DeviceName),
			loop.DetectedTime.Format("2006-01-02 15:04:05"),
			loop.PacketCount,
		)
	}

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("⚠️  LOOP SOURCES are likely connected to the interface where they are detected")
	fmt.Println("   Check for accidentally connected ports or faulty STP configuration")
}

// DisplayDevices shows information about network devices seen on the network
func (t *Terminal) DisplayDevices() {
	devices := t.detector.GetSeenDevices()

	if len(devices) == 0 {
		fmt.Println("\nNo network devices detected yet.")
		return
	}

	// Sort devices by packet count (descending)
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].PacketCount > devices[j].PacketCount
	})

	fmt.Println("\n======= NETWORK DEVICES DETECTED =======")
	fmt.Println("MAC Address            Vendor         Packets    First Seen           Interfaces")
	fmt.Println("--------------------------------------------------------------------------------")

	// Get loop information to highlight loop-causing devices
	loops := t.detector.GetDetectedLoops()
	loopMacs := make(map[string]bool)
	for _, loop := range loops {
		loopMacs[loop.MACAddress.String()] = true
	}

	for _, device := range devices {
		// Get a list of interfaces where this device was seen
		interfaces := make([]string, 0, len(device.Interfaces))
		for iface := range device.Interfaces {
			interfaces = append(interfaces, formatInterfaceName(iface))
		}

		// Format the output, highlighting loop-causing devices
		macStr := device.MACAddress.String()
		if loopMacs[macStr] {
			fmt.Printf("%-22s %-14s %-10d %-20s %s ⚠️ LOOP SOURCE!\n",
				macStr,
				truncateString(device.VendorName, 12),
				device.PacketCount,
				device.FirstSeen.Format("2006-01-02 15:04:05"),
				strings.Join(interfaces, ", "),
			)
		} else {
			fmt.Printf("%-22s %-14s %-10d %-20s %s\n",
				macStr,
				truncateString(device.VendorName, 12),
				device.PacketCount,
				device.FirstSeen.Format("2006-01-02 15:04:05"),
				strings.Join(interfaces, ", "),
			)
		}
	}

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("Total devices: %d\n", len(devices))
}

// DisplayInterfaces shows information about available network interfaces
func (t *Terminal) DisplayInterfaces(devices []string) {
	fmt.Println("\n======= MONITORING INTERFACES =======")
	for i, device := range devices {
		fmt.Printf("[%d] %s\n", i+1, formatInterfaceName(device))
	}
	fmt.Println("-------------------------------------")
}

// DisplayHelp shows help information
func (t *Terminal) DisplayHelp() {
	fmt.Println("\n======= SPANSCAN HELP =======")
	fmt.Println("q, Ctrl+C - Quit the application")
	fmt.Println("s         - Start monitoring")
	fmt.Println("p         - Pause monitoring")
	fmt.Println("h         - Display this help")
	fmt.Println("r         - Refresh the display")
	fmt.Println("d         - Show network devices")
	fmt.Println("i         - Show monitored interfaces")
	fmt.Println("l         - Show detected loops")
	fmt.Println("===============================")
}

// DisplayStatus shows the current status
func (t *Terminal) DisplayStatus(duration time.Duration) {
	fmt.Printf("\nMonitoring network for %s\n", formatDuration(duration))

	// Count devices and loops
	devices := t.detector.GetSeenDevices()
	loops := t.detector.GetDetectedLoops()

	if len(loops) > 0 {
		fmt.Printf("⚠️ %d network loops detected! ⚠️\n", len(loops))
	}

	fmt.Printf("Devices detected: %d\n", len(devices))
	fmt.Println("Press 'h' for help, 'q' to quit")
}

// Helper functions
func formatInterfaceName(name string) string {
	// For Windows interfaces, trim the long device path
	if strings.HasPrefix(name, "\\Device\\NPF_") {
		return strings.TrimPrefix(name, "\\Device\\NPF_")
	}
	return name
}

func formatDuration(d time.Duration) string {
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
