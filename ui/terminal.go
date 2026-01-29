package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spanscan/detector"
)

// ANSI color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBgRed  = "\033[41m"
	colorBold   = "\033[1m"
)

// Terminal handles the terminal user interface for the application
type Terminal struct {
	detector   *detector.Detector
	enableBell bool
}

// New creates a new Terminal UI instance
func New(det *detector.Detector) *Terminal {
	enableBell := true
	if cfg := det.GetConfig(); cfg != nil {
		enableBell = cfg.EnableBell
	}
	return &Terminal{
		detector:   det,
		enableBell: enableBell,
	}
}

// Ring the terminal bell for critical alerts
func (t *Terminal) ringBell() {
	if t.enableBell {
		fmt.Print("\a")
	}
}

// severityColor returns the ANSI color for a severity level
func severityColor(severity detector.LoopSeverity) string {
	switch severity {
	case detector.SeverityCritical:
		return colorBgRed
	case detector.SeverityHigh:
		return colorRed
	case detector.SeverityMedium:
		return colorYellow
	case detector.SeverityLow:
		return colorCyan
	default:
		return colorReset
	}
}

// DisplayLoops shows the currently detected loops with enhanced information
func (t *Terminal) DisplayLoops() {
	loops := t.detector.GetDetectedLoops()

	if len(loops) == 0 {
		fmt.Println("\n" + colorGreen + "✓ No network loops detected." + colorReset)
		return
	}

	// Ring bell for critical alerts
	for _, loop := range loops {
		if loop.Severity >= detector.SeverityHigh {
			t.ringBell()
			break
		}
	}

	fmt.Println("\n" + colorBold + "======= DETECTED NETWORK LOOPS =======" + colorReset)
	fmt.Println("Severity   MAC Address            Vendor         Confidence  Interface       Packets")
	fmt.Println("----------------------------------------------------------------------------------------")

	for _, loop := range loops {
		color := severityColor(loop.Severity)
		severityStr := fmt.Sprintf("%-10s", loop.Severity.String())

		fmt.Printf("%s%s%s %-22s %-14s %-10.0f%% %-15s %d\n",
			color, severityStr, colorReset,
			loop.MACAddress.String(),
			truncateString(loop.VendorName, 12),
			loop.ConfidenceScore*100,
			formatInterfaceName(loop.DeviceName),
			loop.PacketCount,
		)

		// Show evidence for high severity loops
		if loop.Severity >= detector.SeverityMedium && len(loop.Evidence) > 0 {
			fmt.Printf("           %sEvidence: %s%s\n", colorCyan, strings.Join(loop.Evidence, ", "), colorReset)
		}
	}

	fmt.Println("----------------------------------------------------------------------------------------")
	fmt.Println(colorYellow + "⚠️  LOOP SOURCES are likely connected to the interface where they are detected" + colorReset)

	// Show origin analysis if available
	if analysis := t.detector.GetLoopOriginAnalysis(); analysis != nil && analysis.ConfidenceScore > 0.5 {
		fmt.Println()
		fmt.Printf("%sMost likely source: %s (%s) - %.0f%% confidence%s\n",
			colorBold, analysis.SuspectedOrigin.MACAddress.String(),
			analysis.SuspectedOrigin.VendorName,
			analysis.ConfidenceScore*100, colorReset)
		for i, action := range analysis.SuggestedActions {
			fmt.Printf("   %d. %s\n", i+1, action)
		}
	}
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

	fmt.Println("\n" + colorBold + "======= NETWORK DEVICES DETECTED =======" + colorReset)
	fmt.Println("MAC Address            Vendor         Packets    First Seen           Interfaces")
	fmt.Println("--------------------------------------------------------------------------------")

	for _, device := range devices {
		// Get a list of interfaces where this device was seen
		interfaces := make([]string, 0, len(device.Interfaces))
		for iface := range device.Interfaces {
			interfaces = append(interfaces, formatInterfaceName(iface))
		}

		// Format the output, highlighting loop-causing devices
		macStr := device.MACAddress.String()
		if device.IsLoopSource {
			fmt.Printf("%s%-22s %-14s %-10d %-20s %s ⚠️ LOOP SOURCE!%s\n",
				colorRed,
				macStr,
				truncateString(device.VendorName, 12),
				device.PacketCount,
				device.FirstSeen.Format("2006-01-02 15:04:05"),
				strings.Join(interfaces, ", "),
				colorReset,
			)
		} else if len(interfaces) > 1 {
			// Highlight devices seen on multiple interfaces
			fmt.Printf("%s%-22s %-14s %-10d %-20s %s [%d interfaces]%s\n",
				colorYellow,
				macStr,
				truncateString(device.VendorName, 12),
				device.PacketCount,
				device.FirstSeen.Format("2006-01-02 15:04:05"),
				strings.Join(interfaces, ", "),
				len(interfaces),
				colorReset,
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
	fmt.Println("\n" + colorBold + "======= MONITORING INTERFACES =======" + colorReset)
	for i, device := range devices {
		fmt.Printf("[%d] %s\n", i+1, formatInterfaceName(device))
	}
	fmt.Println("-------------------------------------")
}

// DisplayHelp shows help information
func (t *Terminal) DisplayHelp() {
	fmt.Println("\n" + colorBold + "======= SPANSCAN HELP =======" + colorReset)
	fmt.Println(colorCyan + "Control Commands:" + colorReset)
	fmt.Println("  s         - Start monitoring")
	fmt.Println("  p         - Pause monitoring")
	fmt.Println("  q, Ctrl+C - Quit the application")
	fmt.Println()
	fmt.Println(colorCyan + "View Commands:" + colorReset)
	fmt.Println("  r         - Refresh display (status + loops + devices)")
	fmt.Println("  l         - Show detected loops")
	fmt.Println("  d         - Show network devices")
	fmt.Println("  i         - Show monitored interfaces")
	fmt.Println("  b         - Show broadcast storms")
	fmt.Println("  m         - Show duplicate MAC events")
	fmt.Println("  t         - Show STP topology info")
	fmt.Println("  a         - Show loop origin analysis")
	fmt.Println()
	fmt.Println(colorCyan + "Export Commands:" + colorReset)
	fmt.Println("  e         - Export events to JSON file")
	fmt.Println("  h         - Display this help")
	fmt.Println("==============================")
}

// DisplayStatus shows the current status with enhanced statistics
func (t *Terminal) DisplayStatus(duration time.Duration) {
	stats := t.detector.GetStats()

	fmt.Printf("\n%sMonitoring network for %s%s\n", colorBold, formatDuration(duration), colorReset)

	loops := t.detector.GetDetectedLoops()
	if len(loops) > 0 {
		// Count by severity
		criticalCount := 0
		highCount := 0
		for _, loop := range loops {
			if loop.Severity == detector.SeverityCritical {
				criticalCount++
			} else if loop.Severity == detector.SeverityHigh {
				highCount++
			}
		}

		if criticalCount > 0 {
			fmt.Printf("%s🔥 %d CRITICAL loop(s) detected! 🔥%s\n", colorBgRed, criticalCount, colorReset)
			t.ringBell()
		} else if highCount > 0 {
			fmt.Printf("%s⚠️ %d high-severity loop(s) detected!%s\n", colorRed, highCount, colorReset)
		} else {
			fmt.Printf("%s⚠️ %d loop(s) detected%s\n", colorYellow, len(loops), colorReset)
		}
	}

	// Show statistics
	fmt.Printf("📊 Packets: %d | Devices: %d | Loops: %d | Storms: %d | Duplicate MACs: %d\n",
		stats["totalPackets"],
		stats["devicesDetected"],
		stats["loopsDetected"],
		stats["broadcastStorms"],
		stats["duplicateMACs"],
	)

	// STP info
	if rootCount, ok := stats["rootBridges"].(int); ok && rootCount > 1 {
		fmt.Printf("%s⚠️ Multiple STP root bridges detected: %d%s\n", colorYellow, rootCount, colorReset)
	}

	fmt.Println("Press 'h' for help, 'q' to quit")
}

// DisplayBroadcastStorms shows active and recent broadcast storms
func (t *Terminal) DisplayBroadcastStorms() {
	storms := t.detector.GetBroadcastStorms()

	if len(storms) == 0 {
		fmt.Println("\n" + colorGreen + "✓ No broadcast storms detected." + colorReset)
		return
	}

	fmt.Println("\n" + colorBold + "======= BROADCAST STORMS =======" + colorReset)
	fmt.Println("Interface              Packets/sec    Status         Detected")
	fmt.Println("----------------------------------------------------------------")

	for _, storm := range storms {
		status := colorGreen + "Cleared" + colorReset
		if storm.IsActive {
			status = colorRed + "ACTIVE" + colorReset
		}

		fmt.Printf("%-22s %-14d %s  %s\n",
			formatInterfaceName(storm.InterfaceName),
			storm.PacketsPerSecond,
			status,
			storm.DetectedTime.Format("15:04:05"),
		)
	}
	fmt.Println("----------------------------------------------------------------")
}

// DisplayDuplicateMACs shows MAC addresses seen on multiple interfaces
func (t *Terminal) DisplayDuplicateMACs() {
	events := t.detector.GetDuplicateMACs()

	if len(events) == 0 {
		fmt.Println("\n" + colorGreen + "✓ No duplicate MAC addresses detected." + colorReset)
		return
	}

	fmt.Println("\n" + colorBold + "======= DUPLICATE MAC ADDRESSES =======" + colorReset)
	fmt.Println(colorYellow + "These MACs were seen on multiple interfaces - strong loop indicator!" + colorReset)
	fmt.Println("MAC Address            Vendor         Interfaces             Time Window")
	fmt.Println("------------------------------------------------------------------------")

	for _, event := range events {
		interfaces := make([]string, 0)
		for _, iface := range event.Interfaces {
			interfaces = append(interfaces, formatInterfaceName(iface))
		}

		fmt.Printf("%-22s %-14s %-22s %s\n",
			event.MACAddress.String(),
			truncateString(event.VendorName, 12),
			strings.Join(interfaces, ", "),
			event.TimeWindow.String(),
		)
	}
	fmt.Println("------------------------------------------------------------------------")
}

// DisplaySTPInfo shows STP topology information
func (t *Terminal) DisplaySTPInfo() {
	parser := t.detector.GetSTPParser()

	fmt.Println("\n" + colorBold + "======= STP TOPOLOGY INFO =======" + colorReset)

	// Root bridges
	roots := parser.GetRootBridges()
	if len(roots) == 0 {
		fmt.Println("No STP root bridges detected yet.")
	} else if len(roots) == 1 {
		fmt.Printf("%s✓ Single root bridge detected (normal)%s\n", colorGreen, colorReset)
		fmt.Printf("  Root: %s\n", roots[0].String())
	} else {
		fmt.Printf("%s⚠️ MULTIPLE ROOT BRIDGES DETECTED: %d%s\n", colorRed, len(roots), colorReset)
		fmt.Println("  This indicates STP misconfiguration!")
		for i, root := range roots {
			fmt.Printf("  %d. %s\n", i+1, root.String())
		}
	}

	// TCN count
	tcnCount := parser.GetTCNCount()
	fmt.Printf("\nTopology changes: %d\n", tcnCount)
	if tcnCount > 10 {
		fmt.Printf("%s⚠️ High number of topology changes - network may be unstable%s\n",
			colorYellow, colorReset)
	}

	// Recent BPDUs
	recentBPDUs := parser.GetRecentBPDUs(5)
	if len(recentBPDUs) > 0 {
		fmt.Println("\nRecent BPDUs:")
		for _, bpdu := range recentBPDUs {
			fmt.Printf("  %s - %s from %s on %s\n",
				bpdu.CaptureTime.Format("15:04:05"),
				bpdu.BPDUTypeString(),
				bpdu.SenderBridgeID.String(),
				formatInterfaceName(bpdu.InterfaceName),
			)
		}
	}

	fmt.Println("==================================")
}

// DisplayLoopAnalysis shows detailed loop origin analysis
func (t *Terminal) DisplayLoopAnalysis() {
	analysis := t.detector.GetLoopOriginAnalysis()

	if analysis == nil {
		fmt.Println("\n" + colorGreen + "✓ No loops detected - no analysis available." + colorReset)
		return
	}

	fmt.Println("\n" + colorBold + "======= LOOP ORIGIN ANALYSIS =======" + colorReset)

	origin := analysis.SuspectedOrigin
	color := severityColor(origin.Severity)

	fmt.Printf("\n%sSuspected Loop Origin:%s\n", colorBold, colorReset)
	fmt.Printf("  MAC Address: %s%s%s\n", color, origin.MACAddress.String(), colorReset)
	fmt.Printf("  Vendor:      %s\n", origin.VendorName)
	fmt.Printf("  Interface:   %s\n", formatInterfaceName(origin.DeviceName))
	fmt.Printf("  Severity:    %s%s%s\n", color, origin.Severity.String(), colorReset)
	fmt.Printf("  Confidence:  %.0f%%\n", analysis.ConfidenceScore*100)

	fmt.Printf("\n%sEvidence:%s\n", colorBold, colorReset)
	for i, evidence := range analysis.Evidence {
		fmt.Printf("  %d. %s\n", i+1, evidence)
	}

	fmt.Printf("\n%sSuggested Actions:%s\n", colorBold, colorReset)
	for i, action := range analysis.SuggestedActions {
		fmt.Printf("  %d. %s\n", i+1, action)
	}

	if len(analysis.RelatedDevices) > 0 && len(analysis.RelatedDevices) <= 10 {
		fmt.Printf("\n%sOther devices on same interface (%d):%s\n", colorBold, len(analysis.RelatedDevices), colorReset)
		for _, mac := range analysis.RelatedDevices {
			fmt.Printf("  - %s\n", mac.String())
		}
	}

	fmt.Println("=====================================")
}

// ExportEvents exports all logged events to a file
func (t *Terminal) ExportEvents() {
	logger := t.detector.GetLogger()

	filename := fmt.Sprintf("spanscan_events_%s.json", time.Now().Format("20060102_150405"))
	err := logger.ExportToFile(filename)
	if err != nil {
		fmt.Printf("%sError exporting events: %v%s\n", colorRed, err, colorReset)
		return
	}

	events := logger.GetEvents()
	fmt.Printf("%s✓ Exported %d events to %s%s\n", colorGreen, len(events), filename, colorReset)
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
