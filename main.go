package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spanscan/config"
	"github.com/spanscan/detector"
	"github.com/spanscan/tui"
)

func main() {
	// Parse command line flags
	cfg, useLegacyUI := parseFlags()

	// Check for administrator privileges on Windows
	if runtime.GOOS == "windows" {
		checkWindowsAdminRights()
	}

	// Initialize detector with configuration
	d, err := detector.NewWithConfig(cfg)
	if err != nil {
		handleInitializationError(err)
		return
	}

	if useLegacyUI {
		// Run legacy terminal UI
		runLegacyUI(d)
	} else {
		// Run beautiful TUI
		runTUI(d)
	}
}

func runTUI(d *detector.Detector) {
	p := tea.NewProgram(
		tui.New(d),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}

func runLegacyUI(d *detector.Detector) {
	fmt.Println("SpanScan - Network Loop & STP Issue Detector (Legacy Mode)")
	fmt.Println("-----------------------------------------------------------")
	fmt.Println("Use without --legacy flag for the beautiful TUI experience!")
	fmt.Println()

	// The old terminal interface code would go here
	// For now, just start monitoring directly
	fmt.Println("Starting monitoring...")
	if err := d.Start(); err != nil {
		log.Fatal(err)
	}
}

// parseFlags handles command line argument parsing
func parseFlags() (*config.Config, bool) {
	cfg := config.DefaultConfig()

	// Define flags
	configFile := flag.String("config", "", "Path to configuration file (JSON)")
	threshold := flag.Int("threshold", 0, "Packet count threshold for loop detection")
	sampleTime := flag.Int("sample-time", 0, "Sampling period in seconds")
	broadcastThreshold := flag.Int("broadcast-threshold", 0, "Broadcast storm threshold (packets/second)")
	logFile := flag.String("log", "", "Path to log file for event recording")
	jsonOutput := flag.Bool("json", false, "Output log in JSON format")
	bpfFilter := flag.String("filter", "", "Custom BPF filter (e.g., 'ether proto 0x8809')")
	noBell := flag.Bool("no-bell", false, "Disable terminal bell for alerts")
	legacyUI := flag.Bool("legacy", false, "Use legacy terminal UI instead of TUI")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SpanScan - Network Loop & STP Issue Detector\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s                                    # Launch beautiful TUI\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --threshold=50 --sample-time=5\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --log=events.log --json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --legacy                           # Use legacy terminal mode\n", os.Args[0])
	}

	flag.Parse()

	// Load config file if specified
	if *configFile != "" {
		fileCfg, err := config.LoadFromFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not load config file: %v\n", err)
		} else {
			cfg = fileCfg
		}
	}

	// Override with command line flags
	if *threshold > 0 {
		cfg.PacketCountThreshold = *threshold
	}
	if *sampleTime > 0 {
		cfg.SamplingPeriod = time.Duration(*sampleTime) * time.Second
	}
	if *broadcastThreshold > 0 {
		cfg.BroadcastStormThreshold = *broadcastThreshold
	}
	if *logFile != "" {
		cfg.LogFile = *logFile
	}
	if *jsonOutput {
		cfg.JSONOutput = true
	}
	if *bpfFilter != "" {
		cfg.BPFFilter = *bpfFilter
	}
	if *noBell {
		cfg.EnableBell = false
	}

	return cfg, *legacyUI
}

// handleInitializationError provides helpful error messages based on the error
func handleInitializationError(err error) {
	errorMsg := err.Error()

	if strings.Contains(errorMsg, "no suitable devices found") ||
		strings.Contains(errorMsg, "finding network devices") {
		fmt.Println("\nERROR: Unable to find suitable network interfaces.")
		if runtime.GOOS == "windows" {
			fmt.Println("\nPossible solutions:")
			fmt.Println("1. Make sure Npcap or WinPcap is installed:")
			fmt.Println("   - Npcap: https://nmap.org/npcap/")
			fmt.Println("   - WinPcap: https://www.winpcap.org/")
			fmt.Println("2. Run SpanScan as Administrator")
			fmt.Println("3. Check if your antivirus or security software is blocking access")
		} else if runtime.GOOS == "linux" {
			fmt.Println("\nPossible solutions:")
			fmt.Println("1. Make sure libpcap-dev is installed:")
			fmt.Println("   sudo apt-get install libpcap-dev")
			fmt.Println("2. Run SpanScan with sudo privileges:")
			fmt.Println("   sudo ./spanscan")
		} else if runtime.GOOS == "darwin" {
			fmt.Println("\nPossible solutions:")
			fmt.Println("1. Make sure libpcap is installed:")
			fmt.Println("   brew install libpcap")
			fmt.Println("2. Run SpanScan with sudo privileges:")
			fmt.Println("   sudo ./spanscan")
		}
	} else {
		log.Fatalf("Failed to initialize detector: %v", err)
	}
}

// checkWindowsAdminRights checks if running with admin privileges on Windows
func checkWindowsAdminRights() {
	// Simple check - try to open a privileged file
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		fmt.Println("WARNING: SpanScan may not be running with Administrator privileges.")
		fmt.Println("         Some network interfaces may not be accessible.")
		fmt.Println("         Right-click and select 'Run as administrator' for full functionality.")
		fmt.Println("")
		time.Sleep(3 * time.Second)
	}
}
