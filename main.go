package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spanscan/config"
	"github.com/spanscan/detector"
	"github.com/spanscan/ui"
)

func main() {
	// Parse command line flags
	cfg := parseFlags()

	fmt.Println("SpanScan - Network Loop & STP Issue Detector")
	fmt.Println("--------------------------------------------")

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

	// Initialize UI
	terminal := ui.New(d)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start in passive mode - don't start scanning until user requests it
	isScanning := false
	var startTime time.Time
	var errChan chan error

	// Prepare for keyboard input
	inputChan := make(chan string, 1)
	go readInput(inputChan)

	// Display welcome message and instructions
	displayWelcomeMessage(cfg)

	// Main event loop
	running := true
	for running {
		select {
		case <-sigChan:
			fmt.Println("\nShutting down...")
			if isScanning {
				d.Stop()
			}
			running = false
		case input := <-inputChan:
			switch input {
			case "q":
				fmt.Println("\nShutting down...")
				if isScanning {
					d.Stop()
				}
				running = false
			case "h":
				terminal.DisplayHelp()
			case "s":
				if !isScanning {
					// Start scanning
					isScanning = true
					startTime = time.Now()
					errChan = make(chan error, 1)
					go func() {
						errChan <- d.Start()
					}()
					fmt.Println("\n[STARTED] Network monitoring is now active")
					terminal.DisplayStatus(0)
				} else {
					fmt.Println("\nMonitoring is already active")
				}
			case "p":
				if isScanning {
					// Stop scanning
					d.Stop()
					isScanning = false
					fmt.Println("\n[PAUSED] Network monitoring has been paused")
				} else {
					fmt.Println("\nMonitoring is not active")
				}
			case "r":
				if isScanning {
					terminal.DisplayStatus(time.Since(startTime))
					terminal.DisplayLoops()
					terminal.DisplayDevices()
				} else {
					fmt.Println("\nMonitoring is not active. Press 's' to start monitoring.")
				}
			case "d":
				if isScanning {
					terminal.DisplayDevices()
				} else {
					fmt.Println("\nNo devices detected. Press 's' to start monitoring.")
				}
			case "i":
				// Get device names from the detector
				devices := []string{}
				for _, device := range d.GetDevices() {
					devices = append(devices, device.Name)
				}
				terminal.DisplayInterfaces(devices)
			case "l":
				if isScanning {
					terminal.DisplayLoops()
				} else {
					fmt.Println("\nNo loops detected. Press 's' to start monitoring.")
				}
			case "b":
				if isScanning {
					terminal.DisplayBroadcastStorms()
				} else {
					fmt.Println("\nNo broadcast storms detected. Press 's' to start monitoring.")
				}
			case "m":
				if isScanning {
					terminal.DisplayDuplicateMACs()
				} else {
					fmt.Println("\nNo duplicate MACs detected. Press 's' to start monitoring.")
				}
			case "t":
				if isScanning {
					terminal.DisplaySTPInfo()
				} else {
					fmt.Println("\nNo STP data available. Press 's' to start monitoring.")
				}
			case "a":
				if isScanning {
					terminal.DisplayLoopAnalysis()
				} else {
					fmt.Println("\nNo analysis available. Press 's' to start monitoring.")
				}
			case "e":
				terminal.ExportEvents()
			}
		case err := <-errChan:
			if err != nil {
				log.Fatalf("Detector error: %v", err)
			}
			isScanning = false
		case <-time.After(5 * time.Second):
			// Only update status if scanning is active
			if isScanning {
				// Refresh the status every 5 seconds
				terminal.DisplayStatus(time.Since(startTime))

				// Automatically display loops if any are detected
				loops := d.GetDetectedLoops()
				if len(loops) > 0 {
					terminal.DisplayLoops()
				}
			}
		}
	}
}

// parseFlags handles command line argument parsing
func parseFlags() *config.Config {
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

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SpanScan - Network Loop & STP Issue Detector\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --threshold=50 --sample-time=5\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --log=events.log --json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --filter='ether dst 01:80:c2:00:00:00'\n", os.Args[0])
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

	return cfg
}

// displayWelcomeMessage shows initial instructions when the app starts
func displayWelcomeMessage(cfg *config.Config) {
	fmt.Println("\nWelcome to SpanScan!")
	fmt.Println("\nThis tool helps detect network loops and STP issues on your network.")

	// Show current configuration
	fmt.Println("\nCurrent settings:")
	fmt.Printf("  • Loop threshold: %d packets per %s\n", cfg.PacketCountThreshold, cfg.SamplingPeriod)
	fmt.Printf("  • Broadcast storm threshold: %d packets/sec\n", cfg.BroadcastStormThreshold)
	if cfg.BPFFilter != "" {
		fmt.Printf("  • BPF filter: %s\n", cfg.BPFFilter)
	} else {
		fmt.Println("  • BPF filter: (capturing all traffic)")
	}
	if cfg.LogFile != "" {
		fmt.Printf("  • Logging to: %s\n", cfg.LogFile)
	}

	fmt.Println("\nAvailable commands:")
	fmt.Println("  s - Start monitoring    l - Show loops      d - Show devices")
	fmt.Println("  p - Pause monitoring    b - Broadcast storms  m - Duplicate MACs")
	fmt.Println("  r - Refresh display     t - STP topology    a - Loop analysis")
	fmt.Println("  i - Show interfaces     e - Export events   h - Help")
	fmt.Println("  q - Quit")
	fmt.Println("\nTo begin, press 's' to start monitoring...")
}

// readInput handles keyboard input
func readInput(inputChan chan<- string) {
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		if len(input) > 0 {
			// Send the first character of input
			inputChan <- string(input[0])
		}
	}
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
