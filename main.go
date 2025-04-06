package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spanscan/detector"
	"github.com/spanscan/ui"
)

func main() {
	fmt.Println("SpanScan - Network Loop & STP Issue Detector")
	fmt.Println("--------------------------------------------")

	// Check for administrator privileges on Windows
	if runtime.GOOS == "windows" {
		checkWindowsAdminRights()
	}

	// Initialize detector
	d, err := detector.New()
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
	displayWelcomeMessage()

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

// displayWelcomeMessage shows initial instructions when the app starts
func displayWelcomeMessage() {
	fmt.Println("\nWelcome to SpanScan!")
	fmt.Println("\nThis tool helps detect network loops and STP issues on your network.")
	fmt.Println("\nAvailable commands:")
	fmt.Println("  s - Start monitoring")
	fmt.Println("  p - Pause monitoring")
	fmt.Println("  r - Refresh display")
	fmt.Println("  d - Show detected devices")
	fmt.Println("  i - Show network interfaces")
	fmt.Println("  l - Show detected loops")
	fmt.Println("  h - Show help")
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
