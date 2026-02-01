package main

import (
	"flag"
	"fmt"
	"log"
	"os"
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

// parseFlags handles command line arguments
func parseFlags() (*config.Config, bool) {
	cfg := config.DefaultConfig()

	// Define flags
	configFile := flag.String("config", "", "Path to configuration file (JSON)")
	threshold := flag.Int("threshold", 0, "Packet count threshold for loop detection")
	pollInterval := flag.Int("poll-interval", 0, "SNMP polling interval in seconds")
	broadcastThreshold := flag.Int("broadcast-threshold", 0, "Broadcast storm threshold (packets/second)")
	logFile := flag.String("log", "", "Path to log file for event recording")
	jsonOutput := flag.Bool("json", false, "Output log in JSON format")
	noBell := flag.Bool("no-bell", false, "Disable terminal bell for alerts")
	legacyUI := flag.Bool("legacy", false, "Use legacy terminal UI instead of TUI")

	// SNMP specific
	snmpTargets := flag.String("targets", "", "Comma-separated list of SNMP target IPs")
	snmpCommunity := flag.String("community", "", "SNMP Community string")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SpanScan - Network Loop & STP Issue Detector (SNMP Mode)\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --targets=192.168.1.10,192.168.1.11 --community=public\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --config=config.json\n", os.Args[0])
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
	if *pollInterval > 0 {
		cfg.PollInterval = time.Duration(*pollInterval) * time.Second
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
	if *noBell {
		cfg.EnableBell = false
	}

	// If CLI flags are present, they override/append to headers
	if *snmpTargets != "" {
		targets := strings.Split(*snmpTargets, ",")
		community := *snmpCommunity
		if community == "" {
			community = "public"
		}

		// If only using flags, maybe we should clear existing config targets to avoid confusion?
		// For now, let's just append or replace if empty
		if len(cfg.Targets) == 0 {
			for _, t := range targets {
				cfg.Targets = append(cfg.Targets, config.SNMPTargetConfig{
					Address:   strings.TrimSpace(t),
					Version:   config.SNMPVersion2c,
					Community: community,
				})
			}
		} else {
			// If we have existing configs, this gets tricky with simple flags.
			// Let's assume flags add to the session.
			for _, t := range targets {
				cfg.Targets = append(cfg.Targets, config.SNMPTargetConfig{
					Address:   strings.TrimSpace(t),
					Version:   config.SNMPVersion2c,
					Community: community,
				})
			}
		}
	}

	return cfg, *legacyUI
}

// handleInitializationError provides helpful error messages based on the error
func handleInitializationError(err error) {
	fmt.Printf("Error initializing detector: %v\n", err)
}
