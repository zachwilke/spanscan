# SpanScan

**A Network Loop & STP Issue Detector with Modern TUI**

SpanScan is a real-time network monitoring tool designed to detect Layer 2 network loops, broadcast storms, and Spanning Tree Protocol (STP) misconfigurations. It uses multiple detection algorithms running in parallel to identify loop sources with high confidence.

![SpanScan TUI](docs/tui-screenshot.png)

---

## Table of Contents

- [How Network Loops Work](#how-network-loops-work)
- [Detection Algorithms](#detection-algorithms)
- [Technical Architecture](#technical-architecture)
- [STP/BPDU Analysis](#stpbpdu-analysis)
- [Severity Classification](#severity-classification)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## How Network Loops Work

### What is a Layer 2 Loop?

A Layer 2 (Data Link) network loop occurs when there are multiple active paths between network switches, creating a circular route for Ethernet frames. Unlike IP packets (Layer 3), Ethernet frames have no Time-To-Live (TTL) field, so they can circulate indefinitely.

```
    Switch A ─────────── Switch B
        │                    │
        │    ┌──────────────┘
        │    │  (Loop!)
        │    ▼
    Switch C ◄───────────────┘
```

### Why Loops Are Destructive

1. **Broadcast Storms**: A single broadcast frame gets replicated infinitely, exponentially consuming bandwidth
2. **MAC Table Instability**: The same MAC address appears on multiple ports, causing constant table updates
3. **CPU Overload**: Switches exhaust CPU processing duplicate frames
4. **Network Outage**: Within seconds, a loop can bring down an entire VLAN or network segment

### Common Causes

| Cause | Description |
|-------|-------------|
| Cabling errors | Accidentally connecting two ports on the same switch |
| STP failure | Disabled STP, misconfigured priorities, or BPDU filtering |
| Rogue devices | Unmanaged switches or hubs introduced to the network |
| Convergence issues | RSTP/STP taking too long to block redundant paths |
| Split brain | Network partition causing multiple root bridges |

---

## Detection Algorithms

SpanScan employs four independent detection algorithms that run concurrently. When multiple algorithms agree, the confidence score increases.

### 1. Packet Rate Threshold Detection

**Principle**: During a loop, the same source MAC generates abnormally high packet counts as frames are replicated.

**Implementation** (`detector/detector.go`):

```go
// Every sampling period (default: 10 seconds), count packets per source MAC per interface
packetCounters[deviceName][srcMAC]++

// If count exceeds threshold, flag as potential loop
if count > config.PacketCountThreshold {
    // Create LoopInfo with severity based on count
}
```

**Thresholds**:
- Default: 100 packets per 10-second window
- Configurable via `--threshold` flag
- Lower values = more sensitive but more false positives

**Limitations**: 
- Legitimate high-traffic hosts may trigger false positives
- May miss slow loops or loops on quiet networks

### 2. MAC Address Duplication Detection

**Principle**: In a properly functioning network, a MAC address should only appear on ONE interface at a time. If the same source MAC appears on multiple interfaces within a short time window, it strongly indicates a loop.

**Implementation**:

```go
// Track when each MAC was last seen on each interface
macInterfaceTimes[srcMAC][deviceName] = time.Now()

// If MAC appears on 2+ interfaces within the duplicate window (default: 2 seconds)
if len(interfaces) >= 2 && timeWindow <= config.DuplicateMACWindow {
    // This is a HIGH confidence loop indicator
    createDuplicateMACEvent(...)
}
```

**Why This Works**:
```
Normal Network:
  Host A ──► Switch Port 1 ──► Switch Port 2 ──► Destination
  MAC A only visible on Port 1

Loop Condition:  
  Host A ──► Port 1 ──┐      ┌──► Port 3
                      │ LOOP │
                      └──────┘
  MAC A now visible on Port 1 AND Port 3!
```

**Confidence Boost**: +30% when detected

### 3. Broadcast Storm Detection

**Principle**: Loops cause broadcast frames (destination `FF:FF:FF:FF:FF:FF`) to multiply exponentially, creating a "storm" measurable by packets-per-second.

**Implementation**:

```go
// Count broadcast packets per interface per sampling period
if dstMAC == "ff:ff:ff:ff:ff:ff" {
    broadcastCounters[deviceName]++
}

// Calculate rate
pps := count / samplingPeriod.Seconds()

if pps > config.BroadcastStormThreshold {
    // Broadcast storm detected - CRITICAL severity
}
```

**Thresholds**:
- Default: 500 packets/second
- A normal network might see 10-50 broadcast pps
- During a storm, this can exceed 10,000+ pps

**Storm Lifecycle Tracking**:
```go
type BroadcastStormInfo struct {
    InterfaceName    string
    PacketsPerSecond int
    DetectedTime     time.Time
    IsActive         bool  // Tracks if storm is ongoing or cleared
}
```

### 4. STP/BPDU Analysis

**Principle**: Spanning Tree Protocol is designed to prevent loops. Abnormal STP behavior often precedes or accompanies loops.

**What We Monitor**:

| Indicator | Normal | Abnormal |
|-----------|--------|----------|
| Root bridges | 1 per VLAN | Multiple (STP misconfiguration) |
| BPDU rate | ~0.5/sec (hello timer) | >50/sec indicates issues |
| Topology Change (TC) flags | Rare | Frequent = instability |
| TCN BPDUs | Rare | Many = devices flapping |

**BPDU Parsing** (`stp/parser.go`):

```go
type BPDUInfo struct {
    ProtocolVersion  uint8
    BPDUType         BPDUType    // Configuration, TCN, RSTP, MST
    RootBridgeID     BridgeID    // Priority + MAC of root
    SenderBridgeID   BridgeID    // Who sent this BPDU
    RootPathCost     uint32      // Cost to reach root
    PortID           uint16      // Sender's port number
    Flags            BPDUFlags   // TC, TCA, Port Role, etc.
    MessageAge       time.Duration
    // ... timers
}
```

**Multiple Root Detection**:
```go
func (p *Parser) HasMultipleRoots() bool {
    return len(p.rootBridges) > 1
}
// If true, STP is misconfigured - different switches think 
// THEY are the root, leading to no loop prevention
```

---

## Technical Architecture

### Packet Capture Flow

```
┌──────────────────────────────────────────────────────────────┐
│                        SpanScan                               │
├──────────────┬───────────────┬──────────────┬────────────────┤
│   Interface  │   Interface   │  Interface   │  Interface     │
│     eth0     │     eth1      │    wlan0     │    ...         │
├──────────────┴───────────────┴──────────────┴────────────────┤
│                    libpcap/gopacket                           │
│                  (Promiscuous Mode)                           │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                     Packet Processing                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Ethernet    │  │ Update      │  │ Parse STP/BPDU     │  │
│  │ Layer Parse │─▶│ Counters    │─▶│ (if applicable)    │  │
│  │ (src/dst)   │  │ & Devices   │  │                    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│              Periodic Analysis (every 10s)                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  detectLoops()         - Packet threshold analysis   │   │
│  │  detectBroadcastStorms() - Broadcast rate analysis  │   │
│  │  checkSTPIssues()      - Root bridge & TCN analysis │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                   Severity Calculation                        │
│                                                               │
│  Base confidence from packet count                           │
│    + 0.30 if duplicate MAC detected                          │
│    + 0.20 if broadcast storm active                          │
│    + 0.10 if multiple STP roots                              │
│  ────────────────────────────────                            │
│  = Final confidence (capped at 1.0)                          │
│                                                               │
│  Severity mapping:                                           │
│    >= 0.80 confidence OR broadcast storm = CRITICAL          │
│    >= 0.50 confidence OR dup MAC = HIGH                      │
│    >= 0.30 confidence = MEDIUM                               │
│    < 0.30 confidence = LOW                                   │
└──────────────────────────────────────────────────────────────┘
```

### Concurrency Model

```go
// Main goroutines:
go d.processPackets(deviceName, handle)  // One per interface
go d.periodicAnalysis()                   // Analysis loop

// Thread-safe access via mutex
d.mutex.Lock()
d.seenDevices[srcMAC] = ...
d.mutex.Unlock()
```

### Data Structures

```go
// Core detection state
type Detector struct {
    // Packet capture handles (one per interface)
    handles map[string]*pcap.Handle
    
    // Detection data
    packetCounters    map[string]map[string]int      // [interface][MAC] -> count
    seenDevices       map[string]*DeviceInfo          // [MAC] -> device info
    macInterfaceTimes map[string]map[string]time.Time // [MAC][interface] -> time
    broadcastCounters map[string]int                  // [interface] -> count
    
    // Detected issues
    loopDetections    map[string]*LoopInfo
    broadcastStorms   map[string]*BroadcastStormInfo
    duplicateMACs     map[string]*DuplicateMACEvent
    
    // Components
    stpParser    *stp.Parser
    vendorLookup *macvendor.LookupService
    logger       *logging.Logger
}
```

---

## STP/BPDU Analysis

### BPDU Packet Structure

SpanScan parses the following BPDU fields (IEEE 802.1D):

```
Bytes 0-1:   Protocol ID (0x0000 for STP)
Byte 2:      Protocol Version (0=STP, 2=RSTP, 3=MSTP)
Byte 3:      BPDU Type (0x00=Config, 0x80=TCN, 0x02=RSTP)
Byte 4:      Flags (TC, TCA, Port Role, etc.)
Bytes 5-12:  Root Bridge ID (Priority + MAC)
Bytes 13-16: Root Path Cost
Bytes 17-24: Sender Bridge ID
Bytes 25-26: Port ID
Bytes 27-34: Timers (Message Age, Max Age, Hello, Forward Delay)
```

### Bridge ID Decoding

```go
type BridgeID struct {
    Priority   uint16           // Upper 4 bits (0-61440 in steps of 4096)
    SystemIDEx uint16           // Lower 12 bits (VLAN ID for PVST+)
    SystemID   net.HardwareAddr // Switch MAC address
}

// Example: Priority 32768, MAC aa:bb:cc:dd:ee:ff
// Displays as: "32768/aa:bb:cc:dd:ee:ff"
```

### Flag Analysis

```go
type BPDUFlags struct {
    TopologyChange    bool // Bit 0: TC occurred somewhere
    Proposal          bool // Bit 1: RSTP proposal
    PortRole          PortRole // Bits 2-3: Unknown/Alt/Root/Designated
    Learning          bool // Bit 4: Port is learning MACs
    Forwarding        bool // Bit 5: Port is forwarding frames
    Agreement         bool // Bit 6: RSTP agreement
    TopologyChangeAck bool // Bit 7: Acknowledging TC
}
```

### Multi-Root Detection Logic

```go
// Every BPDU contains the sender's view of who the root bridge is
func (p *Parser) trackRootBridge(bridge BridgeID) {
    key := bridge.String()
    p.rootBridges[key] = bridge
}

// If we see BPDUs claiming different roots, STP is broken
func (p *Parser) HasMultipleRoots() bool {
    return len(p.rootBridges) > 1
}
```

---

## Severity Classification

### Severity Levels

| Level | Color | Threshold | Meaning |
|-------|-------|-----------|---------|
| CRITICAL | 🔴 Red BG | Broadcast storm OR confidence ≥ 0.9 | Active network damage, immediate action required |
| HIGH | 🟠 Orange | Confidence ≥ 0.5 OR duplicate MAC | Definite loop, should investigate immediately |
| MEDIUM | 🟡 Yellow | Confidence ≥ 0.3 OR STP issues | Likely loop, investigation recommended |
| LOW | 🔵 Cyan | Confidence < 0.3 | Possible loop, continue monitoring |

### Confidence Calculation

```go
func calculateLoopSeverity(macAddr, deviceName string, packetCount int) {
    // Base: packet count relative to threshold
    confidence := min(packetCount / (threshold * 10), 0.5)
    
    // Boost: duplicate MAC is strong evidence
    if duplicateMACs[macAddr] exists {
        confidence += 0.30
    }
    
    // Boost: active broadcast storm
    if broadcastStorms[deviceName].IsActive {
        confidence += 0.20
    }
    
    // Boost: STP misconfiguration
    if stpParser.HasMultipleRoots() {
        confidence += 0.10
    }
    
    confidence = min(confidence, 1.0)
}
```

### Evidence Collection

Each loop detection includes human-readable evidence:

```go
evidence := []string{
    "High packet rate: 450 packets",
    "MAC on 2 interfaces",
    "Broadcast storm active",
}
```

---

## Installation

### Prerequisites

| OS | Requirements |
|----|--------------|
| Linux | `sudo apt install libpcap-dev` |
| macOS | `brew install libpcap` (usually pre-installed) |
| Windows | [Npcap](https://nmap.org/npcap/) or WinPcap |

### Build

```bash
git clone https://github.com/yourusername/spanscan.git
cd spanscan
go build -o spanscan
```

### Dependencies

```
github.com/google/gopacket      # Packet capture and parsing
github.com/charmbracelet/bubbletea  # TUI framework
github.com/charmbracelet/lipgloss   # TUI styling
github.com/charmbracelet/bubbles    # TUI components
```

---

## Usage

### Basic Usage

```bash
# Launch TUI (requires root/admin for packet capture)
sudo ./spanscan

# Legacy terminal mode
sudo ./spanscan --legacy
```

### TUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `s` | Start monitoring |
| `p` | Pause monitoring |
| `Tab` / `1-5` | Switch tabs |
| `j` / `k` or `↑` / `↓` | Scroll |
| `q` | Quit |

### Command Line Options

```bash
./spanscan [options]

Detection Tuning:
  --threshold=N           Packet count threshold (default: 100)
  --sample-time=N         Sampling period in seconds (default: 10)
  --broadcast-threshold=N Broadcast storm threshold pps (default: 500)
  --filter="..."          Custom BPF filter

Logging:
  --log=FILE              Path to log file
  --json                  Output log in JSON Lines format

UI:
  --legacy                Use legacy terminal UI
  --no-bell               Disable terminal bell on alerts

Config:
  --config=FILE           Load settings from JSON file
```

### Examples

```bash
# More sensitive detection (lower thresholds)
sudo ./spanscan --threshold=50 --sample-time=5

# Only monitor STP traffic
sudo ./spanscan --filter='ether dst 01:80:c2:00:00:00'

# Log all events to JSON
sudo ./spanscan --log=events.jsonl --json

# Production monitoring
sudo ./spanscan --threshold=200 --log=/var/log/spanscan.log --no-bell
```

---

## Configuration

### JSON Configuration File

```json
{
  "packetCountThreshold": 100,
  "broadcastStormThreshold": 500,
  "samplingPeriodSec": 10,
  "duplicateMACWindowSec": 2,
  "bpfFilter": "",
  "logFile": "/var/log/spanscan.log",
  "jsonOutput": true,
  "enableBell": false
}
```

Load with: `sudo ./spanscan --config=config.json`

### BPF Filters

| Filter | Effect |
|--------|--------|
| `""` (empty) | Capture all traffic |
| `ether dst 01:80:c2:00:00:00` | STP BPDUs only |
| `ether proto 0x8809` | LACP only |
| `broadcast` | Broadcast frames only |
| `ether src aa:bb:cc:dd:ee:ff` | Specific source MAC |

---

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| "No interfaces found" | Install Npcap (Windows) or run with sudo (Linux/macOS) |
| "Permission denied" | Run as root/administrator |
| No packets captured | Ensure promiscuous mode is supported; try physical NIC |
| High CPU usage | Increase `--sample-time` or use more specific BPF filter |
| Many false positives | Increase `--threshold` value |

### Debug Mode

To see all captured packets (verbose):

```bash
# Use tcpdump alongside SpanScan
sudo tcpdump -i eth0 -n 'ether dst 01:80:c2:00:00:00' &
sudo ./spanscan
```

### Log Analysis

```bash
# View recent critical events
jq 'select(.severity >= 3)' events.jsonl

# Count events by type
jq -s 'group_by(.eventType) | map({type: .[0].eventType, count: length})' events.jsonl

# Find most common loop sources
jq -s 'map(select(.eventType == "loop_detected")) | group_by(.details.macAddress) | map({mac: .[0].details.macAddress, count: length}) | sort_by(.count) | reverse' events.jsonl
```

---

## Project Structure

```
spanscan/
├── main.go              # Entry point, CLI flags, TUI launcher
├── config/
│   └── config.go        # Configuration management
├── detector/
│   └── detector.go      # Core detection engine
├── stp/
│   └── parser.go        # STP/BPDU packet parser
├── macvendor/
│   └── lookup.go        # MAC vendor database (150+ entries)
├── logging/
│   └── logger.go        # Structured event logging
├── tui/
│   └── tui.go           # Bubbletea TUI implementation
└── ui/
    └── terminal.go      # Legacy terminal UI
```

---

## License

MIT License

---

## References

- [IEEE 802.1D - Spanning Tree Protocol](https://standards.ieee.org/standard/802_1D-2004.html)
- [Cisco - Understanding STP](https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/5234-5.html)
- [Network Loops Explained](https://www.netadmintools.com/network-loop-detection)
- [gopacket Documentation](https://pkg.go.dev/github.com/google/gopacket)
- [Charm.sh TUI Libraries](https://charm.sh/)