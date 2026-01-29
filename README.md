# SpanScan

A terminal application for detecting network loops and STP (Spanning Tree Protocol) issues on your Layer 2 network.

## Features

- **Multi-Algorithm Loop Detection**:
  - Packet rate threshold detection
  - MAC address duplication across interfaces (strong loop indicator)
  - Broadcast storm detection
  - STP/BPDU analysis with topology change tracking
  
- **STP Topology Awareness**:
  - Full BPDU packet parsing (Configuration, TCN, RSTP)
  - Root bridge detection and multiple-root warnings
  - Topology change notification tracking
  - BPDU rate monitoring

- **Smart Loop Origin Analysis**:
  - Confidence scoring for detected loops
  - Evidence-based severity classification (Critical/High/Medium/Low)
  - Suggested remediation actions
  - Vendor-aware recommendations

- **Device Intelligence**:
  - MAC vendor identification (150+ vendors in local database)
  - Device type classification (Switch, Router, AP, Firewall, IoT)
  - Online MAC lookup fallback

- **Configurable Thresholds**:
  - Packet count threshold
  - Broadcast storm threshold
  - Sampling period
  - Custom BPF filters

- **Logging & Export**:
  - JSON lines log output
  - Event export to file
  - Session summaries

## Requirements

- Go 1.16 or later
- Administrative/root privileges (for packet capturing)
- libpcap development files (on Linux/macOS)
- Npcap or WinPcap (on Windows)

## Installation

### Install dependencies

#### Windows
1. Download and install [Npcap](https://nmap.org/npcap/) or [WinPcap](https://www.winpcap.org/)

#### Linux
```bash
sudo apt-get install libpcap-dev
```

#### macOS
```bash
brew install libpcap
```

### Build SpanScan

```bash
git clone https://github.com/yourusername/spanscan.git
cd spanscan
go build -o spanscan
```

## Usage

Run with administrative privileges:

### Basic Usage
```bash
# Linux/macOS
sudo ./spanscan

# Windows (Run as Administrator)
spanscan.exe
```

### Advanced Options

```bash
# Custom detection thresholds
sudo ./spanscan --threshold=50 --sample-time=5

# Enable logging
sudo ./spanscan --log=events.json --json

# Lower broadcast storm threshold for sensitive detection
sudo ./spanscan --broadcast-threshold=200

# Custom BPF filter (STP only)
sudo ./spanscan --filter='ether dst 01:80:c2:00:00:00'

# Disable terminal bell alerts
sudo ./spanscan --no-bell
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--threshold` | Packet count threshold for loop detection | 100 |
| `--sample-time` | Sampling period in seconds | 10 |
| `--broadcast-threshold` | Broadcast packets/sec for storm detection | 500 |
| `--filter` | Custom BPF filter | (capture all) |
| `--log` | Path to log file | (no logging) |
| `--json` | Output log in JSON format | false |
| `--config` | Path to JSON config file | - |
| `--no-bell` | Disable terminal bell for alerts | false |

## Interactive Commands

| Key | Description |
|-----|-------------|
| `s` | Start network monitoring |
| `p` | Pause network monitoring |
| `q` | Quit the application |
| `r` | Refresh display (status + loops + devices) |
| `l` | Show detected loops |
| `d` | Show network devices |
| `i` | Show monitored interfaces |
| `b` | Show broadcast storms |
| `m` | Show duplicate MAC addresses |
| `t` | Show STP topology info |
| `a` | Show loop origin analysis |
| `e` | Export events to JSON file |
| `h` | Display help |

## How It Works

SpanScan uses multiple detection methods to identify network loops:

### 1. Packet Rate Analysis
Monitors packet counts per source MAC per interface. When a MAC exceeds the threshold within the sampling period, it's flagged as a potential loop source.

### 2. MAC Duplication Detection
Tracks when the same source MAC appears on multiple interfaces within a short time window (default: 2 seconds). This is a strong indicator of a loop.

### 3. Broadcast Storm Detection  
Monitors broadcast traffic rates. When broadcast packets/second exceed the threshold, it indicates an active storm likely caused by a loop.

### 4. STP/BPDU Analysis
Parses STP packets to detect:
- Topology Change Notifications (frequent = unstable network)
- Multiple root bridges (STP misconfiguration)
- Abnormal BPDU rates

### Severity Classification

| Severity | Indicators |
|----------|------------|
| **CRITICAL** | Active broadcast storm |
| **HIGH** | MAC on 2+ interfaces OR very high packet rate |
| **MEDIUM** | Threshold exceeded OR frequent topology changes |
| **LOW** | Elevated packet counts, monitoring recommended |

## Configuration File

Create a JSON configuration file:

```json
{
  "packetCountThreshold": 100,
  "broadcastStormThreshold": 500,
  "samplingPeriodSec": 10,
  "duplicateMACWindowSec": 2,
  "bpfFilter": "",
  "logFile": "spanscan.log",
  "jsonOutput": true,
  "enableBell": true
}
```

Load with: `sudo ./spanscan --config=config.json`

## Log Format

When JSON logging is enabled, events are written in JSON Lines format:

```json
{"timestamp":"2024-01-15T10:30:00Z","eventType":"loop_detected","severity":3,"message":"Loop detected from AA:BB:CC:DD:EE:FF (Cisco)","details":{"macAddress":"AA:BB:CC:DD:EE:FF","vendorName":"Cisco","interfaceName":"eth0","packetCount":250,"confidenceScore":0.85,"evidence":["High packet rate: 250 packets","MAC on 2 interfaces"]}}
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| "No interfaces found" | Install Npcap/WinPcap and run as Administrator |
| "Unable to open device" | Check administrative privileges |
| No packets captured | Try physical interface, check virtualization settings |
| No vendor information | Online lookup may be rate-limited; local DB has 150+ vendors |

## Project Structure

```
spanscan/
├── main.go           # CLI and main event loop
├── config/
│   └── config.go     # Configuration management
├── detector/
│   └── detector.go   # Core loop detection engine
├── stp/
│   └── parser.go     # STP/BPDU packet parser
├── macvendor/
│   └── lookup.go     # MAC vendor lookup service
├── logging/
│   └── logger.go     # Structured event logging
└── ui/
    └── terminal.go   # Terminal user interface
```

## License

MIT