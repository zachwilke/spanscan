# SpanScan

A terminal application for detecting network loops and STP (Spanning Tree Protocol) issues on your network.

## Features

- Monitors all network interfaces for potential loops
- Detects STP (Spanning Tree Protocol) issues
- Identifies the MAC address and network location of loop sources
- Shows vendor information for detected devices
- Tracks all devices seen on the network
- Clearly highlights which devices are causing network loops
- Simple terminal UI with real-time updates
- Starts in passive mode without active monitoring until explicitly enabled

## Requirements

- Go 1.16 or later
- Administrative/root privileges (for packet capturing)
- libpcap development files (on Linux/macOS)
- Npcap or WinPcap (on Windows)

## Dependencies

### Windows Packet Capture (Npcap/WinPcap)

SpanScan requires a packet capture driver to be installed on your Windows system. This is a limitation that cannot be avoided, as Windows does not include native packet capture capabilities.

#### Why can't Npcap be included with SpanScan?

- **Licensing restrictions**: Npcap is developed by the Nmap Project and has specific licensing terms that generally don't allow for redistribution in most applications.
- **System-level drivers**: Npcap installs kernel-level drivers that require proper Windows installation procedures.
- **Administrative privileges**: Driver installation requires elevated privileges and Windows driver installation framework.

#### Installation Options

1. **Npcap** (Recommended): 
   - Download from [https://nmap.org/npcap/](https://nmap.org/npcap/)
   - Free for personal and non-commercial use
   - Better performance and compatibility with modern Windows versions
   - Supports raw 802.11 Wi-Fi packet capture

2. **WinPcap**:
   - Legacy alternative, no longer actively maintained
   - Download from [https://www.winpcap.org/](https://www.winpcap.org/)
   - Compatible with older Windows versions

#### Installation Notes

- During Npcap installation, select "Install Npcap in WinPcap API-compatible Mode" for best compatibility with SpanScan
- You may need to restart your computer after installing Npcap/WinPcap
- SpanScan must be run with administrative privileges even after driver installation

## Installation

### Install dependencies

#### Windows
1. Download and install [Npcap](https://nmap.org/npcap/) or [WinPcap](https://www.winpcap.org/) as described above

#### Linux
```
sudo apt-get install libpcap-dev
```

#### macOS
```
brew install libpcap
```

### Install SpanScan

```
git clone https://github.com/yourusername/spanscan.git
cd spanscan
go build
```

## Usage

Run with administrative privileges:

### Windows
Run as Administrator:
```
spanscan.exe
```

### Linux/macOS
```
sudo ./spanscan
```

When SpanScan starts, it will display instructions and wait for your command. No network monitoring will occur until you explicitly start it by pressing 's'.

## Interactive Commands

While the application is running, you can use the following commands:

- `s` - Start network monitoring
- `p` - Pause network monitoring
- `q` - Quit the application
- `h` - Display help
- `r` - Refresh all displays
- `d` - Show network devices with vendor information
- `i` - Show monitored interfaces
- `l` - Show detected loops

## How It Works

SpanScan captures network packets on all interfaces and analyzes them for patterns that indicate network loops or STP issues. It specifically looks for:

1. BPDU (Bridge Protocol Data Units) packets - used by STP
2. Unusually high rates of identical packets - indicates a potential loop
3. Packets with specific destination addresses used in STP (01:80:c2:00:00:00)

When a loop is detected, SpanScan identifies:
- Source MAC address (the device causing the loop)
- Vendor information (Cisco, Juniper, HP/Aruba, etc.)
- Interface where the loop was detected
- Time of detection
- Number of looped packets observed

### Device Tracking

SpanScan monitors all network devices visible to your interfaces, providing:
- MAC address
- Vendor identification
- First and last seen times
- Packet counts
- Which interfaces the device was seen on
- Clear indication when a device is a loop source

This helps network administrators quickly pinpoint the exact source of network issues.

## Workflow

1. Start SpanScan with appropriate privileges
2. Review the available interfaces with the `i` command
3. Press `s` to start monitoring
4. Use `d` to see detected devices and their vendor information
5. If loops are detected, use `l` to view detailed information
6. Pause monitoring with `p` when needed
7. Resume monitoring with `s` at any time

## Troubleshooting

- **Error: "No interfaces found"**: Verify that Npcap/WinPcap is properly installed and that you're running SpanScan as Administrator
- **Error: "Unable to open device"**: Make sure you have administrative privileges and that the network interface exists
- **No packets captured**: Some virtualized environments or network configurations might restrict packet capturing; try on a physical network interface
- **No vendor information**: If vendor lookups fail, a local database of common network equipment vendors is still used

## License

MIT 