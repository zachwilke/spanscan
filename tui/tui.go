package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spanscan/detector"
)

// Tokyo Night color palette
// https://github.com/enkia/tokyo-night-vscode-theme
var (
	// Background colors
	bgDark      = lipgloss.Color("#1a1b26") // Tokyo Night background
	bgHighlight = lipgloss.Color("#24283b") // Tokyo Night highlight
	bgCard      = lipgloss.Color("#1f2335") // Slightly lighter background
	bgSelection = lipgloss.Color("#33467c") // Selection blue

	// Foreground colors
	fgDefault = lipgloss.Color("#a9b1d6") // Default text
	fgBright  = lipgloss.Color("#c0caf5") // Bright text
	fgMuted   = lipgloss.Color("#565f89") // Comments/muted
	fgDark    = lipgloss.Color("#414868") // Darker text

	// Accent colors
	blue    = lipgloss.Color("#7aa2f7") // Primary blue
	cyan    = lipgloss.Color("#7dcfff") // Cyan
	purple  = lipgloss.Color("#bb9af7") // Purple/Magenta
	magenta = lipgloss.Color("#ff007c") // Hot pink
	green   = lipgloss.Color("#9ece6a") // Green
	yellow  = lipgloss.Color("#e0af68") // Yellow/Orange
	orange  = lipgloss.Color("#ff9e64") // Orange
	red     = lipgloss.Color("#f7768e") // Red
	teal    = lipgloss.Color("#73daca") // Teal

	// Semantic colors
	primaryColor   = blue
	secondaryColor = cyan
	accentColor    = purple

	// Severity colors (using Tokyo Night palette)
	criticalColor = red
	highColor     = orange
	mediumColor   = yellow
	lowColor      = cyan
	infoColor     = green

	// Styles
	titleStyle = lipgloss.NewStyle().
			Foreground(fgBright).
			Background(blue).
			Bold(true).
			Padding(0, 2)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(fgMuted).
			Italic(true)

	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(fgDark).
			Padding(1, 2)

	activeCardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(blue).
			Padding(1, 2)

	headerStyle = lipgloss.NewStyle().
			Foreground(fgBright).
			Bold(true).
			MarginBottom(1)

	valueStyle = lipgloss.NewStyle().
			Foreground(cyan).
			Bold(true)

	mutedStyle = lipgloss.NewStyle().
			Foreground(fgMuted)

	criticalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#1a1b26")).
			Background(red).
			Bold(true).
			Padding(0, 1)

	highStyle = lipgloss.NewStyle().
			Foreground(orange).
			Bold(true)

	mediumStyle = lipgloss.NewStyle().
			Foreground(yellow)

	lowStyle = lipgloss.NewStyle().
			Foreground(cyan)

	successStyle = lipgloss.NewStyle().
			Foreground(green)

	tabActiveStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#1a1b26")).
			Background(blue).
			Padding(0, 2).
			Bold(true)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(fgMuted).
				Background(bgCard).
				Padding(0, 2)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(fgDefault).
			Background(bgHighlight).
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(fgMuted)

	// Logo style with Tokyo Night purple
	logoStyle = lipgloss.NewStyle().
			Foreground(purple).
			Bold(true)
)

// Tab represents a navigation tab
type Tab int

const (
	TabDashboard Tab = iota
	TabLoops
	TabDevices
	TabSTP
	TabLogs
)

func (t Tab) String() string {
	switch t {
	case TabDashboard:
		return "📊 Dashboard"
	case TabLoops:
		return "🔴 Loops"
	case TabDevices:
		return "🖥️ Devices"
	case TabSTP:
		return "🌳 STP"
	case TabLogs:
		return "📋 Logs"
	default:
		return "Unknown"
	}
}

// Model represents the TUI state
type Model struct {
	detector     *detector.Detector
	width        int
	height       int
	activeTab    Tab
	isMonitoring bool
	startTime    time.Time
	spinner      spinner.Model
	viewport     viewport.Model
	ready        bool
	scrollPos    int

	// Cached data for display
	loops   []*detector.LoopInfo
	devices []*detector.DeviceInfo
	storms  []*detector.BroadcastStormInfo
	dupMACs []*detector.DuplicateMACEvent
}

// Messages
type tickMsg time.Time
type detectorStartedMsg struct{}
type detectorStoppedMsg struct{}

// New creates a new TUI model
func New(det *detector.Detector) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(primaryColor)

	return Model{
		detector:  det,
		activeTab: TabDashboard,
		spinner:   s,
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update handles messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.isMonitoring {
				m.detector.Stop()
			}
			return m, tea.Quit
		case "tab", "right", "l":
			m.activeTab = (m.activeTab + 1) % 5
		case "shift+tab", "left", "h":
			m.activeTab = (m.activeTab + 4) % 5
		case "s":
			if !m.isMonitoring {
				m.isMonitoring = true
				m.startTime = time.Now()
				go func() {
					m.detector.Start()
				}()
			}
		case "p":
			if m.isMonitoring {
				m.detector.Stop()
				m.isMonitoring = false
			}
		case "1":
			m.activeTab = TabDashboard
		case "2":
			m.activeTab = TabLoops
		case "3":
			m.activeTab = TabDevices
		case "4":
			m.activeTab = TabSTP
		case "5":
			m.activeTab = TabLogs
		case "j", "down":
			m.scrollPos++
		case "k", "up":
			if m.scrollPos > 0 {
				m.scrollPos--
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true

	case tickMsg:
		// Update cached data
		if m.isMonitoring {
			m.loops = m.detector.GetDetectedLoops()
			m.devices = m.detector.GetSeenDevices()
			m.storms = m.detector.GetBroadcastStorms()
			m.dupMACs = m.detector.GetDuplicateMACs()
		}
		cmds = append(cmds, tickCmd())

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// View renders the UI
func (m Model) View() string {
	if !m.ready {
		return "\n  Loading..."
	}

	var b strings.Builder

	// Header
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	// Tabs
	b.WriteString(m.renderTabs())
	b.WriteString("\n\n")

	// Content based on active tab
	contentHeight := m.height - 10 // Reserve space for header, tabs, status bar
	content := m.renderContent(contentHeight)
	b.WriteString(content)

	// Status bar at bottom
	b.WriteString("\n")
	b.WriteString(m.renderStatusBar())

	return b.String()
}

func (m Model) renderHeader() string {
	logo := `
   ____                   ____                  
  / ___| _ __   __ _ _ __/ ___|  ___ __ _ _ __  
  \___ \| '_ \ / _` + "`" + ` | '_ \___ \ / __/ _` + "`" + ` | '_ \ 
   ___) | |_) | (_| | | | |__) | (_| (_| | | | |
  |____/| .__/ \__,_|_| |_|____/ \___\__,_|_| |_|
        |_|`

	logoStyle := lipgloss.NewStyle().
		Foreground(primaryColor).
		Bold(true)

	statusText := ""
	if m.isMonitoring {
		elapsed := time.Since(m.startTime)
		statusText = fmt.Sprintf("%s Monitoring • %s", m.spinner.View(), formatDuration(elapsed))
	} else {
		statusText = mutedStyle.Render("● Not Monitoring - Press 's' to start")
	}

	header := lipgloss.JoinHorizontal(
		lipgloss.Top,
		logoStyle.Render(logo),
		"  ",
		lipgloss.NewStyle().MarginTop(2).Render(statusText),
	)

	return header
}

func (m Model) renderTabs() string {
	tabs := []Tab{TabDashboard, TabLoops, TabDevices, TabSTP, TabLogs}
	var renderedTabs []string

	for _, tab := range tabs {
		if tab == m.activeTab {
			renderedTabs = append(renderedTabs, tabActiveStyle.Render(tab.String()))
		} else {
			renderedTabs = append(renderedTabs, tabInactiveStyle.Render(tab.String()))
		}
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
}

func (m Model) renderContent(height int) string {
	switch m.activeTab {
	case TabDashboard:
		return m.renderDashboard(height)
	case TabLoops:
		return m.renderLoopsTab(height)
	case TabDevices:
		return m.renderDevicesTab(height)
	case TabSTP:
		return m.renderSTPTab(height)
	case TabLogs:
		return m.renderLogsTab(height)
	default:
		return ""
	}
}

func (m Model) renderDashboard(height int) string {
	if !m.isMonitoring {
		return m.renderWelcome()
	}

	// Stats cards
	stats := m.detector.GetStats()

	// Calculate widths for side-by-side layout
	statsWidth := (m.width * 2) / 3
	alertsWidth := m.width - statsWidth - 4

	// Card width for 2-column grid within stats section
	cardWidth := (statsWidth - 6) / 2
	if cardWidth < 18 {
		cardWidth = 18
	}
	if cardWidth > 28 {
		cardWidth = 28
	}

	// Create stat cards with icons
	packetsCard := m.renderStatCardSized("Packets", fmt.Sprintf("%v", stats["totalPackets"]), "📦", cyan, cardWidth)
	devicesCard := m.renderStatCardSized("Devices", fmt.Sprintf("%v", stats["devicesDetected"]), "🖥️", green, cardWidth)
	loopsCard := m.renderStatCardSized("Loops", fmt.Sprintf("%v", stats["loopsDetected"]), "🔴", m.getLoopColor(), cardWidth)
	dupMACsCard := m.renderStatCardSized("Dup MACs", fmt.Sprintf("%v", stats["duplicateMACs"]), "🔀", yellow, cardWidth)
	stormsCard := m.renderStatCardSized("Storms", fmt.Sprintf("%v", stats["broadcastStorms"]), "⚡", orange, cardWidth)
	tcnCard := m.renderStatCardSized("TCN Count", fmt.Sprintf("%v", stats["tcnCount"]), "🔗", purple, cardWidth)

	// Arrange cards in 3 rows, 2 columns
	row1 := lipgloss.JoinHorizontal(lipgloss.Top, packetsCard, " ", devicesCard)
	row2 := lipgloss.JoinHorizontal(lipgloss.Top, loopsCard, " ", dupMACsCard)
	row3 := lipgloss.JoinHorizontal(lipgloss.Top, stormsCard, " ", tcnCard)

	statsSection := lipgloss.JoinVertical(lipgloss.Left, row1, "", row2, "", row3)

	// Recent Alerts panel on the right
	alertsPanel := m.renderAlertsPanel(alertsWidth, height-4)

	// Join stats and alerts side by side
	content := lipgloss.JoinHorizontal(lipgloss.Top, statsSection, "  ", alertsPanel)

	return content
}

func (m Model) renderWelcome() string {
	welcome := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(blue).
		Padding(2, 4).
		Width(60).
		Align(lipgloss.Center).
		Render(
			headerStyle.Render("Welcome to SpanScan!") + "\n\n" +
				mutedStyle.Render("Network Loop & STP Issue Detector") + "\n\n" +
				"Press " + valueStyle.Render("s") + " to start monitoring\n" +
				"Press " + valueStyle.Render("q") + " to quit\n\n" +
				subtitleStyle.Render("Use Tab or 1-5 to switch views"))

	return lipgloss.Place(m.width-4, 15, lipgloss.Center, lipgloss.Center, welcome)
}

func (m Model) renderStatCardSized(title string, value string, icon string, color lipgloss.Color, width int) string {
	// Icon and title on same line
	titleLine := lipgloss.NewStyle().Foreground(fgMuted).Render(title) +
		"  " +
		lipgloss.NewStyle().Foreground(fgDark).Render(icon)

	// Large value below
	valueLine := lipgloss.NewStyle().
		Foreground(color).
		Bold(true).
		Render(value)

	card := lipgloss.JoinVertical(lipgloss.Left, titleLine, "", valueLine)

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(fgDark).
		Width(width).
		Height(5).
		Padding(1, 2).
		Render(card)
}

func (m Model) renderStatCard(title string, value string, color lipgloss.Color) string {
	return m.renderStatCardSized(title, value, "", color, 24)
}

func (m Model) renderAlertsPanel(width int, height int) string {
	headerText := lipgloss.NewStyle().
		Foreground(fgBright).
		Bold(true).
		Render("Recent Alerts")

	var alertLines []string
	alertLines = append(alertLines, headerText)
	alertLines = append(alertLines, "")

	if len(m.loops) == 0 && len(m.storms) == 0 && len(m.dupMACs) == 0 {
		alertLines = append(alertLines, mutedStyle.Render("No alerts yet"))
	} else {
		// Add loop alerts
		for i, loop := range m.loops {
			if i >= 4 {
				break
			}
			severity := m.renderSeverityBadge(loop.Severity)
			details := fmt.Sprintf("%s (%s)",
				truncate(loop.VendorName, 20),
				truncate(loop.DeviceName, 12),
			)
			timestamp := loop.DetectedTime.Format("15:04:05")

			alertLines = append(alertLines, severity+": "+details)
			alertLines = append(alertLines, mutedStyle.Render(timestamp))
			alertLines = append(alertLines, "")
		}

		// Add storm alerts
		for _, storm := range m.storms {
			if storm.IsActive {
				alertLines = append(alertLines, criticalStyle.Render("CRITICAL")+": Broadcast")
				alertLines = append(alertLines, fmt.Sprintf("Storm Detected (%s)", truncate(storm.InterfaceName, 10)))
				alertLines = append(alertLines, mutedStyle.Render(storm.DetectedTime.Format("15:04:05")))
				alertLines = append(alertLines, "")
			}
		}

		// Add duplicate MAC alerts
		for _, dup := range m.dupMACs {
			alertLines = append(alertLines, mediumStyle.Render("WARNING")+": Duplicate MAC")
			alertLines = append(alertLines, "Address Found (MAC")
			alertLines = append(alertLines, truncate(dup.MACAddress.String(), 17)+")")
			alertLines = append(alertLines, mutedStyle.Render(dup.FirstSeen.Format("15:04:05")))
			alertLines = append(alertLines, "")
		}
	}

	content := strings.Join(alertLines, "\n")

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(orange).
		Width(width).
		Height(height).
		Padding(1, 2).
		Render(content)
}

func (m Model) renderSeverityBadge(severity detector.LoopSeverity) string {
	switch severity {
	case detector.SeverityCritical:
		return criticalStyle.Render("CRITICAL")
	case detector.SeverityHigh:
		return highStyle.Render("HIGH")
	case detector.SeverityMedium:
		return mediumStyle.Render("WARNING")
	case detector.SeverityLow:
		return lowStyle.Render("INFO")
	default:
		return mutedStyle.Render("UNKNOWN")
	}
}

func (m Model) renderRecentAlerts() string {
	return m.renderAlertsPanel(m.width-4, 10)
}

func (m Model) renderLoopsTab(height int) string {
	if len(m.loops) == 0 {
		return m.renderEmptyState("🔴", "No Loops Detected", "Network is healthy")
	}

	var rows []string
	rows = append(rows, m.renderTableHeader([]string{"SEVERITY", "MAC ADDRESS", "VENDOR", "INTERFACE", "CONFIDENCE", "PACKETS"}))
	rows = append(rows, strings.Repeat("─", m.width-4))

	for i, loop := range m.loops {
		if i >= height-4 {
			break
		}
		row := m.renderLoopRow(loop)
		rows = append(rows, row)
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(highColor).
		Padding(1, 2).
		Width(m.width - 4).
		Render(strings.Join(rows, "\n"))
}

func (m Model) renderLoopRow(loop *detector.LoopInfo) string {
	severity := m.renderSeverity(loop.Severity)
	confidence := fmt.Sprintf("%.0f%%", loop.ConfidenceScore*100)

	return fmt.Sprintf("%-12s %-20s %-14s %-18s %-12s %d",
		severity,
		loop.MACAddress.String(),
		truncate(loop.VendorName, 12),
		truncate(loop.DeviceName, 16),
		confidence,
		loop.PacketCount,
	)
}

func (m Model) renderDevicesTab(height int) string {
	if len(m.devices) == 0 {
		return m.renderEmptyState("🖥️", "No Devices Detected", "Start monitoring to discover devices")
	}

	var rows []string
	rows = append(rows, m.renderTableHeader([]string{"MAC ADDRESS", "VENDOR", "PACKETS", "FIRST SEEN", "INTERFACES", "STATUS"}))
	rows = append(rows, strings.Repeat("─", m.width-4))

	for i, device := range m.devices {
		if i >= height-4 {
			break
		}
		row := m.renderDeviceRow(device)
		rows = append(rows, row)
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(secondaryColor).
		Padding(1, 2).
		Width(m.width - 4).
		Render(strings.Join(rows, "\n"))
}

func (m Model) renderDeviceRow(device *detector.DeviceInfo) string {
	status := successStyle.Render("●")
	if device.IsLoopSource {
		status = criticalStyle.Render("⚠ LOOP")
	}

	interfaces := len(device.Interfaces)
	interfaceStr := fmt.Sprintf("%d iface", interfaces)
	if interfaces > 1 {
		interfaceStr = mediumStyle.Render(fmt.Sprintf("%d ifaces!", interfaces))
	}

	return fmt.Sprintf("%-20s %-14s %-10d %-12s %-12s %s",
		device.MACAddress.String(),
		truncate(device.VendorName, 12),
		device.PacketCount,
		device.FirstSeen.Format("15:04:05"),
		interfaceStr,
		status,
	)
}

func (m Model) renderSTPTab(height int) string {
	parser := m.detector.GetSTPParser()
	roots := parser.GetRootBridges()
	tcnCount := parser.GetTCNCount()
	recentBPDUs := parser.GetRecentBPDUs(10)

	var sections []string

	// Root bridges section
	rootSection := headerStyle.Render("🌳 Root Bridges") + "\n"
	if len(roots) == 0 {
		rootSection += mutedStyle.Render("No STP root bridges detected")
	} else if len(roots) == 1 {
		rootSection += successStyle.Render("✓ Single root bridge (healthy)") + "\n"
		rootSection += fmt.Sprintf("  Root: %s", roots[0].String())
	} else {
		rootSection += criticalStyle.Render(fmt.Sprintf("⚠ MULTIPLE ROOTS DETECTED: %d", len(roots))) + "\n"
		for i, root := range roots {
			rootSection += fmt.Sprintf("  %d. %s\n", i+1, root.String())
		}
	}
	sections = append(sections, rootSection)

	// TCN section
	tcnSection := headerStyle.Render("📡 Topology Changes") + "\n"
	tcnSection += fmt.Sprintf("Total TCNs: %s", valueStyle.Render(fmt.Sprintf("%d", tcnCount)))
	if tcnCount > 10 {
		tcnSection += "\n" + mediumStyle.Render("⚠ High topology change count - network may be unstable")
	}
	sections = append(sections, tcnSection)

	// Recent BPDUs
	bpduSection := headerStyle.Render("📋 Recent BPDUs") + "\n"
	if len(recentBPDUs) == 0 {
		bpduSection += mutedStyle.Render("No BPDUs captured yet")
	} else {
		for _, bpdu := range recentBPDUs {
			bpduSection += fmt.Sprintf("  %s - %s from %s\n",
				bpdu.CaptureTime.Format("15:04:05"),
				bpdu.BPDUTypeString(),
				bpdu.SenderBridgeID.String(),
			)
		}
	}
	sections = append(sections, bpduSection)

	content := strings.Join(sections, "\n\n")

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(primaryColor).
		Padding(1, 2).
		Width(m.width - 4).
		Render(content)
}

func (m Model) renderLogsTab(height int) string {
	logger := m.detector.GetLogger()
	events := logger.GetEvents()

	if len(events) == 0 {
		return m.renderEmptyState("📋", "No Events", "Events will appear here")
	}

	var rows []string
	rows = append(rows, m.renderTableHeader([]string{"TIME", "TYPE", "SEVERITY", "MESSAGE"}))
	rows = append(rows, strings.Repeat("─", m.width-4))

	// Show most recent events first
	start := len(events) - height + 4
	if start < 0 {
		start = 0
	}

	for i := len(events) - 1; i >= start; i-- {
		event := events[i]
		row := fmt.Sprintf("%-10s %-18s %-10s %s",
			event.Timestamp.Format("15:04:05"),
			truncate(string(event.EventType), 16),
			event.Severity.String(),
			truncate(event.Message, 40),
		)
		rows = append(rows, row)
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(fgMuted).
		Padding(1, 2).
		Width(m.width - 4).
		Render(strings.Join(rows, "\n"))
}

func (m Model) renderTableHeader(columns []string) string {
	header := strings.Join(columns, "  ")
	return lipgloss.NewStyle().Bold(true).Foreground(fgBright).Render(header)
}

func (m Model) renderEmptyState(icon, title, subtitle string) string {
	content := lipgloss.JoinVertical(
		lipgloss.Center,
		lipgloss.NewStyle().MarginBottom(1).Render(icon),
		headerStyle.Render(title),
		mutedStyle.Render(subtitle),
	)

	return lipgloss.Place(m.width-4, 10, lipgloss.Center, lipgloss.Center, content)
}

func (m Model) renderSeverity(severity detector.LoopSeverity) string {
	switch severity {
	case detector.SeverityCritical:
		return criticalStyle.Render("CRITICAL")
	case detector.SeverityHigh:
		return highStyle.Render("HIGH")
	case detector.SeverityMedium:
		return mediumStyle.Render("MEDIUM")
	case detector.SeverityLow:
		return lowStyle.Render("LOW")
	default:
		return mutedStyle.Render("UNKNOWN")
	}
}

func (m Model) renderStatusBar() string {
	left := " SpanScan v2.0"

	help := "s:start  p:pause  Tab:switch  q:quit  ↑↓:scroll"

	right := ""
	if m.isMonitoring {
		right = fmt.Sprintf("📊 %d loops | %d devices ",
			len(m.loops),
			len(m.devices),
		)
	}

	// Calculate padding
	padding := m.width - len(left) - len(help) - len(right) - 4
	if padding < 0 {
		padding = 0
	}

	bar := left + strings.Repeat(" ", padding/2) + helpStyle.Render(help) + strings.Repeat(" ", padding/2) + right

	return statusBarStyle.Width(m.width).Render(bar)
}

func (m Model) getLoopColor() lipgloss.Color {
	if len(m.loops) == 0 {
		return infoColor
	}
	// Check for critical loops
	for _, loop := range m.loops {
		if loop.Severity == detector.SeverityCritical {
			return criticalColor
		}
	}
	return highColor
}

// Helper functions
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
