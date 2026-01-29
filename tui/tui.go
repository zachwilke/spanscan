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

// Theme colors - Modern dark theme with accent colors
var (
	// Primary colors
	primaryColor   = lipgloss.Color("#7C3AED") // Purple
	secondaryColor = lipgloss.Color("#06B6D4") // Cyan
	accentColor    = lipgloss.Color("#F59E0B") // Amber

	// Severity colors
	criticalColor = lipgloss.Color("#EF4444") // Red
	highColor     = lipgloss.Color("#F97316") // Orange
	mediumColor   = lipgloss.Color("#FBBF24") // Yellow
	lowColor      = lipgloss.Color("#22D3EE") // Cyan
	infoColor     = lipgloss.Color("#22C55E") // Green

	// Background colors
	bgDark    = lipgloss.Color("#0F172A") // Slate 900
	bgCard    = lipgloss.Color("#1E293B") // Slate 800
	bgHover   = lipgloss.Color("#334155") // Slate 700
	textMuted = lipgloss.Color("#94A3B8") // Slate 400
	textLight = lipgloss.Color("#F1F5F9") // Slate 100

	// Styles
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(primaryColor).
			Bold(true).
			Padding(0, 2)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(textMuted).
			Italic(true)

	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#475569")).
			Padding(1, 2)

	activeCardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(1, 2)

	headerStyle = lipgloss.NewStyle().
			Foreground(textLight).
			Bold(true).
			MarginBottom(1)

	valueStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			Bold(true)

	mutedStyle = lipgloss.NewStyle().
			Foreground(textMuted)

	criticalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(criticalColor).
			Bold(true).
			Padding(0, 1)

	highStyle = lipgloss.NewStyle().
			Foreground(highColor).
			Bold(true)

	mediumStyle = lipgloss.NewStyle().
			Foreground(mediumColor)

	lowStyle = lipgloss.NewStyle().
			Foreground(lowColor)

	successStyle = lipgloss.NewStyle().
			Foreground(infoColor)

	tabActiveStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(primaryColor).
			Padding(0, 2).
			Bold(true)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(textMuted).
				Background(bgCard).
				Padding(0, 2)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(textLight).
			Background(bgCard).
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(textMuted)
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

	// Create stat cards
	cards := []string{
		m.renderStatCard("📦 Packets", fmt.Sprintf("%v", stats["totalPackets"]), secondaryColor),
		m.renderStatCard("🖥️ Devices", fmt.Sprintf("%v", stats["devicesDetected"]), infoColor),
		m.renderStatCard("🔴 Loops", fmt.Sprintf("%v", stats["loopsDetected"]), m.getLoopColor()),
		m.renderStatCard("🔥 Storms", fmt.Sprintf("%v", stats["broadcastStorms"]), accentColor),
		m.renderStatCard("🔀 Dup MACs", fmt.Sprintf("%v", stats["duplicateMACs"]), mediumColor),
		m.renderStatCard("📡 TCN Count", fmt.Sprintf("%v", stats["tcnCount"]), primaryColor),
	}

	// Arrange cards in a grid
	row1 := lipgloss.JoinHorizontal(lipgloss.Top, cards[0], " ", cards[1], " ", cards[2])
	row2 := lipgloss.JoinHorizontal(lipgloss.Top, cards[3], " ", cards[4], " ", cards[5])

	content := lipgloss.JoinVertical(lipgloss.Left, row1, "", row2)

	// Add recent alerts section
	if len(m.loops) > 0 {
		content = lipgloss.JoinVertical(lipgloss.Left, content, "", m.renderRecentAlerts())
	}

	return content
}

func (m Model) renderWelcome() string {
	welcome := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(primaryColor).
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

func (m Model) renderStatCard(title string, value string, color lipgloss.Color) string {
	cardWidth := (m.width - 10) / 3
	if cardWidth < 20 {
		cardWidth = 20
	}
	if cardWidth > 30 {
		cardWidth = 30
	}

	titleStyled := lipgloss.NewStyle().Foreground(textMuted).Render(title)
	valueStyled := lipgloss.NewStyle().
		Foreground(color).
		Bold(true).
		MarginTop(1).
		Render(value)

	card := lipgloss.JoinVertical(lipgloss.Center, titleStyled, valueStyled)

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#475569")).
		Width(cardWidth).
		Padding(1, 2).
		Align(lipgloss.Center).
		Render(card)
}

func (m Model) renderRecentAlerts() string {
	var alerts []string
	alerts = append(alerts, headerStyle.Render("⚠️ Recent Alerts"))

	for i, loop := range m.loops {
		if i >= 5 {
			break
		}
		severity := m.renderSeverity(loop.Severity)
		alert := fmt.Sprintf("%s %s (%s) on %s",
			severity,
			loop.MACAddress.String(),
			truncate(loop.VendorName, 12),
			truncate(loop.DeviceName, 15),
		)
		alerts = append(alerts, alert)
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(highColor).
		Padding(1, 2).
		Width(m.width - 4).
		Render(strings.Join(alerts, "\n"))
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
		BorderForeground(textMuted).
		Padding(1, 2).
		Width(m.width - 4).
		Render(strings.Join(rows, "\n"))
}

func (m Model) renderTableHeader(columns []string) string {
	header := strings.Join(columns, "  ")
	return lipgloss.NewStyle().Bold(true).Foreground(textLight).Render(header)
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
