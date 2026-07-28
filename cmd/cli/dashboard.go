package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// `fides dashboard` is an interactive terminal dashboard that pulls live stats
// from the Fides server and renders them bomly-`scan --interactive` style: a
// top tab strip, a row of bordered stat cards, and a controls-coverage bar
// panel. It talks to the HTTP API directly (reusing getRequest), NOT via the
// MCP server. Read-only. On a non-TTY it prints a JSON snapshot and exits 0 so
// it degrades cleanly in pipelines instead of hanging.
//
// ponytail: MVP is the Overview tab only. Environments/Trails/Metrics tabs are
// tracked as Phase 2 follow-ups — add them as TabSpec-style entries when needed.

// ----- server response shapes (see cmd/mcp/main.go for the same endpoints) -----

type envView struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Drifts        []string `json:"drifts"`
	ShadowChanges []string `json:"shadowChanges"`
}

type covControl struct {
	Control    string   `json:"control"`
	EnforcedIn []string `json:"enforcedIn"`
	Coverage   float64  `json:"coverage"`
}

type covResp struct {
	TotalEnvironments int          `json:"totalEnvironments"`
	Controls          []covControl `json:"controls"`
}

// ----- async load messages -----

type flowsMsg struct {
	n   int
	err error
}
type policiesMsg struct {
	n   int
	err error
}
type envsMsg struct {
	envs []envView
	err  error
}
type coverageMsg struct {
	cov covResp
	err error
}

// ----- model -----

type dashModel struct {
	config      CLIConfig
	w, h        int
	tab         int
	confirmQuit bool

	flows       int
	flowsErr    error
	flowsLoaded bool

	policies       int
	policiesErr    error
	policiesLoaded bool

	envs       []envView
	envsErr    error
	envsLoaded bool

	cov       covResp
	covErr    error
	covLoaded bool
}

func (m dashModel) Init() tea.Cmd {
	return tea.Batch(m.fetchFlows, m.fetchPolicies, m.fetchEnvs, m.fetchCoverage)
}

// fetch* are tea.Cmds (func() tea.Msg): each hits one endpoint and returns a
// typed message. One slow/failed endpoint never blocks the others or the UI.

func (m dashModel) fetchFlows() tea.Msg {
	body, err := getRequest(m.config, "/api/v1/flows")
	if err != nil {
		return flowsMsg{err: err}
	}
	var a []json.RawMessage
	err = json.Unmarshal([]byte(body), &a)
	return flowsMsg{n: len(a), err: err}
}

func (m dashModel) fetchPolicies() tea.Msg {
	body, err := getRequest(m.config, "/api/v1/policies")
	if err != nil {
		return policiesMsg{err: err}
	}
	var a []json.RawMessage
	err = json.Unmarshal([]byte(body), &a)
	return policiesMsg{n: len(a), err: err}
}

func (m dashModel) fetchEnvs() tea.Msg {
	body, err := getRequest(m.config, "/api/v1/environments")
	if err != nil {
		return envsMsg{err: err}
	}
	var e []envView
	err = json.Unmarshal([]byte(body), &e)
	return envsMsg{envs: e, err: err}
}

func (m dashModel) fetchCoverage() tea.Msg {
	body, err := getRequest(m.config, "/api/v1/controls/coverage")
	if err != nil {
		return coverageMsg{err: err}
	}
	var c covResp
	err = json.Unmarshal([]byte(body), &c)
	return coverageMsg{cov: c, err: err}
}

func (m dashModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			// Two-step quit: first press arms, second confirms.
			if m.confirmQuit {
				return m, tea.Quit
			}
			m.confirmQuit = true
			return m, nil
		case "r":
			m.flowsLoaded, m.policiesLoaded, m.envsLoaded, m.covLoaded = false, false, false, false
			m.flowsErr, m.policiesErr, m.envsErr, m.covErr = nil, nil, nil, nil
			m.confirmQuit = false
			return m, tea.Batch(m.fetchFlows, m.fetchPolicies, m.fetchEnvs, m.fetchCoverage)
		case "tab", "1":
			m.tab = 0 // only Overview for now
		}
		m.confirmQuit = false
	case flowsMsg:
		m.flows, m.flowsErr, m.flowsLoaded = msg.n, msg.err, true
	case policiesMsg:
		m.policies, m.policiesErr, m.policiesLoaded = msg.n, msg.err, true
	case envsMsg:
		m.envs, m.envsErr, m.envsLoaded = msg.envs, msg.err, true
	case coverageMsg:
		m.cov, m.covErr, m.covLoaded = msg.cov, msg.err, true
	}
	return m, nil
}

func (m dashModel) View() string {
	if m.w == 0 {
		m.w = 100
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		m.tabStrip(),
		"",
		m.overview(),
		"",
		m.footer(),
	)
}

// ----- rendering -----

var (
	colTitle  = lipgloss.Color("39")
	colBig    = lipgloss.Color("252")
	colDim    = lipgloss.Color("244")
	colGood   = lipgloss.Color("34")
	colMid    = lipgloss.Color("208")
	colBad    = lipgloss.Color("196")
	colEmpty  = lipgloss.Color("237")
	colBorder = lipgloss.Color("240")
	colActive = lipgloss.Color("220")
)

func (m dashModel) tabStrip() string {
	brand := lipgloss.NewStyle().
		Background(lipgloss.Color("205")).Foreground(lipgloss.Color("231")).
		Bold(true).Padding(0, 1).Render("Fides")
	tabs := []string{"Overview"}
	parts := make([]string, 0, len(tabs))
	for i, t := range tabs {
		lbl := fmt.Sprintf("[%d] %s", i+1, t)
		if i == m.tab {
			parts = append(parts, lipgloss.NewStyle().Foreground(colActive).Bold(true).Render(lbl))
		} else {
			parts = append(parts, lipgloss.NewStyle().Foreground(colDim).Render(lbl))
		}
	}
	sep := lipgloss.NewStyle().Foreground(colDim).Render(" | ")
	return brand + "  " + strings.Join(parts, sep)
}

func (m dashModel) overview() string {
	cardW := (m.w - 8) / 4
	if cardW < 14 {
		cardW = 14
	}

	driftCount := 0
	for _, e := range m.envs {
		if len(e.Drifts) > 0 || len(e.ShadowChanges) > 0 {
			driftCount++
		}
	}
	avg := m.avgCoverage()

	cards := lipgloss.JoinHorizontal(lipgloss.Top,
		statCard("Flows", statVal(m.flowsLoaded, m.flowsErr, fmt.Sprintf("%d", m.flows)), "pipelines", cardW, colTitle),
		" ",
		statCard("Environments", statVal(m.envsLoaded, m.envsErr, fmt.Sprintf("%d", len(m.envs))), fmt.Sprintf("%d with drift", driftCount), cardW, colMid),
		" ",
		statCard("Policies", statVal(m.policiesLoaded, m.policiesErr, fmt.Sprintf("%d", m.policies)), "active", cardW, lipgloss.Color("135")),
		" ",
		statCard("Controls", statVal(m.covLoaded, m.covErr, fmt.Sprintf("%.0f%%", avg*100)), fmt.Sprintf("%d controls", len(m.cov.Controls)), cardW, covColor(avg)),
	)
	return lipgloss.JoinVertical(lipgloss.Left, cards, "", m.coveragePanel(m.w))
}

func statCard(title, big, sub string, w int, accent lipgloss.Color) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(colBorder).
		Padding(0, 1).Width(w).Align(lipgloss.Center)
	inner := lipgloss.JoinVertical(lipgloss.Center,
		lipgloss.NewStyle().Foreground(accent).Bold(true).Render(title),
		lipgloss.NewStyle().Foreground(colBig).Bold(true).Render(big),
		lipgloss.NewStyle().Foreground(colDim).Render(sub),
	)
	return box.Render(inner)
}

func (m dashModel) coveragePanel(w int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(colBorder).
		Padding(0, 1).Width(w - 2)
	title := lipgloss.NewStyle().Foreground(colTitle).Bold(true).Render("Controls Coverage")

	var lines []string
	switch {
	case m.covErr != nil:
		lines = append(lines, lipgloss.NewStyle().Foreground(colBad).Render("error: "+m.covErr.Error()))
	case !m.covLoaded:
		lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render("loading…"))
	case len(m.cov.Controls) == 0:
		lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render("no controls defined"))
	default:
		ctrls := make([]covControl, len(m.cov.Controls))
		copy(ctrls, m.cov.Controls)
		// Weakest coverage first — surface the gaps at the top.
		sort.SliceStable(ctrls, func(i, j int) bool { return ctrls[i].Coverage < ctrls[j].Coverage })
		barW := w - 40
		if barW < 10 {
			barW = 10
		}
		const limit = 8
		for i, c := range ctrls {
			if i >= limit {
				lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render(fmt.Sprintf("… and %d more", len(ctrls)-limit)))
				break
			}
			lines = append(lines, coverageBar(c.Control, c.Coverage, barW))
		}
	}
	return box.Render(title + "\n\n" + strings.Join(lines, "\n"))
}

// coverageBar renders "SOC2-CC7.1            ████████░░░░  67%".
func coverageBar(label string, pct float64, barW int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 1 {
		pct = 1
	}
	filled := int(pct*float64(barW) + 0.5)
	if filled > barW {
		filled = barW
	}
	fill := lipgloss.NewStyle().Foreground(covColor(pct)).Render(strings.Repeat("█", filled))
	empty := lipgloss.NewStyle().Foreground(colEmpty).Render(strings.Repeat("░", barW-filled))
	return fmt.Sprintf("%-24s %s%s %3.0f%%", truncate(label, 24), fill, empty, pct*100)
}

func (m dashModel) footer() string {
	summary := fmt.Sprintf(" Flows: %s · Envs: %s · Policies: %s · Coverage: %s ",
		statVal(m.flowsLoaded, m.flowsErr, fmt.Sprintf("%d", m.flows)),
		statVal(m.envsLoaded, m.envsErr, fmt.Sprintf("%d", len(m.envs))),
		statVal(m.policiesLoaded, m.policiesErr, fmt.Sprintf("%d", m.policies)),
		statVal(m.covLoaded, m.covErr, fmt.Sprintf("%.0f%%", m.avgCoverage()*100)))
	bar := lipgloss.NewStyle().
		Background(lipgloss.Color("24")).Foreground(lipgloss.Color("231")).
		Width(m.w).MaxHeight(1).Render(truncate(summary, m.w))
	help := "tab switch · r refresh · q quit"
	if m.confirmQuit {
		help = "press q again to quit"
	}
	return lipgloss.JoinVertical(lipgloss.Left, bar, lipgloss.NewStyle().Foreground(colDim).Render(help))
}

// ----- helpers -----

func (m dashModel) avgCoverage() float64 {
	if len(m.cov.Controls) == 0 {
		return 0
	}
	var sum float64
	for _, c := range m.cov.Controls {
		sum += c.Coverage
	}
	return sum / float64(len(m.cov.Controls))
}

func covColor(p float64) lipgloss.Color {
	switch {
	case p >= 0.8:
		return colGood
	case p >= 0.4:
		return colMid
	default:
		return colBad
	}
}

func statVal(loaded bool, err error, s string) string {
	if err != nil {
		return "—"
	}
	if !loaded {
		return "…"
	}
	return s
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n == 1 {
		return s[:1]
	}
	return s[:n-1] + "…"
}

// ----- entrypoints -----

func runDashboard(config CLIConfig, _ []string) {
	// Non-TTY (piped / CI): print a JSON snapshot and exit rather than hang.
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		dashboardSnapshot(config)
		return
	}
	m := dashModel{config: config}
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "dashboard error:", err)
		os.Exit(1)
	}
}

func dashboardSnapshot(config CLIConfig) {
	snap := map[string]any{}
	if b, err := getRequest(config, "/api/v1/flows"); err == nil {
		var a []json.RawMessage
		_ = json.Unmarshal([]byte(b), &a)
		snap["flows"] = len(a)
	}
	if b, err := getRequest(config, "/api/v1/environments"); err == nil {
		var e []envView
		_ = json.Unmarshal([]byte(b), &e)
		snap["environments"] = len(e)
	}
	if b, err := getRequest(config, "/api/v1/policies"); err == nil {
		var a []json.RawMessage
		_ = json.Unmarshal([]byte(b), &a)
		snap["policies"] = len(a)
	}
	if b, err := getRequest(config, "/api/v1/controls/coverage"); err == nil {
		var c covResp
		_ = json.Unmarshal([]byte(b), &c)
		snap["controls"] = c
	}
	out, _ := json.MarshalIndent(snap, "", "  ")
	fmt.Println(string(out))
}
