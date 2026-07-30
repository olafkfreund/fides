package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"fides/pkg/cliout"

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
// ponytail: Overview + Environments + Metrics + Policies + Artifacts tabs, each
// over an existing endpoint (no server changes). A dedicated Trails tab is not
// built: there is no org-wide GET /api/v1/trails list endpoint (trails are
// per-flow), and #333 forbids new server endpoints — Artifacts (which carry
// their trail name) covers the trail view. Add a tab = a name in tabNames + a
// case in View().

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

// dfRow is one (environment, ISO-week) deployment count from
// /api/v1/metrics/deployment-frequency (see pkg/api/metrics.go).
type dfRow struct {
	Environment string `json:"environment"`
	Week        string `json:"week"`
	Deployments int    `json:"deployments"`
}

// polView / artView are the subset of /api/v1/policies and /api/v1/artifacts we
// render (see handleListPolicies / handleListArtifacts).
type polView struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}
type artView struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	TrailName string `json:"trail_name"`
}

// ----- async load messages -----

type flowsMsg struct {
	n   int
	err error
}
type policiesMsg struct {
	policies []polView
	err      error
}
type artifactsMsg struct {
	artifacts []artView
	err       error
}
type envsMsg struct {
	envs []envView
	err  error
}
type coverageMsg struct {
	cov covResp
	err error
}
type metricsMsg struct {
	rows []dfRow
	err  error
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
	policyList     []polView
	policiesErr    error
	policiesLoaded bool

	artifacts       []artView
	artifactsErr    error
	artifactsLoaded bool

	envs       []envView
	envsErr    error
	envsLoaded bool

	cov       covResp
	covErr    error
	covLoaded bool

	metrics       []dfRow
	metricsErr    error
	metricsLoaded bool
}

func (m dashModel) Init() tea.Cmd {
	return tea.Batch(m.fetchFlows, m.fetchPolicies, m.fetchEnvs, m.fetchCoverage, m.fetchMetrics, m.fetchArtifacts)
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
	var p []polView
	err = json.Unmarshal([]byte(body), &p)
	return policiesMsg{policies: p, err: err}
}

func (m dashModel) fetchArtifacts() tea.Msg {
	body, err := getRequest(m.config, "/api/v1/artifacts")
	if err != nil {
		return artifactsMsg{err: err}
	}
	var a []artView
	err = json.Unmarshal([]byte(body), &a)
	return artifactsMsg{artifacts: a, err: err}
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

func (m dashModel) fetchMetrics() tea.Msg {
	body, err := getRequest(m.config, "/api/v1/metrics/deployment-frequency?weeks=12")
	if err != nil {
		return metricsMsg{err: err}
	}
	var rows []dfRow
	err = json.Unmarshal([]byte(body), &rows)
	return metricsMsg{rows: rows, err: err}
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
			m.flowsLoaded, m.policiesLoaded, m.envsLoaded, m.covLoaded, m.metricsLoaded, m.artifactsLoaded = false, false, false, false, false, false
			m.flowsErr, m.policiesErr, m.envsErr, m.covErr, m.metricsErr, m.artifactsErr = nil, nil, nil, nil, nil, nil
			m.confirmQuit = false
			return m, tea.Batch(m.fetchFlows, m.fetchPolicies, m.fetchEnvs, m.fetchCoverage, m.fetchMetrics, m.fetchArtifacts)
		case "tab", "right", "l":
			m.tab = (m.tab + 1) % len(tabNames)
		case "shift+tab", "left", "h":
			m.tab = (m.tab - 1 + len(tabNames)) % len(tabNames)
		case "1", "2", "3", "4", "5", "6", "7", "8", "9":
			if n := int(msg.String()[0] - '1'); n < len(tabNames) {
				m.tab = n
			}
		}
		m.confirmQuit = false
	case flowsMsg:
		m.flows, m.flowsErr, m.flowsLoaded = msg.n, msg.err, true
	case policiesMsg:
		m.policyList, m.policies, m.policiesErr, m.policiesLoaded = msg.policies, len(msg.policies), msg.err, true
	case artifactsMsg:
		m.artifacts, m.artifactsErr, m.artifactsLoaded = msg.artifacts, msg.err, true
	case envsMsg:
		m.envs, m.envsErr, m.envsLoaded = msg.envs, msg.err, true
	case coverageMsg:
		m.cov, m.covErr, m.covLoaded = msg.cov, msg.err, true
	case metricsMsg:
		m.metrics, m.metricsErr, m.metricsLoaded = msg.rows, msg.err, true
	}
	return m, nil
}

func (m dashModel) View() string {
	if m.w == 0 {
		m.w = 100
	}
	body := m.overview()
	switch m.tab {
	case 1:
		body = m.environments()
	case 2:
		body = m.metricsPanel()
	case 3:
		body = m.policiesPanel()
	case 4:
		body = m.artifactsPanel()
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		m.tabStrip(),
		"",
		body,
		"",
		m.footer(),
	)
}

// ----- rendering -----

// tabNames is the single source of truth for the tab strip and navigation, so
// tabStrip/Update/View can't drift on how many tabs exist.
var tabNames = []string{"Overview", "Environments", "Metrics", "Policies", "Artifacts"}

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
	parts := make([]string, 0, len(tabNames))
	for i, t := range tabNames {
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

// environments renders the Environments tab: one line per env with its
// compliance status, plus a bounded drift/shadow-change drill-down. Reuses the
// data fetchEnvs already loaded for the Overview — no extra endpoint.
func (m dashModel) environments() string {
	w := m.w
	if w == 0 {
		w = 100
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(colBorder).
		Padding(0, 1).Width(w - 2)
	title := lipgloss.NewStyle().Foreground(colTitle).Bold(true).Render("Environments")

	var lines []string
	switch {
	case m.envsErr != nil:
		lines = append(lines, lipgloss.NewStyle().Foreground(colBad).Render("error: "+m.envsErr.Error()))
	case !m.envsLoaded:
		lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render("loading…"))
	case len(m.envs) == 0:
		lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render("no environments"))
	default:
		for _, e := range m.envs {
			lines = append(lines, envLine(e))
			for _, d := range boundedDetail(e) {
				lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render("    "+d))
			}
		}
	}
	return box.Render(title + "\n\n" + strings.Join(lines, "\n"))
}

// envLine renders "prod             (k8s)     ✓ compliant" or a ⚠ drift summary.
func envLine(e envView) string {
	name := lipgloss.NewStyle().Foreground(colBig).Bold(true).Render(fmt.Sprintf("%-16s", truncate(e.Name, 16)))
	typ := lipgloss.NewStyle().Foreground(colDim).Render(fmt.Sprintf("%-9s", "("+e.Type+")"))
	var status string
	if nd, ns := len(e.Drifts), len(e.ShadowChanges); nd == 0 && ns == 0 {
		status = lipgloss.NewStyle().Foreground(colGood).Render("✓ compliant")
	} else {
		status = lipgloss.NewStyle().Foreground(colMid).Render(fmt.Sprintf("⚠ %d drift, %d shadow", nd, ns))
	}
	return fmt.Sprintf("%s %s %s", name, typ, status)
}

// boundedDetail lists an env's drifts then shadow changes, capped so a noisy
// env can't blow out the panel.
func boundedDetail(e envView) []string {
	const limit = 4
	var out []string
	for _, d := range e.Drifts {
		out = append(out, "drift: "+d)
	}
	for _, s := range e.ShadowChanges {
		out = append(out, "shadow: "+s)
	}
	if len(out) > limit {
		extra := len(out) - limit
		out = append(out[:limit], fmt.Sprintf("… and %d more", extra))
	}
	return out
}

// metrics renders the Metrics tab: DORA deployment frequency over the last 12
// weeks — a sparkline of weekly totals plus a per-week bar breakdown.
func (m dashModel) metricsPanel() string {
	w := m.w
	if w == 0 {
		w = 100
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(colBorder).
		Padding(0, 1).Width(w - 2)
	title := lipgloss.NewStyle().Foreground(colTitle).Bold(true).Render("Deployment Frequency (DORA) — last 12 weeks")

	var lines []string
	switch {
	case m.metricsErr != nil:
		lines = append(lines, lipgloss.NewStyle().Foreground(colBad).Render("error: "+m.metricsErr.Error()))
	case !m.metricsLoaded:
		lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render("loading…"))
	case len(m.metrics) == 0:
		lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render("no deployments recorded"))
	default:
		weeks, counts := weeklyTotals(m.metrics)
		total, max := 0, 0
		for _, c := range counts {
			total += c
			if c > max {
				max = c
			}
		}
		lines = append(lines,
			fmt.Sprintf("%d deployments across %d weeks", total, len(weeks)),
			"",
			lipgloss.NewStyle().Foreground(colTitle).Render(sparkline(counts)),
			"")
		barW := w - 30
		if barW < 10 {
			barW = 10
		}
		for i, wk := range weeks {
			lines = append(lines, intBar(wk, counts[i], max, barW))
		}
	}
	return box.Render(title + "\n\n" + strings.Join(lines, "\n"))
}

// weeklyTotals collapses per-(env,week) rows into ordered weekly totals. Input
// rows are week-ordered (see the endpoint's ORDER BY), so first-seen order is
// chronological.
func weeklyTotals(rows []dfRow) (weeks []string, counts []int) {
	pos := map[string]int{}
	for _, r := range rows {
		i, ok := pos[r.Week]
		if !ok {
			i = len(weeks)
			pos[r.Week] = i
			weeks = append(weeks, r.Week)
			counts = append(counts, 0)
		}
		counts[i] += r.Deployments
	}
	return weeks, counts
}

var sparkChars = []rune("▁▂▃▄▅▆▇█")

// sparkline maps values to block glyphs scaled to the series max (all-zero or
// empty series render as the lowest glyph / empty string).
func sparkline(vals []int) string {
	if len(vals) == 0 {
		return ""
	}
	max := 0
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for _, v := range vals {
		idx := 0
		if max > 0 {
			idx = v * (len(sparkChars) - 1) / max
		}
		b.WriteRune(sparkChars[idx])
	}
	return b.String()
}

// intBar renders "2026-W30     ████████░░░░   7".
func intBar(label string, val, max, barW int) string {
	filled := 0
	if max > 0 {
		filled = val * barW / max
	}
	if filled > barW {
		filled = barW
	}
	fill := lipgloss.NewStyle().Foreground(colGood).Render(strings.Repeat("█", filled))
	empty := lipgloss.NewStyle().Foreground(colEmpty).Render(strings.Repeat("░", barW-filled))
	return fmt.Sprintf("%-12s %s%s %3d", truncate(label, 12), fill, empty, val)
}

// listPanel is the shared box/title/loading/error/empty scaffold for simple
// bounded-list tabs. rows(limit) returns at most `limit` rendered lines; a
// "… and N more" note is appended when total exceeds what was shown.
func (m dashModel) listPanel(title string, loaded bool, loadErr error, emptyMsg string, total int, rows func(limit int) []string) string {
	w := m.w
	if w == 0 {
		w = 100
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(colBorder).
		Padding(0, 1).Width(w - 2)
	head := lipgloss.NewStyle().Foreground(colTitle).Bold(true).Render(title)

	const limit = 12
	var lines []string
	switch {
	case loadErr != nil:
		lines = append(lines, lipgloss.NewStyle().Foreground(colBad).Render("error: "+loadErr.Error()))
	case !loaded:
		lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render("loading…"))
	case total == 0:
		lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render(emptyMsg))
	default:
		lines = rows(limit)
		if more := moreLine(total, len(lines)); more != "" {
			lines = append(lines, lipgloss.NewStyle().Foreground(colDim).Render(more))
		}
	}
	return box.Render(head + "\n\n" + strings.Join(lines, "\n"))
}

// moreLine returns a "… and N more" note when a list was truncated, else "".
func moreLine(total, shown int) string {
	if total > shown {
		return fmt.Sprintf("… and %d more", total-shown)
	}
	return ""
}

func (m dashModel) policiesPanel() string {
	return m.listPanel("Policies", m.policiesLoaded, m.policiesErr, "no policies defined", len(m.policyList),
		func(limit int) []string {
			var lines []string
			for i, p := range m.policyList {
				if i >= limit {
					break
				}
				target := p.Target
				if target == "" {
					target = "—"
				}
				name := lipgloss.NewStyle().Foreground(colBig).Bold(true).Render(fmt.Sprintf("%-24s", truncate(p.Name, 24)))
				lines = append(lines, name+" "+lipgloss.NewStyle().Foreground(colDim).Render("→ "+truncate(target, 40)))
			}
			return lines
		})
}

func (m dashModel) artifactsPanel() string {
	return m.listPanel("Artifacts (newest first)", m.artifactsLoaded, m.artifactsErr, "no artifacts recorded", len(m.artifacts),
		func(limit int) []string {
			var lines []string
			for i, a := range m.artifacts {
				if i >= limit {
					break
				}
				name := lipgloss.NewStyle().Foreground(colBig).Bold(true).Render(fmt.Sprintf("%-28s", truncate(a.Name, 28)))
				typ := lipgloss.NewStyle().Foreground(colDim).Render(fmt.Sprintf("%-8s", a.Type))
				trail := ""
				if a.TrailName != "" {
					trail = lipgloss.NewStyle().Foreground(colDim).Render("→ " + truncate(a.TrailName, 24))
				}
				lines = append(lines, name+" "+typ+" "+trail)
			}
			return lines
		})
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
	if err := cliout.Render(os.Stdout, "json", snap); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
