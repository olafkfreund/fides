package main

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// dashFixture returns a dashModel pre-loaded with representative data across
// every tab, so View()/rendering helpers exercise their non-empty,
// non-loading, non-error branches.
func dashFixture() dashModel {
	return dashModel{
		w: 120, h: 40,
		flows: 3, flowsLoaded: true,
		policies: 2, policiesLoaded: true,
		policyList: []polView{
			{Name: "no-secrets", Target: "prod"},
			{Name: "sbom-required", Target: ""},
		},
		artifacts: []artView{
			{Name: "app.tar", Type: "image", TrailName: "trail-1"},
			{Name: "sbom.json", Type: "sbom", TrailName: ""},
		},
		artifactsLoaded: true,
		envs: []envView{
			{Name: "prod", Type: "k8s"},
			{Name: "staging", Type: "k8s", Drifts: []string{"d1"}, ShadowChanges: []string{"s1"}},
		},
		envsLoaded: true,
		cov: covResp{
			TotalEnvironments: 2,
			Controls: []covControl{
				{Control: "SOC2-CC7.1", EnforcedIn: []string{"prod"}, Coverage: 0.9},
				{Control: "SOC2-CC6.1", Coverage: 0.1},
			},
		},
		covLoaded: true,
		metrics: []dfRow{
			{Environment: "prod", Week: "2026-W29", Deployments: 2},
			{Environment: "prod", Week: "2026-W30", Deployments: 5},
		},
		metricsLoaded: true,
	}
}

// ----- Update -----

func TestDashUpdate_WindowSize(t *testing.T) {
	m := dashModel{}
	next, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m2 := next.(dashModel)
	if m2.w != 80 || m2.h != 24 {
		t.Fatalf("got w=%d h=%d, want 80x24", m2.w, m2.h)
	}
	if cmd != nil {
		t.Errorf("expected nil cmd, got %v", cmd)
	}
}

func TestDashUpdate_QuitArmsThenConfirms(t *testing.T) {
	m := dashModel{}
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	m = next.(dashModel)
	if !m.confirmQuit {
		t.Fatal("first q should arm confirmQuit")
	}
	if cmd != nil {
		t.Errorf("first q should not quit yet, got cmd %v", cmd)
	}
	next, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	m = next.(dashModel)
	if cmd == nil {
		t.Fatal("second q should return tea.Quit")
	}
}

func TestDashUpdate_EscAndCtrlCAlsoQuit(t *testing.T) {
	for _, km := range []tea.KeyMsg{
		{Type: tea.KeyEsc},
		{Type: tea.KeyCtrlC},
	} {
		m := dashModel{confirmQuit: true}
		_, cmd := m.Update(km)
		if cmd == nil {
			t.Errorf("key %v with confirmQuit=true should quit", km)
		}
	}
}

func TestDashUpdate_AnyOtherKeyDisarmsQuit(t *testing.T) {
	m := dashModel{confirmQuit: true}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	m = next.(dashModel)
	if m.confirmQuit {
		t.Fatal("an unrelated key should disarm confirmQuit")
	}
}

func TestDashUpdate_TabNavigation(t *testing.T) {
	m := dashModel{tab: 0}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = next.(dashModel)
	if m.tab != 1 {
		t.Fatalf("tab after 'tab' = %d, want 1", m.tab)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRight})
	m = next.(dashModel)
	if m.tab != 2 {
		t.Fatalf("tab after 'right' = %d, want 2", m.tab)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	m = next.(dashModel)
	if m.tab != 1 {
		t.Fatalf("tab after 'shift+tab' = %d, want 1", m.tab)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	m = next.(dashModel)
	if m.tab != 0 {
		t.Fatalf("tab after 'left' = %d, want 0", m.tab)
	}

	// Wraps around backwards from 0.
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	m = next.(dashModel)
	if m.tab != len(tabNames)-1 {
		t.Fatalf("tab after wrap = %d, want %d", m.tab, len(tabNames)-1)
	}
}

func TestDashUpdate_NumberKeySelectsTab(t *testing.T) {
	m := dashModel{tab: 0}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	m = next.(dashModel)
	if m.tab != 2 {
		t.Fatalf("tab after '3' = %d, want 2", m.tab)
	}

	// Out-of-range digit (beyond len(tabNames)) leaves tab unchanged.
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("9")})
	m2 := next.(dashModel)
	if m2.tab != m.tab {
		t.Fatalf("out-of-range digit changed tab to %d, want unchanged %d", m2.tab, m.tab)
	}
}

func TestDashUpdate_RefreshResetsLoadedFlags(t *testing.T) {
	m := dashFixture()
	m.confirmQuit = true
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m = next.(dashModel)
	if m.flowsLoaded || m.policiesLoaded || m.envsLoaded || m.covLoaded || m.metricsLoaded || m.artifactsLoaded {
		t.Fatal("refresh should clear all *Loaded flags")
	}
	if m.confirmQuit {
		t.Fatal("refresh should disarm confirmQuit")
	}
	if cmd == nil {
		t.Fatal("refresh should return a batch of fetch cmds")
	}
}

func TestDashUpdate_LoadMessages(t *testing.T) {
	m := dashModel{}

	next, _ := m.Update(flowsMsg{n: 5})
	m = next.(dashModel)
	if !m.flowsLoaded || m.flows != 5 || m.flowsErr != nil {
		t.Fatalf("flowsMsg not applied: %+v", m)
	}

	next, _ = m.Update(policiesMsg{policies: []polView{{Name: "p1"}}})
	m = next.(dashModel)
	if !m.policiesLoaded || m.policies != 1 || len(m.policyList) != 1 {
		t.Fatalf("policiesMsg not applied: %+v", m)
	}

	next, _ = m.Update(artifactsMsg{artifacts: []artView{{Name: "a1"}}})
	m = next.(dashModel)
	if !m.artifactsLoaded || len(m.artifacts) != 1 {
		t.Fatalf("artifactsMsg not applied: %+v", m)
	}

	next, _ = m.Update(envsMsg{envs: []envView{{Name: "e1"}}})
	m = next.(dashModel)
	if !m.envsLoaded || len(m.envs) != 1 {
		t.Fatalf("envsMsg not applied: %+v", m)
	}

	next, _ = m.Update(coverageMsg{cov: covResp{TotalEnvironments: 2}})
	m = next.(dashModel)
	if !m.covLoaded || m.cov.TotalEnvironments != 2 {
		t.Fatalf("coverageMsg not applied: %+v", m)
	}

	next, _ = m.Update(metricsMsg{rows: []dfRow{{Week: "w1"}}})
	m = next.(dashModel)
	if !m.metricsLoaded || len(m.metrics) != 1 {
		t.Fatalf("metricsMsg not applied: %+v", m)
	}

	// Error variants set the *Err field and still mark loaded.
	next, _ = m.Update(flowsMsg{err: errors.New("boom")})
	m = next.(dashModel)
	if m.flowsErr == nil || !m.flowsLoaded {
		t.Fatalf("errored flowsMsg not applied: %+v", m)
	}
}

func TestDashInit_BatchesAllFetches(t *testing.T) {
	m := dashModel{}
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("Init() should return a non-nil batch cmd")
	}
}

// ----- View / rendering -----

func TestDashView_AllTabsContainExpectedData(t *testing.T) {
	m := dashFixture()

	for tab, want := range map[int]string{
		0: "Flows",
		1: "staging",
		2: "Deployment Frequency",
		3: "no-secrets",
		4: "app.tar",
	} {
		m.tab = tab
		out := m.View()
		if !strings.Contains(out, want) {
			t.Errorf("tab %d view missing %q; got:\n%s", tab, want, out)
		}
	}
}

func TestDashView_ZeroWidthDefaultsTo100(t *testing.T) {
	m := dashModel{} // w == 0
	out := m.View()
	if out == "" {
		t.Fatal("expected non-empty view even with zero width")
	}
}

func TestDashView_LoadingAndErrorStates(t *testing.T) {
	m := dashModel{w: 100}
	out := m.View()
	if !strings.Contains(out, "loading") {
		t.Errorf("unloaded overview should show loading indicator, got:\n%s", out)
	}

	m.covErr = errors.New("server down")
	m.covLoaded = true
	out = m.View()
	if !strings.Contains(out, "error: server down") {
		t.Errorf("coverage error not rendered, got:\n%s", out)
	}
}

func TestDashView_EmptyStates(t *testing.T) {
	m := dashModel{
		w:               100,
		envsLoaded:      true,
		policiesLoaded:  true,
		artifactsLoaded: true,
		metricsLoaded:   true,
		covLoaded:       true,
	}
	m.tab = 1
	if out := m.View(); !strings.Contains(out, "no environments") {
		t.Errorf("empty environments view = %q", out)
	}
	m.tab = 2
	if out := m.View(); !strings.Contains(out, "no deployments recorded") {
		t.Errorf("empty metrics view = %q", out)
	}
	m.tab = 3
	if out := m.View(); !strings.Contains(out, "no policies defined") {
		t.Errorf("empty policies view = %q", out)
	}
	m.tab = 4
	if out := m.View(); !strings.Contains(out, "no artifacts recorded") {
		t.Errorf("empty artifacts view = %q", out)
	}
}

func TestDashFooter_ConfirmQuitHelpText(t *testing.T) {
	m := dashFixture()
	if !strings.Contains(m.footer(), "r refresh") {
		t.Errorf("normal footer missing hint")
	}
	m.confirmQuit = true
	if !strings.Contains(m.footer(), "press q again") {
		t.Errorf("confirmQuit footer missing warning")
	}
}

func TestStatCardRendersFields(t *testing.T) {
	out := statCard("Flows", "3", "pipelines", 20, colTitle)
	for _, want := range []string{"Flows", "3", "pipelines"} {
		if !strings.Contains(out, want) {
			t.Errorf("statCard missing %q in:\n%s", want, out)
		}
	}
}

func TestTabStripHighlightsActiveTab(t *testing.T) {
	m := dashModel{tab: 2}
	out := m.tabStrip()
	if !strings.Contains(out, "[3] Metrics") {
		t.Errorf("tabStrip missing active tab label, got:\n%s", out)
	}
	if !strings.Contains(out, "Fides") {
		t.Errorf("tabStrip missing brand, got:\n%s", out)
	}
}

func TestCovColorThresholds(t *testing.T) {
	cases := []struct {
		p    float64
		want lipgloss.Color
	}{
		{0.9, colGood},
		{0.5, colMid},
		{0.1, colBad},
	}
	for _, c := range cases {
		if got := covColor(c.p); got != c.want {
			t.Errorf("covColor(%v) = %v, want %v", c.p, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 0, ""},
		{"hello", -1, ""},
		{"hello", 1, "h"},
		{"hello world", 5, "hell…"},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.n); got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// ----- fetch* commands -----

func TestDashFetchers_Success(t *testing.T) {
	srv, _ := recordingServer(t, `[{"a":1},{"b":2}]`)
	m := dashModel{config: cfg(srv)}

	msg := m.fetchFlows()
	fm, ok := msg.(flowsMsg)
	if !ok || fm.err != nil || fm.n != 2 {
		t.Fatalf("fetchFlows = %#v", msg)
	}
}

func TestDashFetchers_Policies(t *testing.T) {
	srv, _ := recordingServer(t, `[{"name":"p1","target":"prod"}]`)
	m := dashModel{config: cfg(srv)}
	msg := m.fetchPolicies().(policiesMsg)
	if msg.err != nil || len(msg.policies) != 1 || msg.policies[0].Name != "p1" {
		t.Fatalf("fetchPolicies = %#v", msg)
	}
}

func TestDashFetchers_Artifacts(t *testing.T) {
	srv, _ := recordingServer(t, `[{"name":"a1","type":"image"}]`)
	m := dashModel{config: cfg(srv)}
	msg := m.fetchArtifacts().(artifactsMsg)
	if msg.err != nil || len(msg.artifacts) != 1 {
		t.Fatalf("fetchArtifacts = %#v", msg)
	}
}

func TestDashFetchers_Envs(t *testing.T) {
	srv, _ := recordingServer(t, `[{"name":"prod","type":"k8s"}]`)
	m := dashModel{config: cfg(srv)}
	msg := m.fetchEnvs().(envsMsg)
	if msg.err != nil || len(msg.envs) != 1 {
		t.Fatalf("fetchEnvs = %#v", msg)
	}
}

func TestDashFetchers_Coverage(t *testing.T) {
	srv, _ := recordingServer(t, `{"totalEnvironments":3,"controls":[]}`)
	m := dashModel{config: cfg(srv)}
	msg := m.fetchCoverage().(coverageMsg)
	if msg.err != nil || msg.cov.TotalEnvironments != 3 {
		t.Fatalf("fetchCoverage = %#v", msg)
	}
}

func TestDashFetchers_Metrics(t *testing.T) {
	srv, _ := recordingServer(t, `[{"environment":"prod","week":"2026-W29","deployments":4}]`)
	m := dashModel{config: cfg(srv)}
	msg := m.fetchMetrics().(metricsMsg)
	if msg.err != nil || len(msg.rows) != 1 || msg.rows[0].Deployments != 4 {
		t.Fatalf("fetchMetrics = %#v", msg)
	}
}

func TestDashFetchers_ErrorPropagates(t *testing.T) {
	// An unreachable server URL makes getRequest fail, which every fetch*
	// must surface as msg.err rather than panicking.
	m := dashModel{config: CLIConfig{ServerURL: "http://127.0.0.1:1", Token: "t"}}

	if msg := m.fetchFlows().(flowsMsg); msg.err == nil {
		t.Error("fetchFlows should surface a transport error")
	}
	if msg := m.fetchPolicies().(policiesMsg); msg.err == nil {
		t.Error("fetchPolicies should surface a transport error")
	}
	if msg := m.fetchArtifacts().(artifactsMsg); msg.err == nil {
		t.Error("fetchArtifacts should surface a transport error")
	}
	if msg := m.fetchEnvs().(envsMsg); msg.err == nil {
		t.Error("fetchEnvs should surface a transport error")
	}
	if msg := m.fetchCoverage().(coverageMsg); msg.err == nil {
		t.Error("fetchCoverage should surface a transport error")
	}
	if msg := m.fetchMetrics().(metricsMsg); msg.err == nil {
		t.Error("fetchMetrics should surface a transport error")
	}
}

// ----- dashboardSnapshot (non-TTY entrypoint) -----

func TestDashboardSnapshot_PrintsJSON(t *testing.T) {
	srv, _ := recordingServer(t, `{"totalEnvironments":1,"controls":[]}`)
	// dashboardSnapshot writes to os.Stdout directly; just make sure it
	// doesn't panic and completes against a live server.
	dashboardSnapshot(cfg(srv))
}
