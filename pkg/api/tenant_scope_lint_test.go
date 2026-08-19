package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestEveryHandlerEstablishesTenantScope is a structural check, not a unit test.
//
// Fides is multi-tenant, and RLS is opt-in behind FIDES_RLS_ENABLED — off by
// default. So on a default deployment the ONLY thing keeping one tenant out of
// another's data is an org predicate in the query. A handler that forgets one
// does not fail, misbehave, or look wrong in review: it quietly serves whatever
// id it was handed.
//
// That is not hypothetical. #326, #371, #456, #457 and #458 were all the same
// omission, and this check was written after the fourth. It immediately found a
// fifth (handleCreateTrail, planting a build record in another tenant's flow)
// that three careful manual sweeps had missed.
//
// A handler passes if it does any ONE of:
//
//   - calls an ownership guard (requireTrailInOrg, requireEnvInOrg, ...),
//     directly or through a helper;
//   - runs at least one tenant-table query carrying org_id, i.e. establishes
//     ownership and then works from the verified id (audit.go does this);
//   - touches no tenant-scoped table at all.
//
// KNOWN LIMIT, stated rather than hidden: this proves a handler establishes
// tenancy SOMEWHERE, not that every individual query is scoped. A handler that
// checks ownership of resource A and then reads unrelated resource B unscoped
// still passes. Closing that needs dataflow analysis; this catches the failure
// mode that has actually occurred five times, which is a handler that never
// establishes tenancy at all.
func TestEveryHandlerEstablishesTenantScope(t *testing.T) {
	// Tables carrying tenant data. Kept in step with pkg/db/schema-rls.sql:
	// the direct list, the FK-derived child list, and the three tables that file
	// deliberately excludes from RLS — those have NO backstop, so an unscoped
	// query against them leaks even when RLS is switched on.
	tenantTables := strings.Fields(`
		tenant_auth_configs tenant_storage_settings tenant_vault_settings tenant_llm_settings
		flows artifacts attestation_types environments policies system_audit_logs users
		sso_group_mappings tenant_webhooks tenant_git_providers tenant_servicenow_settings
		tenant_slack_settings controls trail_approvals logical_environments remediation_actions
		change_control_links deployment_anchors
		trails attestations llm_assessments evidence_attachments environment_snapshots
		snapshot_artifacts environment_mcp_servers environment_allowlist environment_policies
		logical_environment_members
		service_accounts service_account_keys integration_events`)

	guards := map[string]bool{
		"requireTrailInOrg": true, "requireEnvInOrg": true, "requireFlowInOrg": true,
		"trailInOrg": true, "envInOrg": true, "flowInOrg": true, "logicalEnvInOrg": true,
	}

	// Handlers that are legitimately cross-tenant or unscoped. Every entry needs
	// a reason. Adding one is a deliberate, reviewable decision — deleting or
	// weakening this test is not.
	allowed := map[string]string{}

	sqlVerb := regexp.MustCompile(`(?is)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b`)
	orgPred := regexp.MustCompile(`(?i)org_id`)
	tableRe := map[string]*regexp.Regexp{}
	for _, tb := range tenantTables {
		tableRe[tb] = regexp.MustCompile(`\b` + tb + `\b`)
	}

	type fnInfo struct {
		file       string
		line       int
		callees    []string
		unscoped   []string
		callsGuard bool
		hasScoped  bool
	}

	fset := token.NewFileSet()
	fns := map[string]*fnInfo{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			cur := &fnInfo{file: f, line: fset.Position(fd.Pos()).Line}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					var nm string
					switch s := x.Fun.(type) {
					case *ast.Ident:
						nm = s.Name
					case *ast.SelectorExpr:
						nm = s.Sel.Name
					}
					if nm != "" {
						cur.callees = append(cur.callees, nm)
						if guards[nm] {
							cur.callsGuard = true
						}
					}
				case *ast.BasicLit:
					if x.Kind != token.STRING {
						return true
					}
					sql := strings.Trim(x.Value, "`\"")
					if !sqlVerb.MatchString(sql) {
						return true
					}
					var used []string
					for _, tb := range tenantTables {
						if tableRe[tb].MatchString(sql) {
							used = append(used, tb)
						}
					}
					if len(used) == 0 {
						return true
					}
					if orgPred.MatchString(sql) {
						cur.hasScoped = true
						return true
					}
					cur.unscoped = append(cur.unscoped, fmt.Sprintf("%s:%d [%s] %.100s",
						f, fset.Position(x.Pos()).Line, strings.Join(used, ","),
						strings.Join(strings.Fields(sql), " ")))
				}
				return true
			})
			fns[fd.Name.Name] = cur
		}
	}
	if len(fns) == 0 {
		t.Fatal("parsed no functions — the check would pass vacuously")
	}

	var scoped func(string, map[string]bool) bool
	scoped = func(n string, seen map[string]bool) bool {
		f, ok := fns[n]
		if !ok || seen[n] {
			return false
		}
		seen[n] = true
		if f.callsGuard || f.hasScoped {
			return true
		}
		for _, c := range f.callees {
			if scoped(c, seen) {
				return true
			}
		}
		return false
	}
	var gather func(string, map[string]bool) []string
	gather = func(n string, seen map[string]bool) []string {
		f, ok := fns[n]
		if !ok || seen[n] {
			return nil
		}
		seen[n] = true
		out := append([]string{}, f.unscoped...)
		for _, c := range f.callees {
			out = append(out, gather(c, seen)...)
		}
		return out
	}

	var names []string
	for n := range fns {
		names = append(names, n)
	}
	sort.Strings(names)

	checked := 0
	for _, n := range names {
		if !strings.HasPrefix(n, "handle") {
			continue
		}
		checked++
		if reason, ok := allowed[n]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is allowlisted with an empty reason", n)
			}
			continue
		}
		if scoped(n, map[string]bool{}) {
			continue
		}
		if q := gather(n, map[string]bool{}); len(q) > 0 {
			t.Errorf("%s (%s:%d) never establishes tenant scope, yet reaches tenant tables:\n    %s\n"+
				"  Fix it by calling an ownership guard (requireTrailInOrg / requireEnvInOrg /\n"+
				"  requireFlowInOrg) or adding an org_id predicate. If it is genuinely\n"+
				"  cross-tenant, add it to `allowed` in this test with a reason.",
				n, fns[n].file, fns[n].line, strings.Join(q, "\n    "))
		}
	}
	if checked < 50 {
		t.Fatalf("only %d handlers checked — the matcher is probably broken", checked)
	}
	t.Logf("checked %d handlers", checked)
}
