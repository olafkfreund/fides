package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"strings"
	"testing"
)

type mutationAuth string

const (
	adminOnly      mutationAuth = "Admin enforced"
	writerOnly     mutationAuth = "Writer or Admin enforced"
	roleUndecided  mutationAuth = "authenticated, write role unspecified"
	authenticated  mutationAuth = "authenticated, read or preview"
	signedCallback mutationAuth = "public provider signature or token"
	localLogin     mutationAuth = "public local password exchange"
	admissionTLS   mutationAuth = "public admission, ingress authentication"
	ssoState       mutationAuth = "public SSO state"
)

type mutationRoute struct {
	pattern string
	id      string // fixture for {id}; other placeholders are named in the route
	body    string
	auth    mutationAuth
	status  int
	check   string // table changed on success, exact downstream error otherwise
	foreign bool   // ownership check exercised with the other tenant's session
}

// Role checks cover the documented write contract. Governance actions without
// a documented minimum role are classified separately. The inventory also
// includes POST previews and the two stateful SSO GETs.
var mutationRoutes = []mutationRoute{
	{"POST /api/v1/orgs", "", `{"name":"created-org"}`, adminOnly, 201, "organizations", false},
	{"POST /api/v1/flows", "", `{"name":"created-flow"}`, adminOnly, 201, "flows", false},
	{"PUT /api/v1/flows", "", `{"id":"$flow","name":"renamed-flow"}`, adminOnly, 200, "flows", true},
	{"POST /api/v1/trails", "", `{"flow_id":"$flow","name":"created-trail"}`, writerOnly, 201, "trails", true},
	{"POST /api/v1/trails/{id}/anchor", "trail", `{}`, adminOnly, 400, "no TSA is configured: set FIDES_TSA_URL, or FIDES_TSA_URLS to the endpoints callers may choose between", false},
	{"POST /api/v1/trails/{id}/approvals", "trail", `{"reason":"fixture review"}`, roleUndecided, 201, "trail_approvals", true},
	{"POST /api/v1/vex", "", `{"cve":"CVE-2024-0001","status":"not_affected","justification":"fixture review"}`, adminOnly, 201, "vex_statements", false},
	{"POST /api/v1/vulnerabilities/backfill", "", `{}`, adminOnly, 200, "", false},
	{"POST /api/v1/environments/{id}/snapshots/reevaluate-change", "env", `{"change_number":"CHG0012345"}`, roleUndecided, 200, "", true},
	{"POST /api/v1/controls", "", `{"key":"added","name":"New control","required_types":["fixture"]}`, adminOnly, 201, "controls", false},
	{"POST /api/v1/controls/{id}/archive", "control", `{}`, adminOnly, 200, "controls", true},
	{"POST /api/v1/controls/{id}/unarchive", "control", `{}`, adminOnly, 200, "controls", true},
	{"POST /api/v1/controls/{key}/enforce", "", `{"environment_id":"$env"}`, adminOnly, 201, "environment_policies", true},
	{"POST /api/v1/exceptions", "", `{"control_key":"fixture","reason":"test waiver","expires_in_days":1}`, roleUndecided, 201, "control_exceptions", false},
	{"POST /api/v1/exceptions/{id}/revoke", "exception", `{}`, roleUndecided, 200, "control_exceptions", true},
	{"POST /api/v1/services", "", `{"service":"fixture","tier":2}`, roleUndecided, 201, "service_owners", false},
	{"POST /api/v1/training", "", `{"person":"Fixture User","course":"Fixture Course"}`, roleUndecided, 201, "training_records", false},
	{"POST /api/v1/verify-branch-protection", "", `{"trail_id":"$trail","repo":"fixture/project","provider":"github"}`, writerOnly, 200, "attestations", true},
	{"POST /api/v1/controls/import-framework", "", `{"framework":"SOC2"}`, adminOnly, 201, "controls", false},
	{"POST /api/v1/tenant/slack", "", `{"webhook_secret_path":"FIXTURE_SLACK","enabled":false}`, adminOnly, 200, "tenant_slack_settings", false},
	{"POST /api/v1/logical-environments", "", `{"name":"created-logical"}`, roleUndecided, 201, "logical_environments", false},
	{"POST /api/v1/logical-environments/{id}/members", "logical", `{"environment_id":"$env"}`, roleUndecided, 201, "logical_environment_members", true},
	{"DELETE /api/v1/logical-environments/{id}/members/{envId}", "removeMember", "", roleUndecided, 200, "logical_environment_members", true},
	{"POST /api/v1/environments/{id}/policies", "env", `{"name":"new-policy","required_types":["fixture"]}`, adminOnly, 201, "environment_policies", true},
	{"DELETE /api/v1/environments/{id}/policies/{policyId}", "env", "", adminOnly, 200, "environment_policies", true},
	{"POST /api/v1/environments/{id}/tags", "env", `{"tags":{"purpose":"auth-test"}}`, roleUndecided, 200, "environments", true},
	{"POST /api/v1/flows/{id}/tags", "flow", `{"tags":{"purpose":"auth-test"}}`, adminOnly, 200, "flows", true},
	{"POST /api/v1/environments/{id}/allowlist", "env", `{"artifact_sha256":"$sha","reason":"fixture review"}`, roleUndecided, 201, "environment_allowlist", true},
	{"DELETE /api/v1/environments/{id}/allowlist/{sha}", "env", "", roleUndecided, 200, "environment_allowlist", true},
	{"POST /api/v1/remediation", "", `{"environment_id":"$env","domain":"allowlist_entry","reason":"fixture review","params":{"artifact_sha256":"$sha"}}`, roleUndecided, 201, "remediation_actions", true},
	{"POST /api/v1/remediation/{id}/approve", "approve", `{"reason":"fixture approval"}`, roleUndecided, 200, "remediation_actions", true},
	{"POST /api/v1/remediation/{id}/reject", "reject", `{"reason":"fixture rejection"}`, roleUndecided, 200, "remediation_actions", true},
	{"POST /api/v1/remediation/{id}/apply", "apply", `{}`, roleUndecided, 200, "remediation_actions", true},
	{"POST /api/v1/artifacts", "", `{"sha256":"$sha","trail_id":"$trail","name":"fixture-image","type":"docker"}`, writerOnly, 201, "artifacts", true},
	{"POST /api/v1/attestation-types", "", `{"name":"fixture","schema":"{}","jq_rules":[]}`, roleUndecided, 201, "attestation_types", false},
	{"POST /api/v1/attestations", "", `{"trail_id":"$trail","name":"fixture evidence","type_name":"fixture","payload":"{}"}`, writerOnly, 201, "attestations", true},
	{"POST /api/v1/snapshots", "", `{"environment_id":"$env","artifacts":[]}`, writerOnly, 201, "environment_snapshots", true},
	{"POST /api/v1/environments", "", `{"name":"created-environment","type":"k8s"}`, roleUndecided, 201, "environments", false},
	{"POST /api/v1/environments/{id}/archive", "env", `{}`, adminOnly, 200, "environments", true},
	{"POST /api/v1/environments/{id}/unarchive", "env", `{}`, adminOnly, 200, "environments", true},
	{"POST /api/v1/policies", "", `{"id":"$policy","yaml":"{\"jq\":[\"true\"]}"}`, adminOnly, 200, "policies", true},
	{"POST /api/v1/policies/create", "", `{"name":"created-policy","rules":"{}"}`, adminOnly, 201, "policies", false},
	{"DELETE /api/v1/policies/{id}", "policy", "", adminOnly, 200, "policies", true},
	{"POST /api/v1/tenant/webhooks", "", `{"name":"fixture","url":"https://hooks.example.invalid","secret_path":"FIXTURE_HOOK","event_types":[],"enabled":false}`, adminOnly, 200, "tenant_webhooks", false},
	{"POST /api/v1/tenant/git-providers", "", `{"provider":"github","host":"git.example.invalid","api_base":"https://git.example.invalid","token_path":"FIXTURE_GIT","enabled":false}`, adminOnly, 200, "tenant_git_providers", false},
	{"POST /api/v1/attest/fetch", "", `{"trail_id":"$trail","artifact_sha256":"$sha","repo":"fixture/project","provider":"github"}`, writerOnly, 200, "attestations", true},
	{"POST /api/v1/tenant/servicenow", "", `{"instance_url":"https://snow.example.invalid","auth_type":"basic","client_id":"fixture","secret_path":"FIXTURE_SNOW","enabled":false}`, adminOnly, 200, "tenant_servicenow_settings", false},
	{"POST /api/v1/servicenow/change-check", "", `{"trail_id":"$trail","change_number":"CHG0012345"}`, writerOnly, 400, "ServiceNow is not configured for this organization", true},
	{"POST /api/v1/servicenow/change-gate", "", `{"trail_id":"$trail","change_number":"CHG0012345"}`, roleUndecided, 400, "ServiceNow is not configured for this organization", true},
	{"POST /api/v1/servicenow/link-control", "", `{"trail_id":"$trail","control":"fixture","change_number":"CHG0012345"}`, roleUndecided, 201, "change_control_links", true},
	{"POST /api/v1/webhooks/{provider}", "", "", signedCallback, 0, "", false},
	{"POST /api/v1/flags/changed", "", `{"flag_key":"fixture","new_state":"on"}`, writerOnly, 201, "attestations", false},
	{"POST /api/v1/flags/webhook/{provider}", "", `{"type":"feature-enabled","featureName":"fixture"}`, writerOnly, 201, "attestations", false},
	{"POST /api/v1/servicenow/incident", "", `{"short_description":"Fixture incident"}`, roleUndecided, 400, "ServiceNow is not configured", false},
	{"POST /api/v1/servicenow/deployment-anchor", "", `{"trail_id":"$trail","change_number":"CHG0012345"}`, writerOnly, 400, "ServiceNow is not configured for this organization", false},
	{"POST /api/v1/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, authenticated, 200, "", false},
	{"POST /api/v1/servicenow/mcp/lookup", "", `{"table":"cmdb_ci","limit":1}`, authenticated, 400, "ServiceNow is not configured for this organization", false},
	{"POST /api/v1/servicenow/mcp/tools", "", `{"server":"fixture"}`, authenticated, 400, "ServiceNow is not configured for this organization", false},
	{"POST /api/v1/servicenow/mcp/call", "", `{"server":"fixture","tool":"lookup"}`, roleUndecided, 400, "ServiceNow is not configured for this organization", false},
	{"POST /api/v1/admission/validate", "", "", admissionTLS, 0, "", false},
	{"POST /api/v1/environments/mcp", "", `{"environment_id":"$env","name":"inactive-sensor","transport":"sse","url":"https://sensor.example.invalid","args":[],"env_vars":{}}`, adminOnly, 200, "environment_mcp_servers", true},
	{"POST /api/v1/environments/mcp/query", "", `{"environment_id":"$env","server_name":"inactive","tool_name":"read"}`, authenticated, 400, "Only stdio transport is supported currently in this environment", true},
	{"POST /api/v1/environments/mcp/verify", "", `{"environment_id":"$env","server_name":"inactive","tool_name":"read","rules":["true"]}`, roleUndecided, 400, "Only stdio transport is supported currently in this environment", true},
	{"POST /api/v1/tenant/settings", "", `{"storage":{"storage_driver":"local"}}`, adminOnly, 200, "tenant_storage_settings", false},
	{"GET /api/v1/auth/login", "", "", ssoState, 0, "", false},
	{"GET /api/v1/auth/callback", "", "", ssoState, 0, "", false},
	{"POST /api/v1/auth/local-login", "", "", localLogin, 0, "", false},
	{"POST /api/v1/tenant/users", "", `{"name":"New user","email":"new-user@example.invalid","role":"Writer","groups":[]}`, adminOnly, 200, "users", false},
	{"POST /api/v1/tenant/users/{id}/password", "user", `{"password":"auth-fixture-local-password"}`, adminOnly, 200, "users", true},
	{"POST /api/v1/tenant/service-accounts", "", `{"name":"new-ci","role":"Writer"}`, adminOnly, 201, "service_accounts", false},
	{"POST /api/v1/tenant/service-accounts/{id}/keys", "account", `{"label":"fixture","expires_hours":1}`, adminOnly, 201, "service_account_keys", true},
	{"DELETE /api/v1/tenant/service-accounts/{id}/keys/{keyId}", "account", "", adminOnly, 200, "service_account_keys", true},
	{"POST /api/v1/tenant/service-accounts/{id}/delegation", "account", `{"may_delegate_approvals":true}`, adminOnly, 200, "service_accounts", true},
	{"POST /api/v1/tenant/group-mappings", "", `{"external_group":"fixture-audit","role":"Auditor"}`, adminOnly, 200, "sso_group_mappings", false},
	{"POST /api/v1/ai/generate-policy", "", `{"framework":"fixture","description":"test policy"}`, authenticated, 200, "", false},
	{"POST /api/v1/ai/lint-policy", "", `{"rules":"{\"jq\":[\"true\"]}"}`, authenticated, 200, "", false},
	{"POST /api/v1/ai/chat", "", `{"message":"create flow assistant-fixture"}`, adminOnly, 200, "flows", false},
}

// Parse the direct ServeMux registrations because ServeMux offers no route
// iterator. Run this in the DB-free suite so a new route has to pick a class.
func TestMutationRouteInventory(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	classified := make(map[string]mutationAuth)
	for _, route := range mutationRoutes {
		if _, duplicate := classified[route.pattern]; duplicate {
			t.Errorf("duplicate inventory entry %s", route.pattern)
		}
		switch route.auth {
		case adminOnly, writerOnly, roleUndecided, authenticated:
			if route.status == 0 {
				t.Errorf("missing HTTP assertion for %s", route.pattern)
			}
		case signedCallback, localLogin, admissionTLS, ssoState:
			if route.status != 0 {
				t.Errorf("public route %s must use its own credential checks", route.pattern)
			}
		default:
			t.Errorf("unclassified route %s", route.pattern)
		}
		classified[route.pattern] = route.auth
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Errorf("route registration must use a literal pattern for the authorization inventory")
			return true
		}
		pattern := strings.Trim(literal.Value, "\"`")
		method, path, _ := strings.Cut(pattern, " ")
		if strings.HasPrefix(pattern, "/api/v1/") {
			t.Errorf("methodless API registration must be explicitly scoped: %s", pattern)
		}
		if !strings.HasPrefix(path, "/api/v1/") {
			return true
		}
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			if !strings.HasPrefix(path, "/api/v1/auth/") {
				return true
			}
		}
		if _, ok := classified[pattern]; !ok {
			t.Errorf("classify new route %s in mutationRoutes", pattern)
		}
		delete(classified, pattern)
		return true
	})
	for pattern := range classified {
		t.Errorf("inventory entry %s has no registered route", pattern)
	}
}
