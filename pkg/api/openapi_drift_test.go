package api

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The API spec is hand-written, and a hand-written spec drifts. When this test
// was added it documented 20 of the 116 /api/v1 routes the server actually
// serves -- so five out of six endpoints existed only in the code, and nothing
// anywhere said so.
//
// This does not try to generate the spec. Schemas, descriptions and examples
// are worth writing by hand and a generator would produce something worse. What
// it does is make the one failure that matters impossible: adding a route and
// forgetting to document it. The route list is read from the source, so it
// cannot fall behind the code the way a checked-in list would.

// registeredRoutes reads every mux.HandleFunc("METHOD /path", ...) registration
// out of this package's source. Parsing the AST rather than matching text so
// that reformatting, line breaks or a renamed mux variable cannot silently
// shrink the list -- a drift check that quietly stops checking is worse than
// none.
func registeredRoutes(t *testing.T) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	routes := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		{
			file, err := parser.ParseFile(fset, name, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "HandleFunc" {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				pattern, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				method, path, found := strings.Cut(pattern, " ")
				if !found {
					// A pattern with no method still registers a path.
					method, path = "GET", pattern
				}
				routes[path] = append(routes[path], method)
				return true
			})
		}
	}
	if len(routes) == 0 {
		t.Fatal("found no route registrations — the extraction is broken, not the spec")
	}
	return routes
}

// specPaths returns the paths the OpenAPI document declares, normalised onto
// the same absolute form the routes use. The spec sets a server of /api/v1 and
// writes paths relative to it.
func specPaths(t *testing.T) map[string]map[string]bool {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(SwaggerJSON), &doc); err != nil {
		t.Fatalf("the shipped OpenAPI document is not valid JSON: %v", err)
	}
	out := map[string]map[string]bool{}
	for p, ops := range doc.Paths {
		abs := p
		if !strings.HasPrefix(abs, "/api/v1") {
			abs = "/api/v1" + abs
		}
		methods := map[string]bool{}
		for m := range ops {
			methods[strings.ToUpper(m)] = true
		}
		out[abs] = methods
	}
	return out
}

// The document has to parse before anything else is worth asserting: a spec
// that Swagger UI cannot load is not a spec.
func TestOpenAPIDocumentIsValidJSON(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(SwaggerJSON), &doc); err != nil {
		t.Fatalf("SwaggerJSON does not parse: %v", err)
	}
	for _, k := range []string{"openapi", "info", "paths"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("the document has no %q", k)
		}
	}
}

// Every documented path must exist. This direction catches the opposite drift:
// a route renamed or removed while the spec still advertises it, which sends
// integrators at an endpoint that 404s.
func TestEveryDocumentedPathIsRegistered(t *testing.T) {
	routes := registeredRoutes(t)
	var missing []string
	for p := range specPaths(t) {
		if _, ok := routes[p]; !ok {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the spec documents %d path(s) the server does not serve:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// The gate. Adding a route without documenting it fails here.
//
// documentedGap exists so this check could be introduced without a flag day.
// It is empty: every /api/v1 route the server registers has an entry. Keep it
// that way -- a new route belongs in the document, not in this list.
var documentedGap []string

func TestEveryRouteIsDocumented(t *testing.T) {
	routes := registeredRoutes(t)
	spec := specPaths(t)

	var undocumented []string
	for p := range routes {
		if !strings.HasPrefix(p, "/api/v1/") {
			continue // static assets and health endpoints are not API surface
		}
		if _, ok := spec[p]; !ok {
			undocumented = append(undocumented, p)
		}
	}
	sort.Strings(undocumented)

	known := map[string]bool{}
	for _, p := range documentedGap {
		known[p] = true
	}

	var fresh []string
	for _, p := range undocumented {
		if !known[p] {
			fresh = append(fresh, p)
		}
	}
	if len(fresh) > 0 {
		t.Errorf("%d route(s) are registered but not in the OpenAPI document:\n  %s\n\n"+
			"Add them to SwaggerJSON in swagger.go. Do not add them to documentedGap —\n"+
			"that list is the backlog from when this check was introduced and only shrinks.",
			len(fresh), strings.Join(fresh, "\n  "))
	}

	// The backlog must also not rot: an entry that is now documented, or whose
	// route is gone, should leave the list.
	var stale []string
	for _, p := range documentedGap {
		if _, ok := spec[p]; ok {
			stale = append(stale, p+" (now documented)")
			continue
		}
		if _, ok := routes[p]; !ok {
			stale = append(stale, p+" (route no longer exists)")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("documentedGap has %d stale entry/entries — remove them:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}

	t.Logf("OpenAPI coverage: %d of %d /api/v1 routes documented, %d in the known backlog",
		countAPIRoutes(routes)-len(undocumented), countAPIRoutes(routes), len(documentedGap))
}

func countAPIRoutes(routes map[string][]string) int {
	n := 0
	for p := range routes {
		if strings.HasPrefix(p, "/api/v1/") {
			n++
		}
	}
	return n
}
