package depcheck

import (
	"slices"
	"strings"
	"testing"
)

// graph returns the listed packages with Deps filled in: the transitive
// imports of each package, the way go list -deps reports them.
func graph(pkgs ...listedPackage) []listedPackage {
	byPath := make(map[string]*listedPackage, len(pkgs))
	for i := range pkgs {
		byPath[pkgs[i].ImportPath] = &pkgs[i]
	}
	var visit func(p *listedPackage, seen map[string]bool)
	visit = func(p *listedPackage, seen map[string]bool) {
		for _, imp := range p.Imports {
			if seen[imp] {
				continue
			}
			seen[imp] = true
			if q := byPath[imp]; q != nil {
				visit(q, seen)
			}
		}
	}
	for i := range pkgs {
		seen := map[string]bool{}
		visit(&pkgs[i], seen)
		for d := range seen {
			pkgs[i].Deps = append(pkgs[i].Deps, d)
		}
		slices.Sort(pkgs[i].Deps)
	}
	return pkgs
}

// pkg is a package of module mod ("" for the standard library).
func pkg(path, mod string, imports ...string) listedPackage {
	p := listedPackage{ImportPath: path, Imports: imports, Standard: mod == ""}
	if mod != "" {
		p.Module = &struct{ Path string }{mod}
	}
	return p
}

const (
	pgx    = "github.com/jackc/pgx/v5"
	puddle = "github.com/jackc/puddle/v2"
	xsync  = "golang.org/x/sync"
	xsys   = "golang.org/x/sys"
	ldap   = "github.com/go-ldap/ldap/v3"
	asn1   = "github.com/go-asn1-ber/asn1-ber"
)

// thirdParty is the part of the graph outside the module: pgx/v5/stdlib
// reaches a package of a second module (puddle), which reaches a third
// (x/sync); ldap/v3 reaches asn1-ber.
var thirdParty = []listedPackage{
	pkg("strings", ""),
	pkg("database/sql", ""),
	pkg(pgx+"/stdlib", pgx, "database/sql", pgx+"/pgxpool"),
	pkg(pgx+"/pgxpool", pgx, puddle),
	pkg(puddle, puddle, xsync+"/semaphore"),
	pkg(xsync+"/semaphore", xsync),
	pkg(xsys+"/windows", xsys),
	pkg(ldap, ldap, asn1),
	pkg(asn1, asn1),
	pkg("hop.top/kit/go/console/cli", "hop.top/kit"),
}

// listing is one platform's go list output: the module's packages on top
// of the third-party graph.
func listing(own ...listedPackage) []listedPackage {
	return graph(append(slices.Clone(thirdParty), own...)...)
}

// adapterTree is the module with the three allowlisted adapters as their
// task text names them, each importing its one module, plus the test
// variants of the database adapter.
func adapterTree(windows bool) []listedPackage {
	files := pkg(module+"/adapters/files", module, "strings")
	if windows {
		files.Imports = append(files.Imports, xsys+"/windows")
	}
	return listing(
		pkg(module+"/core", module, "strings"),
		files,
		pkg(module+"/adapters/db", module, "database/sql", pgx+"/stdlib", module+"/core"),
		pkg(module+"/adapters/db_test [hop.top/pact-go/adapters/db.test]", module, module+"/adapters/db", module+"/core"),
		pkg(module+"/adapters/db.test", module, module+"/adapters/db", module+"/adapters/db_test [hop.top/pact-go/adapters/db.test]"),
		pkg(module+"/adapters/ldap", module, ldap),
	)
}

// adapterRequires is what go mod tidy writes for adapterTree: the three
// named modules and the modules they reach.
var adapterRequires = []string{pgx, puddle, xsync, xsys, ldap, asn1}

func TestRulesAllowlistedImportsPass(t *testing.T) {
	listings := map[string][]listedPackage{
		"linux/amd64":   adapterTree(false),
		"windows/amd64": adapterTree(true),
	}
	if problems := evaluate(adapterRequires, listings); len(problems) > 0 {
		t.Fatalf("problems for the allowlisted adapters:\n  %s", strings.Join(problems, "\n  "))
	}
	if problems := evaluate(nil, map[string][]listedPackage{"linux/amd64": listing(pkg(module+"/core", module, "strings"))}); len(problems) > 0 {
		t.Fatalf("problems for a standard-library-only module:\n  %s", strings.Join(problems, "\n  "))
	}
}

func TestRulesReject(t *testing.T) {
	for _, tc := range []struct {
		name     string
		requires []string
		own      []listedPackage
		want     string
	}{
		// (a) a package outside the allowlist uses a module.
		{"outside allowlist, direct", []string{pgx, puddle, xsync},
			[]listedPackage{pkg(module+"/core", module, pgx+"/stdlib")},
			"package hop.top/pact-go/core uses module " + pgx},
		{"outside allowlist, through an adapter", []string{pgx, puddle, xsync},
			[]listedPackage{
				pkg(module+"/adapters/db", module, pgx+"/stdlib"),
				pkg(module+"/runner", module, module+"/adapters/db"),
			},
			"package hop.top/pact-go/runner uses module " + pgx},
		{"outside allowlist, test variant", []string{"hop.top/kit"},
			[]listedPackage{pkg(module+"/core [hop.top/pact-go/core.test]", module, "hop.top/kit/go/console/cli")},
			"package hop.top/pact-go/core [hop.top/pact-go/core.test] uses module hop.top/kit"},
		{"outside allowlist, subpackage of an adapter", []string{pgx, puddle, xsync},
			[]listedPackage{pkg(module+"/adapters/db/internal/conv", module, pgx+"/stdlib")},
			"package hop.top/pact-go/adapters/db/internal/conv uses module " + pgx},
		// (b) an allowlisted package uses a module other than its own.
		{"other module, direct", []string{pgx, puddle, xsync, ldap, asn1},
			[]listedPackage{pkg(module+"/adapters/db", module, pgx+"/stdlib", ldap)},
			"package hop.top/pact-go/adapters/db imports " + ldap + " of module " + ldap},
		{"other module, direct, also reached through its own", []string{pgx, puddle, xsync},
			[]listedPackage{pkg(module+"/adapters/db", module, pgx+"/stdlib", xsync+"/semaphore")},
			"package hop.top/pact-go/adapters/db imports " + xsync + "/semaphore of module " + xsync},
		{"other module, through another adapter", []string{pgx, puddle, xsync, ldap, asn1},
			[]listedPackage{
				pkg(module+"/adapters/ldap", module, ldap),
				pkg(module+"/adapters/db", module, pgx+"/stdlib", module+"/adapters/ldap"),
			},
			"package hop.top/pact-go/adapters/db uses module " + ldap},
		// (c) a require line no allowlisted package reaches.
		{"require, unreached module", []string{pgx, puddle, xsync, ldap},
			[]listedPackage{pkg(module+"/adapters/db", module, pgx+"/stdlib")},
			"go.mod requires " + ldap},
		{"require, nothing imported", []string{"hop.top/kit"},
			[]listedPackage{pkg(module+"/core", module, "strings")},
			"go.mod requires hop.top/kit"},
		{"require, reached only outside the allowlist", []string{"hop.top/kit"},
			[]listedPackage{pkg(module+"/core", module, "hop.top/kit/go/console/cli")},
			"go.mod requires hop.top/kit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problems := evaluate(tc.requires, map[string][]listedPackage{"linux/amd64": listing(tc.own...)})
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.want) }) {
				t.Fatalf("problems = %q, want one naming %q", problems, tc.want)
			}
		})
	}
}

// TestRulesPlatforms: a module reached on one platform only counts as
// reached, and a package that uses a module on one platform only is caught.
func TestRulesPlatforms(t *testing.T) {
	linuxOnly := map[string][]listedPackage{"linux/amd64": adapterTree(false)}
	if problems := evaluate(adapterRequires, linuxOnly); !slices.ContainsFunc(problems, func(p string) bool {
		return strings.Contains(p, "go.mod requires "+xsys)
	}) {
		t.Fatalf("linux listing alone: problems = %q, want the x/sys require reported", problems)
	}
	listings := map[string][]listedPackage{
		"linux/amd64":   listing(pkg(module+"/core", module, "strings")),
		"windows/amd64": listing(pkg(module+"/core", module, "strings", xsys+"/windows")),
	}
	problems := evaluate([]string{xsys}, listings)
	if !slices.ContainsFunc(problems, func(p string) bool {
		return strings.Contains(p, "package hop.top/pact-go/core uses module "+xsys) && strings.Contains(p, "windows/amd64")
	}) {
		t.Fatalf("problems = %q, want core's windows-only use of x/sys reported", problems)
	}
}

// TestAllowlist pins the table to the owner's decision: three adapter
// packages, one module each.
func TestAllowlist(t *testing.T) {
	want := map[string]string{
		"hop.top/pact-go/adapters/files": "golang.org/x/sys",
		"hop.top/pact-go/adapters/db":    "github.com/jackc/pgx/v5",
		"hop.top/pact-go/adapters/ldap":  "github.com/go-ldap/ldap/v3",
	}
	if len(allowed) != len(want) {
		t.Fatalf("allowed = %v, want %v", allowed, want)
	}
	for p, m := range want {
		if allowed[p] != m {
			t.Errorf("allowed[%q] = %q, want %q", p, allowed[p], m)
		}
	}
}
