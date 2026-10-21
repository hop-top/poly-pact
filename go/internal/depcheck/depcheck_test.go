package depcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// module is the path of the library module.
const module = "hop.top/pact-go"

// goCmd runs the go command in dir outside any workspace, offline, and
// returns its standard output. go test puts its own GOROOT/bin first on PATH.
func goCmd(dir string, args ...string) ([]byte, error) {
	return goCmdEnv(dir, nil, args...)
}

// goCmdEnv is goCmd with extra environment variables.
func goCmdEnv(dir string, env []string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly", "GOPROXY=off", "GOTOOLCHAIN=local"), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return out, nil
}

// allowed is the allowlist: the only packages of the module that may use a
// module outside the standard library, each the one module it may use.
// Every other package, tests included, uses the standard library and the
// module only.
var allowed = map[string]string{
	module + "/adapters/files": "golang.org/x/sys",           // Windows impersonation
	module + "/adapters/db":    "github.com/jackc/pgx/v5",    // its database/sql driver
	module + "/adapters/ldap":  "github.com/go-ldap/ldap/v3", // LDAP client
}

// platforms are the targets go list resolves build constraints for: a
// file such as x_windows.go adds imports on one platform only, and go mod
// tidy, which ignores build constraints, keeps the modules they reach.
var platforms = []string{"linux/amd64", "darwin/arm64", "windows/amd64"}

// listedPackage holds the go list -json fields the check reads.
type listedPackage struct {
	ImportPath string
	Standard   bool
	Module     *struct{ Path string }
	Imports    []string
	Deps       []string
}

// owner returns the package a listed package belongs to: the import path of
// a test variant, an external test package or a test main without its
// test suffix ("hop.top/pact-go/core [hop.top/pact-go/core.test]",
// "hop.top/pact-go/core_test", "hop.top/pact-go/core.test").
func owner(importPath string) string {
	p, _, _ := strings.Cut(importPath, " ")
	p = strings.TrimSuffix(p, ".test")
	return strings.TrimSuffix(p, "_test")
}

// evaluate applies the allowlist to the require lines of go.mod and to one
// go list -deps -test listing per platform, and returns the problems.
//
//   - A package outside the allowlist depends, directly or through other
//     packages, on no package outside the standard library and the module.
//   - An allowlisted package imports, outside the standard library and the
//     module, only packages of its module, and depends on packages of other
//     modules only through those imports.
//   - Every require line names a module that an allowlisted package reaches
//     on at least one platform.
func evaluate(requires []string, listings map[string][]listedPackage) []string {
	var problems []string
	reached := map[string]bool{}
	for _, platform := range slices.Sorted(maps.Keys(listings)) {
		pkgs := listings[platform]
		byPath := make(map[string]listedPackage, len(pkgs))
		for _, p := range pkgs {
			byPath[p.ImportPath] = p
		}
		// external reports the module of a package outside the standard
		// library and the module.
		external := func(path string) (string, bool) {
			p, ok := byPath[path]
			if !ok || p.Standard || p.Module == nil || p.Module.Path == module {
				return "", false
			}
			return p.Module.Path, true
		}
		for _, p := range pkgs {
			if p.Standard || p.Module == nil || p.Module.Path != module {
				continue
			}
			own := owner(p.ImportPath)
			allowedModule, isAllowed := allowed[own]
			// through: the packages p may depend on because it reaches them
			// through an import of its module, or through the package it
			// belongs to (test variants and test mains).
			through := map[string]bool{}
			for _, imp := range p.Imports {
				mod, ext := external(imp)
				via := isAllowed && (ext && mod == allowedModule || !ext && owner(imp) == own && imp != p.ImportPath)
				if isAllowed && ext && mod != allowedModule {
					problems = append(problems, fmt.Sprintf("%s: package %s imports %s of module %s%s", platform, p.ImportPath, imp, mod, allowedNote(own)))
				}
				if !via {
					continue
				}
				through[imp] = true
				for _, d := range byPath[imp].Deps {
					through[d] = true
				}
			}
			used := map[string]string{}
			for _, d := range p.Deps {
				mod, ext := external(d)
				if !ext || through[d] {
					if ext {
						reached[mod] = true
					}
					continue
				}
				if _, seen := used[mod]; !seen {
					used[mod] = d
				}
			}
			for _, mod := range slices.Sorted(maps.Keys(used)) {
				problems = append(problems, fmt.Sprintf("%s: package %s uses module %s (package %s)%s", platform, p.ImportPath, mod, used[mod], allowedNote(own)))
			}
		}
	}
	for _, r := range requires {
		if !reached[r] {
			problems = append(problems, fmt.Sprintf("go.mod requires %s, which no allowlisted package reaches on %s", r, strings.Join(platforms, ", ")))
		}
	}
	slices.Sort(problems)
	return slices.Compact(problems)
}

// allowedNote says what the package owning a problem may use.
func allowedNote(own string) string {
	if m, ok := allowed[own]; ok {
		return fmt.Sprintf("; it may use only %s", m)
	}
	return "; it is not on the allowlist"
}

// check runs the go command on the module rooted at dir and applies the
// allowlist to every require line of its go.mod and to every package of
// the module, tests included, on each of the platforms. A package go list
// cannot resolve is an error too.
func check(dir string) error {
	out, err := goCmd(dir, "mod", "edit", "-json")
	if err != nil {
		return err
	}
	var mod struct {
		Module  struct{ Path string }
		Require []struct{ Path, Version string }
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		return fmt.Errorf("go mod edit -json: %v", err)
	}
	if mod.Module.Path != module {
		return fmt.Errorf("%s/go.mod is module %q, want %q", dir, mod.Module.Path, module)
	}
	var requires []string
	for _, r := range mod.Require {
		requires = append(requires, r.Path)
	}
	listings := map[string][]listedPackage{}
	for _, platform := range platforms {
		goos, goarch, _ := strings.Cut(platform, "/")
		out, err := goCmdEnv(dir, []string{"GOOS=" + goos, "GOARCH=" + goarch},
			"list", "-buildvcs=false", "-deps", "-test", "-json=ImportPath,Standard,Module,Imports,Deps", "./...")
		if err != nil {
			return fmt.Errorf("%s: %v", platform, err)
		}
		dec := json.NewDecoder(bytes.NewReader(out))
		for {
			var p listedPackage
			if err := dec.Decode(&p); err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("%s: go list -json: %v", platform, err)
			}
			listings[platform] = append(listings[platform], p)
		}
	}
	if problems := evaluate(requires, listings); len(problems) > 0 {
		return fmt.Errorf("module %s uses the standard library only, except the allowlisted packages:\n  %s", module, strings.Join(problems, "\n  "))
	}
	return nil
}

// root returns the directory of the library go.mod.
func root(t *testing.T) string {
	t.Helper()
	out, err := goCmd(".", "env", "GOMOD")
	if err != nil {
		t.Fatal(err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		t.Fatalf("go env GOMOD = %q: not in a module", gomod)
	}
	return filepath.Dir(gomod)
}

func TestStandardLibraryOnly(t *testing.T) {
	if err := check(root(t)); err != nil {
		t.Fatal(err)
	}
}

// copyModule copies the library module to a new directory: every file but
// built binaries.
func copyModule(t *testing.T) string {
	t.Helper()
	src, dst := root(t), t.TempDir()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if filepath.ToSlash(rel) == "bin" {
			return fs.SkipDir
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCheckCatches is the negative control: on a copy of the module, the
// check passes untouched and fails once a require line, a third-party
// import, a third-party test import or a third-party import in a file
// built for one platform only is added. The copy has no go.sum and the go
// command runs offline, so go list fails on an import it cannot resolve;
// TestRulesReject covers the rules on synthetic listings.
func TestCheckCatches(t *testing.T) {
	if err := check(copyModule(t)); err != nil {
		t.Fatalf("unchanged copy: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, dir string)
		want string
	}{
		{"require line", func(t *testing.T, dir string) {
			if _, err := goCmd(dir, "mod", "edit", "-require=hop.top/kit@v0.5.0-alpha.25"); err != nil {
				t.Fatal(err)
			}
		}, "go.mod requires hop.top/kit"},
		{"import", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "core", "zz_kit.go"), "package core\n\nimport _ \"hop.top/kit/go/console/cli\"\n")
		}, "hop.top/kit/go/console/cli"},
		{"test import", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "core", "zz_text_test.go"), "package core\n\nimport _ \"golang.org/x/text/unicode/norm\"\n")
		}, "golang.org/x/text"},
		{"windows-only import", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "core", "zz_sys_windows.go"), "package core\n\nimport _ \"golang.org/x/sys/windows\"\n")
		}, "windows/amd64: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyModule(t)
			tc.edit(t, dir)
			err := check(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("check = %v, want an error naming %s", err, tc.want)
			}
		})
	}
}
