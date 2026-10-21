package main

import (
	"fmt"
	"html"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"hop.top/pact-go/runner/manifest"
)

// Rules of check links.
const (
	// ruleLinkOutside: a relative link leaves spec/ (root-absolute links
	// included), and spec/.links-allow does not list it.
	ruleLinkOutside = "link-outside"
	// ruleLinkMissing: a link inside spec/ names no file or directory.
	ruleLinkMissing = "link-missing"
	// ruleLinkMirror: a link resolves in place but not in the copy laid out
	// as the mirror, with spec/ at its root.
	ruleLinkMirror = "link-mirror"
	// ruleAllowList: an entry of spec/.links-allow matches no link.
	ruleAllowList = "allow-list"
)

// mirrorDir is the directory of the temporary copy that stands for the
// spec mirror, which holds the spec/ tree at its root. It is a
// subdirectory, so that a link out of the copy leads nowhere.
const mirrorDir = "mirror"

const allowFile = ".links-allow"

var (
	schemeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:`)
	escapeRE = regexp.MustCompile("\\\\([!-/:-@\\[-`{-~])")
)

type linkStats struct {
	files, links, allowed int
}

// localLink is a link that stays inside spec/: its source and its target,
// both relative to spec/.
type localLink struct {
	where, source, target string
}

// checkLinks checks every relative link of the Markdown files under the spec
// tree spec, as scripts/check-spec-selfcontained.py does, and also that the
// target exists, in place and in a copy of spec/ laid out as the mirror,
// with spec/ at its root. Links listed in spec/.links-allow may leave spec/.
// An error means the check could not run: a malformed allow-list or an
// unreadable file.
func checkLinks(spec string) (manifest.Problems, linkStats, error) {
	var ps manifest.Problems
	var st linkStats
	repo := filepath.Dir(filepath.Clean(spec))
	allow, err := loadAllowList(filepath.Join(spec, allowFile))
	if err != nil {
		return nil, st, err
	}
	used := map[[2]string]bool{}
	var local []localLink
	err = filepath.WalkDir(spec, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".md") {
			return nil
		}
		rel, err := filepath.Rel(spec, p)
		if err != nil {
			return err
		}
		source := "spec/" + filepath.ToSlash(rel)
		text, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		st.files++
		normalized := strings.ReplaceAll(strings.ReplaceAll(string(text), "\r\n", "\n"), "\r", "\n")
		for _, l := range extractLinks(strings.TrimPrefix(normalized, "\ufeff")) {
			target, escapes, ok := resolveLink(source, l.dest)
			if !ok {
				continue
			}
			st.links++
			where := source + ":" + strconv.Itoa(l.line)
			key := [2]string{source, target}
			switch {
			case escapes && allow[key] > 0:
				used[key] = true
				st.allowed++
			case escapes:
				ps = append(ps, manifest.Problem{Rule: ruleLinkOutside, Where: where,
					Msg: fmt.Sprintf("link %s leaves spec/ (resolves to %s); the mirror carries only spec/ (allow with: %s -> %s)", l.dest, target, source, target)})
			default:
				if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(target))); err != nil {
					ps = append(ps, manifest.Problem{Rule: ruleLinkMissing, Where: where,
						Msg: fmt.Sprintf("link %s: %s does not exist", l.dest, target)})
					continue
				}
				local = append(local, localLink{where: where, source: source, target: target})
			}
		}
		return nil
	})
	if err != nil {
		return nil, st, err
	}
	for _, key := range sortedAllow(allow) {
		if !used[key] {
			ps = append(ps, manifest.Problem{Rule: ruleAllowList, Where: "spec/" + allowFile + ":" + strconv.Itoa(allow[key]),
				Msg: fmt.Sprintf("stale entry, no such link: %s -> %s", key[0], key[1])})
		}
	}

	mirror, err := os.MkdirTemp("", "pactfix-mirror-")
	if err != nil {
		return nil, st, err
	}
	defer func() { _ = os.RemoveAll(mirror) }()
	root := filepath.Join(mirror, mirrorDir)
	if err := copyTree(spec, root); err != nil {
		return nil, st, fmt.Errorf("copy spec/ as the mirror root: %w", err)
	}
	for _, l := range local {
		target := strings.TrimPrefix(l.target, "spec")
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(target))); err != nil {
			ps = append(ps, manifest.Problem{Rule: ruleLinkMirror, Where: l.where,
				Msg: fmt.Sprintf("%s does not resolve in the mirror, which holds spec/ at its root", l.target)})
		}
	}
	return ps, st, nil
}

// resolveLink resolves a destination written in source (a path under spec/).
// ok is false when it is not a local path: a scheme, //host, or only a
// fragment or query. Otherwise target is the repository-relative path it
// names, and escapes is true when spec/, taken as the root, does not contain
// it: a path that leaves spec/ and comes back, and a root-absolute path,
// escape too.
func resolveLink(source, dest string) (target string, escapes, ok bool) {
	dest = strings.TrimSpace(html.UnescapeString(escapeRE.ReplaceAllString(dest, "$1")))
	if schemeRE.MatchString(dest) || strings.HasPrefix(dest, "//") {
		return "", false, false
	}
	p := dest
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	if p == "" {
		return "", false, false
	}
	if strings.HasPrefix(p, "/") {
		norm := path.Clean(strings.TrimLeft(p, "/"))
		if norm == "." {
			return "/", true, true
		}
		return "/" + norm, true, true
	}
	inside := path.Clean(path.Join(path.Dir(strings.TrimPrefix(source, "spec/")), p))
	escapes = inside == ".." || strings.HasPrefix(inside, "../")
	return path.Clean(path.Join("spec", inside)), escapes, true
}

// loadAllowList reads spec/.links-allow: one "<source> -> <target>" per line,
// both repository-relative; blank lines and # comments are ignored. It maps
// each entry to its line number.
func loadAllowList(file string) (map[[2]string]int, error) {
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return map[[2]string]int{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[[2]string]int{}
	var bad []string
	for i, raw := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, " -> ")
		var problem string
		switch {
		case len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "":
			problem = `expected "<source> -> <target>"`
		default:
			source, target := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch {
			case !strings.HasPrefix(source, "spec/") || path.Clean(source) != source:
				problem = "source must be a normalized path under spec/"
			case strings.Contains(target, `\`) || path.Clean(strings.TrimLeft(target, "/")) != strings.TrimLeft(target, "/"):
				problem = "target must be a normalized repository-relative path"
			default:
				out[[2]string{source, target}] = i + 1
			}
		}
		if problem != "" {
			bad = append(bad, fmt.Sprintf("spec/%s:%d: malformed entry %q: %s", allowFile, i+1, line, problem))
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(bad, "\n"))
	}
	return out, nil
}

func sortedAllow(allow map[[2]string]int) [][2]string {
	keys := make([][2]string, 0, len(allow))
	for k := range allow {
		keys = append(keys, k)
	}
	// By line, the order of the file.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && allow[keys[j]] < allow[keys[j-1]]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// copyTree copies src to dst. Symbolic links are copied as links, not
// followed, so a link that leads out of spec/ is dead in the copy, as it is
// in the mirror.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, out)
		case d.IsDir():
			return os.MkdirAll(out, 0o755)
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(out, b, 0o644)
		}
	})
}
