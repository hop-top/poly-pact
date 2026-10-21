package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// The lint rules of profile validate. Each checks a schema-valid profile for
// something the schema cannot express or that the claim depends on; text
// that is empty or only white space counts as empty.
const (
	// ruleRouteEnforcement: when protected_routes is not empty,
	// enforcement_points has at least one entry for each of
	// authenticate_native, map_operation and authorize_native, the functions
	// every protected route runs through (template section 3).
	ruleRouteEnforcement = "route-enforcement"
	// ruleBypassControl: every bypass_paths entry has a control.
	ruleBypassControl = "bypass-control"
	// ruleBypassEvidence: every bypass_paths entry has non-empty evidence.
	ruleBypassEvidence = "bypass-evidence"
	// ruleAdapters: claim.adapters is not empty.
	ruleAdapters = "adapters"
	// ruleMappingRevision: every claim.adapters entry has a non-empty
	// mapping_revision.
	ruleMappingRevision = "mapping-revision"
	// ruleUnsupportedForms: unsupported_forms is not empty, and no entry is.
	ruleUnsupportedForms = "unsupported-forms"
	// ruleFixturePath: every fixtures[].path, relative to the spec directory,
	// stays inside it and exists.
	ruleFixturePath = "fixture-path"
	// ruleFixtureID: every fixtures[].id is an entry id of
	// fixtures/manifest.json.
	ruleFixtureID = "fixture-id"
	// ruleFreshnessCoverage: when native_dependencies lists component C02 or
	// C05, freshness has at least one row. A freshness row names no
	// component, so the rule cannot tie a row to one.
	ruleFreshnessCoverage = "freshness-coverage"
	// ruleAttributeFreshness: every attribute_sources[].freshness is the
	// source of a freshness entry, spelled exactly as there.
	ruleAttributeFreshness = "attribute-freshness"
)

// routeFunctions are the adapter functions every protected route runs
// through (draft sections 2.3 and 17.1).
var routeFunctions = []string{"authenticate_native", "map_operation", "authorize_native"}

// freshnessComponents are the native dependency components whose sources the
// freshness rows bound: C02, native authentication and claim adapters, and
// C05, evidence and authoritative status sources.
var freshnessComponents = []string{"C02", "C05"}

// profileDoc is the part of a schema-valid profile that the lint reads.
type profileDoc struct {
	Claim struct {
		Adapters []adapterDoc `json:"adapters"`
	} `json:"claim"`
	ProtectedRoutes    []json.RawMessage    `json:"protected_routes"`
	EnforcementPoints  []enforcementDoc     `json:"enforcement_points"`
	NativeDependencies []dependencyDoc      `json:"native_dependencies"`
	BypassPaths        []bypassDoc          `json:"bypass_paths"`
	UnsupportedForms   []string             `json:"unsupported_forms"`
	Freshness          []freshnessDoc       `json:"freshness"`
	AttributeSources   []attributeSourceDoc `json:"attribute_sources"`
	Fixtures           []fixtureDoc         `json:"fixtures"`
}

type enforcementDoc struct {
	Function string `json:"function"`
}

type dependencyDoc struct {
	Component string `json:"component"`
}

type freshnessDoc struct {
	Source string `json:"source"`
}

type attributeSourceDoc struct {
	Freshness string `json:"freshness"`
}

type adapterDoc struct {
	MappingRevision *string `json:"mapping_revision"`
}

type bypassDoc struct {
	Control  *string `json:"control"`
	Evidence *string `json:"evidence"`
}

type fixtureDoc struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

// lintProfile applies the lint rules to p and returns the failures sorted by
// location. exists reports whether a fixture path, already known to stay
// inside the spec directory, exists; registered holds the manifest entry ids.
func lintProfile(p *profileDoc, exists func(rel string) bool, registered map[string]bool) []finding {
	var out []finding
	add := func(ptr, rule, format string, args ...any) {
		out = append(out, finding{Pointer: ptr, Check: checkLint, Rule: rule, Message: fmt.Sprintf(format, args...)})
	}

	if n := len(p.ProtectedRoutes); n > 0 {
		for _, fn := range routeFunctions {
			if !slices.ContainsFunc(p.EnforcementPoints, func(e enforcementDoc) bool { return e.Function == fn }) {
				add("/enforcement_points", ruleRouteEnforcement,
					"no %s entry; each of the %d protected routes runs through one", fn, n)
			}
		}
	}

	for i, b := range p.BypassPaths {
		at := fmt.Sprintf("/bypass_paths/%d", i)
		switch {
		case b.Control == nil:
			add(at, ruleBypassControl, "bypass path has no control")
		case blank(*b.Control):
			add(at+"/control", ruleBypassControl, "control is empty")
		}
		switch {
		case b.Evidence == nil:
			add(at, ruleBypassEvidence, "bypass path has no evidence")
		case blank(*b.Evidence):
			add(at+"/evidence", ruleBypassEvidence, "evidence is empty")
		}
	}

	if len(p.Claim.Adapters) == 0 {
		add("/claim/adapters", ruleAdapters, "no adapter is claimed; list each native-protocol adapter with its mapping_revision")
	}
	for i, a := range p.Claim.Adapters {
		at := fmt.Sprintf("/claim/adapters/%d", i)
		switch {
		case a.MappingRevision == nil:
			add(at, ruleMappingRevision, "adapter has no mapping_revision")
		case blank(*a.MappingRevision):
			add(at+"/mapping_revision", ruleMappingRevision, "mapping_revision is empty")
		}
	}

	if len(p.UnsupportedForms) == 0 {
		add("/unsupported_forms", ruleUnsupportedForms, "no unsupported form is stated")
	}
	for i, s := range p.UnsupportedForms {
		if blank(s) {
			add(fmt.Sprintf("/unsupported_forms/%d", i), ruleUnsupportedForms, "unsupported form is empty")
		}
	}

	for i, f := range p.Fixtures {
		at := fmt.Sprintf("/fixtures/%d", i)
		switch {
		case !insideSpec(f.Path):
			add(at+"/path", ruleFixturePath, "%q is not a relative path inside the spec directory", f.Path)
		case !exists(f.Path):
			add(at+"/path", ruleFixturePath, "%s does not exist in the spec directory", f.Path)
		}
		if !registered[f.ID] {
			add(at+"/id", ruleFixtureID, "%q is not an entry id in fixtures/manifest.json", f.ID)
		}
	}

	if len(p.Freshness) == 0 {
		for i, d := range p.NativeDependencies {
			if slices.Contains(freshnessComponents, d.Component) {
				add("/freshness", ruleFreshnessCoverage,
					"no freshness row bounds the sources of %s (/native_dependencies/%d)", d.Component, i)
			}
		}
	}

	sources := make(map[string]bool, len(p.Freshness))
	for _, f := range p.Freshness {
		sources[f.Source] = true
	}
	for i, a := range p.AttributeSources {
		if !sources[a.Freshness] {
			add(fmt.Sprintf("/attribute_sources/%d/freshness", i), ruleAttributeFreshness,
				"%q is not the source of a freshness entry", a.Freshness)
		}
	}

	sortFindings(out)
	return out
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }

// insideSpec reports whether rel is a slash-separated relative path with no
// empty, "." or ".." segment, so that it names something inside the spec
// directory on every platform.
func insideSpec(rel string) bool {
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return false
	}
	return !slices.ContainsFunc(strings.Split(rel, "/"), func(s string) bool {
		return s == "" || s == "." || s == ".."
	})
}
