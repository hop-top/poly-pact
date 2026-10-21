package sourcetest_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/sourcetest"
)

// toy is the in-package test source, model toy/1: a pushed store whose
// inbound messages put or delete facts directly. Its source member is
// {model, source_id, lag_seconds, paths}; an inbound message is
// {op: put|delete, principal, path, value, event_time}; a step's expect is
// {status: ok|refused}. A defect, when set, breaks the source in one way.
type toy struct {
	defect string
}

type toySource struct {
	Model      string   `json:"model"`
	SourceID   string   `json:"source_id"`
	LagSeconds int64    `json:"lag_seconds"`
	Paths      []string `json:"paths"`
}

type toyInbound struct {
	Op        string          `json:"op"`
	Principal string          `json:"principal"`
	Path      string          `json:"path"`
	Value     json.RawMessage `json:"value"`
	EventTime int64           `json:"event_time"`
}

func (d toy) driver() sourcetest.Driver {
	return sourcetest.Driver{Model: "toy/1", Open: d.open}
}

func (d toy) open(t testing.TB, env sourcetest.Env) (sourcetest.Subject, error) {
	var cfg toySource
	if err := json.Unmarshal(env.Source, &cfg); err != nil {
		return sourcetest.Subject{}, err
	}
	st := source.NewMemory()
	r, err := source.NewReader(source.Config{
		Store: st, SourceID: cfg.SourceID, Paths: cfg.Paths,
		Lag: time.Duration(cfg.LagSeconds) * time.Second, Clock: env.Clock,
	})
	if err != nil {
		return sourcetest.Subject{}, err
	}
	var reader adapter.ClaimReader = r
	switch d.defect {
	case "restamp", "no-source", "ahead", "panic", "wrong-value", "error-without-code":
		reader = brokenReader{r: r, defect: d.defect, now: env.Clock.Now}
	}
	apply := func(ctx context.Context, inbound, expect json.RawMessage) error {
		if d.defect == "calls-out" {
			env.Hooks.Fire("outbound")
		}
		var in toyInbound
		if err := json.Unmarshal(inbound, &in); err != nil {
			return err
		}
		var err error
		switch in.Op {
		case "put":
			var v any
			if err := json.Unmarshal(in.Value, &v); err != nil {
				return err
			}
			f := source.Fact{Value: v}
			if in.EventTime != 0 {
				f.ObservedAt, f.StatusCheckedAt = time.Unix(in.EventTime, 0), time.Unix(in.EventTime, 0)
			}
			err = st.Put(ctx, in.Principal, in.Path, f)
		case "delete":
			if d.defect != "ignores-delete" {
				err = st.Delete(ctx, in.Principal)
			}
		default:
			return fmt.Errorf("toy: unknown op %q", in.Op)
		}
		status := "ok"
		if err != nil || d.defect == "refuses" {
			status = "refused"
		}
		var want struct {
			Status string `json:"status"`
		}
		if len(expect) > 0 {
			if err := json.Unmarshal(expect, &want); err != nil {
				return err
			}
		}
		if want.Status != "" && want.Status != status {
			return fmt.Errorf("status %s, want %s", status, want.Status)
		}
		return nil
	}
	if d.defect == "no-apply" {
		apply = nil
	}
	return sourcetest.Subject{Reader: reader, Apply: apply}, nil
}

// brokenReader breaks a correct reader in one way.
type brokenReader struct {
	r      adapter.ClaimReader
	defect string
	now    func() time.Time
}

func (b brokenReader) ReadNativeClaim(ctx context.Context, p string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if b.defect == "panic" {
		panic("broken reader")
	}
	c, err := b.r.ReadNativeClaim(ctx, p, cc)
	switch b.defect {
	case "restamp":
		c.ObservedAt, c.StatusCheckedAt = b.now(), b.now()
	case "no-source":
		c.SourceID = ""
	case "ahead":
		if err == nil {
			c.StatusCheckedAt = b.now().Add(6 * time.Second)
		}
	case "wrong-value":
		if err == nil {
			c.Value = []string{"admin"}
		}
	case "error-without-code":
		if err != nil {
			err = errors.New(err.Error())
		}
	}
	return c, err
}

func toyFixtures() sourcetest.Options {
	return sourcetest.Options{Fixtures: os.DirFS("testdata"), Source: "toy"}
}

// TestToyPasses: a correct pushed-state source passes every toy case.
func TestToyPasses(t *testing.T) {
	sourcetest.Run(t, toy{}.driver(), toyFixtures())
}

// TestBrokenSourcesFail: each defect fails the case that exposes it, and no
// defect makes the harness crash.
func TestBrokenSourcesFail(t *testing.T) {
	for defect, c := range map[string]struct {
		id, failure string
	}{
		"restamp":            {"TOY-01.as-of-time", "observed_at"},
		"no-source":          {"TOY-01.as-of-time", "names no source"},
		"ahead":              {"TOY-01.as-of-time", "later than"},
		"wrong-value":        {"TOY-01.as-of-time", "value"},
		"ignores-delete":     {"TOY-02.deleted", "want an error"},
		"error-without-code": {"TOY-02.deleted", "carries no draft 13.4 code"},
		"panic":              {"TOY-01.as-of-time", "panicked"},
		"calls-out":          {"TOY-01.as-of-time", "outbound"},
		"refuses":            {"TOY-01.as-of-time", "status refused"},
		"no-apply":           {"TOY-01.as-of-time", "no Apply"},
	} {
		t.Run(defect, func(t *testing.T) {
			results, err := sourcetest.Evaluate(t, toy{defect: defect}.driver(), toyFixtures())
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range results {
				if r.ID != c.id {
					continue
				}
				found = true
				if r.Passed() {
					t.Fatalf("%s passed with the defect %s", r.ID, defect)
				}
				if !strings.Contains(strings.Join(r.Failures, "\n"), c.failure) {
					t.Errorf("failures %q do not mention %q", r.Failures, c.failure)
				}
			}
			if !found {
				t.Fatalf("no result for %s", c.id)
			}
		})
	}
}

// TestModelMismatchFails: a driver is run only on cases of its model.
func TestModelMismatchFails(t *testing.T) {
	d := toy{}.driver()
	d.Model = "other/1"
	results, err := sourcetest.Evaluate(t, d, toyFixtures())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Passed() || !strings.Contains(strings.Join(r.Failures, "\n"), "model") {
			t.Errorf("%s: %v, want a model failure", r.ID, r.Failures)
		}
	}
}

// valid is a minimal valid case; each malformed variant breaks one rule.
const valid = `{"case_version": 1, "id": "TOY-09", "title": "t", "draft": ["17.2"],
 "source": {"model": "toy/1", "source_id": "s", "lag_seconds": 0, "paths": ["/principal/groups"]},
 "reads": [{"native_path": "/principal/groups", "principal": "x-toy:a:b", "expect": {"outcome": "error", "reason_code": "MISSING_FIELD"}}]}`

func TestMalformedCasesAreErrors(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"unknown member":   func(s string) string { return strings.Replace(s, `"title": "t"`, `"title": "t", "extra": 1`, 1) },
		"duplicate member": func(s string) string { return strings.Replace(s, `"title": "t"`, `"title": "t", "title": "u"`, 1) },
		"case version 2":   func(s string) string { return strings.Replace(s, `"case_version": 1`, `"case_version": 2`, 1) },
		"no id":            func(s string) string { return strings.Replace(s, `"id": "TOY-09", `, ``, 1) },
		"no draft":         func(s string) string { return strings.Replace(s, `"draft": ["17.2"],`, ``, 1) },
		"no model":         func(s string) string { return strings.Replace(s, `"model": "toy/1", `, ``, 1) },
		"no reads": func(s string) string {
			return s[:strings.Index(s, `,
 "reads"`)] + "}"
		},
		"unknown outcome": func(s string) string { return strings.Replace(s, `"outcome": "error"`, `"outcome": "claim"`, 1) },
		"no native path":  func(s string) string { return strings.Replace(s, `"native_path": "/principal/groups", `, ``, 1) },
		"no principal":    func(s string) string { return strings.Replace(s, `"principal": "x-toy:a:b", `, ``, 1) },
		"time goes back": func(s string) string {
			return strings.Replace(s, `"reads": [{`, `"steps": [{"at": 1792080010, "inbound": {}}], "reads": [{"at": 1792080000, `, 1)
		},
		"step without inbound": func(s string) string {
			return strings.Replace(s, `"reads": [{`, `"steps": [{"at": 1792080000}], "reads": [{`, 1)
		},
		"time a string":   func(s string) string { return strings.Replace(s, `"reads": [{`, `"reads": [{"at": "now", `, 1) },
		"unknown in read": func(s string) string { return strings.Replace(s, `"reads": [{`, `"reads": [{"call": 1, `, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{"sources/toy/toy-09.json": {Data: []byte(edit(valid))}}
			if _, err := sourcetest.Evaluate(t, toy{}.driver(), sourcetest.Options{Fixtures: fsys, Source: "toy"}); err == nil {
				t.Error("Evaluate accepted the malformed case")
			}
		})
	}
	fsys := fstest.MapFS{"sources/toy/toy-09.json": {Data: []byte(valid)}, "sources/toy/README.md": {Data: []byte("# x")}}
	results, err := sourcetest.Evaluate(t, toy{}.driver(), sourcetest.Options{Fixtures: fsys, Source: "toy"})
	if err != nil || len(results) != 1 || !results[0].Passed() {
		t.Errorf("valid case: %+v %v", results, err)
	}
}

func TestOptionsAreChecked(t *testing.T) {
	for name, o := range map[string]sourcetest.Options{
		"no source":      {Fixtures: os.DirFS("testdata")},
		"nested source":  {Fixtures: os.DirFS("testdata"), Source: "toy/x"},
		"unknown source": {Fixtures: os.DirFS("testdata"), Source: "absent"},
	} {
		if _, err := sourcetest.Evaluate(t, toy{}.driver(), o); err == nil {
			t.Errorf("%s: Evaluate accepted the options", name)
		}
	}
	if _, err := sourcetest.Evaluate(t, sourcetest.Driver{Model: "toy/1"}, toyFixtures()); err == nil {
		t.Error("a driver without Open was accepted")
	}
}
