package adapter

import (
	"context"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"hop.top/pact-go/core"
)

const draftPath = "../../spec/v1.0/draft.md"

// fn is one row of the draft 17.1 table with the Go name the package gives it.
// The Go names and signatures below are written from the 17.1 table and the
// package contract, not derived from the package under test.
type fn struct {
	draft     string // function name in the draft table
	iface     reflect.Type
	method    string
	signature string // method type without receiver
}

var functions = []fn{
	{"authenticate_native", reflect.TypeFor[NativeAuthenticator](), "AuthenticateNative",
		"func(context.Context, *http.Request) (adapter.Principal, error)"},
	{"resolve_agent_binding", reflect.TypeFor[BindingResolver](), "ResolveAgentBinding",
		"func(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error)"},
	{"map_operation", reflect.TypeFor[OperationMapper](), "MapOperation",
		"func(context.Context, *http.Request, adapter.Principal, string) (core.OperationContext, error)"},
	{"read_native_claim", reflect.TypeFor[ClaimReader](), "ReadNativeClaim",
		"func(context.Context, string, adapter.ClaimContext) (adapter.NativeClaim, error)"},
	{"check_context", reflect.TypeFor[ContextChecker](), "CheckContext",
		"func(context.Context, string, adapter.CheckInput) adapter.CheckOutcome"},
	{"authorize_native", reflect.TypeFor[NativeAuthorizer](), "AuthorizeNative",
		"func(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error)"},
	{"record_outcome", reflect.TypeFor[OutcomeRecorder](), "RecordOutcome",
		"func(context.Context, adapter.Observation) (adapter.Recorded, error)"},
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// draftSection returns the text of the draft section that starts at the
// heading line "### <heading>" and runs to the next heading of level 1 to 3.
func draftSection(t *testing.T, heading string) string {
	t.Helper()
	d := readFile(t, draftPath)
	start := strings.Index(d, "\n"+heading+"\n")
	if start < 0 {
		t.Fatalf("draft has no heading %q", heading)
	}
	rest := d[start+1+len(heading):]
	end := regexp.MustCompile(`(?m)^#{1,3} `).FindStringIndex(rest)
	if end == nil {
		return rest
	}
	return rest[:end[0]]
}

type draftRow struct{ fn, input, output string }

// draftRows parses the 17.1 table of the draft.
func draftRows(t *testing.T) []draftRow {
	t.Helper()
	sec := draftSection(t, "### 17.1 Required adapter capabilities")
	re := regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\| (.+?) \\| (.+?) \\|$")
	var rows []draftRow
	for _, m := range re.FindAllStringSubmatch(sec, -1) {
		rows = append(rows, draftRow{m[1], m[2], m[3]})
	}
	return rows
}

func TestDraftTableHasSevenFunctions(t *testing.T) {
	rows := draftRows(t)
	if len(rows) != len(functions) {
		t.Fatalf("draft 17.1 table has %d rows, package maps %d", len(rows), len(functions))
	}
	for i, r := range rows {
		if r.fn != functions[i].draft {
			t.Errorf("row %d: draft says %q, package maps %q", i, r.fn, functions[i].draft)
		}
	}
}

func TestOneInterfacePerFunction(t *testing.T) {
	for _, f := range functions {
		t.Run(f.draft, func(t *testing.T) {
			if f.iface.Kind() != reflect.Interface {
				t.Fatalf("%v is not an interface", f.iface)
			}
			if f.iface.NumMethod() != 1 {
				t.Fatalf("%v has %d methods, want 1", f.iface, f.iface.NumMethod())
			}
			m := f.iface.Method(0)
			if m.Name != f.method {
				t.Errorf("method = %s, want %s", m.Name, f.method)
			}
			if got := m.Type.String(); got != f.signature {
				t.Errorf("signature\n got %s\nwant %s", got, f.signature)
			}
		})
	}
}

func TestCompositeExposesAllSeven(t *testing.T) {
	ad := reflect.TypeFor[Adapter]()
	if ad.Kind() != reflect.Interface {
		t.Fatalf("Adapter is %v, want interface", ad.Kind())
	}
	want := map[string]string{"Describe": "func() adapter.Descriptor"}
	for _, f := range functions {
		want[f.method] = f.signature
		if !ad.Implements(f.iface) {
			t.Errorf("Adapter does not implement %v", f.iface)
		}
	}
	if ad.NumMethod() != len(want) {
		t.Errorf("Adapter has %d methods, want %d", ad.NumMethod(), len(want))
	}
	for name, sig := range want {
		m, ok := ad.MethodByName(name)
		if !ok {
			t.Errorf("Adapter lacks method %s", name)
			continue
		}
		if got := m.Type.String(); got != sig {
			t.Errorf("Adapter.%s\n got %s\nwant %s", name, got, sig)
		}
	}
}

// stub implements every method; it exists to prove the composite is
// satisfiable. The package itself ships no implementation.
type stub struct{}

func (stub) AuthenticateNative(context.Context, *http.Request) (Principal, error) {
	return Principal{}, nil
}

func (stub) ResolveAgentBinding(context.Context, Realm, Workload, AgentID) (AgentBinding, error) {
	return AgentBinding{}, nil
}

func (stub) MapOperation(context.Context, *http.Request, Principal, string) (core.OperationContext, error) {
	return core.OperationContext{}, nil
}

func (stub) ReadNativeClaim(context.Context, string, ClaimContext) (NativeClaim, error) {
	return NativeClaim{}, nil
}

func (stub) CheckContext(context.Context, string, CheckInput) CheckOutcome {
	return CheckOutcome{}
}

func (stub) AuthorizeNative(context.Context, Principal, core.OperationContext) (Decision, error) {
	return Decision{}, nil
}

func (stub) RecordOutcome(context.Context, Observation) (Recorded, error) {
	return NoVisibility{Reason: "stub"}, nil
}
func (stub) Describe() Descriptor { return Descriptor{} }

var (
	_ NativeAuthenticator = stub{}
	_ BindingResolver     = stub{}
	_ OperationMapper     = stub{}
	_ ClaimReader         = stub{}
	_ ContextChecker      = stub{}
	_ NativeAuthorizer    = stub{}
	_ OutcomeRecorder     = stub{}
	_ Adapter             = stub{}
)

// normalize collapses all whitespace runs, so a wrapped comment line matches
// the single-line draft cell.
func normalize(s string) string { return strings.Join(strings.Fields(s), " ") }

// docText returns the package comment of doc.go with comment markers removed.
func docText(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for line := range strings.Lines(readFile(t, "doc.go")) {
		if strings.HasPrefix(line, "package ") {
			break
		}
		b.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "//"), "\t"))
	}
	return b.String()
}

func TestDocReproducesDraftTableRowByRow(t *testing.T) {
	doc := normalize(docText(t))
	rows := draftRows(t)
	for i, r := range rows {
		f := functions[i]
		goName := f.iface.Name() + "." + f.method
		for _, want := range []string{r.fn, goName, r.input, r.output} {
			if !strings.Contains(doc, normalize(want)) {
				t.Errorf("doc.go row %d (%s) lacks %q", i, r.fn, want)
			}
		}
	}
}

func TestDocStatesTheTwoInvariants(t *testing.T) {
	doc := normalize(docText(t))
	for _, want := range []string{
		"authenticated context",
		"configured authoritative lookup",
		"draft 8.5",
		"original source observation",
		"draft 8.3",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("doc.go lacks %q", want)
		}
	}
}
