package rebac_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strings"
	"sync"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/strictjson"
)

// rebacModel is the model of the native state of the ReBAC cases, defined in
// spec/v1.0/fixtures/adapters/rebac/README.md.
const rebacModel = "rebac/1"

// casesDir is the directory of the ReBAC cases in the fixture tree; the model
// file paths of a state are relative to it.
const casesDir = "adapters/rebac"

// The hooks the fake store fires (spec/v1.0/fixtures/adapters/rebac/README.md).
const (
	hookCheck       = "check"
	hookLatestModel = "check-latest-model"
	hookCached      = "check-cached"
	hookContextual  = "contextual-tuples"
	hookExecute     = "execute"
)

// higherConsistency is the consistency preference that skips the caches
// (profile [OF-1], [OF-2]).
const higherConsistency = "HIGHER_CONSISTENCY"

// rebacState is the rebac/1 native state of a case.
type rebacState struct {
	Model           string           `json:"model"`
	Gateway         memory.Gateway   `json:"gateway"`
	Mappings        []memory.Mapping `json:"mappings"`
	Relations       []relationRow    `json:"relations"`
	Pin             pinState         `json:"pin"`
	Subjects        []subjectEntry   `json:"subjects"`
	Objects         []objectEntry    `json:"objects"`
	StoreCredential string           `json:"store_credential"`
	Store           storeState       `json:"store"`
}

type relationRow struct {
	Action     string `json:"action"`
	Relation   string `json:"relation"`
	ObjectType string `json:"object_type"`
}

type pinState struct {
	StoreID              string `json:"store_id"`
	AuthorizationModelID string `json:"authorization_model_id"`
	MappingRevision      string `json:"mapping_revision"`
}

type subjectEntry struct {
	Realm     memory.Realm `json:"realm"`
	Principal string       `json:"principal"`
	SubjectID string       `json:"subject_id"`
}

type objectEntry struct {
	Realm    memory.Realm `json:"realm"`
	Resource string       `json:"resource"`
	ObjectID string       `json:"object_id"`
}

// storeState is the OpenFGA server of a case and the state of its store.
type storeState struct {
	ID           string       `json:"id"`
	Credential   string       `json:"credential"`
	Models       []modelRef   `json:"models"`
	Tuples       []tupleKey   `json:"tuples"`
	CachedTuples *[]tupleKey  `json:"cached_tuples"`
	Unreachable  bool         `json:"unreachable"`
	Hang         bool         `json:"hang"`
	Answer       *answerState `json:"answer"`
}

type modelRef struct {
	ID   string `json:"id"`
	File string `json:"file"`
}

type tupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type answerState struct {
	Status   int             `json:"status"`
	Body     json.RawMessage `json:"body"`
	BodyText *string         `json:"body_text"`
}

// world is a parsed rebac/1 state with its models read.
type world struct {
	st     rebacState
	models map[string]*fgaModel
	latest string
}

// modelOf returns the model member of a native state.
func modelOf(raw []byte) (string, error) {
	var probe struct {
		Model string `json:"model"`
	}
	// Only the model member is read here; the full parse is strict.
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	return probe.Model, nil
}

func fixtures() (fs.FS, error) { return adaptertest.DefaultFixtures() }

// loadWorld parses a rebac/1 state strictly and reads its models from the
// fixture tree.
func loadWorld(raw []byte, fsys fs.FS) (*world, error) {
	var st rebacState
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &st); err != nil {
		return nil, fmt.Errorf("rebac/1 state: %w", err)
	}
	if st.Model != rebacModel {
		return nil, fmt.Errorf("model %q, want %q", st.Model, rebacModel)
	}
	if st.Store.ID == "" || len(st.Store.Models) == 0 {
		return nil, errors.New("rebac/1 state: the store has no id or no model")
	}
	w := &world{st: st, models: map[string]*fgaModel{}}
	for _, m := range st.Store.Models {
		src, err := fs.ReadFile(fsys, path.Join(casesDir, m.File))
		if err != nil {
			return nil, err
		}
		fm, err := parseModel(src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.File, err)
		}
		if _, dup := w.models[m.ID]; dup {
			return nil, fmt.Errorf("model id %s twice", m.ID)
		}
		w.models[m.ID] = fm
		w.latest = m.ID
	}
	return w, nil
}

// subject returns the subject id of principal in realm, or "".
func (w *world) subject(realm memory.Realm, principal string) string {
	for _, s := range w.st.Subjects {
		if s.Realm == realm && s.Principal == principal {
			return s.SubjectID
		}
	}
	return ""
}

// object returns the object id of resource in realm, or "".
func (w *world) object(realm memory.Realm, resource string) string {
	for _, o := range w.st.Objects {
		if o.Realm == realm && o.Resource == resource {
			return o.ObjectID
		}
	}
	return ""
}

// The FGA modeling language, the subset the assets use: a "model" header with
// "schema 1.1", "type" blocks with "relations", and "define" lines whose
// rewrite is a union ("or") of direct types ("[user, group#member,
// user:*]"), computed relations ("editor") and tuple-to-userset terms
// ("member from parent"), the forms of the sample stores of the OpenFGA
// project.

// fgaModel is a parsed model.
type fgaModel struct {
	types map[string]map[string][]term
	order []string
}

// term is one operand of a union.
type term struct {
	direct   []string // the directly related user types, when the term is direct
	relation string   // the computed relation, or the relation of a tuple-to-userset term
	from     string   // the tupleset relation of a tuple-to-userset term
}

// parseModel reads a model in the FGA modeling language.
func parseModel(src []byte) (*fgaModel, error) {
	m := &fgaModel{types: map[string]map[string][]term{}}
	sc := bufio.NewScanner(bytes.NewReader(src))
	cur := ""
	header, schema := false, false
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case line == "model":
			header = true
		case line == "schema 1.1":
			if !header {
				return nil, fmt.Errorf("line %d: schema before model", n)
			}
			schema = true
		case strings.HasPrefix(line, "type "):
			cur = strings.TrimSpace(strings.TrimPrefix(line, "type "))
			if _, dup := m.types[cur]; dup || cur == "" {
				return nil, fmt.Errorf("line %d: type %q", n, cur)
			}
			m.types[cur] = map[string][]term{}
			m.order = append(m.order, cur)
		case line == "relations":
			if cur == "" {
				return nil, fmt.Errorf("line %d: relations outside a type", n)
			}
		case strings.HasPrefix(line, "define "):
			name, expr, ok := strings.Cut(strings.TrimPrefix(line, "define "), ":")
			name = strings.TrimSpace(name)
			if !ok || cur == "" || name == "" {
				return nil, fmt.Errorf("line %d: malformed define", n)
			}
			if _, dup := m.types[cur][name]; dup {
				return nil, fmt.Errorf("line %d: relation %s#%s twice", n, cur, name)
			}
			terms, err := parseRewrite(strings.TrimSpace(expr))
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			m.types[cur][name] = terms
		default:
			return nil, fmt.Errorf("line %d: %q is not in the supported subset", n, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !header || !schema {
		return nil, errors.New("no model header with schema 1.1")
	}
	return m, nil
}

func parseRewrite(expr string) ([]term, error) {
	var out []term
	for part := range strings.SplitSeq(expr, " or ") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]"):
			var types []string
			for t := range strings.SplitSeq(part[1:len(part)-1], ",") {
				if t = strings.TrimSpace(t); t == "" {
					return nil, fmt.Errorf("empty type in %q", part)
				}
				types = append(types, t)
			}
			out = append(out, term{direct: types})
		case strings.Contains(part, " from "):
			rel, ts, _ := strings.Cut(part, " from ")
			out = append(out, term{relation: strings.TrimSpace(rel), from: strings.TrimSpace(ts)})
		case part != "" && !strings.ContainsAny(part, " []#:"):
			out = append(out, term{relation: part})
		default:
			return nil, fmt.Errorf("term %q is not in the supported subset", part)
		}
	}
	return out, nil
}

// errUnknownRelation is a Check on a relation the model does not define.
var errUnknownRelation = errors.New("relation not found")

// check evaluates whether user has relation with object under the model and
// tuples: a direct tuple, a wildcard tuple of the user's type, a computed
// relation, or a relation of an object the tupleset relates (profile [OF-2],
// [OF-12]). A userset of the object and relation themselves is
// self-defining ([OF-2]).
func (m *fgaModel) check(user, relation, object string, tuples []tupleKey, depth int) (bool, error) {
	if depth > 25 {
		return false, errors.New("resolution too complex")
	}
	typ, _, _ := strings.Cut(object, ":")
	terms, ok := m.types[typ][relation]
	if !ok {
		return false, fmt.Errorf("%w: %s#%s", errUnknownRelation, typ, relation)
	}
	if user == object+"#"+relation {
		return true, nil
	}
	userType, _, _ := strings.Cut(user, ":")
	for _, t := range terms {
		switch {
		case t.direct != nil:
			for _, k := range tuples {
				if k.Relation == relation && k.Object == object && (k.User == user || k.User == userType+":*") {
					return true, nil
				}
			}
		case t.from == "":
			if ok, err := m.check(user, t.relation, object, tuples, depth+1); ok || err != nil {
				return ok, err
			}
		default:
			for _, k := range tuples {
				if k.Relation != t.from || k.Object != object {
					continue
				}
				parentType, _, _ := strings.Cut(k.User, ":")
				if _, defined := m.types[parentType][t.relation]; !defined {
					continue
				}
				if ok, err := m.check(user, t.relation, k.User, tuples, depth+1); ok || err != nil {
					return ok, err
				}
			}
		}
	}
	return false, nil
}

// typeDefinitions is the model in the JSON form of the API that writes an
// authorization model (profile [OF-18]).
func (m *fgaModel) typeDefinitions() []map[string]any {
	var defs []map[string]any
	for _, typ := range m.order {
		def := map[string]any{"type": typ}
		rels := m.types[typ]
		if len(rels) > 0 {
			relations, meta := map[string]any{}, map[string]any{}
			for name, terms := range rels {
				var children []any
				var direct []any
				for _, t := range terms {
					switch {
					case t.direct != nil:
						children = append(children, map[string]any{"this": map[string]any{}})
						for _, d := range t.direct {
							switch {
							case strings.HasSuffix(d, ":*"):
								direct = append(direct, map[string]any{"type": strings.TrimSuffix(d, ":*"), "wildcard": map[string]any{}})
							case strings.Contains(d, "#"):
								dt, dr, _ := strings.Cut(d, "#")
								direct = append(direct, map[string]any{"type": dt, "relation": dr})
							default:
								direct = append(direct, map[string]any{"type": d})
							}
						}
					case t.from == "":
						children = append(children, map[string]any{"computedUserset": map[string]any{"object": "", "relation": t.relation}})
					default:
						children = append(children, map[string]any{"tupleToUserset": map[string]any{
							"tupleset":        map[string]any{"object": "", "relation": t.from},
							"computedUserset": map[string]any{"object": "", "relation": t.relation},
						}})
					}
				}
				if len(children) == 1 {
					relations[name] = children[0]
				} else {
					relations[name] = map[string]any{"union": map[string]any{"child": children}}
				}
				if direct != nil {
					meta[name] = map[string]any{"directly_related_user_types": direct}
				}
			}
			def["relations"] = relations
			def["metadata"] = map[string]any{"relations": meta}
		}
		defs = append(defs, def)
	}
	return defs
}

// checkBody is the Check request body (profile [OF-2]).
type checkBody struct {
	TupleKey             *tupleKey `json:"tuple_key"`
	AuthorizationModelID string    `json:"authorization_model_id"`
	Consistency          string    `json:"consistency"`
	ContextualTuples     *struct {
		TupleKeys []tupleKey `json:"tuple_keys"`
	} `json:"contextual_tuples"`
}

// fakeStore is an OpenFGA server over the store of a world: it answers the
// Check API of profile [OF-2] as section "Model rebac/1" of the cases README
// describes, and records every Check body it receives.
type fakeStore struct {
	w     *world
	hooks *adaptertest.Hooks
	srv   *httptest.Server
	url   string

	// closing is closed when the server stops, so that a hanging answer
	// ends.
	closing chan struct{}

	mu     sync.Mutex
	checks []checkBody
}

// newFakeStore starts the server of w over TLS. An unreachable store gets the
// URL of a closed port instead.
func newFakeStore(w *world, hooks *adaptertest.Hooks) (*fakeStore, error) {
	f := &fakeStore{w: w, hooks: hooks, closing: make(chan struct{})}
	if w.st.Store.Unreachable {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		f.url = "https://" + ln.Addr().String()
		if err := ln.Close(); err != nil {
			return nil, err
		}
		return f, nil
	}
	f.srv = httptest.NewTLSServer(f)
	f.url = f.srv.URL
	return f, nil
}

// Close stops the server.
func (f *fakeStore) Close() {
	close(f.closing)
	if f.srv != nil {
		f.srv.Close()
	}
}

// Client returns a client that trusts the server's certificate.
func (f *fakeStore) Client() *http.Client {
	if f.srv == nil {
		return &http.Client{Transport: &http.Transport{}}
	}
	return f.srv.Client()
}

// Checks returns the Check bodies received so far.
func (f *fakeStore) Checks() []checkBody {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.checks)
}

func writeJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(v)
}

func fgaError(rw http.ResponseWriter, status int, code, msg string) {
	writeJSON(rw, status, map[string]string{"code": code, "message": msg})
}

func (f *fakeStore) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	st := f.w.st.Store
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if r.Method != http.MethodPost || len(segs) != 3 || segs[0] != "stores" || segs[2] != "check" {
		fgaError(rw, http.StatusNotFound, "undefined_endpoint", "Not Found")
		return
	}
	f.hooks.Fire(hookCheck)
	if st.Hang {
		select {
		case <-r.Context().Done():
		case <-f.closing:
		}
		return
	}
	if st.Credential != "" {
		switch got := r.Header.Get("Authorization"); got {
		case "":
			fgaError(rw, http.StatusUnauthorized, "bearer_token_missing", "missing bearer token")
			return
		case "Bearer " + st.Credential:
		default:
			fgaError(rw, http.StatusUnauthorized, "unauthenticated", "unauthenticated")
			return
		}
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		fgaError(rw, http.StatusBadRequest, "validation_error", "unreadable body")
		return
	}
	var body checkBody
	if err := json.Unmarshal(raw, &body); err != nil || body.TupleKey == nil {
		fgaError(rw, http.StatusBadRequest, "validation_error", "invalid CheckRequest")
		return
	}
	f.mu.Lock()
	f.checks = append(f.checks, body)
	f.mu.Unlock()
	if a := st.Answer; a != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(a.Status)
		if a.BodyText != nil {
			_, _ = io.WriteString(rw, *a.BodyText)
		} else {
			_, _ = rw.Write(a.Body)
		}
		return
	}
	modelID := body.AuthorizationModelID
	if modelID == "" {
		f.hooks.Fire(hookLatestModel)
	}
	if segs[1] != st.ID {
		if modelID == "" {
			fgaError(rw, http.StatusBadRequest, "latest_authorization_model_not_found", "No authorization models found for store")
		} else {
			fgaError(rw, http.StatusBadRequest, "authorization_model_not_found", "Authorization Model not found")
		}
		return
	}
	if modelID == "" {
		modelID = f.w.latest
	}
	model, ok := f.w.models[modelID]
	if !ok {
		fgaError(rw, http.StatusBadRequest, "authorization_model_not_found", "Authorization Model '"+modelID+"' not found")
		return
	}
	tuples := st.Tuples
	if body.Consistency != higherConsistency {
		f.hooks.Fire(hookCached)
		if st.CachedTuples != nil {
			tuples = *st.CachedTuples
		}
	}
	if body.ContextualTuples != nil && len(body.ContextualTuples.TupleKeys) > 0 {
		f.hooks.Fire(hookContextual)
		tuples = append(slices.Clone(tuples), body.ContextualTuples.TupleKeys...)
	}
	k := body.TupleKey
	allowed, err := model.check(k.User, k.Relation, k.Object, tuples, 0)
	if err != nil {
		fgaError(rw, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"allowed": allowed, "resolution": ""})
}

// postCheck sends a Check body to the store as a client would; it is the
// transport of the stub.
func postCheck(ctx context.Context, f *fakeStore, credential string, body map[string]any) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url+"/stores/"+f.w.st.Pin.StoreID+"/check", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	return f.Client().Do(req)
}
