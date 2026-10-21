package rebac_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
)

// The environment of the integration tier. Without envURL the tier is
// skipped.
const (
	// envURL is the base URL of the OpenFGA HTTP API: https, or http on a
	// loopback address.
	envURL = "PACT_TEST_OPENFGA_URL"
	// envKey is the server's pre-shared key, when it requires one. The cases
	// that present a wrong key need it.
	envKey = "PACT_TEST_OPENFGA_KEY"
)

// TestIntegration runs the ReBAC cases that one OpenFGA server can realize
// against the server at $PACT_TEST_OPENFGA_URL. For each case it creates a
// store, writes the case's models in order and its tuples, and runs the case
// against that store; the store and model ids the server returns replace the
// case's. A case with cached_tuples writes them first, sends a Check without
// HIGHER_CONSISTENCY for each subject, relation and object of the case, and
// then changes the store to its tuples, so that a server with its Check
// caches enabled holds the stale answer. Cases with a fixed answer, an
// unreachable or hanging store run in the unit tier only, and the common
// cases run against the unit tier's fake. The hooks are fired by the client:
// it reads every request the adapter sends to the store.
func TestIntegration(t *testing.T) {
	base := os.Getenv(envURL)
	if base == "" {
		t.Skip(envURL + " is not set; the integration tier needs an OpenFGA server")
	}
	it := &integration{base: strings.TrimSuffix(base, "/"), key: os.Getenv(envKey), client: &http.Client{Timeout: 10 * time.Second}}
	adaptertest.Run(t, it.factory, adaptertest.Options{Adapter: "rebac", Replaced: replaced})
}

// storeSeq numbers the stores the tier creates.
var storeSeq atomic.Int64

type integration struct {
	base, key string
	client    *http.Client
}

func (it *integration) factory(tb testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != rebacModel {
		return rebacFactory(tb, env)
	}
	fsys, err := fixtures()
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := loadWorld(env.State, fsys)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	st := &w.st
	switch {
	case st.Store.Answer != nil || st.Store.Unreachable || st.Store.Hang:
		tb.Skip("unit tier only: a fixed answer or an outage")
	case st.StoreCredential != st.Store.Credential && it.key == "":
		tb.Skip("unit tier only: a wrong key needs a server with a pre-shared key")
	}
	ctx := context.Background()
	var created struct {
		ID string `json:"id"`
	}
	if err := it.call(ctx, "/stores", map[string]any{"name": fmt.Sprintf("pact-rebac-case-%d", storeSeq.Add(1))}, http.StatusCreated, &created); err != nil {
		return adaptertest.Subject{}, err
	}
	ids := map[string]string{}
	for _, m := range st.Store.Models {
		src, err := fs.ReadFile(fsys, path.Join(casesDir, m.File))
		if err != nil {
			return adaptertest.Subject{}, err
		}
		fm, err := parseModel(src)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		var written struct {
			ID string `json:"authorization_model_id"`
		}
		body := map[string]any{"schema_version": "1.1", "type_definitions": fm.typeDefinitions()}
		if err := it.call(ctx, "/stores/"+created.ID+"/authorization-models", body, http.StatusCreated, &written); err != nil {
			return adaptertest.Subject{}, err
		}
		ids[m.ID] = written.ID
	}
	pinnedModel, ok := ids[st.Pin.AuthorizationModelID]
	if !ok {
		return adaptertest.Subject{}, errors.New("the pinned model is not among the store's models")
	}
	if st.Store.CachedTuples != nil {
		if err := it.write(ctx, created.ID, *st.Store.CachedTuples, nil); err != nil {
			return adaptertest.Subject{}, err
		}
		if err := it.warm(ctx, created.ID, pinnedModel, w); err != nil {
			return adaptertest.Subject{}, err
		}
		add := slices.DeleteFunc(slices.Clone(st.Store.Tuples), func(k tupleKey) bool { return slices.Contains(*st.Store.CachedTuples, k) })
		del := slices.DeleteFunc(slices.Clone(*st.Store.CachedTuples), func(k tupleKey) bool { return slices.Contains(st.Store.Tuples, k) })
		if err := it.write(ctx, created.ID, add, del); err != nil {
			return adaptertest.Subject{}, err
		}
	} else if err := it.write(ctx, created.ID, st.Store.Tuples, nil); err != nil {
		return adaptertest.Subject{}, err
	}
	key := it.key
	if st.StoreCredential != st.Store.Credential {
		key = st.StoreCredential
	}
	back := map[string]string{created.ID: st.Pin.StoreID}
	for fixture, server := range ids {
		back[server] = fixture
	}
	st.Pin.StoreID, st.Pin.AuthorizationModelID, st.StoreCredential = created.ID, pinnedModel, key
	client := &http.Client{Transport: hookTransport{hooks: env.Hooks, next: http.DefaultTransport}}
	a, err := newAdapter(w, it.base, client, env)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{
		Adapter: renamed{Adapter: a, back: back},
		Arrive:  func(r *http.Request) *http.Request { return r },
		Credential: func(*http.Request, string) error {
			return errors.New("the rebac/1 cases name no credential")
		},
	}, nil
}

// renamed reports the decision with the case's store and model ids in place
// of those the server assigned, reversing the substitution of the factory.
type renamed struct {
	adapter.Adapter
	back map[string]string
}

func (r renamed) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	d, err := r.Adapter.AuthorizeNative(ctx, p, op)
	if id, ok := r.back[d.SourceID]; ok {
		d.SourceID = id
	}
	if id, ok := r.back[d.PolicyRevision]; ok {
		d.PolicyRevision = id
	}
	return d, err
}

// call posts body to the API path and decodes the answer into out.
func (it *integration) call(ctx context.Context, apiPath string, body any, want int, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, it.base+apiPath, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if it.key != "" {
		req.Header.Set("Authorization", "Bearer "+it.key)
	}
	resp, err := it.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != want {
		return fmt.Errorf("%s: %d %s", apiPath, resp.StatusCode, answer)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(answer, out)
}

// write applies writes and deletes to the store ([OF-8]).
func (it *integration) write(ctx context.Context, store string, writes, deletes []tupleKey) error {
	body := map[string]any{}
	if len(writes) > 0 {
		body["writes"] = map[string]any{"tuple_keys": writes}
	}
	if len(deletes) > 0 {
		body["deletes"] = map[string]any{"tuple_keys": deletes}
	}
	if len(body) == 0 {
		return nil
	}
	return it.call(ctx, "/stores/"+store+"/write", body, http.StatusOK, nil)
}

// warm sends a Check that may be answered from the caches for every subject,
// relation and object of the world.
func (it *integration) warm(ctx context.Context, store, model string, w *world) error {
	for _, s := range w.st.Subjects {
		for _, o := range w.st.Objects {
			for _, r := range w.st.Relations {
				body := map[string]any{
					"tuple_key":              tupleKey{User: "user:" + s.SubjectID, Relation: r.Relation, Object: r.ObjectType + ":" + o.ObjectID},
					"authorization_model_id": model,
					"consistency":            "MINIMIZE_LATENCY",
				}
				if err := it.call(ctx, "/stores/"+store+"/check", body, http.StatusOK, nil); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// hookTransport fires the hooks of the cases README for each Check the
// adapter sends, from the request body as the store receives it.
type hookTransport struct {
	hooks *adaptertest.Hooks
	next  http.RoundTripper
}

func (h hookTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil && strings.HasSuffix(r.URL.Path, "/check") {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var body checkBody
		_ = json.Unmarshal(raw, &body)
		h.hooks.Fire(hookCheck)
		if body.AuthorizationModelID == "" {
			h.hooks.Fire(hookLatestModel)
		}
		if body.Consistency != higherConsistency {
			h.hooks.Fire(hookCached)
		}
		if body.ContextualTuples != nil && len(body.ContextualTuples.TupleKeys) > 0 {
			h.hooks.Fire(hookContextual)
		}
	}
	return h.next.RoundTrip(r)
}
