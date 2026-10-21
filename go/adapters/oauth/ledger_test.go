package oauth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
)

// refreshAS is an authorization server that answers each token with its
// subject and client: t1 and t2 are Maya's token and its refresh, t3 is
// another user's token of the same client, t4 Maya's token of another
// client.
type refreshAS struct{}

func (refreshAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	who := map[string][2]string{
		"tok-t1": {"248289761001", "crm-assistant"},
		"tok-t2": {"248289761001", "crm-assistant"},
		"tok-t3": {"771020034512", "crm-assistant"},
		"tok-t4": {"248289761001", "crm-batch"},
	}[r.PostForm.Get("token")]
	sub, client := who[0], who[1]
	iat := int64(tNow - 600)
	if r.PostForm.Get("token") == "tok-t2" {
		iat = tNow + 600 // the refresh is issued later
	}
	if sub == "" {
		_, _ = fmt.Fprint(w, `{"active":false}`)
		return
	}
	_, _ = fmt.Fprintf(w, `{"active":true,"sub":%q,"client_id":%q,"scope":"crm.customers.read","aud":"https://gateway.acme.example","iat":%d,"exp":%d}`,
		sub, client, iat, tNow+3000)
}

// renewalTask is the task registry of example I03: one task, which every
// client value "renewal-C-481" names.
type renewalTask struct{}

func (renewalTask) Resolve(context.Context, adapter.Realm, string, adapter.AgentID, string) ([]task.Ref, error) {
	return []task.Ref{"crm-task:renewal-C-481"}, nil
}

func (renewalTask) Lookup(_ context.Context, _ adapter.Realm, ref task.Ref) (task.Record, error) {
	return task.Record{Ref: ref, State: task.StateActive, Limits: task.Limits{
		MaxOperations: task.Bounded(3), MaxPages: task.Bounded(0), MaxBytes: task.Unbounded(), Deadline: time.Unix(tNow+900, 0),
	}}, nil
}

// TestRefreshedAuthority is the refreshed-authority detection of rule MO-7
// of the multi-operation profile, worked in its table for example I03: the
// task ledger binds its entry to the principal, the agent and the workload
// that this adapter authenticates. A refreshed token of the same user and
// client authenticates to the same principal and workload and shares the
// entry; a token of another user, or of another client, is task-mismatch and
// changes no counter. Nothing in the binding comes from the token itself:
// the issue time and the token identifier of a refresh differ (OAUTH-36).
func TestRefreshedAuthority(t *testing.T) {
	clk := clock.NewFake(time.Unix(tNow, 0))
	entry := formIEntry(0)
	entry.Clients = []string{"crm-assistant", "crm-batch"}
	a := newAdapter(t, clk, &http.Client{Transport: &handlerTransport{h: refreshAS{}}}, entry)
	l := task.NewMemory(task.Config{Registry: renewalTask{}, Clock: clk})
	agent := adapter.AgentID("https://agents.acme.example/renewal-assistant")
	seq := 0
	read := func(tok string) error {
		p, err := a.AuthenticateNative(context.Background(), bearer(t, tok))
		if err != nil {
			t.Fatalf("%s: %v", tok, err)
		}
		seq++
		_, err = l.Reserve(context.Background(), task.Request{
			Principal: p, AgentID: agent, TaskID: "renewal-C-481",
			Route: task.Route{ID: "crm-read", Version: "1", Class: task.ClassRead},
			Operation: core.OperationContext{
				OperationID: fmt.Sprintf("op-%d", seq), EnvironmentID: p.Realm.EnvironmentID, PrincipalID: p.ID,
				Action: "crm.customer.read", Resources: []string{"customer:C-481"}, Method: http.MethodGet,
				TargetURI: "https://gateway.acme.example/customers/C-481", BodyDigest: digest.BytesDigest(nil), Headers: map[string]string{},
			},
		})
		return err
	}
	if err := read("tok-t1"); err != nil {
		t.Fatalf("row 1, token t1: %v", err)
	}
	clk.Advance(10 * time.Minute)
	if err := read("tok-t2"); err != nil {
		t.Errorf("row 2, the refreshed token t2: %v, want the same entry", err)
	}
	for tok, what := range map[string]string{"tok-t3": "row 3, another user's token", "tok-t4": "the user's token of another client"} {
		var r *task.Refusal
		if err := read(tok); !errors.As(err, &r) || r.Label != task.LabelTaskMismatch {
			t.Errorf("%s: %v, want task-mismatch", what, err)
		}
	}
	e, err := l.Entry(context.Background(), task.Key{Realm: adapter.Realm{TenantID: "acme", EnvironmentID: "https://gateway.acme.example/environments/crm"}, Task: "crm-task:renewal-C-481"})
	if err != nil || e.Budget.Operations != 2 {
		t.Errorf("entry %+v %v, want 2 operations", e.Budget, err)
	}
}
