package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/gateway"
	"hop.top/pact-go/holder"
	"hop.top/pact-go/validator"
)

// Example puts PACT admission in front of an invoice API and sends one agent
// request twice: without a presentation, then with the signed presentation
// the holder builds from the gateway's contract. Native authentication and
// native policy come from the in-memory reference adapter; keys and stores
// are in memory.
func Example() {
	ctx := context.Background()
	const (
		origin    = "https://gateway.example"
		audience  = "https://gateway.example/api"
		env       = "https://gateway.example/environments/prod"
		publisher = "https://gateway.example/publisher"
		agentID   = "https://identity.example/agents/invoice-assistant"
		principal = "https://identity.example/principals/alice"
		mapping   = "map-1"
		check     = "purpose-operation-v1"
	)
	clk := clock.NewFake(time.Unix(1792080000, 0))
	realm := adapter.Realm{TenantID: "acme", EnvironmentID: env}

	// The agent's holder key, enrolled on alice's workload.
	holderKey := must(holder.NewMemoryKeyES256(exampleKey()))
	jkt := must(jws.Thumbprint(must(holderKey.PublicJWK(ctx))))

	// The native system: one identity, one enrollment, one route, one rule.
	seen := clk.Now().Unix() - 600
	mr := memory.Realm{TenantID: realm.TenantID, EnvironmentID: env}
	native := must(memory.New(memory.State{
		Model:   memory.Model,
		Gateway: memory.Gateway{TenantID: realm.TenantID, EnvironmentID: env, Origin: origin},
		Mappings: []memory.Mapping{{Version: mapping, Routes: []memory.Route{
			{Method: "GET", Path: "/invoices/{id}", Action: "invoice.read", Resource: "https://invoices.example/invoices/{id}"},
		}}},
		Identities: []memory.Identity{{Ref: "alice", ID: principal, Realm: mr, Workload: "workload:invoice-assistant", Secret: "alice-token"}},
		Enrollments: []memory.Enrollment{{
			Realm: mr, Workload: "workload:invoice-assistant", AgentID: agentID,
			OperatorID: "https://identity.example/operators/acme", HolderJKT: string(jkt),
			Status: string(adapter.BindingActive), ObservedAt: &seen, StatusCheckedAt: &seen, SourceID: "enrollment",
		}},
		Checks: []memory.CheckRecord{{
			ID: check, Result: string(adapter.VerdictPass), ReasonCode: "REQUIREMENT_SATISFIED",
			SourceID: "purpose-mapping", ObservedAt: &seen,
		}},
		Policy: []memory.PolicyRule{{Realm: mr, Principal: principal, Action: "invoice.read", Effect: "ALLOW"}},
	}, clk))

	// The requirement publisher and the validator, each with its own key.
	pubKey := exampleKey()
	publishers := map[string]*jws.KeySet{publisher: exampleKeySet(pubKey, "publisher-1")}
	replay := contract.NewMemoryReplay(1024)
	policy := contract.Policy{
		BaseRevision:           "base-1",
		LearningPolicyDigest:   digest.BytesDigest([]byte("learning policy")),
		LearningArtifactDigest: digest.BytesDigest([]byte("learning artifact")),
	}

	val := &validator.Validator{
		Config: validator.Config{
			Audience: audience, Realm: realm, Issuer: "https://gateway.example/validator",
			SourceID: "gateway-validator", Publishers: publishers, InstalledChecks: []string{check},
		},
		Native: native, Replay: replay, Receipts: validator.NewMemoryReceipts(),
		Holds:    gateway.NewMemoryHolds(),
		Policies: gateway.StaticPolicy{ActivePolicy: validator.ActivePolicy{Policy: policy, ConservativeSet: "base"}},
		Status:   gateway.NewMemoryStatus(),
		Signer:   validator.ES256Signer{Kid: "validator-1", Key: exampleKey()},
		Clock:    clk,
	}
	pub := &contract.Publisher{
		Issuer: publisher, Audience: audience, Realm: realm,
		Signer: contract.ES256Signer{Kid: "publisher-1", Key: pubKey}, Replay: replay,
	}
	reqs := gateway.RequirementsFunc(func(context.Context, adapter.Principal, core.ContractRequest) (contract.Requirements, error) {
		return contract.Requirements{Policy: policy, SelectedSet: "base", ConservativeSet: "base", ContextChecks: []string{check}}, nil
	})

	// The middleware in front of the application; every route is enforced.
	mw := must(gateway.New(gateway.Config{
		Adapter:        native,
		Validator:      val,
		Publisher:      pub,
		Requirements:   reqs,
		Records:        gateway.NewMemoryRecords(1024),
		MappingVersion: mapping,
	}))
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adm, _ := gateway.FromContext(r.Context())
		_, _ = fmt.Fprintf(w, "invoice for %s, receipt %s", adm.Principal.ID, adm.Receipt.Attestation.Decision)
	})
	protected := mw(app)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(w, memory.Arrive(r))
	}))
	defer srv.Close()

	// The agent's request, with alice's native credential.
	req := must(http.NewRequest(http.MethodGet, srv.URL+"/invoices/INV-1042", nil))
	req.Header.Set("Authorization", "Bearer alice-token")
	fmt.Println(exampleSend(req))

	// The agent side: propose the operation, fetch and verify the contract,
	// and attach the signed presentation.
	op := must(holder.OperationFromRequest(
		binding.Config{Origin: origin, HeaderNormalizationID: "memory-header-normalization-1", MappingVersion: mapping, MaxBody: 8 << 20},
		req, "op-1", env, principal, "invoice.read", []string{"https://invoices.example/invoices/INV-1042"}))
	intent := core.Intent{IntentID: "intent-1", PurposeID: "invoice-summary", Description: "Summarize an invoice", TaskID: "task-1"}
	agent := &holder.Holder{AgentID: agentID, Keys: holderKey, Gateway: audience, Realm: realm, Publishers: publishers}
	cr := must(json.Marshal(core.ContractRequest{AgentID: agentID, HolderJKT: jkt, Intent: intent, Operation: op}))
	creq := must(http.NewRequest(http.MethodPost, srv.URL+gateway.RequirementsPath, bytes.NewReader(cr)))
	creq.Header.Set("Authorization", "Bearer alice-token")
	creq.Header.Set("Content-Type", "application/json")
	cresp := must(http.DefaultClient.Do(creq))
	compact := string(must(io.ReadAll(cresp.Body)))
	_ = cresp.Body.Close()
	c := must(agent.VerifyContract(ctx, compact, intent, op, clk.Now()))
	p := must(agent.Present(ctx, holder.Input{Contract: c.Compact, Intent: intent, Operation: op, Profile: core.AgentProfile{
		ProfileID: "profile-1", Revision: 1, AgentID: agentID, OperatorID: "https://identity.example/operators/acme",
		TenantID: realm.TenantID, HolderJKT: jkt, CreatedAt: clk.Now().Unix() - 60, ExpiresAt: clk.Now().Unix() + 3600,
		Attributes: core.Object{},
	}}, clk.Now()))
	req.Header.Set(gateway.HeaderPresentation, p.Compact)
	fmt.Println(exampleSend(req))

	// Output:
	// 401 INVALID_PROOF
	// 200 invoice for https://identity.example/principals/alice, receipt ADMISSIBLE
}

// exampleSend sends r and returns the status and the body, or the problem
// code of a refusal.
func exampleSend(r *http.Request) string {
	resp := must(http.DefaultClient.Do(r))
	defer func() { _ = resp.Body.Close() }()
	body := must(io.ReadAll(resp.Body))
	if resp.StatusCode != http.StatusOK {
		var p core.Problem
		if json.Unmarshal(body, &p) == nil {
			return fmt.Sprintf("%d %s", resp.StatusCode, p.Code)
		}
	}
	return fmt.Sprintf("%d %s", resp.StatusCode, body)
}

func exampleKey() *ecdsa.PrivateKey {
	return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
}

func exampleKeySet(k *ecdsa.PrivateKey, kid string) *jws.KeySet {
	jwk := must(jws.PublicJWK(&k.PublicKey))
	jwk.Kid = kid
	return must(jws.NewKeySet(jwk))
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
