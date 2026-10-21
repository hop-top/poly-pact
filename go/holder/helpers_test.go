package holder_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/holder"
)

const (
	draftPath    = "../../spec/v1.0/draft.md"
	fixturesRoot = "../../spec/v1.0/fixtures"
	validCase    = "admission/valid/"
)

// Values of draft Appendix B (B.1 to B.7) and of the fixture configuration
// of spec/v1.0/fixtures/admission/valid, written out here from the draft text.
const (
	bTime         = 1792080000
	bContractExp  = 1792080060
	bPublisher    = "https://trust.example/issuers/finance"
	bReputation   = "https://reputation.example/finance"
	bAgent        = "https://identity.example/agents/invoice-assistant"
	bGateway      = "https://gateway.example/finance"
	bTenant       = "acme"
	bEnv          = "https://gateway.example/environments/finance"
	bHolderJKT    = core.Digest("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M")
	bPrincipal    = "https://identity.example/principals/alice"
	bOperator     = "https://identity.example/operators/acme"
	bBase         = "finance-base-3"
	bPolicyDig    = core.Digest("mIu2mtBMHPAf6CgJkuwuDsUWhs9bu-Wkenl4QlrcQAQ")
	bArtDig       = core.Digest("Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0")
	bOpDigest     = core.Digest("R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0")
	bIntentDigest = core.Digest("t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M")
	// B.7: the receipt's presentation_id and profile_digest.
	bPresentationID = "v6wxT-_cB0Ua8Xkqgcuu2g"
	bProfileDigest  = core.Digest("b6pNI8i5pX5MtuxkaBw0M-4tmzdkGsHVS_Kyji7_uOU")
)

var bRealm = adapter.Realm{TenantID: bTenant, EnvironmentID: bEnv}

var bg = context.Background()

func at(sec int64) time.Time { return time.Unix(sec, 0) }

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func fixture(t testing.TB, rel string) []byte {
	t.Helper()
	return readFile(t, filepath.Join(fixturesRoot, filepath.FromSlash(rel)))
}

func compactOf(t testing.TB, rel string) string {
	t.Helper()
	return strings.TrimSpace(string(fixture(t, rel)))
}

// draftBlock returns the first json block under the heading "### <section> ".
func draftBlock(t testing.TB, section string) []byte {
	t.Helper()
	re := regexp.MustCompile(`(?m)^### ` + regexp.QuoteMeta(section) + ` [^\n]*\n(?:[^\n#][^\n]*\n|\n)*?` + "```json\n" + `((?s:.*?))\n` + "```\n")
	m := re.FindSubmatch(readFile(t, draftPath))
	if m == nil {
		t.Fatalf("draft has no json block under %s", section)
	}
	return m[1]
}

func canonical(t testing.TB, b []byte) string {
	t.Helper()
	c, err := jcs.Canonicalize(b)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	return string(c)
}

func canonicalOf(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return canonical(t, b)
}

func decodeStrict(t testing.TB, b []byte, v any) {
	t.Helper()
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func segment(t testing.TB, compact string, i int) []byte {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[i])
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signingInput(compact string) string {
	return compact[:strings.LastIndexByte(compact, '.')]
}

// scalarKey is the P-256 test key of private scalar n
// (spec/v1.0/fixtures/keys/README.md): 1 holder, 2 issuer, 3 adversarial, 4
// reputation service, 10 second holder.
func scalarKey(t testing.TB, n byte) *ecdsa.PrivateKey {
	t.Helper()
	d := make([]byte, 32)
	d[31] = n
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// edKey is the Ed25519 test key of spec/v1.0/fixtures/keys/test-private-scalars.json.
func edKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	var f struct {
		Keys []struct {
			Kty string `json:"kty"`
			D   string `json:"d"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(fixture(t, "keys/test-private-scalars.json"), &f); err != nil {
		t.Fatal(err)
	}
	for _, k := range f.Keys {
		if k.Kty == "OKP" {
			seed, err := base64.RawURLEncoding.DecodeString(k.D)
			if err != nil {
				t.Fatal(err)
			}
			return ed25519.NewKeyFromSeed(seed)
		}
	}
	t.Fatal("no Ed25519 test key")
	return nil
}

func memoryKey(t testing.TB, n byte) *holder.MemoryKey {
	t.Helper()
	k, err := holder.NewMemoryKeyES256(scalarKey(t, n))
	if err != nil {
		t.Fatalf("NewMemoryKeyES256: %v", err)
	}
	return k
}

func fixtureKeySet(t testing.TB, algs jws.Algorithms, names ...string) *jws.KeySet {
	t.Helper()
	var keys []jws.JWK
	for _, n := range names {
		k, err := algs.ParseJWK(fixture(t, "keys/"+n+".jwk.json"))
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		keys = append(keys, k)
	}
	s, err := algs.NewKeySet(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// bHolder is the B.4 agent with the holder key (scalar 1), presenting to
// the finance gateway and trusting the finance publisher (the issuer key).
func bHolder(t testing.TB, keys holder.KeySource) *holder.Holder {
	t.Helper()
	return &holder.Holder{
		AgentID:    bAgent,
		Keys:       keys,
		Gateway:    bGateway,
		Realm:      bRealm,
		Publishers: map[string]*jws.KeySet{bPublisher: fixtureKeySet(t, nil, "issuer")},
		Skew:       5 * time.Second,
	}
}

func bIntent(t testing.TB) core.Intent {
	t.Helper()
	var in core.Intent
	decodeStrict(t, draftBlock(t, "B.2"), &in)
	return in
}

func bOperation(t testing.TB) core.OperationContext {
	t.Helper()
	var op core.OperationContext
	decodeStrict(t, draftBlock(t, "B.3"), &op)
	return op
}

// bProfile is the B.1 profile.
func bProfile(t testing.TB) core.AgentProfile {
	t.Helper()
	var p core.AgentProfile
	decodeStrict(t, draftBlock(t, "B.1"), &p)
	return p
}

// sourceProfile is what the agent holds before disclosure: the B.1 core
// fields and attributes, without the reputation value (the snapshot
// supplies it, draft 15.2), plus attributes no B.4 rule asks for.
func sourceProfile(t testing.TB) core.AgentProfile {
	t.Helper()
	p := bProfile(t)
	attrs := core.Object{}
	for k, v := range p.Attributes {
		if k != "reputation" {
			attrs[k] = v
		}
	}
	attrs["environment"] = json.RawMessage(`{"principal_id":"https://identity.example/principals/alice","roles":["finance-reader"],"display_name":"Invoice assistant"}`)
	attrs["capabilities"] = json.RawMessage(`{"languages":["en","fr"]}`)
	attrs["runtime"] = json.RawMessage(`{"isolation":"managed","host":"build-17"}`)
	p.Attributes = attrs
	return p
}

// bInput is the input of the Appendix B presentation: the fixture's signed
// B.4 contract, B.5 evidence and B.6 snapshot, the B.2 intent, the B.3
// operation and the source profile.
func bInput(t testing.TB) holder.Input {
	t.Helper()
	return holder.Input{
		Contract:   compactOf(t, validCase+"signed/contract.jws"),
		Intent:     bIntent(t),
		Operation:  bOperation(t),
		Profile:    sourceProfile(t),
		Evidence:   []string{compactOf(t, validCase+"signed/evidence/runtime.jws")},
		Reputation: compactOf(t, validCase+"signed/reputation.jws"),
	}
}

// jtiRandom returns the random source that yields the jti v (its 16 octets).
func jtiRandom(t testing.TB, v string) *bytes.Reader {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

// signEvidence signs an evidence payload as the issuer key n (kid of the
// fixture keys), for evidence variations the fixtures do not carry.
func signEvidence(t testing.TB, n byte, kid string, e core.Evidence) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.Sign(jws.Header{Typ: jws.TypEvidence, Kid: kid}, b, scalarKey(t, n))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// bEvidence is the decoded B.5 evidence.
func bEvidence(t testing.TB) core.Evidence {
	t.Helper()
	var e core.Evidence
	decodeStrict(t, draftBlock(t, "B.5"), &e)
	return e
}

// bPolicy is the active policy the B.4 contract pins.
func bPolicy() contract.Policy {
	return contract.Policy{BaseRevision: bBase, LearningPolicyDigest: bPolicyDig, LearningArtifactDigest: bArtDig}
}

// bRequirements are the effective requirements of the B.4 contract.
func bRequirements(t testing.TB) contract.Requirements {
	t.Helper()
	var c core.RequirementContract
	decodeStrict(t, draftBlock(t, "B.4"), &c)
	return contract.Requirements{
		Policy: bPolicy(), SelectedSet: "supervised", ConservativeSet: "supervised",
		FieldRules: c.FieldRules, ContextChecks: c.ContextChecks, Mode: core.ModeEnforced,
	}
}

// issue has the finance publisher issue a contract at now for op and the
// B.2 intent, bound to holderJKT, registering its nonce in store.
func issue(t testing.TB, store contract.ReplayStore, holderJKT core.Digest, r contract.Requirements, op core.OperationContext, now time.Time) contract.Contract {
	t.Helper()
	p := &contract.Publisher{
		Issuer: bPublisher, Audience: bGateway, Realm: bRealm,
		Signer: contract.ES256Signer{Kid: "test-issuer-key-1", Key: scalarKey(t, 2)},
		Replay: store,
	}
	auth := contract.Authenticated{
		Principal: adapter.Principal{ID: bPrincipal, Realm: bRealm, Workload: "workload:invoice-assistant", AuthenticatedAt: now},
		Binding: adapter.AgentBinding{
			AgentID: bAgent, OperatorID: bOperator, HolderJKT: holderJKT, Status: adapter.BindingActive,
			ObservedAt: now, StatusCheckedAt: now, SourceID: "enrollment",
		},
	}
	req := core.ContractRequest{AgentID: bAgent, HolderJKT: holderJKT, Intent: bIntent(t), Operation: op}
	c, err := p.Issue(bg, req, auth, r, now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return c
}

// gatewayChecks are the presentation checks of draft 11.2 and 11.3 that the
// packages on main implement, applied independently of package holder: the
// holder signature under the enrolled holder_jkt (step 2), the contract
// (step 3), the presentation time bounds and nonce association (step 4),
// the operation and intent binding against the actual operation (step 5),
// the profile's subject, holder and tenant (step 6), and the signatures of
// the embedded evidence and snapshot (steps 7 and 9). It returns the
// decoded presentation and the contract's nonce record as the presentation
// binds it.
type gatewayChecks struct {
	enrolled jws.JWK
	algs     jws.Algorithms
	actual   core.OperationContext
	now      time.Time
}

func (g gatewayChecks) run(t testing.TB, compact string) (core.Presentation, contract.NonceRecord, error) {
	t.Helper()
	var p core.Presentation
	enrolledJKT, err := jws.Thumbprint(g.enrolled)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jws.Verifier{Keys: jws.StaticResolver{ExpectedHolderJKT: enrolledJKT}, Typ: jws.TypPresentation, Algorithms: g.algs}.Verify(compact)
	if err != nil {
		return p, contract.NonceRecord{}, fmt.Errorf("step 2 signature: %w", err)
	}
	if err := strictjson.Unmarshal(parsed.Payload, strictjson.Limits{}, &p); err != nil {
		return p, contract.NonceRecord{}, fmt.Errorf("step 1 decode: %w", err)
	}
	if p.PactVersion != core.Version {
		return p, contract.NonceRecord{}, fmt.Errorf("step 1 version %q", p.PactVersion)
	}
	if p.Issuer != p.Profile.AgentID || p.Subject != p.Profile.AgentID || p.Audience != bGateway || p.TenantID != bTenant {
		return p, contract.NonceRecord{}, errors.New("11.2 iss, sub, aud or tenant")
	}
	v := contract.Verifier{Publishers: map[string]*jws.KeySet{bPublisher: fixtureKeySet(t, nil, "issuer")}, Skew: 5 * time.Second}
	c, err := v.Verify(p.Contract, g.now)
	if err != nil {
		return p, contract.NonceRecord{}, fmt.Errorf("step 3 contract: %w", err)
	}
	if err := c.Check(contract.Expect{AgentID: p.Subject, Audience: bGateway, Realm: bRealm}); err != nil {
		return p, contract.NonceRecord{}, fmt.Errorf("step 3 context: %w", err)
	}
	if err := c.CheckActive(bPolicy()); err != nil {
		return p, contract.NonceRecord{}, fmt.Errorf("step 3 active: %w", err)
	}
	if err := clock.CheckPresentation(p.IssuedAt, p.NotBefore, p.Expiry, g.now, 5*time.Second); err != nil {
		return p, contract.NonceRecord{}, fmt.Errorf("step 4 time: %w", err)
	}
	if p.Nonce != c.Claims.Nonce {
		return p, contract.NonceRecord{}, errors.New("step 4 nonce differs from the contract's")
	}
	if parsed.KeyThumbprint != c.Claims.HolderJKT || p.Profile.HolderJKT != c.Claims.HolderJKT {
		return p, contract.NonceRecord{}, errors.New("11.2 key, profile and contract holder_jkt differ")
	}
	actual, err := digest.ObjectDigest(g.actual)
	if err != nil {
		t.Fatal(err)
	}
	presented, err := digest.ObjectDigest(p.Operation)
	if err != nil {
		t.Fatal(err)
	}
	if actual != c.Claims.OperationDigest || presented != c.Claims.OperationDigest {
		return p, contract.NonceRecord{}, errors.New("step 5 operation digest differs")
	}
	intent, err := digest.ObjectDigest(p.Intent)
	if err != nil {
		t.Fatal(err)
	}
	if intent != c.Claims.IntentDigest {
		return p, contract.NonceRecord{}, errors.New("step 5 intent digest differs")
	}
	if p.Profile.AgentID != c.Claims.Subject || p.Profile.TenantID != c.Claims.TenantID {
		return p, contract.NonceRecord{}, errors.New("step 6 profile subject or tenant")
	}
	if err := clock.CheckWindow(p.Profile.CreatedAt, p.Profile.CreatedAt, p.Profile.ExpiresAt, g.now, 5*time.Second); err != nil {
		return p, contract.NonceRecord{}, fmt.Errorf("step 6 profile age: %w", err)
	}
	issuers := jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{
		jws.RoleIssuer:            fixtureKeySet(t, nil, "issuer"),
		jws.RoleReputationService: fixtureKeySet(t, nil, "reputation-service"),
	}}
	for _, e := range p.Evidence {
		if _, err := (jws.Verifier{Keys: issuers, Typ: jws.TypEvidence}).Verify(e); err != nil {
			return p, contract.NonceRecord{}, fmt.Errorf("step 7 evidence: %w", err)
		}
	}
	if p.Reputation != nil {
		if _, err := (jws.Verifier{Keys: issuers, Typ: jws.TypReputation}).Verify(*p.Reputation); err != nil {
			return p, contract.NonceRecord{}, fmt.Errorf("step 9 snapshot: %w", err)
		}
	}
	rec := contract.NonceRecord{
		Nonce: p.Nonce, AgentID: p.Subject, HolderJKT: parsed.KeyThumbprint,
		Realm: adapter.Realm{TenantID: p.TenantID, EnvironmentID: p.Operation.EnvironmentID}, OperationDigest: actual, RequirementsDigest: c.Digest,
	}
	return p, rec, nil
}

func holderJWK(t testing.TB) jws.JWK {
	t.Helper()
	k, err := jws.ParseJWK(fixture(t, "keys/holder.jwk.json"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func bChecks(t testing.TB, actual core.OperationContext, now time.Time) gatewayChecks {
	t.Helper()
	return gatewayChecks{enrolled: holderJWK(t), actual: actual, now: now}
}

var sentinels = []error{
	holder.ErrInvalidMessage, holder.ErrUnsupportedVersion, holder.ErrInvalidProof, holder.ErrContextMismatch,
	holder.ErrUnsupportedRequirement, holder.ErrMissingField, holder.ErrConflictingEvidence, holder.ErrExpired,
	holder.ErrDependencyUnavailable,
}

// wantErr fails unless err wraps want and no other sentinel of the package.
func wantErr(t testing.TB, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error %v, want %v", err, want)
	}
	for _, other := range sentinels {
		if other != want && errors.Is(err, other) {
			t.Fatalf("error %v also wraps %v", err, other)
		}
	}
}

// countingKey is a KeySource that counts its signatures and can sign with
// another key than the one it advertises.
type countingKey struct {
	public holder.KeySource
	signer holder.KeySource
	signs  int
}

func (c *countingKey) PublicJWK(ctx context.Context) (jws.JWK, error) { return c.public.PublicJWK(ctx) }

func (c *countingKey) Sign(ctx context.Context, in []byte) ([]byte, error) {
	c.signs++
	return c.signer.Sign(ctx, in)
}

// failingKey is a KeySource whose signer is unavailable.
type failingKey struct{ public holder.KeySource }

func (f failingKey) PublicJWK(ctx context.Context) (jws.JWK, error) { return f.public.PublicJWK(ctx) }

func (failingKey) Sign(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("keychain locked")
}
