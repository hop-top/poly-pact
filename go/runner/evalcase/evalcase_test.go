package evalcase_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
)

// designedUntrusted lists the committed signed files that a case makes fail
// verification against its trust records on purpose, with the jws reason.
// An artifact entry with payload_signed must fail with signature-invalid
// (spec/v1.0/fixtures/README.md, Generator contract) and need not be listed. A
// new case whose artifact fails verification by design adds a row here.
var designedUntrusted = map[string]jws.Reason{
	// The presentation is signed by a holder key other than the enrolled
	// one (native_context.json authenticated.holder_jkt).
	"admission/old-holder-key/signed/presentation.jws": jws.ErrHolderJKTMismatch,
	// The presentation is signed by the key that a rotation retired; the
	// enrollment names the key after the rotation.
	"admission/rotated-holder-key/signed/presentation.jws": jws.ErrHolderJKTMismatch,
	// The presented agent has no binding on the authenticated workload:
	// native_context.json authenticated.holder_jkt is null, so no enrolled
	// key exists to verify the presentation against.
	"admission/agent-of-other-workload/signed/presentation.jws":        jws.ErrKeyUnavailable,
	"admission/other-realm-agent-other-tenant/signed/presentation.jws": jws.ErrKeyUnavailable,
	"admission/unenrolled-agent/signed/presentation.jws":               jws.ErrKeyUnavailable,
	"admission/workload-two-enrollments/signed/presentation.jws":       jws.ErrKeyUnavailable,
}

func evaluateEntries(t testing.TB) []manifest.Entry {
	t.Helper()
	m, err := manifest.Load(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var out []manifest.Entry
	for _, e := range m.Entries {
		if e.Kind == manifest.KindEvaluate {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		t.Fatal("no evaluate entry in the manifest")
	}
	return out
}

// TestLoadsEveryCommittedCase: every evaluate entry of the manifest loads,
// v1 and v2 alike; every signed file its signing.json names is read and
// verified, and verifies against the case's trust records unless the case
// makes it fail by design.
func TestLoadsEveryCommittedCase(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range evaluateEntries(t) {
		t.Run(e.ID, func(t *testing.T) {
			c, err := evalcase.Load(repoFixtures, e.ID)
			if err != nil {
				t.Fatal(err)
			}
			if c.ID != e.ID || c.Path != e.Path || len(c.Exchanges) == 0 {
				t.Fatalf("case %q path %q with %d exchanges", c.ID, c.Path, len(c.Exchanges))
			}
			if s := c.Exchanges[c.Subject]; s.ExpectedPath != *e.Expected {
				t.Errorf("subject exchange expected file %s, manifest %s", s.ExpectedPath, *e.Expected)
			}
			for _, x := range c.Exchanges {
				if x.Config.Now == 0 || len(x.Config.Trust) == 0 || x.NativeContext.Authenticated == nil {
					t.Errorf("%s: config or native context not read", x.Path)
				}
				if n := len(x.Signing.Artifacts) + len(x.Signing.Presentations); len(x.Signed) != n || n == 0 {
					t.Errorf("%s: %d signed files for %d signing.json entries", x.Path, len(x.Signed), n)
				}
				if got := x.Expected.ExpectedResponses(); len(got) != len(x.Submissions) {
					t.Errorf("%s: %d expected responses for %d submissions", x.Path, len(got), len(x.Submissions))
				}
				tampered := map[string]bool{}
				for _, a := range x.Signing.Artifacts {
					if a.PayloadSigned != nil {
						tampered[a.Signed] = true
					}
				}
				for _, s := range x.Signed {
					id := x.Path + "/" + s.Path
					want, designed := designedUntrusted[id]
					if tampered[s.Path] {
						want, designed = jws.ErrSignatureInvalid, true
					}
					seen[id] = true
					switch {
					case designed && jws.ReasonOf(s.Trust) != want:
						t.Errorf("%s: trust %v, want reason %s by design", id, s.Trust, want)
					case !designed && s.Trust != nil:
						t.Errorf("%s: does not verify against the trust records: %v", id, s.Trust)
					}
				}
			}
		})
	}
	for id := range designedUntrusted {
		if !seen[id] {
			t.Errorf("designedUntrusted lists %s, which no case signs", id)
		}
	}
}

// TestVerifiesEverySignedDirectory: Verify accepts every directory that
// Dirs lists, outcome cases included, and returns one result per signed
// file found under it.
func TestVerifiesEverySignedDirectory(t *testing.T) {
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := evalcase.Dirs(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	total, kinds := 0, map[string]bool{}
	for _, d := range dirs {
		signed, err := evalcase.Verify(repoFixtures, d, keys)
		if err != nil {
			t.Errorf("%s: %v", d.ID, err)
			continue
		}
		kinds[strings.SplitN(d.Entry, "/", 2)[0]] = true
		var files []string
		root := filepath.Join(repoFixtures, filepath.FromSlash(d.Path))
		_ = filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
			if err == nil && !de.IsDir() && path.Ext(p) == ".jws" {
				r, _ := filepath.Rel(root, p)
				files = append(files, filepath.ToSlash(r))
			}
			return err
		})
		var got []string
		for _, s := range signed {
			got = append(got, s.Path)
		}
		slices.Sort(files)
		slices.Sort(got)
		if !slices.Equal(files, got) {
			t.Errorf("%s: verified %v, signed files %v", d.ID, got, files)
		}
		total += len(signed)
	}
	if total == 0 || !kinds["admission"] || !kinds["outcomes"] {
		t.Errorf("%d signed files in groups %v", total, kinds)
	}
}

// TestValidCase: admission/valid reads into the values of the README
// section admission/valid and the defaults of format v2 for a case without
// exchange.json.
func TestValidCase(t *testing.T) {
	c, err := evalcase.Load(repoFixtures, "admission/valid")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Exchanges) != 1 || c.Subject != 0 {
		t.Fatalf("%d exchanges, subject %d", len(c.Exchanges), c.Subject)
	}
	x := c.Exchanges[0]
	if x.Name != "" || x.Path != "admission/valid" || x.ExpectedPath != "expected/admission/valid/decision.json" {
		t.Errorf("exchange name %q path %q expected %q", x.Name, x.Path, x.ExpectedPath)
	}
	cfg := x.Config
	if cfg.Mode != core.ModeEnforced || cfg.Now != 1792080000 || cfg.ClockSkewSeconds != 5 {
		t.Errorf("mode %s now %d skew %d", cfg.Mode, cfg.Now, cfg.ClockSkewSeconds)
	}
	if cfg.Gateway.GatewayID != "https://gateway.example/finance" || cfg.Gateway.TenantID != "acme" {
		t.Errorf("gateway %+v", cfg.Gateway)
	}
	if len(cfg.Trust) != 3 || cfg.Trust[2].Role != jws.RoleReputationService || !slices.Equal(cfg.Trust[2].Keys, []string{"keys/reputation-service.jwk.json"}) {
		t.Errorf("trust %+v", cfg.Trust)
	}
	if cfg.Validator.Key != "keys/validator.jwk.json" || cfg.Limits["evaluation_seconds"] != 30 || cfg.Selection != nil {
		t.Errorf("validator %+v, limits %v, selection %v", cfg.Validator, cfg.Limits, cfg.Selection)
	}
	nc := x.NativeContext
	if a := nc.Authenticated; a.HolderJKT == nil || *a.HolderJKT != "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M" || !nc.Authorize {
		t.Errorf("authenticated %+v, authorize %v", nc.Authenticated, nc.Authorize)
	}
	if nc.Approval == nil || nc.Approval.State != "approved" || nc.Delegation == nil || nc.Delegation.State != "active" {
		t.Errorf("approval %+v, delegation %+v", nc.Approval, nc.Delegation)
	}
	if len(x.Submissions) != 1 {
		t.Fatalf("%d submissions", len(x.Submissions))
	}
	s := x.Submissions[0]
	if s.Signed != "signed/presentation.jws" || s.JTI != "v6wxT-_cB0Ua8Xkqgcuu2g" || s.Replica != "r1" || s.Concurrent ||
		s.EvictReplayRecords || s.ActualOperation != "actual_operation.json" || s.Evaluation.StartedAt != 1792080000 ||
		s.Evaluation.NativeReadsAt != nil || s.Evaluation.CancelledAt != nil {
		t.Errorf("default submission %+v", s)
	}
	if x.Availability.ReplayStore != "available" || len(x.Availability.Sources) != 0 || len(x.Handoff) != 0 {
		t.Errorf("availability %+v, handoff %+v", x.Availability, x.Handoff)
	}
	want := []struct{ path, typ, jti string }{
		{"signed/contract.jws", jws.TypRequirements, "zIMh1jdcSU0EP90CYPIbwA"},
		{"signed/evidence/runtime.jws", jws.TypEvidence, "7oJQ-3bglLNLRx8Tpz275Q"},
		{"signed/reputation.jws", jws.TypReputation, "VW7HSF227CWWBU7wN09Q5A"},
		{"signed/presentation.jws", jws.TypPresentation, "v6wxT-_cB0Ua8Xkqgcuu2g"},
	}
	if len(x.Signed) != len(want) {
		t.Fatalf("%d signed files", len(x.Signed))
	}
	for i, w := range want {
		got := x.Signed[i]
		var claims struct {
			JTI string `json:"jti"`
		}
		if err := json.Unmarshal(got.Payload, &claims); err != nil {
			t.Fatal(err)
		}
		if got.Path != w.path || got.Typ != w.typ || claims.JTI != w.jti || got.Trust != nil {
			t.Errorf("signed[%d] %s typ %s jti %s trust %v; want %s %s %s", i, got.Path, got.Typ, claims.JTI, got.Trust, w.path, w.typ, w.jti)
		}
		if raw := readFile(t, filepath.Join(repoFixtures, "admission", "valid", filepath.FromSlash(w.path))); got.Compact != string(raw) {
			t.Errorf("%s: compact is not the committed file", w.path)
		}
	}
	if !bytes.Equal(x.Signed[0].Payload, x.Decoded["contract.json"]) {
		t.Error("the contract payload is not contract.json")
	}
	for _, f := range []string{"profile.json", "intent.json", "operation.json", "actual_operation.json", "contract.json", "evidence/runtime.json", "reputation.json"} {
		if len(x.Decoded[f]) == 0 {
			t.Errorf("decoded %s not read", f)
		}
	}
	for _, f := range []string{"config.json", "native_context.json", "signing.json"} {
		if _, ok := x.Decoded[f]; ok {
			t.Errorf("control file %s listed as a decoded object", f)
		}
	}
	rs := x.Expected.ExpectedResponses()
	if len(rs) != 1 || rs[0].Decision == nil || *rs[0].Decision != core.DecisionAdmissible || len(rs[0].Checks) != 20 || rs[0].TransportCode != nil {
		t.Fatalf("expected responses %+v", rs)
	}
	if rs[0].Receipt == nil || rs[0].Receipt.Typ != "pact-admission+jwt" || rs[0].Receipt.Signer != "keys/validator.jwk.json" {
		t.Errorf("receipt %+v", rs[0].Receipt)
	}
}

// TestExchangeDefaults: exchange.json members fill the submissions and
// handoff attempts with the defaults of README section exchange.json.
func TestExchangeDefaults(t *testing.T) {
	c, err := evalcase.Load(repoFixtures, "admission/attestation-reuse")
	if err != nil {
		t.Fatal(err)
	}
	x := c.Exchanges[0]
	if len(x.Submissions) != 1 || len(x.Handoff) != 3 || len(x.Expected.Handoff) != 3 {
		t.Fatalf("%d submissions, %d handoff attempts, %d expected", len(x.Submissions), len(x.Handoff), len(x.Expected.Handoff))
	}
	first := x.Submissions[0]
	for i, h := range x.Handoff {
		op := "actual_operation.json"
		if i == 0 {
			op = "other_operation.json"
		}
		if h.Presentation != first.JTI || h.ActualOperation != op || h.At != first.Evaluation.StartedAt {
			t.Errorf("handoff[%d] %+v, want presentation %s, operation %s, at %d", i, h, first.JTI, op, first.Evaluation.StartedAt)
		}
	}
	if len(x.Decoded["other_operation.json"]) == 0 {
		t.Error("other_operation.json not read")
	}

	c, err = evalcase.Load(repoFixtures, "admission/replay-same-nonce-two-replicas")
	if err != nil {
		t.Fatal(err)
	}
	ss := c.Exchanges[0].Submissions
	if len(ss) != 2 || ss[0].Replica != "r1" || ss[1].Replica != "r2" || !ss[0].Concurrent || !ss[1].Concurrent {
		t.Errorf("submissions %+v", ss)
	}

	c, err = evalcase.Load(repoFixtures, "admission/old-presentation-after-eviction")
	if err != nil {
		t.Fatal(err)
	}
	if ss := c.Exchanges[0].Submissions; len(ss) != 2 || ss[0].Replica != "r1" || ss[1].Replica != "r1" || !ss[1].EvictReplayRecords ||
		ss[0].Evaluation.StartedAt != 1792080000 || ss[1].Evaluation.StartedAt != 1792080070 {
		t.Errorf("submissions %+v", ss)
	}

	c, err = evalcase.Load(repoFixtures, "admission/replay-store-unavailable")
	if err != nil {
		t.Fatal(err)
	}
	if x := c.Exchanges[0]; x.Availability.ReplayStore != "unavailable" || len(x.Submissions) != 1 || x.Submissions[0].Signed != "signed/presentation.jws" {
		t.Errorf("availability %+v, submissions %+v", x.Availability, x.Submissions)
	}
}

// TestMultiExchangeCase: a sequence.json case loads each exchange directory
// in order, with the expected file under expected/<id>/<exchange>/, and the
// subject is the exchange sequence.json names.
func TestMultiExchangeCase(t *testing.T) {
	const id = "approval/approved-fresh-exchange"
	c, err := evalcase.Load(repoFixtures, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Exchanges) != 2 || c.Subject != 1 {
		t.Fatalf("%d exchanges, subject %d", len(c.Exchanges), c.Subject)
	}
	for i, x := range c.Exchanges {
		name := "exchanges/" + string(rune('1'+i))
		if x.Name != name || x.Path != id+"/"+name || x.ExpectedPath != "expected/"+id+"/"+name+"/decision.json" || len(x.Signed) == 0 {
			t.Errorf("exchange %d: name %q path %q expected %q, %d signed", i, x.Name, x.Path, x.ExpectedPath, len(x.Signed))
		}
	}
}

// TestStaleSignatureFails: a signed file that is not what the generator
// would keep (spec/v1.0/fixtures/README.md, Signed artifacts) fails Load and
// Verify, naming the file.
func TestStaleSignatureFails(t *testing.T) {
	const id = "admission/valid"
	for _, tc := range []struct {
		name, file string
		mutate     func(t *testing.T, root string)
	}{
		{"decoded edited", "signed/evidence/runtime.jws", func(t *testing.T, root string) {
			edit(t, root, id+"/evidence/runtime.json", "finance-agent-0001", "finance-agent-0009")
		}},
		{"signature octet", "signed/contract.jws", func(t *testing.T, root string) {
			flipSignature(t, root, id+"/signed/contract.jws")
		}},
		{"presentation input edited", "signed/presentation.jws", func(t *testing.T, root string) {
			edit(t, root, id+"/intent.json", "invoice-summary", "invoice-summarx")
		}},
		{"signer changed", "signed/reputation.jws", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["artifacts"].([]any)[2].(map[string]any)["signer"] = "issuer"
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			if _, err := evalcase.Load(root, id); err != nil {
				t.Fatalf("unmodified copy: %v", err)
			}
			tc.mutate(t, root)
			_, err := evalcase.Load(root, id)
			wantErr(t, err, id, tc.file, "stale")
			keys, err := evalcase.LoadKeys(root)
			if err != nil {
				t.Fatal(err)
			}
			dirs, err := evalcase.Dirs(root)
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(dirs, func(d evalcase.Dir) bool { return d.ID == id })
			if i < 0 {
				t.Fatalf("Dirs lists no %s", id)
			}
			_, err = evalcase.Verify(root, dirs[i], keys)
			wantErr(t, err, tc.file, "stale")
		})
	}
}

// TestStaleDigestsFail: a decoded file whose digests member is not the
// artifact_digest of the signed file it names fails Verify, as generate
// -check counts it as changed.
func TestStaleDigestsFail(t *testing.T) {
	root := caseTree(t, "admission/valid")
	editJSON(t, root, "admission/valid/signing.json", func(s map[string]any) {
		a := s["artifacts"].([]any)
		a[1].(map[string]any)["digests"] = map[string]any{"/subject": "signed/contract.jws"}
	})
	keys, err := evalcase.LoadKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := evalcase.Dirs(root)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(dirs, func(d evalcase.Dir) bool { return d.ID == "admission/valid" })
	_, err = evalcase.Verify(root, dirs[i], keys)
	wantErr(t, err, "evidence/runtime.json", "digests")
}

// TestTrustRecords: a signed file that verifies under its signing key but
// not against the trust records loads, with the reason in Trust.
func TestTrustRecords(t *testing.T) {
	const id = "admission/valid"
	for _, tc := range []struct {
		name, file string
		want       jws.Reason
		mutate     func(c map[string]any, n map[string]any)
	}{
		{"no record for the issuer", "signed/reputation.jws", jws.ErrKidUnknown, func(c, _ map[string]any) {
			c["trust"] = c["trust"].([]any)[:2]
		}},
		{"record for another issuer", "signed/reputation.jws", jws.ErrKidUnknown, func(c, _ map[string]any) {
			c["trust"].([]any)[2].(map[string]any)["iss"] = "https://reputation.example/other"
		}},
		{"record for another role", "signed/evidence/runtime.jws", jws.ErrKidUnknown, func(c, _ map[string]any) {
			c["trust"].([]any)[1].(map[string]any)["role"] = "reputation-service"
		}},
		{"record with another key", "signed/contract.jws", jws.ErrKidUnknown, func(c, _ map[string]any) {
			c["trust"].([]any)[0].(map[string]any)["keys"] = []any{"keys/reputation-service.jwk.json"}
		}},
		{"other enrolled holder", "signed/presentation.jws", jws.ErrHolderJKTMismatch, func(_, n map[string]any) {
			n["authenticated"].(map[string]any)["holder_jkt"] = "B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			var cfg, nc map[string]any
			editJSON(t, root, id+"/config.json", func(c map[string]any) { cfg = c })
			editJSON(t, root, id+"/native_context.json", func(n map[string]any) { nc = n })
			tc.mutate(cfg, nc)
			editJSON(t, root, id+"/config.json", func(c map[string]any) {
				for k := range c {
					delete(c, k)
				}
				for k, v := range cfg {
					c[k] = v
				}
			})
			editJSON(t, root, id+"/native_context.json", func(n map[string]any) {
				for k := range n {
					delete(n, k)
				}
				for k, v := range nc {
					n[k] = v
				}
			})
			c, err := evalcase.Load(root, id)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range c.Exchanges[0].Signed {
				if s.Path == tc.file {
					if jws.ReasonOf(s.Trust) != tc.want {
						t.Errorf("%s: trust %v, want reason %s", s.Path, s.Trust, tc.want)
					}
				} else if s.Trust != nil {
					t.Errorf("%s: trust %v", s.Path, s.Trust)
				}
			}
		})
	}
}

// TestLoadRejects: Load fails on a case it cannot read as the format
// defines it.
func TestLoadRejects(t *testing.T) {
	const id = "admission/valid"
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   []string
	}{
		{"unknown config member", func(t *testing.T, root string) {
			editJSON(t, root, id+"/config.json", func(c map[string]any) { c["nowx"] = 1 })
		}, []string{"config.json"}},
		{"no native context", func(t *testing.T, root string) {
			removeFile(t, filepath.Join(root, id, "native_context.json"))
		}, []string{"native_context.json"}},
		{"expected responses for a missing submission", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, id, "exchange.json"), []byte(`{"presentations":[{"signed":"signed/presentation.jws","jti":"v6wxT-_cB0Ua8Xkqgcuu2g"},{"signed":"signed/presentation.jws","jti":"v6wxT-_cB0Ua8Xkqgcuu2g"}]}`))
		}, []string{"decision.json", "2 submissions"}},
		{"unknown exchange member", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, id, "exchange.json"), []byte(`{"presentation":[]}`))
		}, []string{"exchange.json"}},
		{"unknown expected member", func(t *testing.T, root string) {
			editJSON(t, root, "expected/"+id+"/decision.json", func(d map[string]any) { d["decison"] = "ADMISSIBLE" })
		}, []string{"decision.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			tc.mutate(t, root)
			_, err := evalcase.Load(root, id)
			wantErr(t, err, tc.want...)
		})
	}
	_, err := evalcase.Load(repoFixtures, "outcomes/qualification/correction-recompute")
	wantErr(t, err, "outcomes/qualification/correction-recompute", "kind outcomes")
	_, err = evalcase.Load(repoFixtures, "admission/no-such-case")
	wantErr(t, err, "admission/no-such-case", "no manifest entry")
}

// TestRead: Read returns the case that Load does, with no signed file
// verified: it needs no test keys, and a stale signed file is no error. The
// structure of the case is still checked.
func TestRead(t *testing.T) {
	const id = "admission/valid"
	for _, e := range evaluateEntries(t) {
		want, err := evalcase.Load(repoFixtures, e.ID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := evalcase.Read(repoFixtures, e.ID)
		if err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
		for _, x := range got.Exchanges {
			if len(x.Signed) != 0 {
				t.Errorf("%s %s: Read verified %d signed files", e.ID, x.Path, len(x.Signed))
			}
		}
		for _, x := range want.Exchanges {
			x.Signed = nil
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: Read and Load differ beyond the signed files", e.ID)
		}
	}

	t.Run("no keys", func(t *testing.T) {
		root := caseTree(t, id)
		removeFile(t, filepath.Join(root, "keys", "test-private-scalars.json"))
		if _, err := evalcase.Read(root, id); err != nil {
			t.Errorf("Read without the private test values: %v", err)
		}
		if _, err := evalcase.Load(root, id); err == nil {
			t.Error("Load without the private test values succeeded")
		}
	})
	t.Run("stale signed file", func(t *testing.T) {
		root := caseTree(t, id)
		flipSignature(t, root, id+"/signed/contract.jws")
		if _, err := evalcase.Read(root, id); err != nil {
			t.Errorf("Read of a stale signed file: %v", err)
		}
		if _, err := evalcase.Load(root, id); err == nil {
			t.Error("Load of a stale signed file succeeded")
		}
	})
	t.Run("structure", func(t *testing.T) {
		root := caseTree(t, id)
		removeFile(t, filepath.Join(root, "expected", id, "decision.json"))
		_, err := evalcase.Read(root, id)
		wantErr(t, err, id, "decision.json")
		_, err = evalcase.Read(root, "admission/nope")
		wantErr(t, err, "admission/nope", "no manifest entry")
		_, err = evalcase.Read(root, "keys/holder")
		wantErr(t, err, "keys/holder")
	})
}
