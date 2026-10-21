package runner

// The bad-implementation goldens of testdata/fakeimpl. Each is a committed
// answer of the fake implementation in one of its modes: the good golden of
// a case with one defect. This file states the defect of every mutant as
// code. TestMutantGoldens checks the committed files against it, so a golden
// cannot drift from the defect it is named for; `go test -run
// TestMutantGoldens -update-mutants` writes them again. A re-signed receipt
// has a new, randomized signature each time (ES256), so only the decoded
// header and payload and the validity of the signature are compared.

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
)

var updateMutants = flag.Bool("update-mutants", false, "write the mutant goldens of testdata/fakeimpl again")

const goldenDir = "testdata/fakeimpl/golden"

// mutator edits the lines of a good golden.
type mutator struct {
	keys map[string]evalcase.Key
}

// resign decodes the receipt line, applies the edits and signs it again with
// the key of role (the validator when empty) under the validator's kid, so a
// signature that is wrong only by key verifies against the wrong key.
func (m mutator) resign(t *testing.T, line, role string, header func(*jws.Header), payload func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(line, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %.40s", line)
	}
	var h jws.Header
	h.Typ = jws.TypAdmission
	h.Kid = m.keys["validator"].Public.Kid
	raw := decodePart(t, parts[1])
	var p map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		t.Fatal(err)
	}
	if header != nil {
		header(&h)
	}
	if payload != nil {
		payload(p)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if role == "" {
		role = "validator"
	}
	out, err := jws.Sign(h, b, m.keys[role].Private)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// check returns the check result object of the receipt payload with the id.
func check(t *testing.T, p map[string]any, id string) map[string]any {
	t.Helper()
	for _, c := range p["checks"].([]any) {
		if c := c.(map[string]any); c["check_id"] == id {
			return c
		}
	}
	t.Fatalf("receipt has no check %s", id)
	return nil
}

type mutant struct {
	// id is the manifest id of the case whose good golden is edited; mode is
	// the FAKEIMPL_MODE that prints the mutant.
	id, mode string
	// verb is the verb whose golden the mutant replaces, evaluate when empty.
	verb string
	// badSignature: no line of the mutant verifies under the validator key.
	badSignature bool
	// edit returns the lines of the mutant.
	edit func(t *testing.T, m mutator, lines []string) []string
}

// one edits the only line of a good golden.
func one(role string, header func(*jws.Header), payload func(map[string]any)) func(*testing.T, mutator, []string) []string {
	return func(t *testing.T, m mutator, lines []string) []string {
		return []string{m.resign(t, lines[0], role, header, payload)}
	}
}

func set(k string, v any) func(map[string]any) {
	return func(p map[string]any) { p[k] = v }
}

const (
	validCase    = "admission/valid"
	rejectedCase = "admission/old-holder-key"
	twoCase      = "admission/replay-same-nonce-two-replicas"

	pendingCase   = "approval/pending-established-request"
	chatCase      = "approval/chat-says-approved"
	mandatoryCase = "approval/mandatory-survives-high-reputation"
	freshCase     = "approval/approved-fresh-exchange"

	staleCase = "selection/agent-presents-stale-favorable"
	holdCase  = "selection/hold-added-after-issuance"

	fallbackCase = "delegation/broader-credential-fallback"

	snapshotSourceCase = "admission/source-snapshot-only"
	pushOutageCase     = "admission/source-push-outage"
)

// ignoresCapability is the receipt of a gateway that reads the roles claim
// without comparing the rule with the declared capability of its source:
// the cached claim's status age is above status_max_age_seconds, so rule 4
// of the freshness profile fails it as stale, where the draft defers the
// exchange (17.2: a bound the source cannot meet; 18: a cached answer the
// source cannot refresh).
func ignoresCapability(t *testing.T) func(map[string]any) {
	return func(p map[string]any) {
		p["decision"] = "INADMISSIBLE"
		c := check(t, p, "roles")
		c["result"], c["reason_code"] = "FAIL", "STALE_EVIDENCE"
	}
}

// configuredSource gives each of the checks the source_ref of a configured
// validation record, configured-validation-record:example-<check id>.
func configuredSource(t *testing.T, ids ...string) func(map[string]any) {
	return func(p map[string]any) {
		for _, id := range ids {
			check(t, p, id)["source_ref"] = "configured-validation-record:example-" + id
		}
	}
}

// weakerSet is the receipt of a gateway that keeps the contract's weaker
// set although an input is now stricter: selection-consistency-v1 passes
// and nothing defers the exchange (draft 9.4, 11.3 step 9).
func weakerSet(t *testing.T) func(map[string]any) {
	return func(p map[string]any) {
		p["decision"] = "ADMISSIBLE"
		c := check(t, p, "selection-consistency-v1")
		c["result"], c["reason_code"] = "PASS", "REQUIREMENT_SATISFIED"
	}
}

// approvalResult sets the decision of the receipt payload and the result and
// reason code of its native-approval-v1 check.
func approvalResult(t *testing.T, decision, result, reason string) func(map[string]any) {
	return func(p map[string]any) {
		p["decision"] = decision
		c := check(t, p, "native-approval-v1")
		c["result"], c["reason_code"] = result, reason
	}
}

// executorPasses is the receipt of a gateway whose execution-identity-v1
// passes the executor the native context names, with the decision.
func executorPasses(t *testing.T, decision string) func(map[string]any) {
	return func(p map[string]any) {
		p["decision"] = decision
		c := check(t, p, "execution-identity-v1")
		c["result"], c["reason_code"] = "PASS", "REQUIREMENT_SATISFIED"
	}
}

func mutants(t *testing.T, keys map[string]evalcase.Key) []mutant {
	t.Helper()
	otherJKT, err := jws.Thumbprint(keys["holder-2"].Public)
	if err != nil {
		t.Fatal(err)
	}
	otherDigest, err := digest.ObjectDigest(map[string]any{"another": "object"})
	if err != nil {
		t.Fatal(err)
	}
	return []mutant{
		// A Problem where the draft requires a receipt.
		{id: validCase, mode: "problem", edit: func(t *testing.T, m mutator, lines []string) []string {
			return []string{`{"type":"about:blank","title":"Rejected","status":401,"code":"INVALID_PROOF","request_id":"r-valid"}`}
		}},
		// A validly signed receipt for a request rejected before an
		// authenticated evaluation (draft 12.2): the receipt of admission/valid.
		{id: rejectedCase, mode: "receipt-for-rejected", edit: func(t *testing.T, m mutator, lines []string) []string {
			b, err := os.ReadFile(filepath.Join(goldenDir, filepath.FromSlash(validCase), "evaluate.out"))
			if err != nil {
				t.Fatal(err)
			}
			return []string{strings.TrimSpace(string(b))}
		}},
		// Signed with a key the validator trust record does not hold, under the
		// validator's kid.
		{id: validCase, mode: "bad-signature", badSignature: true, edit: one("holder", nil, nil)},
		{id: validCase, mode: "bad-typ", edit: one("", func(h *jws.Header) { h.Typ = jws.TypEvidence }, nil)},
		{id: validCase, mode: "bad-aud", edit: one("", nil, set("aud", "https://gateway.example/other"))},
		{id: validCase, mode: "bad-sub", edit: one("", nil, set("sub", "https://identity.example/agents/other-agent"))},
		{id: validCase, mode: "bad-holder-jkt", edit: one("", nil, set("holder_jkt", string(otherJKT)))},
		{id: validCase, mode: "bad-digest", edit: one("", nil, set("profile_digest", string(otherDigest)))},
		{id: validCase, mode: "bad-exp", edit: one("", nil, func(p map[string]any) {
			iat, err := p["iat"].(json.Number).Int64()
			if err != nil {
				t.Fatal(err)
			}
			p["exp"] = iat + 3600
		})},
		{id: validCase, mode: "bad-terminal-reason", edit: one("", nil, set("terminal_reason", "EXPIRED"))},
		{id: validCase, mode: "bad-check-result", edit: one("", nil, func(p map[string]any) {
			check(t, p, "nonce")["result"] = "FAIL"
		})},
		{id: validCase, mode: "bad-reason-code", edit: one("", nil, func(p map[string]any) {
			check(t, p, "nonce")["reason_code"] = "UNSPECIFIED_REASON"
		})},
		{id: validCase, mode: "missing-check", edit: one("", nil, func(p map[string]any) {
			var kept []any
			for _, c := range p["checks"].([]any) {
				if c.(map[string]any)["check_id"] != "intent-binding" {
					kept = append(kept, c)
				}
			}
			p["checks"] = kept
		})},
		// selection-consistency-v1 is not installed for the conservative set,
		// so the receipt must not carry it (draft 9.4).
		{id: "selection/conservative-set-no-check", mode: "absent-check-present", edit: one("", nil, func(p map[string]any) {
			c := map[string]any{}
			for k, v := range check(t, p, "reputation-context") {
				c[k] = v
			}
			c["check_id"] = "selection-consistency-v1"
			p["checks"] = append(p["checks"].([]any), c)
		})},
		// A check the contract's context_checks names, and that the expected
		// result does not list, is left out of the receipt of a negative
		// case (draft 12.1: one result per context_checks entry, an
		// unevaluated one UNKNOWN NOT_EVALUATED).
		{id: "admission/wrong-audience", mode: "omit-context-check", edit: one("", nil, func(p map[string]any) {
			var kept []any
			for _, c := range p["checks"].([]any) {
				if c.(map[string]any)["check_id"] != "security-hold-v1" {
					kept = append(kept, c)
				}
			}
			p["checks"] = kept
		})},
		// A native field rule whose read was outstanding when the requestor
		// cancelled is recorded as passed (draft 12.1: a check not performed
		// is never recorded as passed).
		{id: "admission/cancelled-evaluation", mode: "unperformed-check-passed", edit: one("", nil, func(p map[string]any) {
			c := check(t, p, "roles")
			c["result"], c["reason_code"] = "PASS", "REQUIREMENT_SATISFIED"
		})},
		{id: "selection/same-snapshot", mode: "bad-evidence-ids", edit: one("", nil, func(p map[string]any) {
			check(t, p, "reputation-context")["evidence_ids"] = []any{}
		})},
		{id: "selection/same-snapshot", mode: "bad-source-ref", edit: one("", nil, func(p map[string]any) {
			check(t, p, "selection-consistency-v1")["source_ref"] = "selection-record:other"
		})},
		// The conservative selection of the Appendix B exchange is recorded
		// too: a configured validation record is not its selection record
		// (draft 9.4, A.2, B.7).
		{id: validCase, mode: "bad-source-ref", edit: one("", nil, configuredSource(t, reputationCheck))},
		// An approval that is requested and undecided is treated as a failed
		// one (draft 17.3.1: UNKNOWN, APPROVAL_PENDING, DEFERRED).
		{id: pendingCase, mode: "pending-inadmissible", edit: one("", nil, approvalResult(t, "INADMISSIBLE", "FAIL", "APPROVAL_PENDING"))},
		// A statement in the conversation is taken for an approval (draft 9.2,
		// 17.3.1: no native approval is MISSING_FIELD).
		{id: chatCase, mode: "chat-approval-honored", edit: one("", nil, approvalResult(t, "ADMISSIBLE", "PASS", "REQUIREMENT_SATISFIED"))},
		// A high reputation waives a mandatory approval (draft 11.3 step 9, 15.5).
		{id: mandatoryCase, mode: "reputation-waives-approval", edit: one("", nil, approvalResult(t, "ADMISSIBLE", "PASS", "REQUIREMENT_SATISFIED"))},
		// The fresh evaluation reuses the identifier of the earlier receipt
		// (draft 12.2: it produces its own receipt).
		{id: freshCase, mode: "reused-jti", edit: func(t *testing.T, m mutator, lines []string) []string {
			_, first := decodeJWS(t, lines[0])
			return []string{lines[0], m.resign(t, lines[1], "", nil, set("jti", first["jti"]))}
		}},
		// The earlier receipt has been converted by the fresh evaluation: a
		// query for it returns the receipt of the second exchange (draft 12.2: a
		// sealed receipt is never reopened, amended or converted).
		{id: freshCase, mode: "reopen-first-receipt", verb: "receipt", edit: func(t *testing.T, m mutator, lines []string) []string {
			return []string{lines[1]}
		}},
		// The gateway keeps the weaker set after a stricter input (draft 9.4).
		{id: staleCase, mode: "weaker-set-kept", edit: one("", nil, weakerSet(t))},
		// The same defect on the second evaluation only: the first one is
		// right (draft 11.3 step 9: the re-derivation is deterministic).
		{id: staleCase, mode: "flip-flop", edit: one("", nil, weakerSet(t))},
		// The snapshot jti is left out of the reputation-context evidence_ids
		// of a case whose expected result does not list that check (draft A.2).
		{id: holdCase, mode: "omit-snapshot-jti", edit: one("", nil, func(p map[string]any) {
			check(t, p, "reputation-context")["evidence_ids"] = []any{}
		})},
		// The checks that the expected result does not list name a
		// configured validation record instead of the gateway's selection
		// record (draft A.2).
		{id: holdCase, mode: "selection-source-configured", edit: one("", nil, configuredSource(t, reputationCheck))},
		{id: "selection/policy-revision-changed", mode: "selection-source-configured", edit: one("", nil, configuredSource(t, selectionCheck))},
		{id: "selection/selector-rolled-back", mode: "selection-source-configured", edit: one("", nil, configuredSource(t, reputationCheck, selectionCheck))},
		// The operation would run under the connector's own broader
		// credential, and execution-identity-v1 passes it (draft 17.5: FAIL,
		// EXECUTOR_MISMATCH): every check passes and the request is admitted.
		{id: fallbackCase, mode: "fallback-executor-admitted", edit: one("", nil, executorPasses(t, "ADMISSIBLE"))},
		// The same check result under the expected decision: only the check
		// differs.
		{id: fallbackCase, mode: "fallback-executor-passes", edit: one("", nil, executorPasses(t, "INADMISSIBLE"))},
		// The declared capability of the roles source is not compared with
		// the rule before the read (spec/v1.0/fixtures/README.md, config.json
		// additions, native_mappings[].source).
		{id: snapshotSourceCase, mode: "ignores-capability", edit: one("", nil, ignoresCapability(t))},
		{id: pushOutageCase, mode: "ignores-capability", edit: one("", nil, ignoresCapability(t))},
		// Two replicas admit the same presentation: both lines are receipts
		// (draft 7.5 allows exactly one).
		{id: twoCase, mode: "two-admissible", edit: func(t *testing.T, m mutator, lines []string) []string {
			return []string{lines[0], lines[0]}
		}},
	}
}

func decodePart(t *testing.T, seg string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// readLines reads a golden file as lines.
func readLines(t *testing.T, p string) []string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func TestMutantGoldens(t *testing.T) {
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	m := mutator{keys: keys}
	vk, err := jws.NewKeySet(keys["validator"].Public)
	if err != nil {
		t.Fatal(err)
	}
	verifier := jws.Verifier{Keys: jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleValidator: vk}}}
	seen := map[string]bool{}
	for _, mu := range mutants(t, keys) {
		name := mu.id + " " + mu.mode
		if seen[name] {
			t.Fatalf("mutant %s twice", name)
		}
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(goldenDir, filepath.FromSlash(mu.id))
			verb := cmp.Or(mu.verb, "evaluate")
			file := filepath.Join(dir, verb+"."+mu.mode+".out")
			want := mu.edit(t, m, readLines(t, filepath.Join(dir, "evaluate.out")))
			if *updateMutants {
				if err := os.WriteFile(file, []byte(strings.Join(want, "\n")+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			got := readLines(t, file)
			if len(got) != len(want) {
				t.Fatalf("%d lines, want %d", len(got), len(want))
			}
			for i := range got {
				if strings.HasPrefix(got[i], "{") {
					if got[i] != want[i] {
						t.Errorf("line %d = %s, want %s", i+1, got[i], want[i])
					}
					continue
				}
				gh, gp := decodeJWS(t, got[i])
				wh, wp := decodeJWS(t, want[i])
				if !reflect.DeepEqual(gh, wh) || !reflect.DeepEqual(gp, wp) {
					t.Errorf("line %d: header/payload differ from the defect %s declares\n got %v %v\nwant %v %v", i+1, mu.mode, gh, gp, wh, wp)
				}
				_, err := verifier.Verify(got[i])
				if bad := mu.badSignature; bad != (jws.ReasonOf(err) == jws.ErrSignatureInvalid) {
					t.Errorf("line %d: verify error %v, badSignature %v", i+1, err, bad)
				}
				if !mu.badSignature && err != nil && mu.mode != "bad-typ" {
					t.Errorf("line %d: %v; the only defect is %s", i+1, err, mu.mode)
				}
			}
		})
	}
}

func decodeJWS(t *testing.T, compact string) (header, payload map[string]any) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %.40s", compact)
	}
	if err := json.Unmarshal(decodePart(t, parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(decodePart(t, parts[1]), &payload); err != nil {
		t.Fatal(err)
	}
	return header, payload
}
