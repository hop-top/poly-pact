package runner

// The goldens of the fake implementation for the outcomes verb. The good
// golden of a case is the outcomes result object (spec/v1.0/fixtures/README.md,
// section Outcomes output) of the reference oracle's replay of the case,
// whose values TestOracleAgreesWithEveryCommittedCase (package reputation)
// checks against the committed expected files; each snapshot is signed with
// the reputation-service test key. Each bad mode is the good golden of one
// case with one defect. This file states every defect as code.
// TestOutcomesGoldens checks the committed files against it, so a golden
// cannot drift from the case or from the defect it is named for; `go test
// -run TestOutcomesGoldens -update-outcomes` writes them again. ES256
// signatures are randomized, so a snapshot is compared by its decoded
// header and payload and the validity of its signature.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/reputation"
)

var updateOutcomes = flag.Bool("update-outcomes", false, "write the outcomes goldens of testdata/fakeimpl again")

// outcomesResult is an outcomes command's output as a generic JSON value.
type outcomesResult = map[string]any

// snapshotJTI is the deterministic jti of the snapshot that answers step of
// case id: 16 octets of SHA-256, base64url.
func snapshotJTI(id string, step int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s/%d", id, step))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// signSnapshot signs the payload with the reputation-service test key.
func signSnapshot(t testing.TB, keys map[string]evalcase.Key, payload any) string {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	k := keys["reputation-service"]
	out, err := jws.Sign(jws.Header{Typ: jws.TypReputation, Kid: k.Public.Kid}, b, k.Private)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func toJSONValue(t testing.TB, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// goodOutcomes is the output of a conforming implementation for case id of
// the fixture directory root: the oracle's answers, each acknowledgment
// with its Acknowledgment, each refusal with its Problem, each query with
// its signed snapshot and provenance manifest, and the qualification of
// every report but the duplicates, null for a refused one.
func goodOutcomes(t testing.TB, root, id string) outcomesResult {
	t.Helper()
	c, err := evalcase.ReadOutcomes(root, id)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := reputation.Replay(root, c)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := evalcase.LoadKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	steps := []any{}
	for i, s := range c.Steps {
		st := rep.Steps[i]
		switch {
		case s.Ingest != "" && st.Answer.Ack != "":
			steps = append(steps, map[string]any{"ack": map[string]any{
				"request_id": fmt.Sprintf("ack-%d", i), "status": string(st.Answer.Ack), "artifact_id": s.Ingest, "received_at": s.ReceivedAt,
			}})
		case s.Ingest != "":
			steps = append(steps, map[string]any{"problem": map[string]any{
				"type": "about:blank", "title": st.Answer.Code, "status": problemStatus[st.Answer.Code], "code": st.Answer.Code, "request_id": fmt.Sprintf("rej-%d", i),
			}})
		case st.Snapshot == nil:
			t.Fatalf("%s step %d: the oracle refuses the query: %s", id, i, st.QueryCode)
		default:
			claims := st.Snapshot.Claims
			claims.JTI = snapshotJTI(id, i)
			steps = append(steps, map[string]any{"snapshot": signSnapshot(t, keys, claims), "provenance": toJSONValue(t, st.Snapshot.Manifest)})
		}
	}
	cls := map[string]any{}
	for event, v := range rep.Verdicts {
		switch {
		case v.Refused:
			cls[event] = nil
		case v.Qualification != "":
			cls[event] = v.Qualification
		}
	}
	return outcomesResult{"steps": steps, "classifications": cls}
}

// payloadMap decodes the payload of a compact JWS into a generic object.
func payloadMap(t testing.TB, compact string) map[string]any {
	t.Helper()
	return payloadOf(t, compact)
}

// stepAt returns the entry of step i.
func stepAt(o outcomesResult, i int) map[string]any { return o["steps"].([]any)[i].(map[string]any) }

// editSnapshot decodes the snapshot of query step i, applies edit and signs
// it again with the reputation-service key.
func editSnapshot(t testing.TB, keys map[string]evalcase.Key, o outcomesResult, i int, edit func(p map[string]any)) {
	t.Helper()
	st := stepAt(o, i)
	p := payloadMap(t, st["snapshot"].(string))
	edit(p)
	st["snapshot"] = signSnapshot(t, keys, p)
}

func dims(p map[string]any, d string) map[string]any {
	return p["value"].(map[string]any)["dimensions"].(map[string]any)[d].(map[string]any)
}

// redigest sets the value's provenance_digest to the object_digest of the
// step's manifest after an edit of the manifest.
func redigest(t testing.TB, o outcomesResult, i int) func(map[string]any) {
	return func(p map[string]any) {
		d, err := digest.ObjectDigest(stepAt(o, i)["provenance"])
		if err != nil {
			t.Fatal(err)
		}
		p["value"].(map[string]any)["provenance_digest"] = string(d)
	}
}

// mismatchCase is the outcomes case of the delegation group: an EXECUTION
// SUCCESS whose cited record names another executor class than the
// execution-identity mapping declares (draft Sections 14.2, 17.5).
const mismatchCase = "delegation/executor-class-mismatch-outcome"

// countsMismatch counts the report of mismatchCase as a qualified success:
// the query lists it, and reliability holds one success observed 50 seconds
// before the query (draft Section 15.3): w = 2^(-50/2592000), alpha = 1 + w,
// beta = 1, so score_bps floor(10000 * alpha / (alpha + beta)) = 6666 and
// confidence_bps floor(10000 * w / (w + 20)) = 476.
func countsMismatch(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
	c, err := evalcase.ReadOutcomes(repoFixtures, mismatchCase)
	if err != nil {
		t.Fatal(err)
	}
	r := c.Reports["execution-event-0001"]
	stepAt(o, 1)["provenance"].(map[string]any)["qualified_event_ids"] = []any{[]any{r.Issuer, r.JTI}}
	editSnapshot(t, keys, o, 1, func(p map[string]any) {
		d := dims(p, "reliability")
		d["score_bps"], d["confidence_bps"], d["independent_tasks"], d["qualified_events"], d["newest_event_at"] = 6666, 476, 1, 1, r.ObservedAt
		redigest(t, o, 1)(p)
	})
}

type outcomesMutant struct {
	id, mode string
	// fails names the detail the mutant must produce; empty for a mutant
	// the runner must pass (a defect within tolerance) or that only skips a
	// sub-check.
	fails string
	edit  func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult)
}

// outcomesMutants are the bad modes of the outcomes verb, each the good
// golden of one case with one defect.
func outcomesMutants() []outcomesMutant {
	return []outcomesMutant{
		{"outcomes/qualification/duplicate-reports-same-tuple", "double-counts-duplicate", "acks.json", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// The second report of the tuple is taken as a new vote: ACCEPTED,
			// listed, and counted.
			stepAt(o, 1)["ack"].(map[string]any)["status"] = "ACCEPTED"
			c, _ := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/duplicate-reports-same-tuple")
			r := c.Reports["execution-event-0002"]
			m := stepAt(o, 2)["provenance"].(map[string]any)
			list := append(m["qualified_event_ids"].([]any), []any{r.Issuer, r.JTI})
			m["qualified_event_ids"] = sortedPairs(list)
			o["classifications"].(map[string]any)["execution-event-0002"] = "QUALIFIED"
			editSnapshot(t, keys, o, 2, func(p map[string]any) {
				dims(p, "reliability")["qualified_events"] = 2
				redigest(t, o, 2)(p)
			})
		}},
		{"reputation/context-no-transfer", "transfers-context", "/value/dimensions/reliability/score_bps", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// The payment-approval query gets the invoice history.
			from := payloadMap(t, stepAt(o, 12)["snapshot"].(string))
			stepAt(o, 13)["provenance"].(map[string]any)["qualified_event_ids"] = stepAt(o, 12)["provenance"].(map[string]any)["qualified_event_ids"]
			editSnapshot(t, keys, o, 13, func(p map[string]any) {
				p["value"].(map[string]any)["dimensions"] = from["value"].(map[string]any)["dimensions"]
				redigest(t, o, 13)(p)
			})
		}},
		{"reputation/security-hold-no-decay", "hold-decays", "/value/security_status", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// 400 days later the hold has decayed away with the score.
			for _, i := range []int{13, 15} {
				editSnapshot(t, keys, o, i, func(p map[string]any) {
					p["value"].(map[string]any)["security_status"] = "CLEAR"
					p["value"].(map[string]any)["hold_refs"] = []any{}
				})
			}
		}},
		{"reputation/security-hold-no-decay", "unauthorized-clears-hold", "step 15 (query): snapshot /value/security_status", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// The remediation of a security authority that is not a hold
			// clearance authority clears the hold.
			editSnapshot(t, keys, o, 15, func(p map[string]any) {
				p["value"].(map[string]any)["security_status"] = "CLEAR"
				p["value"].(map[string]any)["hold_refs"] = []any{}
			})
		}},
		{"outcomes/qualification/repeated-admissions", "admission-raises-reputation", "/value/dimensions/reliability", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// Every passed admission counts toward reliability, one task group:
			// one unit and seven events.
			c, _ := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/repeated-admissions")
			var list []any
			for _, r := range c.Reports {
				list = append(list, []any{r.Issuer, r.JTI})
			}
			stepAt(o, 7)["provenance"].(map[string]any)["qualified_event_ids"] = sortedPairs(list)
			editSnapshot(t, keys, o, 7, func(p map[string]any) {
				d := dims(p, "reliability")
				d["score_bps"], d["confidence_bps"], d["independent_tasks"], d["qualified_events"], d["newest_event_at"] = 6666, 476, 1, 7, 1792079960
				redigest(t, o, 7)(p)
			})
		}},
		{"outcomes/qualification/correction-recompute", "value-off-2bp", "/value/dimensions/reliability/score_bps is 3335, want 3333 within 1 bp", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			editSnapshot(t, keys, o, 3, func(p map[string]any) { dims(p, "reliability")["score_bps"] = 3335 })
		}},
		{"outcomes/qualification/correction-recompute", "value-off-1bp", "", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// Within the one basis point of Section 15.3: the runner passes it.
			editSnapshot(t, keys, o, 1, func(p map[string]any) { dims(p, "reliability")["score_bps"] = 6667 })
			editSnapshot(t, keys, o, 3, func(p map[string]any) { dims(p, "reliability")["confidence_bps"] = 475 })
		}},
		{"outcomes/mapping/hidden-row-read-as-task-success", "bad-snapshot-signature", "does not verify", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// Signed with another key under the reputation service's kid.
			st := stepAt(o, 2)
			p := payloadMap(t, st["snapshot"].(string))
			b, _ := json.Marshal(p)
			out, err := jws.Sign(jws.Header{Typ: jws.TypReputation, Kid: keys["reputation-service"].Public.Kid}, b, keys["issuer"].Private)
			if err != nil {
				t.Fatal(err)
			}
			st["snapshot"] = out
		}},
		{"outcomes/mapping/async-accept-then-complete", "unsigned-snapshot", "does not verify", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// alg none and no signature.
			st := stepAt(o, 2)
			seg := strings.Split(st["snapshot"].(string), ".")
			h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"pact-reputation+jwt"}`))
			st["snapshot"] = h + "." + seg[1] + "."
		}},
		{"outcomes/qualification/self-praise-executor-as-evaluator", "accepts-self-praise", "classifications[quality-event-0002] is QUALIFIED, want UNQUALIFIED", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			o["classifications"].(map[string]any)["quality-event-0002"] = "QUALIFIED"
		}},
		{"outcomes/qualification/rotated-key-same-agent", "bad-provenance-digest", "is not the object_digest of the printed manifest", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// The cold-start snapshot carries the digest of the history's
			// manifest.
			from := payloadMap(t, stepAt(o, 1)["snapshot"].(string))
			editSnapshot(t, keys, o, 2, func(p map[string]any) {
				p["value"].(map[string]any)["provenance_digest"] = from["value"].(map[string]any)["provenance_digest"]
			})
		}},
		{mismatchCase, "qualifies-executor-mismatch", "classifications[execution-event-0001] is QUALIFIED, want UNQUALIFIED", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// The report is qualified and counted although its executor is
			// the connector application, not the declared delegated user.
			countsMismatch(t, keys, o)
			o["classifications"].(map[string]any)["execution-event-0001"] = "QUALIFIED"
		}},
		{mismatchCase, "counts-executor-mismatch", "/value/dimensions/reliability/score_bps", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// The same count with no qualification disclosed: the snapshot
			// alone shows it.
			countsMismatch(t, keys, o)
			delete(o, "classifications")
		}},
		{"outcomes/qualification/client-task-id-unreconciled", "no-classifications", "", func(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) {
			// No qualification disclosed: the sub-check is skipped.
			delete(o, "classifications")
		}},
	}
}

func sortedPairs(list []any) []any {
	pairs := make([][2]string, len(list))
	for i, p := range list {
		pairs[i] = [2]string{p.([]any)[0].(string), p.([]any)[1].(string)}
	}
	reputation.SortPairs(pairs)
	out := make([]any, len(pairs))
	for i, p := range pairs {
		out[i] = []any{p[0], p[1]}
	}
	return out
}

// normalized replaces each snapshot of an outcomes result by its decoded
// header and payload and whether its signature verifies under the
// reputation-service key, so that two signings of one snapshot compare
// equal.
func normalized(t testing.TB, keys map[string]evalcase.Key, o outcomesResult) any {
	t.Helper()
	v := toJSONValue(t, o).(map[string]any)
	ks, err := jws.NewKeySet(keys["reputation-service"].Public)
	if err != nil {
		t.Fatal(err)
	}
	res := jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleReputationService: ks}}
	for _, s := range v["steps"].([]any) {
		st := s.(map[string]any)
		compact, ok := st["snapshot"].(string)
		if !ok {
			continue
		}
		seg := strings.Split(compact, ".")
		h, _ := base64.RawURLEncoding.DecodeString(seg[0])
		var header any
		_ = json.Unmarshal(h, &header)
		_, verr := jws.Verify(compact, res)
		st["snapshot"] = map[string]any{"header": header, "payload": payloadMap(t, compact), "verifies": verr == nil}
	}
	return v
}

func outcomesIDs(t *testing.T) []string {
	t.Helper()
	var ids []string
	for _, e := range repoEntries(t) {
		if kindOf(e) == "outcomes" {
			ids = append(ids, e["id"].(string))
		}
	}
	return ids
}

func writeOutcomes(t testing.TB, path string, o outcomesResult) {
	t.Helper()
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readOutcomes(t testing.TB, path string) outcomesResult {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var o outcomesResult
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return o
}

// TestOutcomesGoldens: every outcomes entry has its good golden, and every
// bad mode the defect this file states; with -update-outcomes it writes
// them.
func TestOutcomesGoldens(t *testing.T) {
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, path string, want outcomesResult) {
		if *updateOutcomes {
			if _, err := os.Stat(path); err == nil && reflect.DeepEqual(normalized(t, keys, readOutcomes(t, path)), normalized(t, keys, want)) {
				return
			}
			writeOutcomes(t, path, want)
			return
		}
		got := normalized(t, keys, readOutcomes(t, path))
		if !reflect.DeepEqual(got, normalized(t, keys, want)) {
			t.Errorf("%s is not what this file states; run go test -run TestOutcomesGoldens -update-outcomes", path)
		}
	}
	good := map[string]outcomesResult{}
	for _, id := range outcomesIDs(t) {
		t.Run(id, func(t *testing.T) {
			o := goodOutcomes(t, repoFixtures, id)
			good[id] = o
			check(t, filepath.Join(goldenDir, filepath.FromSlash(id), "outcomes.out"), o)
		})
	}
	for _, m := range outcomesMutants() {
		t.Run(m.id+"/"+m.mode, func(t *testing.T) {
			base, ok := good[m.id]
			if !ok {
				t.Fatalf("%s is no outcomes entry", m.id)
			}
			o := toJSONValue(t, base).(map[string]any)
			m.edit(t, keys, o)
			check(t, filepath.Join(goldenDir, filepath.FromSlash(m.id), "outcomes."+m.mode+".out"), o)
		})
	}
}
