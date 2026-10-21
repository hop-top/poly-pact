package runner

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/evalcase"
)

// AdmissionTyp is the JWS typ of an admission receipt (draft 7.3).
const AdmissionTyp = "pact-admission+jwt"

// maxReceiptSeconds is the longest verification window of a receipt: exp is
// at most 60 seconds after iat (draft 12.1).
const maxReceiptSeconds = 60

// response is what an evaluate command printed: exactly one of a receipt
// and a Problem.
type response struct {
	problem *core.Problem
	// compact, payload and claims are set for a receipt: the compact JWS
	// as printed, its payload as received, and the payload's members.
	compact     string
	payload     []byte
	claims      map[string]json.RawMessage
	attestation *core.AdmissionAttestation
}

// parseResponse reads one line of an evaluate command's output. Leading and
// trailing white space is ignored. A JSON object must be a Problem; anything
// else must be a compact JWS of typ pact-admission+jwt whose payload is an
// AdmissionAttestation. The signature is checked by receiptDiffs.
func parseResponse(stdout []byte) (response, error) {
	s := strings.TrimSpace(string(stdout))
	if s == "" {
		return response{}, errors.New("no receipt or Problem on stdout")
	}
	if s[0] == '{' {
		var p core.Problem
		if err := strictjson.Unmarshal([]byte(s), strictjson.Limits{}, &p); err != nil {
			return response{}, fmt.Errorf("stdout is a JSON object but not a Problem (RFC 9457, draft 13.4): %w", err)
		}
		if p.Code == "" {
			return response{}, errors.New("stdout is a JSON object but not a Problem (RFC 9457, draft 13.4): no code")
		}
		return response{problem: &p}, nil
	}
	seg := strings.Split(s, ".")
	if len(seg) != 3 {
		return response{}, errors.New("stdout is neither a compact JWS (three base64url segments) nor a Problem JSON object")
	}
	var header map[string]json.RawMessage
	if err := decodeSegment(seg[0], &header); err != nil {
		return response{}, fmt.Errorf("receipt protected header: %w", err)
	}
	var typ string
	if raw, ok := header["typ"]; !ok || json.Unmarshal(raw, &typ) != nil {
		return response{}, fmt.Errorf("receipt protected header has no typ string; want %s", AdmissionTyp)
	}
	if typ != AdmissionTyp {
		return response{}, fmt.Errorf("receipt typ %q, want %s", typ, AdmissionTyp)
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(seg[1])
	if err != nil {
		return response{}, fmt.Errorf("receipt payload: not canonical base64url: %w", err)
	}
	var a core.AdmissionAttestation
	if err := strictjson.Unmarshal(payload, strictjson.Limits{}, &a); err != nil {
		return response{}, fmt.Errorf("receipt payload: %w", err)
	}
	var claims map[string]json.RawMessage
	if err := strictjson.Unmarshal(payload, strictjson.Limits{}, &claims); err != nil {
		return response{}, fmt.Errorf("receipt payload: %w", err)
	}
	return response{compact: s, payload: payload, claims: claims, attestation: &a}, nil
}

// decodeSegment decodes a canonical unpadded base64url JWS segment holding a
// strict JSON object into v.
func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		return fmt.Errorf("not canonical base64url: %w", err)
	}
	return strictjson.Unmarshal(b, strictjson.Limits{}, v)
}

// receiptDiffs returns how a received receipt differs from the expected
// response want, in this order: the signature, the claims, the digests of
// the case files, the expiry, the check results and the checks that must be
// absent. Every difference is reported.
func (j judge) receiptDiffs(want evalcase.Response, resp response) []string {
	var diffs []string
	if d := j.signatureDiff(want, resp); d != "" {
		diffs = append(diffs, d)
	}
	if want.Receipt != nil && want.Receipt.Typ != "" && want.Receipt.Typ != AdmissionTyp {
		diffs = append(diffs, fmt.Sprintf("receipt typ %s, want %s", AdmissionTyp, want.Receipt.Typ))
	}
	diffs = append(diffs, j.claimDiffs(want, resp)...)
	diffs = append(diffs, j.fileDigestDiffs(want, resp)...)
	diffs = append(diffs, expiryDiffs(want, resp)...)
	diffs = append(diffs, checkDiffs(want, resp)...)
	diffs = append(diffs, j.contextCheckDiffs(want, resp)...)
	diffs = append(diffs, j.notPerformedDiffs(want, resp)...)
	diffs = append(diffs, j.capabilityDiffs(want, resp)...)
	return diffs
}

// signatureDiff verifies the receipt's signature under the validator's
// public key (draft 7.2, 7.3): the key file the expected receipt names as
// signer, else config.json's validator.key, under the typ pact-admission+jwt.
// The kid of the receipt must name that key. The receipt's alg must be one
// the gateway publishes, config.json gateway.jws_algorithms (draft 13.1,
// A.3; ES256 alone by default), and the algorithm of that key: ES256 for a
// P-256 key, Ed25519 (RFC 9864) for an OKP Ed25519 key (RFC 8037). A key
// whose algorithm the gateway does not publish fails the case. EdDSA is
// never accepted.
func (j judge) signatureDiff(want evalcase.Response, resp response) string {
	keyPath := j.x.Config.Validator.Key
	if want.Receipt != nil && want.Receipt.Signer != "" {
		keyPath = want.Receipt.Signer
	}
	if keyPath == "" {
		return "receipt signature not verified: the case names no validator key (expected receipt.signer, config.json validator.key)"
	}
	if !validRel(keyPath) {
		return fmt.Sprintf("validator key %q is not a path inside the fixture directory", keyPath)
	}
	b, err := os.ReadFile(filepath.Join(j.root, filepath.FromSlash(keyPath)))
	if err != nil {
		return fmt.Sprintf("validator key %s: %v", keyPath, err)
	}
	jwk, err := jws.Algorithms{jws.AlgES256, jws.AlgEd25519}.ParseJWK(b)
	if err != nil {
		return fmt.Sprintf("validator key %s: %v", keyPath, err)
	}
	keyAlg, err := jwk.Algorithm()
	if err != nil {
		return fmt.Sprintf("validator key %s: %v", keyPath, err)
	}
	algs := j.x.Config.Gateway.Algorithms()
	published := "gateway.jws_algorithms [" + strings.Join(algs, ", ") + "]"
	if !algs.Accepts(keyAlg) {
		return fmt.Sprintf("receipt signature not verified: validator key %s is an %s key, and config.json %s does not list %s (draft 7.2, 13.1)", keyPath, keyAlg, published, keyAlg)
	}
	keys, err := algs.NewKeySet(jwk)
	if err != nil {
		return fmt.Sprintf("validator key %s: %v", keyPath, err)
	}
	v := jws.Verifier{Typ: AdmissionTyp, Algorithms: algs, Keys: jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleValidator: keys}}}
	if _, err := v.Verify(resp.compact); err != nil {
		return fmt.Sprintf("receipt signature: %v (key %s, an %s key; %s, draft 7.2)", err, keyPath, keyAlg, published)
	}
	return ""
}

// claimDiffs compares the members the expected receipt names with the
// payload, by canonical JSON (draft 7.4) so that only the value matters.
// The decision is compared with the decision of the response.
func (j judge) claimDiffs(want evalcase.Response, resp response) []string {
	if want.Receipt == nil {
		return nil
	}
	names := make([]string, 0, len(want.Receipt.Claims))
	for name := range want.Receipt.Claims {
		names = append(names, name)
	}
	sort.Strings(names)
	var diffs []string
	for _, name := range names {
		if name == "decision" {
			continue // compared with the response's decision
		}
		w := canonicalJSON(want.Receipt.Claims[name])
		got, ok := resp.claims[name]
		switch {
		case !ok:
			diffs = append(diffs, fmt.Sprintf("claim %s missing from the receipt, want %s", name, w))
		case canonicalJSON(got) != w:
			diffs = append(diffs, fmt.Sprintf("claim %s = %s, want %s", name, canonicalJSON(got), w))
		}
	}
	return diffs
}

// canonicalJSON returns the RFC 8785 form of raw, or raw as written when it
// cannot be canonicalized.
func canonicalJSON(raw json.RawMessage) string {
	if b, err := jcs.Canonicalize(raw); err == nil {
		return string(b)
	}
	return string(raw)
}

// fileDigestDiffs compares the receipt's profile, intent and requirements
// digests with those of the case's own files (draft 7.4): object_digest of
// profile.json and of intent.json, artifact_digest of signed/contract.jws.
// A digest the expected receipt names is compared by claimDiffs; a case
// without the file is not checked.
func (j judge) fileDigestDiffs(want evalcase.Response, resp response) []string {
	var diffs []string
	check := func(claim, file, kind string, compute func([]byte) (core.Digest, error)) {
		if want.Receipt != nil {
			if _, named := want.Receipt.Claims[claim]; named {
				return
			}
		}
		b, ok := j.x.Decoded[file]
		if !ok {
			var err error
			if b, err = os.ReadFile(filepath.Join(j.root, filepath.FromSlash(j.x.Path), filepath.FromSlash(file))); err != nil {
				return
			}
		}
		d, err := compute(b)
		if err != nil {
			diffs = append(diffs, fmt.Sprintf("%s of the case files: %s: %v", claim, file, err))
			return
		}
		var got string
		_ = json.Unmarshal(resp.claims[claim], &got)
		if got != string(d) {
			diffs = append(diffs, fmt.Sprintf("claim %s = %q, want %s %s of the case files (%s)", claim, got, kind, d, file))
		}
	}
	object := func(b []byte) (core.Digest, error) { return digest.ObjectDigest(json.RawMessage(b)) }
	artifact := func(b []byte) (core.Digest, error) { return digest.ArtifactDigest(string(b)) }
	check("profile_digest", "profile.json", "object_digest", object)
	check("intent_digest", "intent.json", "object_digest", object)
	check("requirements_digest", "signed/contract.jws", "artifact_digest", artifact)
	return diffs
}

// expiryDiffs checks the receipt's exp: no later than the expected exp_max
// and at most 60 seconds after iat (draft 12.1). A receipt without iat or
// exp has no window.
func expiryDiffs(want evalcase.Response, resp response) []string {
	number := func(name string) (int64, bool) {
		raw, ok := resp.claims[name]
		if !ok {
			return 0, false
		}
		var n int64
		return n, json.Unmarshal(raw, &n) == nil
	}
	exp, hasExp := number("exp")
	iat, hasIat := number("iat")
	var diffs []string
	if !hasExp {
		diffs = append(diffs, "receipt has no exp (draft 12.1)")
	}
	if !hasIat {
		diffs = append(diffs, "receipt has no iat (draft 12.1)")
	}
	if hasExp && want.Receipt != nil && want.Receipt.ExpMax > 0 && exp > want.Receipt.ExpMax {
		diffs = append(diffs, fmt.Sprintf("exp %d is later than exp_max %d (draft 12.1)", exp, want.Receipt.ExpMax))
	}
	if hasExp && hasIat && exp-iat > maxReceiptSeconds {
		diffs = append(diffs, fmt.Sprintf("exp %d is more than 60 seconds after iat %d (draft 12.1)", exp, iat))
	}
	return diffs
}

// checkDiffs compares the receipt's check results with the expected ones,
// matched by check_id (every receipt check of that id must agree), and
// reports the checks the receipt must not carry.
func checkDiffs(want evalcase.Response, resp response) []string {
	var diffs []string
	for _, w := range want.Checks {
		found := false
		for _, c := range resp.attestation.Checks {
			if c.CheckID != w.CheckID {
				continue
			}
			found = true
			if string(c.Result) != w.Result {
				diffs = append(diffs, fmt.Sprintf("check %s: result %s, want %s", w.CheckID, c.Result, w.Result))
			}
			if c.ReasonCode != w.ReasonCode {
				diffs = append(diffs, fmt.Sprintf("check %s: reason_code %s, want %s", w.CheckID, c.ReasonCode, w.ReasonCode))
			}
			var missing []string
			for _, id := range w.EvidenceIDsInclude {
				if !slices.Contains(c.EvidenceIDs, id) {
					missing = append(missing, id)
				}
			}
			if len(missing) > 0 {
				diffs = append(diffs, fmt.Sprintf("check %s: evidence_ids %q lack %q", w.CheckID, c.EvidenceIDs, missing))
			}
			if w.SourceRef != nil && (c.SourceRef == nil || *c.SourceRef != *w.SourceRef) {
				got := "null"
				if c.SourceRef != nil {
					got = fmt.Sprintf("%q", *c.SourceRef)
				}
				diffs = append(diffs, fmt.Sprintf("check %s: source_ref %s, want %q", w.CheckID, got, *w.SourceRef))
			}
		}
		if !found {
			diffs = append(diffs, fmt.Sprintf("check %s: receipt carries no such check; want result %s, reason_code %s", w.CheckID, w.Result, w.ReasonCode))
		}
	}
	for _, id := range want.AbsentChecks {
		if slices.ContainsFunc(resp.attestation.Checks, func(c core.CheckResult) bool { return c.CheckID == id }) {
			diffs = append(diffs, fmt.Sprintf("check %s: the receipt must not carry it", id))
		}
	}
	return diffs
}

// contractFile is the signed contract of an exchange directory, the one
// requirements_digest names (spec/v1.0/fixtures/README.md, Runner contract).
const contractFile = "signed/contract.jws"

// signedPayload returns the members of the payload of the compact JWS file
// rel of the exchange directory; ok is false when there is no such file.
func (j judge) signedPayload(rel string) (payload map[string]json.RawMessage, ok bool, err error) {
	b, err := os.ReadFile(filepath.Join(j.root, filepath.FromSlash(j.x.Path), filepath.FromSlash(rel)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	seg := strings.Split(strings.TrimSpace(string(b)), ".")
	if len(seg) != 3 {
		return nil, false, fmt.Errorf("%s is not a compact JWS", rel)
	}
	if err := decodeSegment(seg[1], &payload); err != nil {
		return nil, false, fmt.Errorf("%s payload: %w", rel, err)
	}
	return payload, true, nil
}

// contractMember decodes the member name of the exchange's contract into v;
// found is false when there is no contract or no such member.
func (j judge) contractMember(name string, v any) (found bool, err error) {
	payload, ok, err := j.signedPayload(contractFile)
	if err != nil || !ok {
		return false, err
	}
	raw, ok := payload[name]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, fmt.Errorf("%s %s: %w", contractFile, name, err)
	}
	return true, nil
}

// contextCheckDiffs checks that the receipt carries exactly one result for
// each check the contract's context_checks names (draft 12.1), whether the
// expected result lists it or not; the result of a check it does not list
// is not judged. The contract is the payload of the exchange's
// signed/contract.jws; an exchange without one is not checked. A listed
// check the receipt lacks is reported by checkDiffs alone.
func (j judge) contextCheckDiffs(want evalcase.Response, resp response) []string {
	var contextChecks []string
	if _, err := j.contractMember("context_checks", &contextChecks); err != nil {
		return []string{"context checks not judged: " + err.Error()}
	}
	var diffs []string
	seen := map[string]bool{}
	for _, id := range contextChecks {
		if seen[id] {
			continue
		}
		seen[id] = true
		n := 0
		for _, c := range resp.attestation.Checks {
			if c.CheckID == id {
				n++
			}
		}
		switch {
		case n == 0 && listed(want, id):
			// checkDiffs reports it with the expected result.
		case n == 0:
			diffs = append(diffs, fmt.Sprintf("check %s: the contract's context_checks names it and the receipt carries no result for it; an unevaluated one is UNKNOWN NOT_EVALUATED (draft 12.1)", id))
		case n > 1:
			diffs = append(diffs, fmt.Sprintf("check %s: the contract's context_checks names it and the receipt carries %d results for it; want exactly one (draft 12.1)", id, n))
		}
	}
	return diffs
}

// listed reports whether the expected response lists the check id.
func listed(want evalcase.Response, id string) bool {
	return slices.ContainsFunc(want.Checks, func(w evalcase.ExpectedCheck) bool { return w.CheckID == id })
}

// maxEvaluationSeconds is the longest evaluation time (draft 12.2, 20.1).
const maxEvaluationSeconds = 30

// heldInputsCheck is the context check the validator evaluates from inputs
// it already holds, not through check_context (draft 17.5).
const heldInputsCheck = "native-principal-binding-v1"

// notPerformedDiffs reports each check of the receipt recorded PASS although
// its native reads were outstanding when the evaluation ended, so it was not
// performed (draft 12.1). The reads of a submission are outstanding when its
// evaluation.native_reads_at is later than the end of the evaluation: its
// cancelled_at, or the Section 12.2 deadline, the earliest of the contract
// exp, the presentation exp and started_at plus limits.evaluation_seconds,
// at most 30 (spec/v1.0/fixtures/README.md, exchange.json). The checks that need
// a native read (Section 17.1) are the contract's field rules of source
// native (read_native_claim) and its context checks (check_context), except
// native-principal-binding-v1. A check the expected response lists is judged
// by checkDiffs alone.
func (j judge) notPerformedDiffs(want evalcase.Response, resp response) []string {
	if j.sub == nil || j.sub.Evaluation.NativeReadsAt == nil {
		return nil
	}
	reads := *j.sub.Evaluation.NativeReadsAt
	end, why, err := j.evaluationEnd()
	if err != nil {
		return []string{"unperformed checks not judged: " + err.Error()}
	}
	if reads <= end {
		return nil
	}
	var rules []struct {
		RuleID string `json:"rule_id"`
		Source string `json:"source"`
	}
	var contextChecks []string
	if _, err := j.contractMember("field_rules", &rules); err != nil {
		return []string{"unperformed checks not judged: " + err.Error()}
	}
	if _, err := j.contractMember("context_checks", &contextChecks); err != nil {
		return []string{"unperformed checks not judged: " + err.Error()}
	}
	needsRead := map[string]bool{}
	for _, r := range rules {
		if r.Source == "native" {
			needsRead[r.RuleID] = true
		}
	}
	for _, id := range contextChecks {
		if id != heldInputsCheck {
			needsRead[id] = true
		}
	}
	var diffs []string
	reported := map[string]bool{}
	for _, c := range resp.attestation.Checks {
		if !needsRead[c.CheckID] || c.Result != core.CheckPass || listed(want, c.CheckID) || reported[c.CheckID] {
			continue
		}
		reported[c.CheckID] = true
		diffs = append(diffs, fmt.Sprintf("check %s: PASS, but it was not performed: its native read was outstanding when the evaluation ended at %d (%s), before exchange.json native_reads_at %d; a check not performed is never recorded as passed (draft 12.1)", c.CheckID, end, why, reads))
	}
	return diffs
}

// capabilityDiffs applies the capability rule of a native field rule whose
// mapping names its source (spec/v1.0/fixtures/README.md, config.json additions,
// native_mappings[].source) to a receipt check of that rule that
// decision.json does not list; a listed one is left to checkDiffs. A
// max_age_seconds or status_max_age_seconds below the source's declared best
// bound cannot be met: the check must be UNKNOWN UNSUPPORTED_REQUIREMENT,
// never PASS (draft 17.2). For a rule the source can meet, a claim from a
// source with no live check whose status age, at the start of the
// evaluation, is above status_max_age_seconds is a cached answer the source
// cannot refresh: the check must be UNKNOWN DEPENDENCY_UNAVAILABLE, not FAIL
// (draft 18). A claim with a time later than the start plus the skew is left
// to the freshness rule that outranks it (clock ahead).
func (j judge) capabilityDiffs(want evalcase.Response, resp response) []string {
	var rules []struct {
		RuleID              string  `json:"rule_id"`
		Path                string  `json:"path"`
		Source              string  `json:"source"`
		NativePath          *string `json:"native_path"`
		MaxAgeSeconds       int64   `json:"max_age_seconds"`
		StatusMaxAgeSeconds int64   `json:"status_max_age_seconds"`
	}
	if _, err := j.contractMember("field_rules", &rules); err != nil {
		return []string{"source capability not judged: " + err.Error()}
	}
	start := j.x.Config.Now
	if j.sub != nil {
		start = j.sub.Evaluation.StartedAt
	}
	skew := j.x.Config.ClockSkewSeconds
	required := map[string][2]string{}
	for _, r := range rules {
		if r.Source != "native" || r.NativePath == nil {
			continue
		}
		var src *evalcase.NativeSource
		for _, m := range j.x.Config.NativeMappings {
			if m.Path == r.Path && m.NativePath == *r.NativePath && m.Source != nil {
				src = m.Source
			}
		}
		if src == nil {
			continue
		}
		if r.MaxAgeSeconds < src.BestMaxAgeSeconds || r.StatusMaxAgeSeconds < src.BestStatusMaxAgeSeconds {
			required[r.RuleID] = [2]string{string(core.CheckUnknown) + " " + adapterUnsupported, fmt.Sprintf("its limits max_age_seconds %d and status_max_age_seconds %d are below the declared bounds %d and %d of the source %s, which cannot meet them (draft 17.2)", r.MaxAgeSeconds, r.StatusMaxAgeSeconds, src.BestMaxAgeSeconds, src.BestStatusMaxAgeSeconds, src.SourceID)}
			continue
		}
		if src.LiveCheck {
			continue
		}
		for _, c := range j.x.NativeContext.NativeClaims {
			if c.NativePath != *r.NativePath || c.ObservedAt > start+skew || c.StatusCheckedAt > start+skew {
				continue
			}
			if age := start - c.StatusCheckedAt; age > r.StatusMaxAgeSeconds {
				required[r.RuleID] = [2]string{string(core.CheckUnknown) + " " + adapterUnavailable, fmt.Sprintf("its claim's status age %d is above status_max_age_seconds %d and the source %s has no live check: a cached answer the source cannot refresh (draft 18)", age, r.StatusMaxAgeSeconds, src.SourceID)}
			}
			break
		}
	}
	var diffs []string
	reported := map[string]bool{}
	for _, c := range resp.attestation.Checks {
		need, ok := required[c.CheckID]
		if !ok || listed(want, c.CheckID) || reported[c.CheckID] {
			continue
		}
		if got := string(c.Result) + " " + c.ReasonCode; got != need[0] {
			reported[c.CheckID] = true
			diffs = append(diffs, fmt.Sprintf("check %s: %s, want %s: %s", c.CheckID, got, need[0], need[1]))
		}
	}
	return diffs
}

// The reason codes of the capability rule (draft 13.4).
const (
	adapterUnsupported = "UNSUPPORTED_REQUIREMENT"
	adapterUnavailable = "DEPENDENCY_UNAVAILABLE"
)

// evaluationEnd returns when the submission's evaluation ended, if its
// native reads had not completed: at cancelled_at, or at the Section 12.2
// deadline.
func (j judge) evaluationEnd() (int64, string, error) {
	e := j.sub.Evaluation
	end, why := e.StartedAt+maxEvaluationSeconds, "started_at plus 30 seconds"
	if v, ok := j.x.Config.Limits["evaluation_seconds"]; ok && v < maxEvaluationSeconds {
		end, why = e.StartedAt+v, "started_at plus limits.evaluation_seconds"
	}
	var exp int64
	if found, err := j.contractMember("exp", &exp); err != nil {
		return 0, "", err
	} else if found && exp < end {
		end, why = exp, "the contract exp"
	}
	payload, ok, err := j.signedPayload(j.sub.Signed)
	if err != nil {
		return 0, "", err
	}
	if raw, has := payload["exp"]; ok && has {
		if err := json.Unmarshal(raw, &exp); err != nil {
			return 0, "", fmt.Errorf("%s exp: %w", j.sub.Signed, err)
		}
		if exp < end {
			end, why = exp, "the presentation exp"
		}
	}
	if e.CancelledAt != nil && *e.CancelledAt < end {
		end, why = *e.CancelledAt, "cancelled_at"
	}
	return end, why, nil
}

// validRel reports whether s is a relative / path whose segments are neither
// empty nor dot segments.
func validRel(s string) bool {
	if s == "" || strings.HasPrefix(s, "/") || strings.Contains(s, "\\") {
		return false
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
