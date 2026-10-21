package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/validator"
)

// envelopeOverhead is the room a compact presentation needs beside its
// base64url payload: the JOSE header, the signature and the separators
// (draft 20.1, transport frame).
const envelopeOverhead = 10922

// enforce applies the expression of draft 2.3 to a request of an enforce
// route: native authentication, PACT admission, native authorization. Only a
// request that passes all three reaches next, with its Admission in the
// request context and without its presentation header.
func (g *gateway) enforce(w http.ResponseWriter, r *http.Request, next http.Handler) {
	ctx := r.Context()
	p, err := g.cfg.Adapter.AuthenticateNative(ctx, r)
	switch {
	case err != nil:
		refuse(w, codeOf(err), nil)
		return
	case p.ID == "":
		refuse(w, adapter.CodeInvalidProof, nil)
		return
	}
	pres, code := g.presentation(r)
	if code != "" {
		refuse(w, code, nil)
		return
	}
	op, code := g.actualOperation(ctx, r, p, pres)
	if code != "" {
		refuse(w, code, nil)
		return
	}
	res, err := g.cfg.Validator.Evaluate(ctx, validator.Request{Presentation: pres, Operation: op, Principal: p, Transport: contract.TransportHTTPS})
	if err != nil {
		// A rejection before an authenticated evaluation, or a receipt that
		// could not be recorded durably: never a positive admission (draft
		// 12.2).
		refuse(w, codeOf(err), nil)
		return
	}
	a := res.Attestation
	g.attach(w, res)
	switch {
	case a.Decision != core.DecisionAdmissible:
		refuse(w, refusal(a), receiptRef(a))
		return
	case a.Mode != core.ModeEnforced:
		// An admission in observation mode is not enforced protection
		// (draft 2.3).
		refuse(w, adapter.CodeContextMismatch, receiptRef(a))
		return
	}
	d, err := g.cfg.Adapter.AuthorizeNative(ctx, p, op)
	switch {
	case err != nil, d.Effect != adapter.EffectAllow && d.Effect != adapter.EffectDeny:
		// An unknown term does not authorize execution (draft 2.3).
		w.Header().Del(HeaderAdmission)
		refuse(w, adapter.CodeDependencyUnavailable, nil)
		return
	case !d.Permits():
		w.Header().Del(HeaderAdmission)
		g.denied(w, r)
		return
	}
	admitted := r.WithContext(context.WithValue(ctx, admissionKey{}, Admission{Principal: p, Operation: op, Receipt: res, Native: d}))
	// The presentation is never forwarded (request binding RB-51); no other
	// part of the request changes, and it is not a covered header (RB-20).
	admitted.Header = r.Header.Clone()
	admitted.Header.Del(HeaderPresentation)
	next.ServeHTTP(w, admitted)
}

// observe evaluates a presented request of an observe route, so that its
// receipt is recorded in observation mode, and never refuses it: every
// failure ends the observation, not the request (draft 2.3, 4.4).
func (g *gateway) observe(r *http.Request) {
	ctx := r.Context()
	if len(r.Header.Values(HeaderPresentation)) == 0 {
		return
	}
	p, err := g.cfg.Adapter.AuthenticateNative(ctx, r)
	if err != nil || p.ID == "" {
		return
	}
	pres, code := g.presentation(r)
	if code != "" {
		return
	}
	op, code := g.actualOperation(ctx, r, p, pres)
	if code != "" {
		return
	}
	_, _ = g.cfg.Validator.Evaluate(ctx, validator.Request{Presentation: pres, Operation: op, Principal: p, Transport: contract.TransportHTTPS})
}

// presentation returns the one presentation of r. None is INVALID_PROOF: the
// request carries no holder proof (draft 11.2, 13.4); more than one field
// line, or one larger than a maximal presentation, is INVALID_MESSAGE (draft
// 12.2, 20.1).
func (g *gateway) presentation(r *http.Request) (string, adapter.Code) {
	vals := r.Header.Values(HeaderPresentation)
	switch {
	case len(vals) == 0 || len(vals) == 1 && strings.TrimSpace(vals[0]) == "":
		return "", adapter.CodeInvalidProof
	case len(vals) > 1:
		return "", adapter.CodeInvalidMessage
	}
	pres := strings.TrimSpace(vals[0])
	if len(pres) > g.maxPresentation() {
		return "", adapter.CodeInvalidMessage
	}
	return pres, ""
}

// maxPresentation is the length of the base64url encoding of the largest
// decoded presentation the validator accepts, plus the envelope (draft 20.1).
func (g *gateway) maxPresentation() int {
	n := g.cfg.Validator.Config.Limits.PresentationBytes
	if n == 0 {
		n = core.Defaults().PresentationBytes
	}
	return base64.RawURLEncoding.EncodedLen(n) + envelopeOverhead
}

// actualOperation binds r under the record of the contract the presentation
// embeds: map_operation under the recorded mapping version, and the
// operation_id recorded at issuance in place of the one map_operation
// returns, which is not consulted (draft 10.2). A refusal of the mapping is
// its code.
func (g *gateway) actualOperation(ctx context.Context, r *http.Request, p adapter.Principal, pres string) (core.OperationContext, adapter.Code) {
	rec, code := g.recorded(ctx, pres)
	if code != "" {
		return core.OperationContext{}, code
	}
	op, err := g.cfg.Adapter.MapOperation(ctx, r, p, rec.MappingVersion)
	if err != nil {
		return core.OperationContext{}, codeOf(err)
	}
	op.OperationID = rec.OperationID
	return op, ""
}

// recorded returns the record of the contract the presentation embeds, whose
// mapping version must be the installed one (request binding RB-43):
// another version, or no record, is REQUIREMENTS_CHANGED, the rejection of a
// protected request under an inactive contract before an authenticated
// evaluation (draft 12.2); a store that cannot answer is
// DEPENDENCY_UNAVAILABLE (RB-45, draft 18). The contract is read without
// trusting it: it only selects the record, and the validator verifies it.
func (g *gateway) recorded(ctx context.Context, pres string) (ContractRecord, adapter.Code) {
	d, ok := embeddedContract(pres)
	if !ok {
		return ContractRecord{}, adapter.CodeInvalidMessage
	}
	rec, err := g.cfg.Records.Lookup(ctx, d, g.clock.Now())
	switch {
	case errors.Is(err, ErrNotRecorded):
		return ContractRecord{}, contract.CodeRequirementsChanged
	case err != nil:
		return ContractRecord{}, adapter.CodeDependencyUnavailable
	case rec.MappingVersion != g.cfg.MappingVersion:
		return ContractRecord{}, contract.CodeRequirementsChanged
	}
	return rec, ""
}

// embeddedContract returns the artifact_digest of the contract a compact
// presentation embeds (draft 7.4, Appendix A.2: requirements_digest).
func embeddedContract(pres string) (core.Digest, bool) {
	parts := strings.Split(pres, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Contract string `json:"contract"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Contract == "" {
		return "", false
	}
	d, err := digest.ArtifactDigest(claims.Contract)
	if err != nil {
		return "", false
	}
	return d, true
}

// attach sets the compact receipt as PACT-Admission when it fits (draft
// 13.2).
func (g *gateway) attach(w http.ResponseWriter, res validator.Result) {
	limit := g.cfg.AdmissionHeaderBytes
	if limit == 0 {
		limit = DefaultAdmissionHeaderBytes
	}
	if res.Receipt != "" && len(res.Receipt) <= limit {
		w.Header().Set(HeaderAdmission, res.Receipt)
	}
}

// receiptRef is the extensions member of a refusal after an evaluation: the
// decision and the jti of the recorded receipt.
func receiptRef(a core.AdmissionAttestation) core.Object {
	dec, _ := json.Marshal(string(a.Decision))
	jti, _ := json.Marshal(a.JTI)
	return core.Object{"decision": dec, "receipt_id": jti}
}

// denied answers a native denial: it always wins, and its reason, which may
// name private resources, is not disclosed (draft 2.3, 13.4).
func (g *gateway) denied(w http.ResponseWriter, r *http.Request) {
	if g.cfg.NativeDenial != nil {
		g.cfg.NativeDenial.ServeHTTP(w, r)
		return
	}
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}
