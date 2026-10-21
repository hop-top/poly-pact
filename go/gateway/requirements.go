package gateway

import (
	"bytes"
	"context"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/strictjson"
)

// requirements serves POST /pact/v0.1/requirements (draft 9.1, 11.1 steps 1
// to 3, 13.2): a natively authenticated ContractRequest is answered with a
// signed contract (application/jose) for its proposed operation, in the mode
// of the proposed operation's route. Nothing is issued without native
// authentication and a trustworthy binding of the agent and key (draft 9.1),
// for a proposal the installed mapping does not yield (request binding
// RB-42), for an off route, or in enforced mode for requirements that name a
// transport other than HTTPS (draft 13.3.1); a contract whose record
// (mapping version and proposed operation_id) cannot be recorded is not
// returned.
func (g *gateway) requirements(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
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
	req, code := g.contractRequest(r)
	if code != "" {
		refuse(w, code, nil)
		return
	}
	b, err := g.cfg.Adapter.ResolveAgentBinding(ctx, p.Realm, p.Workload, adapter.AgentID(req.AgentID))
	if err != nil {
		refuse(w, codeOf(err), nil)
		return
	}
	class, code := g.checkProposal(ctx, p, req.Operation)
	if code != "" {
		refuse(w, code, nil)
		return
	}
	rs, err := g.cfg.Requirements.Requirements(ctx, p, req)
	if err != nil {
		refuse(w, codeOf(err), nil)
		return
	}
	rs.Mode = core.ModeEnforced
	if class == ClassObserve {
		rs.Mode = core.ModeObserve
	}
	if rs.Mode == core.ModeEnforced && rs.Transport() != contract.TransportHTTPS {
		// An enforced-mode contract that names another transport is not
		// returned over HTTPS (draft 13.3.1, the downgrade rule).
		refuse(w, adapter.CodeContextMismatch, nil)
		return
	}
	now := g.clock.Now()
	c, err := g.cfg.Publisher.Issue(ctx, req, contract.Authenticated{Principal: p, Binding: b}, rs, now)
	if err != nil {
		refuse(w, codeOf(err), nil)
		return
	}
	until := clock.ReplayRetention(c.Claims.Expiry, c.Claims.IssuedAt, clock.BaselineSkew)
	rec := ContractRecord{MappingVersion: g.cfg.MappingVersion, OperationID: req.Operation.OperationID}
	if err := g.cfg.Records.Record(ctx, c.Digest, rec, now, until); err != nil {
		refuse(w, adapter.CodeDependencyUnavailable, nil)
		return
	}
	w.Header().Set("Content-Type", "application/jose")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, c.Compact)
}

// contractRequest reads the strict ContractRequest of r (draft 7.1,
// Appendix A): malformed, oversized, out of the draft 20.1 limits or
// without an operation_id is INVALID_MESSAGE.
func (g *gateway) contractRequest(r *http.Request) (core.ContractRequest, adapter.Code) {
	lim := g.cfg.Validator.Config.Limits
	if lim == (core.Limits{}) {
		lim = core.Defaults()
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(lim.PresentationBytes)+1))
	if err != nil {
		return core.ContractRequest{}, adapter.CodeInvalidMessage
	}
	var req core.ContractRequest
	if len(body) > lim.PresentationBytes || strictjson.Unmarshal(body, lim.PresentationJSON(), &req) != nil {
		return core.ContractRequest{}, adapter.CodeInvalidMessage
	}
	if req.Operation.OperationID == "" || lim.ValidateOperation(&req.Operation) != nil || lim.ValidateIntent(&req.Intent) != nil {
		return core.ContractRequest{}, adapter.CodeInvalidMessage
	}
	return req, ""
}

// checkProposal applies the installed mapping to the proposed operation
// (request binding RB-42) and returns the class of its route. The proposal
// becomes a request with its method, its target URI in absolute form (whose
// authority the mapping checks and drops, RB-4), its covered headers, and a
// body exactly when its body_digest is not that of the empty body, so that
// content-type is covered as for the actual request (draft 10.2). The body
// bytes are not known before the actual request; its digest is bound by the
// contract and compared at validation (draft 11.3 step 5).
//
// The proposed operation_id is the agent's: the mapping does not yield it
// and it is not compared; the gateway records it with the contract (draft
// 10.2).
//
// A target the mapping refuses is INVALID_MESSAGE; one no route maps is the
// mapping's UNSUPPORTED_REQUIREMENT, as is a route that PACT does not
// protect; a proposal whose method, target, action, resources, principal,
// environment or headers differ from what the mapping yields is
// CONTEXT_MISMATCH.
func (g *gateway) checkProposal(ctx context.Context, p adapter.Principal, op core.OperationContext) (Class, adapter.Code) {
	u, err := url.Parse(op.TargetURI)
	if err != nil || u.Scheme != "https" || u.Host == "" || op.Method == "" {
		return "", adapter.CodeInvalidMessage
	}
	var body io.Reader = http.NoBody
	if op.BodyDigest != digest.BytesDigest(nil) {
		body = bytes.NewReader([]byte{0})
	}
	pr, err := http.NewRequestWithContext(ctx, op.Method, op.TargetURI, body)
	if err != nil {
		return "", adapter.CodeInvalidMessage
	}
	pr.RequestURI = op.TargetURI
	for name, v := range op.Headers {
		if name != strings.ToLower(name) {
			return "", adapter.CodeInvalidMessage
		}
		pr.Header[http.CanonicalHeaderKey(name)] = []string{v}
	}
	mapped, err := g.cfg.Adapter.MapOperation(ctx, pr, p, g.cfg.MappingVersion)
	if err != nil {
		return "", codeOf(err)
	}
	switch {
	case mapped.Method != op.Method, mapped.TargetURI != op.TargetURI, mapped.Action != op.Action,
		!slices.Equal(mapped.Resources, op.Resources), op.PrincipalID != p.ID, mapped.PrincipalID != p.ID,
		mapped.EnvironmentID != op.EnvironmentID, !maps.Equal(mapped.Headers, op.Headers):
		return "", adapter.CodeContextMismatch
	}
	class := g.classify(pr)
	if class == ClassOff {
		return "", adapter.CodeUnsupportedRequirement
	}
	return class, ""
}
