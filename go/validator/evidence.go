package validator

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// artifactFault is why an evidence artifact or a snapshot was rejected or
// could not be established: the result and reason code it gives the check
// and the field rules that rely on it.
type artifactFault struct {
	result core.CheckStatus
	reason string
}

func rejected(reason string) *artifactFault { return &artifactFault{core.CheckFail, reason} }

// evidenceValidity is draft 11.3 step 7 for the evidence artifacts: each is
// verified under its own issuer's authority, never the agent's (draft 11.2).
// An accepted artifact contributes its claims to the field rules; a
// rejected one contributes nothing, and the rules on its paths fail with its
// reason.
func (e *evaluation) evidenceValidity(ctx context.Context) outcome {
	var worst *artifactFault
	ids := []string{}
	for _, compact := range e.p.Evidence {
		ev, fault := e.verifyEvidence(ctx, compact)
		if ev.JTI != "" {
			ids = append(ids, ev.JTI)
		}
		if fault == nil {
			continue
		}
		for _, c := range ev.Claims {
			if fault.result == core.CheckFail {
				e.failedPaths[c.Path] = fault.reason
			} else {
				e.pendingPaths[c.Path] = fault.reason
			}
		}
		if worst == nil || (fault.result == core.CheckFail && worst.result != core.CheckFail) {
			worst = fault
		}
	}
	e.evidenceIDs = ids
	o := pass()
	if worst != nil {
		o = outcome{result: worst.result, reason: worst.reason}
	}
	o.evidence = slices.Clone(ids)
	return o
}

func (e *evaluation) verifyEvidence(ctx context.Context, compact string) (core.Evidence, *artifactFault) {
	cfg, lim := e.v.Config, e.v.limits()
	var ev core.Evidence
	parsed, err := jws.Verifier{Keys: trustKeys(cfg.Issuers), Typ: jws.TypEvidence, Algorithms: cfg.Algorithms, Limits: lim.ArtifactJSON()}.Verify(compact)
	if err == nil {
		err = lim.ValidateArtifactSize(len(parsed.Payload))
	}
	if err == nil {
		err = strictjson.Unmarshal(parsed.Payload, lim.ArtifactJSON(), &ev)
	}
	switch {
	case err != nil && isProofFailure(err):
		return ev, rejected(reasonInvalidProof)
	case err != nil:
		return ev, rejected(reasonInvalidClaim)
	case ev.Subject != e.p.Subject || ev.HolderJKT != e.jkt:
		return ev, rejected(reasonInvalidProof)
	case ev.Audience != cfg.Audience || ev.TenantID != cfg.Realm.TenantID || ev.EnvironmentID != cfg.Realm.EnvironmentID:
		return ev, rejected(reasonContextMismatch)
	case ev.PactVersion != core.Version:
		return ev, rejected(reasonInvalidClaim)
	}
	if f := e.window(clock.Evidence, ev.IssuedAt, ev.NotBefore, ev.Expiry); f != nil {
		return ev, f
	}
	trust := issuerOf(cfg.Issuers, ev.Issuer)
	for _, c := range ev.Claims {
		if trust == nil || !slices.Contains(trust.ClaimPaths, c.Path) {
			// A claim outside the issuer's claim-path authority: the
			// evidence is rejected (draft 8.3, 22.2).
			return ev, rejected(reasonInvalidClaim)
		}
	}
	st, err := e.v.Status.EvidenceStatus(ctx, ev.Issuer, ev.StatusRef)
	switch {
	case err != nil:
		return ev, &artifactFault{core.CheckUnknown, reasonUnavailable}
	case st.Revoked:
		return ev, rejected(reasonRevokedEvidence)
	}
	e.expiries = append(e.expiries, ev.Expiry)
	for _, c := range ev.Claims {
		v, err := decodeJSON(c.Value)
		if err != nil {
			return ev, rejected(reasonInvalidClaim)
		}
		e.claims = append(e.claims, authClaim{
			path: c.Path, issuer: ev.Issuer, value: v, observedAt: time.Unix(ev.IssuedAt, 0),
			statusAt: st.CheckedAt, evidenceID: ev.JTI, sourceID: st.SourceID,
		})
	}
	return ev, nil
}

// window applies the time rules of draft 7.5 and the lifetime of draft 20.1
// to an embedded artifact: an expired one is stale, one from the future or
// with too long a life is invalid.
func (e *evaluation) window(a clock.Artifact, iat, nbf, exp int64) *artifactFault {
	if err := clock.CheckWindow(iat, nbf, exp, e.v.Clock.Now(), e.v.Config.Skew); err != nil {
		if errors.Is(err, clock.ErrExpired) {
			return rejected(reasonStaleEvidence)
		}
		return rejected(reasonInvalidClaim)
	}
	if err := clock.CheckLifetime(a, iat, exp); err != nil {
		return rejected(reasonInvalidClaim)
	}
	return nil
}

func issuerOf(issuers []Issuer, id string) *Issuer {
	for i := range issuers {
		if issuers[i].ID == id {
			return &issuers[i]
		}
	}
	return nil
}

// reputationContext is draft 11.3 step 9 for the presented snapshot: its
// provenance, subject, holder, audience, realm, freshness, scoring-policy
// epoch, context and hold state (draft 15.2, A.2). An accepted snapshot is
// the authoritative value for the reputation paths its service may assert.
// The result names the snapshot and the gateway's selection record (draft
// A.2).
func (e *evaluation) reputationContext(ctx context.Context) outcome {
	snap, fault := e.verifySnapshot(ctx)
	paths := []string{}
	if t := issuerOf(e.v.Config.ReputationServices, snap.Issuer); t != nil {
		paths = t.ClaimPaths
	}
	o := pass()
	if fault != nil {
		o = outcome{result: fault.result, reason: fault.reason}
		for _, p := range paths {
			if fault.result == core.CheckFail {
				e.failedPaths[p] = fault.reason
			} else {
				e.pendingPaths[p] = fault.reason
			}
		}
	} else {
		e.acceptSnapshot(&snap, paths)
		o = o.at(time.Unix(snap.IssuedAt, 0))
	}
	if e.snapshotJTI != "" {
		o.evidence = []string{e.snapshotJTI}
	}
	if e.selErr == nil && e.sel.RecordRef != "" {
		ref := e.sel.RecordRef
		o.sourceRef = &ref
	}
	return o
}

func (e *evaluation) verifySnapshot(ctx context.Context) (core.ReputationSnapshot, *artifactFault) {
	cfg, lim := e.v.Config, e.v.limits()
	var snap core.ReputationSnapshot
	parsed, err := jws.Verifier{Keys: trustKeys(cfg.ReputationServices), Typ: jws.TypReputation, Algorithms: cfg.Algorithms, Limits: lim.ArtifactJSON()}.Verify(*e.p.Reputation)
	if err == nil {
		err = lim.ValidateArtifactSize(len(parsed.Payload))
	}
	if err == nil {
		err = strictjson.Unmarshal(parsed.Payload, lim.ArtifactJSON(), &snap)
	}
	if snap.JTI != "" {
		e.snapshotJTI = snap.JTI
	}
	v := snap.Value
	switch {
	case err != nil && isProofFailure(err):
		return snap, rejected(reasonInvalidProof)
	case err != nil:
		return snap, rejected(reasonInvalidClaim)
	case snap.Subject != e.p.Subject || snap.HolderJKT != e.jkt:
		return snap, rejected(reasonInvalidProof)
	case snap.Audience != cfg.Audience || snap.TenantID != cfg.Realm.TenantID || snap.EnvironmentID != cfg.Realm.EnvironmentID:
		return snap, rejected(reasonContextMismatch)
	case snap.PactVersion != core.Version || v.ProvenanceDigest.Validate() != nil:
		return snap, rejected(reasonInvalidClaim)
	}
	if f := e.window(clock.Snapshot, snap.IssuedAt, snap.NotBefore, snap.Expiry); f != nil {
		return snap, f
	}
	if v.EvidenceCutoff > snap.IssuedAt || time.Unix(v.EvidenceCutoff, 0).After(e.v.Clock.Now().Add(cfg.Skew)) {
		return snap, rejected(reasonInvalidClaim)
	}
	if e.activeErr != nil {
		return snap, &artifactFault{core.CheckUnknown, reasonUnavailable}
	}
	if !slices.Contains(e.active.ScoringPolicyRevisions, v.ScoringPolicyRevision) {
		return snap, rejected(reasonContextMismatch)
	}
	if v.SecurityStatus == core.SecurityHold || len(v.HoldRefs) > 0 {
		return snap, rejected(reasonSecurityHold)
	}
	if !e.bindingKnown {
		return snap, &artifactFault{core.CheckUnknown, reasonUnavailable}
	}
	if e.v.Contexts == nil {
		return snap, &artifactFault{core.CheckUnknown, reasonUnsupported}
	}
	want, err := e.v.Contexts.ReputationContext(ctx, e.checkInput())
	if err != nil {
		code, ok := adapter.CodeOf(err)
		if !ok {
			code = adapter.CodeDependencyUnavailable
		}
		return snap, &artifactFault{core.CheckUnknown, string(code)}
	}
	if !jsonEqual(want, v.Context) {
		return snap, rejected(reasonContextMismatch)
	}
	return snap, nil
}

// acceptSnapshot makes the snapshot value the authoritative value of the
// reputation paths its service may assert (Appendix A.2). Each value is
// observed at the snapshot's iat and status-checked at the evaluation's
// security-hold check, never by the snapshot's own security_status or
// hold_refs.
func (e *evaluation) acceptSnapshot(snap *core.ReputationSnapshot, paths []string) {
	e.snapshot = snap
	e.expiries = append(e.expiries, snap.Expiry)
	value, err := decodeJSON(toJSONBytes(snap.Value))
	if err != nil {
		return
	}
	at := time.Unix(snap.IssuedAt, 0)
	var checked time.Time // none when the hold check could not be made
	if e.holdsErr == nil {
		checked = e.holdsAt
	}
	for _, p := range paths {
		rel, ok := strings.CutPrefix(p, reputationPath)
		if !ok || (rel != "" && !strings.HasPrefix(rel, "/")) {
			continue
		}
		v, found := pointer(value, rel)
		if !found {
			continue
		}
		e.claims = append(e.claims, authClaim{
			path: p, issuer: snap.Issuer, value: v, observedAt: at, statusAt: checked,
			evidenceID: snap.JTI, sourceID: snap.Issuer, holdCheck: true,
		})
	}
}
