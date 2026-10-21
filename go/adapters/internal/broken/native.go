package broken

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

func sameRealm(a memory.Realm, b adapter.Realm) bool {
	return a.TenantID == b.TenantID && a.EnvironmentID == b.EnvironmentID
}

// rawClaim reads the record behind a claim as the source stores it, with no
// check of the times.
func (b *Adapter) rawClaim(path string, cc adapter.ClaimContext) (adapter.NativeClaim, bool) {
	for _, c := range b.State().Claims {
		if !c.Applies(path, cc) {
			continue
		}
		var v any
		if err := json.Unmarshal(c.Value, &v); err != nil {
			return adapter.NativeClaim{}, false
		}
		return adapter.NativeClaim{
			Value:           v,
			ObservedAt:      secs(c.ObservedAt),
			StatusCheckedAt: secs(c.StatusCheckedAt),
			SourceID:        c.SourceID,
			SourceRef:       c.SourceRef,
		}, true
	}
	return adapter.NativeClaim{}, false
}

func secs(s *int64) time.Time {
	if s == nil {
		return time.Time{}
	}
	return time.Unix(*s, 0)
}

// ReadNativeClaim is the memory adapter's, with the claim defects.
func (b *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if b.on[ConflateClaimRealms] {
		// Look the principal up in the realm of the first record that names it.
		for _, rec := range b.State().Claims {
			if rec.Path == nativePath && rec.Principal == cc.Principal.ID {
				cc.Principal.Realm = adapter.Realm{TenantID: rec.Realm.TenantID, EnvironmentID: rec.Realm.EnvironmentID}
				break
			}
		}
	}
	if b.on[IgnoreClaimResource] {
		// Take the first record of the path whatever resource it names, by
		// making its resource the one the operation lists.
		for _, rec := range b.State().Claims {
			unscoped := rec
			unscoped.Resource = ""
			if rec.Resource != "" && unscoped.Applies(nativePath, cc) {
				cc.Operation.Resources = []string{rec.Resource}
				break
			}
		}
	}
	if b.on[IgnoreClaimTask] {
		// Take the first record of the path whatever task it names, by making
		// its task the task of the intent.
		for _, rec := range b.State().Claims {
			unscoped := rec
			unscoped.TaskID = ""
			if rec.TaskID != "" && unscoped.Applies(nativePath, cc) {
				cc.Intent.TaskID = rec.TaskID
				break
			}
		}
	}
	c, err := b.Adapter.ReadNativeClaim(ctx, nativePath, cc)
	if err == nil && b.on[NoStatusSkewAllowance] && c.StatusCheckedAt.After(b.now()) {
		return adapter.NativeClaim{}, fmt.Errorf("broken: the source reports a status check after now: %w", adapter.ErrDependencyUnavailable)
	}
	if err == nil {
		if b.on[RestampObservedAt] {
			c.ObservedAt = b.now()
		}
		if b.on[StampMissingTimes] {
			if c.ObservedAt.IsZero() {
				c.ObservedAt = b.now()
			}
			if c.StatusCheckedAt.IsZero() {
				c.StatusCheckedAt = b.now()
			}
		}
		return c, nil
	}
	// The memory adapter refused a time later than now plus the skew; pass it
	// on.
	raw, ok := b.rawClaim(nativePath, cc)
	if !ok {
		return c, err
	}
	limit := b.now().Add(clock.BaselineSkew)
	futureObserved := raw.ObservedAt.After(limit)
	futureChecked := raw.StatusCheckedAt.After(limit)
	switch {
	case b.on[PassFutureObservedAt] && futureObserved && !futureChecked,
		b.on[PassFutureStatusChecked] && futureChecked && !futureObserved:
		return raw, nil
	case b.on[ClampFutureClaimTimes] && (futureObserved || futureChecked):
		if futureObserved {
			raw.ObservedAt = limit
		}
		if futureChecked {
			raw.StatusCheckedAt = limit
		}
		return raw, nil
	}
	return c, err
}

// CheckContext is the memory adapter's, with the check defects.
func (b *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	installed := b.State().Checks
	verdict := func(c memory.CheckRecord) adapter.CheckOutcome {
		return adapter.CheckOutcome{
			Result:     adapter.Verdict(c.Result),
			ReasonCode: c.ReasonCode,
			SourceID:   c.SourceID,
			SourceRef:  c.SourceRef,
		}
	}
	if b.on[IgnoreCheckScope] || (b.on[TrustEmptyBinding] && in.Binding == (adapter.AgentBinding{})) {
		// Take the first record of the id whatever agent or principal it is
		// for, by making the call the record's own.
		for _, rec := range installed {
			if rec.ID != checkID {
				continue
			}
			if b.on[IgnoreCheckScope] && rec.Principal != "" {
				in.Principal.ID = rec.Principal
			}
			if rec.AgentID != "" {
				in.Binding.AgentID = rec.AgentID
			}
			break
		}
	}
	out := b.checkFreshness(checkID, b.Adapter.CheckContext(ctx, checkID, in))

	if b.on[NeverEvaluateChecks] && out.Result != adapter.VerdictUnknown {
		return adapter.CheckOutcome{Result: adapter.VerdictFail, ReasonCode: "CHECK_FAILED", SourceID: out.SourceID}
	}
	if b.on[PrefixMatchCheck] {
		for _, c := range installed {
			if strings.HasPrefix(c.ID, checkID) {
				return verdict(c)
			}
		}
	}
	if b.on[FoldCaseCheck] {
		for _, c := range installed {
			if strings.EqualFold(c.ID, checkID) {
				return verdict(c)
			}
		}
	}
	if b.on[FailOpenUnknownCheck] && out.Result == adapter.VerdictUnknown {
		return adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED"}
	}
	if b.on[EchoRefsInSource] {
		out.SourceRef = strings.Join(in.EvidenceRefs, " ")
	}
	return out
}

// AuthorizeNative is the memory adapter's, with the authorization defects.
func (b *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	evaluated := p
	if b.on[ConnectorSubstitution] {
		for _, r := range b.State().Policy {
			if r.Effect == string(adapter.EffectAllow) && r.Action == op.Action && r.Principal != p.ID {
				evaluated.ID = r.Principal
				break
			}
		}
	}
	if b.on[ConflatePolicyRealms] {
		for _, r := range b.State().Policy {
			if r.Principal == p.ID && r.Action == op.Action && !sameRealm(r.Realm, p.Realm) {
				evaluated.Realm = adapter.Realm{TenantID: r.Realm.TenantID, EnvironmentID: r.Realm.EnvironmentID}
				break
			}
		}
	}
	d, err := b.Adapter.AuthorizeNative(ctx, evaluated, op)
	if err != nil {
		return d, err
	}

	if b.on[DefaultAllow] && !b.ruleMentions(p.ID, op.Action) {
		d.Effect = adapter.EffectAllow
	}
	if b.on[RewriteReadDeny] && d.Effect == adapter.EffectDeny && op.Method == "GET" {
		d.Effect = adapter.EffectAllow
	}
	if b.on[DropObligations] {
		d.Obligations = nil
	}
	if b.on[DecisionWithoutSource] {
		d.SourceID = ""
	}
	if b.on[FutureDecidedAt] {
		d.DecidedAt = b.now().Add(time.Hour)
	}
	if (b.on[ExecuteOnDeny] && d.Effect == adapter.EffectDeny) || (b.on[ExecuteOnAllow] && d.Effect == adapter.EffectAllow) {
		b.fire("execute")
	}
	return d, nil
}

// ruleMentions reports whether any rule of any realm names the principal for
// the action.
func (b *Adapter) ruleMentions(principal, action string) bool {
	return slices.ContainsFunc(b.State().Policy, func(r memory.PolicyRule) bool {
		return r.Principal == principal && r.Action == action
	})
}
