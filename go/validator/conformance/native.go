package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/validator"
)

const (
	// enrollmentSource is the source of the workload's enrollments.
	enrollmentSource = "fixture:enrollment-source"
	// defaultCheckAge is the source age of an installed check that neither
	// a field rule nor check_freshness bounds (spec/v1.0/fixtures/README.md,
	// config.json additions).
	defaultCheckAge int64 = 30
	// delegationPath is the profile path whose native source is the
	// delegation (draft 8.5, 17.5); its field rule bounds the age of the
	// delegation check.
	delegationPath = "/attributes/delegation/authority_ref"
)

// nativeAdapter builds the in-memory adapter of the exchange's native state
// for a submission whose actual operation is op.
func (g *gateway) nativeAdapter(op core.OperationContext) (*memory.Adapter, error) {
	cfg, nc := g.x.Config, g.x.NativeContext
	pr := g.principal()
	realm := memory.Realm{TenantID: pr.Realm.TenantID, EnvironmentID: pr.Realm.EnvironmentID}
	origin, err := originOf(op.TargetURI)
	if err != nil {
		return nil, err
	}
	st := memory.State{
		Model:   memory.Model,
		Gateway: memory.Gateway{TenantID: cfg.Gateway.TenantID, EnvironmentID: cfg.Gateway.EnvironmentID, Origin: origin},
	}
	if st.Enrollments, err = g.enrollments(realm); err != nil {
		return nil, err
	}
	if g.x.Availability.EnrollmentSource == "unavailable" {
		st.UnavailableSources = append(st.UnavailableSources, enrollmentSource)
	}
	for _, m := range cfg.NativeMappings {
		st.ApprovedPaths = append(st.ApprovedPaths, m.NativePath)
	}
	for _, c := range nc.NativeClaims {
		if !slices.Contains(st.ApprovedPaths, c.NativePath) {
			st.ApprovedPaths = append(st.ApprovedPaths, c.NativePath)
		}
		src := c.SourceID
		if slices.Contains(g.x.Availability.Sources, c.NativePath) {
			src = "fixture:unavailable:" + c.NativePath
			st.UnavailableSources = append(st.UnavailableSources, src)
		}
		st.Claims = append(st.Claims, memory.ClaimRecord{
			Realm: realm, Principal: pr.ID, Path: c.NativePath, Value: c.Value,
			ObservedAt: ptr(c.ObservedAt), StatusCheckedAt: ptr(c.StatusCheckedAt), SourceID: src,
		})
	}
	var intent core.Intent
	if err := json.Unmarshal(g.x.Decoded["intent.json"], &intent); err != nil {
		return nil, fmt.Errorf("intent.json: %w", err)
	}
	st.Checks, st.UnavailableSources = g.checkRecords(intent, op, st.UnavailableSources)
	return memory.New(st, g.clk)
}

// enrollments states native_context.json's authenticated binding as the
// records of the enrollment source (identity mapping IM-11, IM-19).
func (g *gateway) enrollments(realm memory.Realm) ([]memory.Enrollment, error) {
	a := g.auth
	at := ptr(a.AuthenticatedAt)
	rec := func(wl adapter.Workload, agent, operator string, jkt core.Digest, status adapter.BindingStatus) memory.Enrollment {
		return memory.Enrollment{
			Realm: realm, Workload: string(wl), AgentID: agent, OperatorID: operator, HolderJKT: string(jkt),
			Status: string(status), ObservedAt: at, StatusCheckedAt: at, SourceID: enrollmentSource,
		}
	}
	var profile core.AgentProfile
	if err := json.Unmarshal(g.x.Decoded["profile.json"], &profile); err != nil {
		return nil, fmt.Errorf("profile.json: %w", err)
	}
	switch {
	case a.BindingError != nil && *a.BindingError == string(adapter.CodeUnsupportedRequirement):
		return []memory.Enrollment{
			rec(workload, "https://identity.example/agents/fixture-enrollment-1", profile.OperatorID, profile.HolderJKT, adapter.BindingActive),
			rec(workload, "https://identity.example/agents/fixture-enrollment-2", profile.OperatorID, profile.HolderJKT, adapter.BindingActive),
		}, nil
	case a.BindingStatus == evalcase.BindingUnknown || a.AgentID == nil || a.HolderJKT == nil:
		if a.EnrolledElsewhere {
			return []memory.Enrollment{rec("fixture:other-workload", profile.AgentID, profile.OperatorID, profile.HolderJKT, adapter.BindingActive)}, nil
		}
		return nil, nil
	}
	operator := ""
	if a.OperatorID != nil {
		operator = *a.OperatorID
	}
	return []memory.Enrollment{rec(workload, *a.AgentID, operator, *a.HolderJKT, adapter.BindingStatus(strings.ToUpper(a.BindingStatus)))}, nil
}

// checkRecords states the native state of each installed check as the
// verdict the check's rules give it for this submission.
func (g *gateway) checkRecords(intent core.Intent, op core.OperationContext, unavailable []string) ([]memory.CheckRecord, []string) {
	cfg, nc := g.x.Config, g.x.NativeContext
	now := g.clk.Now().Unix()
	ref := func(id string) string { return "configured-validation-record:" + id }
	var out []memory.CheckRecord
	for _, id := range cfg.InstalledChecks {
		r := memory.CheckRecord{ID: id, SourceID: cfg.Validator.SourceID, SourceRef: ref(id), ObservedAt: ptr(now)}
		switch id {
		case "native-approval-v1":
			r = approvalRecord(r, nc.Approval, intent, op, g.checkAge(id))
			if nc.Approval != nil && nc.Approval.State == "unavailable" {
				r.SourceID = "fixture:unavailable:approval"
				unavailable = append(unavailable, r.SourceID)
			}
		case "native-delegation-v1":
			r = delegationRecord(r, nc.Delegation, intent, g.principal(), g.checkAge(id))
		case "execution-identity-v1":
			r = executorRecord(r, nc.Executor, cfg.ExecutorClasses, intent, op)
		case "purpose-operation-v1":
			r = purposeRecord(r, cfg.InstalledPurposes(), intent, op)
		case "security-hold-v1":
			r.Result, r.ReasonCode = verdict(adapter.VerdictPass, "")
			if len(nc.SecurityHolds) > 0 {
				r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "SECURITY_HOLD")
			}
		default:
			continue
		}
		out = append(out, r)
	}
	return out, unavailable
}

// checkAge is the source age bound of an installed check: the field rule
// that maps its source, else check_freshness, else 30 seconds
// (spec/v1.0/fixtures/README.md, config.json additions).
func (g *gateway) checkAge(id string) int64 {
	if id == "native-delegation-v1" {
		var c core.RequirementContract
		if json.Unmarshal(g.x.Decoded["contract.json"], &c) == nil {
			for _, r := range c.FieldRules {
				if r.Path == delegationPath && r.Source == core.RuleSourceNative {
					return r.MaxAgeSeconds
				}
			}
		}
	}
	if s, ok := g.x.Config.CheckFreshness[id]; ok {
		return s
	}
	return defaultCheckAge
}

func verdict(v adapter.Verdict, reason string) (string, string) {
	if reason == "" {
		reason = "REQUIREMENT_SATISFIED"
	}
	return string(v), reason
}

func fresh(age int64) *memory.CheckFreshness {
	return &memory.CheckFreshness{MaxAgeSeconds: ptr(age), StatusMaxAgeSeconds: ptr(age)}
}

// approvalRecord maps the native approval state to the result of draft
// 17.3.1. The record applies only to the agent and the principal the
// approval is bound to; for another one the adapter reports a scope
// mismatch.
func approvalRecord(r memory.CheckRecord, a *evalcase.Approval, in core.Intent, op core.OperationContext, age int64) memory.CheckRecord {
	if a == nil {
		r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "MISSING_FIELD")
		return r
	}
	r.Principal, r.AgentID, r.SourceRef = a.PrincipalID, a.AgentID, a.Ref
	if a.StatusCheckedAt != nil {
		r.ObservedAt, r.StatusCheckedAt, r.Freshness = ptr(*a.StatusCheckedAt), ptr(*a.StatusCheckedAt), fresh(age)
	}
	switch {
	case a.PurposeID != in.PurposeID || a.TaskID != in.TaskID || !amountCovered(a.Amount) || !resourcesCovered(a.Resources, op.Resources):
		r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "APPROVAL_SCOPE_MISMATCH")
		return r
	}
	switch a.State {
	case "approved":
		r.Result, r.ReasonCode = verdict(adapter.VerdictPass, "")
		if aa := a.ApproverAuthority; aa != nil && !slices.Contains(aa.ApproverRoles, aa.RequiredRole) {
			r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "APPROVAL_AUTHORITY_MISMATCH")
		}
	case "pending":
		r.Result, r.ReasonCode = verdict(adapter.VerdictUnknown, "APPROVAL_PENDING")
	case "rejected", "expired", "revoked":
		r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "APPROVAL_"+strings.ToUpper(a.State))
	default:
		r.Result, r.ReasonCode = verdict(adapter.VerdictUnknown, "DEPENDENCY_UNAVAILABLE")
	}
	return r
}

func amountCovered(a *evalcase.Amount) bool {
	if a == nil {
		return true
	}
	approved, ok1 := new(big.Rat).SetString(a.Approved)
	requested, ok2 := new(big.Rat).SetString(a.Requested)
	return ok1 && ok2 && requested.Cmp(approved) <= 0
}

func resourcesCovered(approved, requested []string) bool {
	if approved == nil {
		return true
	}
	for _, r := range requested {
		if !slices.Contains(approved, r) {
			return false
		}
	}
	return true
}

// delegationRecord is native-delegation-v1 (draft 17.5): the native
// delegation is in force, for the authenticated principal and the task of
// the intent; its age is bounded like the source of its field rule.
func delegationRecord(r memory.CheckRecord, d *evalcase.Delegation, in core.Intent, p adapter.Principal, age int64) memory.CheckRecord {
	if d == nil {
		r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "MISSING_FIELD")
		return r
	}
	r.SourceRef = d.AuthorityRef
	r.ObservedAt, r.StatusCheckedAt, r.Freshness = ptr(d.ObservedAt), ptr(d.ObservedAt), fresh(age)
	switch {
	case d.State == "revoked":
		r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "REVOKED_EVIDENCE")
	case d.State != "active":
		r.Result, r.ReasonCode = verdict(adapter.VerdictUnknown, "DEPENDENCY_UNAVAILABLE")
	case d.TaskID != in.TaskID:
		r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "TASK_MISMATCH")
	case d.PrincipalID != p.ID:
		r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "CONTEXT_MISMATCH")
	default:
		r.Result, r.ReasonCode = verdict(adapter.VerdictPass, "")
	}
	return r
}

// executorRecord is execution-identity-v1 (draft 17.5): the executor that
// will run the operation is the declared class and binding.
func executorRecord(r memory.CheckRecord, ex *evalcase.Executor, classes []evalcase.ExecutorClass, in core.Intent, op core.OperationContext) memory.CheckRecord {
	if ex == nil {
		r.Result, r.ReasonCode = verdict(adapter.VerdictUnknown, "DEPENDENCY_UNAVAILABLE")
		return r
	}
	for _, c := range classes {
		if c.PrincipalID != op.PrincipalID || c.TaskID != in.TaskID || c.OperationID != op.OperationID {
			continue
		}
		r.Result, r.ReasonCode = verdict(adapter.VerdictPass, "")
		if c.Class != ex.Class || (c.ExecutorID != nil && *c.ExecutorID != ex.PrincipalID) {
			r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "EXECUTOR_MISMATCH")
		}
		return r
	}
	r.Result, r.ReasonCode = verdict(adapter.VerdictUnknown, "UNSUPPORTED_REQUIREMENT")
	return r
}

// purposeRecord is the verdict of purpose-operation-v1 under the installed
// purpose mapping, config.json's purposes (draft 10.1): an unrecognized
// purpose is UNKNOWN UNSUPPORTED_PURPOSE, an action the purpose does not
// cover FAIL CONTEXT_MISMATCH.
func purposeRecord(r memory.CheckRecord, purposes map[string][]string, in core.Intent, op core.OperationContext) memory.CheckRecord {
	actions, ok := purposes[in.PurposeID]
	switch {
	case !ok:
		r.Result, r.ReasonCode = verdict(adapter.VerdictUnknown, "UNSUPPORTED_PURPOSE")
	case !slices.Contains(actions, op.Action):
		r.Result, r.ReasonCode = verdict(adapter.VerdictFail, "CONTEXT_MISMATCH")
	default:
		r.Result, r.ReasonCode = verdict(adapter.VerdictPass, "")
	}
	return r
}

func originOf(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	return memory.NormalizeOrigin(u.Scheme + "://" + u.Host)
}

func ptr[T any](v T) *T { return &v }

// timedNative holds the native reads of a submission until its
// native_reads_at (spec/v1.0/fixtures/README.md, exchange.json): a read issued
// earlier completes then, moving the clock, unless the requestor cancels
// first at cancelled_at.
type timedNative struct {
	inner  *memory.Adapter
	clk    *clock.Fake
	eval   evalcase.Evaluation
	cancel context.CancelFunc
	mu     sync.Mutex
}

func (t *timedNative) wait(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	at := t.eval.NativeReadsAt
	if at == nil || !t.clk.Now().Before(time.Unix(*at, 0)) {
		return ctx.Err()
	}
	if c := t.eval.CancelledAt; c != nil && *c < *at {
		t.clk.Set(time.Unix(*c, 0))
		t.cancel()
		return ctx.Err()
	}
	t.clk.Set(time.Unix(*at, 0))
	return ctx.Err()
}

func (t *timedNative) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, wl adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	return t.inner.ResolveAgentBinding(ctx, realm, wl, agent)
}

func (t *timedNative) ReadNativeClaim(ctx context.Context, path string, c adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := t.wait(ctx); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("read cancelled: %w: %w", adapter.ErrDependencyUnavailable, err)
	}
	return t.inner.ReadNativeClaim(ctx, path, c)
}

func (t *timedNative) CheckContext(ctx context.Context, id string, in adapter.CheckInput) adapter.CheckOutcome {
	if err := t.wait(ctx); err != nil {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable)}
	}
	return t.inner.CheckContext(ctx, id, in)
}

var _ validator.Native = (*timedNative)(nil)
