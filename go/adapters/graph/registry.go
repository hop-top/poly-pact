package graph

import (
	"context"
	"fmt"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// ExecutorBinding is a record of the executor registry: the executor of one
// mapping row (GR-1, GR-13, GR-14). It changes only through the gateway's
// administrative controls.
type ExecutorBinding struct {
	Realm adapter.Realm
	Row   Row
	// Workload is the workload principal a form A binding is registered
	// for. A form D binding names none: it acts for the authenticated user.
	Workload string
	// Class is the executor identity class of draft 17.5.
	Class string
	// Grant is the token request of the executor.
	Grant Grant
	// AppID and ServicePrincipalID name the application that acts
	// downstream.
	AppID              string
	ServicePrincipalID string
	// MailboxID is the registered mailbox of a form A binding, the
	// directory object ID of its user; empty in form D.
	MailboxID string
	// Ref is the opaque reference of the binding record.
	Ref string
	// ChangedAt is the time of the record's last change.
	ChangedAt time.Time
}

// ExecutorRegistry is the executor registry (G1). It is read whole for each
// evaluation, so that a binding that shares an application or a mailbox with
// another workload's is seen (GR-13).
type ExecutorRegistry interface {
	// Bindings returns every binding of realm; an error means the registry
	// cannot answer.
	Bindings(ctx context.Context, realm adapter.Realm) ([]ExecutorBinding, error)
}

// verdict is what the identity check found.
type verdict struct {
	result adapter.Verdict
	code   string
	source string
}

var (
	vPass        = verdict{adapter.VerdictPass, installed.CodeRequirementSatisfied, SourceExecutorRegistry}
	vMismatch    = verdict{adapter.VerdictFail, CodeExecutorMismatch, SourceExecutorRegistry}
	vNoBinding   = verdict{adapter.VerdictUnknown, string(adapter.CodeDependencyUnavailable), SourceExecutorRegistry}
	vUnsupported = verdict{adapter.VerdictUnknown, string(adapter.CodeUnsupportedRequirement), SourceExecutorRegistry}
)

// bindings reads the registry.
func (a *Adapter) bindings(ctx context.Context) ([]ExecutorBinding, error) {
	bs, err := a.cfg.Registry.Bindings(ctx, a.cfg.Realm)
	if err != nil {
		return nil, fmt.Errorf("graph: the executor registry cannot answer: %w", adapter.ErrDependencyUnavailable)
	}
	for _, b := range bs {
		if err := installed.SourceTimes(a.cfg.Clock.Now(), b.ChangedAt); err != nil {
			return nil, fmt.Errorf("graph: executor registry: %w", err)
		}
	}
	return bs, nil
}

// binding selects the binding of row for principal and judges it under
// GR-13, GR-14 and GR-26, without the preflight. A binding that is absent is
// vNoBinding; one that is not the declared binding is vMismatch.
func (a *Adapter) binding(bs []ExecutorBinding, row Row, principal string) (ExecutorBinding, verdict) {
	var cand []ExecutorBinding
	for _, b := range bs {
		if b.Realm != a.cfg.Realm || b.Row != row {
			continue
		}
		if a.cfg.Form == FormDelegated || b.Workload == principal {
			cand = append(cand, b)
		}
	}
	switch len(cand) {
	case 0:
		return ExecutorBinding{}, vNoBinding
	case 1:
	default:
		return cand[0], vMismatch
	}
	b := cand[0]
	if b.Class != a.class() || b.Grant != a.grant() || b.AppID != a.cfg.Acquirer.ClientID() || b.Ref == "" {
		return b, vMismatch
	}
	if a.cfg.Form == FormDelegated {
		if b.Workload != "" || b.MailboxID != "" {
			return b, vMismatch
		}
		return b, vPass
	}
	if !guidPattern.MatchString(b.MailboxID) {
		return b, vMismatch
	}
	for _, o := range bs {
		if o.Realm == b.Realm && o.Workload != b.Workload && (o.AppID == b.AppID || o.MailboxID == b.MailboxID) {
			return b, vMismatch
		}
	}
	return b, vPass
}

// mailboxOf is the registered mailbox of a workload, from the binding of
// row, or false when the workload has no usable binding.
func (a *Adapter) mailboxOf(bs []ExecutorBinding, row Row, workload string) (string, bool) {
	b, v := a.binding(bs, row, workload)
	return b.MailboxID, v == vPass
}

// identity is execution-identity-v1 for op (GR-26): the binding of the
// operation's row and principal, and in form A the latest preflight (GR-21).
func (a *Adapter) identity(ctx context.Context, op core.OperationContext) (ExecutorBinding, verdict, error) {
	if op.EnvironmentID != a.cfg.Realm.EnvironmentID || op.Action != ActionMailList {
		return ExecutorBinding{}, verdict{adapter.VerdictFail, string(adapter.CodeContextMismatch), SourceExecutorRegistry}, nil
	}
	row, ok := a.rowOf(op.TargetURI)
	if !ok {
		return ExecutorBinding{}, vUnsupported, nil
	}
	bs, err := a.bindings(ctx)
	if err != nil {
		return ExecutorBinding{}, verdict{}, err
	}
	b, v := a.binding(bs, row, op.PrincipalID)
	if v != vPass {
		return b, v, nil
	}
	resource := "mailbox:" + op.PrincipalID
	if a.cfg.Form == FormApplication {
		resource = "mailbox:" + b.MailboxID
	}
	if !slices.Equal(op.Resources, []string{resource}) {
		return b, vMismatch, nil
	}
	if a.cfg.Form == FormApplication {
		if pv := a.preflightVerdict(); pv != vPass {
			return b, pv, nil
		}
	}
	return b, vPass, nil
}

// identityCheck is execution-identity-v1 as an installed check.
type identityCheck struct{ a *Adapter }

func (c identityCheck) Consult(ctx context.Context, in adapter.CheckInput) (installed.CheckRecord, error) {
	b, v, err := c.a.identity(ctx, in.Operation)
	if err != nil {
		return installed.CheckRecord{SourceID: SourceExecutorRegistry}, err
	}
	rec := installed.CheckRecord{Result: v.result, ReasonCode: v.code, SourceID: v.source}
	if v.source == SourceExecutorRegistry && b.Ref != "" {
		rec.SourceRef, rec.ObservedAt = b.Ref, b.ChangedAt
	}
	return rec, nil
}

// claim answers PathExecutionAppID for a form A principal (GR-32): the
// executor identifier of the workload's GA1 binding, observed at its last
// change and status-checked at the read.
func (a *Adapter) claim(ctx context.Context, principal string) (adapter.NativeClaim, error) {
	if a.cfg.Form != FormApplication {
		return adapter.NativeClaim{}, fmt.Errorf("graph: %s has no value on a form D row (GR-32): %w", PathExecutionAppID, adapter.ErrUnsupportedRequirement)
	}
	bs, err := a.bindings(ctx)
	if err != nil {
		return adapter.NativeClaim{}, err
	}
	b, v := a.binding(bs, RowGA1, principal)
	switch v {
	case vPass:
	case vNoBinding:
		return adapter.NativeClaim{}, fmt.Errorf("graph: the workload has no executor binding: %w", adapter.ErrUnsupportedRequirement)
	default:
		return adapter.NativeClaim{}, fmt.Errorf("graph: the workload's executor binding is a configuration error (GR-13): %w", adapter.ErrUnsupportedRequirement)
	}
	return adapter.NativeClaim{
		Value: a.ExecutorID(b.AppID), ObservedAt: b.ChangedAt, StatusCheckedAt: a.cfg.Clock.Now(),
		SourceID: SourceExecutorRegistry, SourceRef: b.Ref,
	}, nil
}
