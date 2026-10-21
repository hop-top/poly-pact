package aws_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapters/aws"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// awsFactory builds the AWS adapter for a case: from the aws/1 state of an
// AWS case or from the common/1 state of a common case. The fixtures realize
// the gateway's configuration and native systems; the adapter is the
// package's.
func awsFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case awsModel:
		w, err := loadWorld(env.State, env.Clock.Now())
		if err != nil {
			return adaptertest.Subject{}, err
		}
		ref, err := memory.New(w.enrollmentState(), env.Clock)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		return worldSubject(w, aws.Config{
			Registry:    referenceRegistry{ref},
			Permissions: commonPolicy{rules: w.st.Policy},
			Clock:       env.Clock,
		})
	case memory.Model:
		return commonSubject(env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// enrollmentState is the common/1 state of the enrollments of an aws/1
// world, for the reference enrollment source.
func (w *world) enrollmentState() memory.State {
	return memory.State{
		Model:              memory.Model,
		Gateway:            w.st.Gateway,
		Enrollments:        w.st.Enrollments,
		UnavailableSources: w.st.UnavailableSources,
	}
}

// defaultExecutionRole is the declared execution role of a state without
// an execution member: the identity the function runs under as well.
func (w *world) defaultExecutionRole() string {
	return "arn:aws:iam::" + w.st.API.AccountID + ":role/service-role/pact-integration"
}

// worldSubject builds the adapter of a world: its configuration, role table,
// configuration check and executor, with the deployment parts of cfg.
func worldSubject(w *world, cfg aws.Config) (adaptertest.Subject, error) {
	cfg.Realm = adapter.Realm{TenantID: w.st.Gateway.TenantID, EnvironmentID: w.st.Gateway.EnvironmentID}
	cfg.Partition = w.st.API.Partition
	cfg.AccountID = w.st.API.AccountID
	cfg.Origin = w.st.Gateway.Origin
	cfg.HeaderAllowlist = w.st.Gateway.HeaderAllowlist
	cfg.CheckInterval = w.interval()
	cfg.PropagationBound = w.propagation()
	if len(w.st.Mappings) > 0 {
		cfg.Mappings = map[string][]aws.Route{}
		for _, m := range w.st.Mappings {
			for _, rt := range m.Routes {
				cfg.Mappings[m.Version] = append(cfg.Mappings[m.Version], aws.Route{
					Route: installed.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource},
					Body:  rt.Body,
				})
			}
		}
	}
	roles := fixtureRoles{down: w.unavailable(srcRoleTable), entries: map[string]aws.RoleEntry{}}
	for _, r := range w.st.Roles {
		roles.entries[r.RoleID] = aws.RoleEntry{
			AccountID: r.AccountID, RoleARN: r.RoleARN, RoleID: r.RoleID,
			SessionName: aws.SessionNameRule{Kind: aws.SessionNameKind(r.SessionName.Rule), Value: r.SessionName.Value},
		}
	}
	cfg.Roles = roles
	check := fixtureCheck{down: w.unavailable(srcConfigCheck)}
	if c := w.st.ConfigurationCheck; c != nil {
		check.report = aws.CheckReport{CompletedAt: time.Unix(c.CompletedAt, 0), Passed: c.Passed, Findings: c.Findings}
	}
	cfg.ConfigCheck = check
	exec := fixtureExecutor{down: w.unavailable(srcExecutor)}
	if e := w.st.Execution; e != nil {
		cfg.ExecutionRoleARN = e.DeclaredRoleARN
		if e.RunningRoleARN != nil {
			exec.running = *e.RunningRoleARN
		}
	} else {
		cfg.ExecutionRoleARN = w.defaultExecutionRole()
		exec.running = cfg.ExecutionRoleARN
	}
	cfg.Executor = exec
	a, err := aws.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{
		Adapter:    a,
		Arrive:     func(r *http.Request) *http.Request { return aws.WithEvent(r, w.mustEvent(r)) },
		Credential: w.Credential,
	}, nil
}

// commonSubject realizes a common/1 state: the identities as role sessions
// of commonWorld, and the claim sources, checks, policy, mappings and signer
// of the state as the deployment's parts.
func commonSubject(env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := commonWorld(st, env.Clock.Now())
	if err != nil {
		return adaptertest.Subject{}, err
	}
	ref, err := memory.New(st, env.Clock)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	claims := map[string]installed.ClaimSource{}
	for _, path := range st.ApprovedPaths {
		claims[path] = commonClaims{st: st}
	}
	checks := map[string]installed.InstalledCheck{}
	for _, c := range st.Checks {
		ic := installed.InstalledCheck{Check: commonCheck{rec: c, down: slices.Contains(st.UnavailableSources, c.SourceID)}, PinnedRevision: c.PinnedRevision}
		if f := c.Freshness; f != nil {
			ic.Freshness = &installed.Freshness{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		}
		checks[c.ID] = ic
	}
	guard := freshness.NewMonotonic(len(st.Sightings) + 4096)
	for _, s := range st.Sightings {
		guard.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: unixTime(s.ObservedAt)})
	}
	return worldSubject(w, aws.Config{
		Registry:         referenceRegistry{ref},
		Claims:           claims,
		Checks:           checks,
		Guard:            guard,
		Permissions:      commonPolicy{rules: st.Policy},
		Reporting:        rp,
		ExecutionVisible: st.Visibility == "execution",
		Clock:            env.Clock,
	})
}

// fixtureRoles is the role table of a world.
type fixtureRoles struct {
	entries map[string]aws.RoleEntry
	down    bool
}

func (t fixtureRoles) Role(_ context.Context, roleID string) (aws.RoleEntry, error) {
	if t.down {
		return aws.RoleEntry{}, fmt.Errorf("the role table cannot answer: %w", adapter.ErrDependencyUnavailable)
	}
	e, ok := t.entries[roleID]
	if !ok {
		return aws.RoleEntry{}, aws.ErrNoRole
	}
	return e, nil
}

// fixtureCheck is the configuration check of a world.
type fixtureCheck struct {
	report aws.CheckReport
	down   bool
}

func (c fixtureCheck) Last(context.Context) (aws.CheckReport, error) {
	if c.down {
		return aws.CheckReport{}, fmt.Errorf("the configuration check cannot complete: %w", adapter.ErrDependencyUnavailable)
	}
	return c.report, nil
}

// fixtureExecutor is the executor source of a world.
type fixtureExecutor struct {
	running string
	down    bool
}

func (e fixtureExecutor) RunningIdentity(context.Context) (string, error) {
	if e.down {
		return "", fmt.Errorf("the executor source cannot answer: %w", adapter.ErrDependencyUnavailable)
	}
	return e.running, nil
}

// referenceRegistry is the enrollment source of the records of a case: the
// lookup of the reference adapter over them, with dedicated workloads.
type referenceRegistry struct{ ref *memory.Adapter }

func (r referenceRegistry) Lookup(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	return r.ref.ResolveAgentBinding(ctx, realm, workload, agent)
}

func (referenceRegistry) Rotate(context.Context, enroll.Actor, string, core.Digest) error {
	return errors.New("the fixture registry is read-only")
}

func (referenceRegistry) MarkCompromised(context.Context, enroll.Actor, string) error {
	return errors.New("the fixture registry is read-only")
}

func unixTime(sec *int64) time.Time {
	if sec == nil {
		return time.Time{}
	}
	return time.Unix(*sec, 0)
}

func reporting(r *memory.Reporting) (*installed.Reporting, error) {
	if r == nil {
		return nil, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &installed.Reporting{Issuer: r.Issuer, Audience: r.Audience, KID: r.KID, Key: key}, nil
}

// commonClaims is the claim source of a common/1 state.
type commonClaims struct{ st memory.State }

func (c commonClaims) Claims(_ context.Context, realm adapter.Realm, principal, path string) ([]installed.ClaimRecord, error) {
	var out []installed.ClaimRecord
	for _, r := range c.st.Claims {
		if r.Path != path || r.Principal != principal || r.Realm.TenantID != realm.TenantID || r.Realm.EnvironmentID != realm.EnvironmentID {
			continue
		}
		if slices.Contains(c.st.UnavailableSources, r.SourceID) {
			return nil, fmt.Errorf("source %s cannot answer: %w", r.SourceID, adapter.ErrDependencyUnavailable)
		}
		var v any
		if err := json.Unmarshal(r.Value, &v); err != nil {
			return nil, err
		}
		out = append(out, installed.ClaimRecord{
			Value: v, Resource: r.Resource, TaskID: r.TaskID,
			ObservedAt: unixTime(r.ObservedAt), StatusCheckedAt: unixTime(r.StatusCheckedAt),
			SourceID: r.SourceID, SourceRef: r.SourceRef,
		})
	}
	return out, nil
}

// commonCheck is an installed check of a common/1 state: its record, with the
// verdict of its native state.
type commonCheck struct {
	rec  memory.CheckRecord
	down bool
}

func (c commonCheck) Consult(_ context.Context, in adapter.CheckInput) (installed.CheckRecord, error) {
	if !c.rec.Applies(in) {
		return installed.CheckRecord{Result: adapter.VerdictFail, ReasonCode: memory.CodeApprovalScopeMismatch, SourceID: c.rec.SourceID}, nil
	}
	if c.down {
		return installed.CheckRecord{SourceID: c.rec.SourceID}, fmt.Errorf("source %s cannot answer: %w", c.rec.SourceID, adapter.ErrDependencyUnavailable)
	}
	return installed.CheckRecord{
		Result: adapter.Verdict(c.rec.Result), ReasonCode: c.rec.ReasonCode,
		SourceID: c.rec.SourceID, SourceRef: c.rec.SourceRef,
		ObservedAt: unixTime(c.rec.ObservedAt), StatusCheckedAt: unixTime(c.rec.StatusCheckedAt),
		Revision: c.rec.Revision,
	}, nil
}

// commonPolicy is the native policy of a state: the rules that name the
// principal in its realm and the action, and the resource when they name
// one, apply; a deny wins over an unknown and an unknown over an allow; no
// rule is a deny of the policy's own source.
type commonPolicy struct{ rules []memory.PolicyRule }

const ownPolicySource = "native-policy"

func (c commonPolicy) Decide(_ context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	rank := map[string]int{"DENY": 3, "UNKNOWN": 2, "ALLOW": 1}
	var best *memory.PolicyRule
	for i := range c.rules {
		r := &c.rules[i]
		if r.Principal != p.ID || r.Realm.TenantID != p.Realm.TenantID || r.Realm.EnvironmentID != p.Realm.EnvironmentID ||
			r.Action != op.Action || (r.Resource != "" && !slices.Contains(op.Resources, r.Resource)) {
			continue
		}
		if best == nil || rank[r.Effect] > rank[best.Effect] {
			best = r
		}
	}
	if best == nil {
		return adapter.Decision{Effect: adapter.EffectDeny, Reason: "no rule allows this principal", SourceID: ownPolicySource}, nil
	}
	d := adapter.Decision{
		Effect: adapter.Effect(best.Effect), Reason: best.Reason, SourceID: best.SourceID,
		SourceRef: best.SourceRef, DecidedAt: unixTime(best.DecidedAt), PolicyRevision: best.PolicyRevision,
	}
	if d.SourceID == "" {
		d.SourceID = ownPolicySource
	}
	for _, o := range best.Obligations {
		d.Obligations = append(d.Obligations, adapter.Obligation{ID: o.ID, Attributes: o.Attributes})
	}
	return d, nil
}

// fixedClock is a clock for unit tests.
func fixedClock(sec int64) clock.Clock { return clock.NewFake(time.Unix(sec, 0)) }
