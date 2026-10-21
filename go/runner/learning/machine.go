package learning

import (
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/runner/evalcase"
)

// Time bounds of draft Section 16.5 and Section 14.3.
const (
	maxEventLifetime    int64 = 300
	maxManifestLifetime int64 = 30 * 24 * 3600
	// defaultIngestionWindow is the baseline ingestion window of Section
	// 14.3, used for a report that arrives before any policy.
	defaultIngestionWindow int64 = 7 * 24 * 3600
)

// Msg is a signed message the service has received and whose signature it
// has verified under the trust record of its signer. ArtifactDigest is the
// artifact_digest of the compact JWS (draft Section 7.4), the identity of an
// artifact and of a policy. ReporterRole, set for outcome reports, is the
// report's reporter_role when a trust record of the signer registers it, and
// empty otherwise (Appendix A.2).
type Msg[T any] struct {
	Claims         T
	ArtifactDigest core.Digest
	ReporterRole   string
}

// Rejection is a rejected message: the Section 13.4 code and the Section
// 16.5 reason codes the Problem's extensions.reason_codes lists.
type Rejection struct {
	Code        string
	ReasonCodes []string
}

// Result is the answer to one message: an acknowledgment status, a
// rejection, or neither (an installed policy and an assessment get no
// answer, README section registry.json).
type Result struct {
	Ack       core.AckStatus
	Rejection *Rejection
}

func reject(code string, reasons ...string) Result {
	return Result{Rejection: &Rejection{Code: code, ReasonCodes: reasons}}
}

func ack(s core.AckStatus) Result { return Result{Ack: s} }

// ArtifactState is the lifecycle state of a registered artifact.
type ArtifactState struct {
	Digest core.Digest
	State  core.LifecycleState
}

// ActiveState is the artifact in force in a context, nil for the
// conservative set.
type ActiveState struct {
	Context  core.ReputationContext
	Artifact *core.Digest
}

// State is the registry at a point of a case: the artifacts in registration
// order, one active entry per context an artifact names, in the order the
// contexts first appear, the active security holds and the artifacts whose
// re-evaluation a correction requires.
type State struct {
	Artifacts  []ArtifactState
	Active     []ActiveState
	Holds      []string
	Reevaluate []core.Digest
}

type artifactRec struct {
	digest core.Digest
	claims core.LearningArtifact
	body   core.Digest
	state  core.LifecycleState
	// shadowAt and shadowPolicy are the service time and the policy digest of
	// the accepted SHADOW event. They are read only in the states SHADOW and
	// ACTIVE, which a SHADOW event always precedes.
	shadowAt     int64
	shadowPolicy core.Digest
	reevaluate   bool
}

type reportRec struct {
	task, operation string
	dimension       core.Dimension
	reporter        string
	// registered is false for a report whose reporter_role the trust records
	// do not register for its signer: it is acknowledged and changes nothing
	// (Appendix A.2).
	registered bool
}

// Machine is the reference registry state machine of the learning service:
// it applies the policy, artifacts, events and outcome reports of draft
// Section 16 in order and answers each. It is the oracle against which the
// expected registry of a case and an implementation's output are judged. It
// holds no clock and does no I/O: the caller passes the service time, and
// verifies signatures first.
type Machine struct {
	cfg          evalcase.LearningConfig
	policy       *core.LearningPolicy
	policyDigest core.Digest

	arts     []*artifactRec
	byDigest map[core.Digest]*artifactRec
	byID     map[string]*artifactRec

	ctxs   []core.ReputationContext
	active map[string]core.Digest

	seen    map[string]core.Digest
	reports map[string]*reportRec
	tuples  map[string]bool
	holds   []string
}

// NewMachine returns a machine with no policy, no artifact and the
// conservative set in every context. cfg supplies the service, the clock
// skew, what evaluation references resolve to, the gate observations and the
// source data manifests; its trust records are the caller's.
func NewMachine(cfg evalcase.LearningConfig) *Machine {
	return &Machine{
		cfg: cfg, byDigest: map[core.Digest]*artifactRec{}, byID: map[string]*artifactRec{},
		active: map[string]core.Digest{}, seen: map[string]core.Digest{}, reports: map[string]*reportRec{}, tuples: map[string]bool{},
	}
}

func ctxKey(c core.ReputationContext) string {
	return c.TenantID + "\x00" + c.EnvironmentID + "\x00" + c.AgentID + "\x00" + c.PurposeID + "\x00" + c.ActionClass + "\x00" + c.ResourceClass + "\x00" + c.RuntimeClass
}

func sameDigest(a, b *core.Digest) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// envelope is the claims every signed message shares, as the checks below
// need them.
type envelope struct {
	aud, tenant      string
	iat, nbf, exp    int64
	maxLifetime      int64
	environment      string // empty: not checked
	expectedAudience string
	expectedTenant   string
	expectedEnv      string
}

// check applies the time rules of Sections 7.5 and 16.5 and the context
// rules of Section 13.4: validity longer than allowed or dated in the future
// is INVALID_MESSAGE, an elapsed exp is EXPIRED and another audience, tenant
// or environment is CONTEXT_MISMATCH.
func (m *Machine) check(e envelope, now int64) *Result {
	skew := m.cfg.ClockSkewSeconds
	switch {
	case e.exp-e.iat > e.maxLifetime, e.iat > now+skew, e.nbf > now+skew:
		r := reject(CodeInvalidMessage)
		return &r
	case now >= e.exp:
		r := reject(CodeExpired)
		return &r
	case e.aud != e.expectedAudience, e.tenant != e.expectedTenant, e.environment != "" && e.environment != e.expectedEnv:
		r := reject(CodeContextMismatch)
		return &r
	}
	return nil
}

func (m *Machine) learningEnvelope(aud, tenant, env string, iat, nbf, exp, lifetime int64) envelope {
	s := m.cfg.LearningService
	return envelope{aud: aud, tenant: tenant, iat: iat, nbf: nbf, exp: exp, maxLifetime: lifetime, environment: env,
		expectedAudience: s.ServiceID, expectedTenant: s.TenantID, expectedEnv: s.EnvironmentID}
}

// dedup applies the durable deduplication by (iss, jti) of Section 7.5: an
// identical message is a duplicate, another payload under the same key is
// ID_CONFLICT. It returns nil for a message not seen.
func (m *Machine) dedup(iss, jti string, payload core.Digest) *Result {
	prev, ok := m.seen[iss+"\x00"+jti]
	switch {
	case !ok:
		return nil
	case prev == payload:
		r := ack(core.AckDuplicate)
		return &r
	}
	r := reject(CodeIDConflict)
	return &r
}

func (m *Machine) remember(iss, jti string, payload core.Digest) { m.seen[iss+"\x00"+jti] = payload }

func payloadDigest(v any) core.Digest {
	d, err := digest.ObjectDigest(v)
	if err != nil {
		// A claims struct always encodes to an object.
		panic("learning: " + err.Error())
	}
	return d
}

// InstallPolicy installs a verified policy, which replaces the previous one
// (README section steps.json). A policy that fails the LearningPolicy schema
// of Appendix A.3, such as one without a release gate, is not installed
// (INVALID_MESSAGE). An installed policy gets no answer.
func (m *Machine) InstallPolicy(msg Msg[core.LearningPolicy], now int64) Result {
	p := msg.Claims
	if err := ValidatePolicy(p); err != nil {
		return reject(CodeInvalidMessage)
	}
	s := m.cfg.LearningService
	env := m.learningEnvelope(p.Audience, p.TenantID, p.EnvironmentID, p.IssuedAt, p.NotBefore, p.Expiry, maxManifestLifetime)
	if r := m.check(env, now); r != nil {
		return *r
	}
	if p.Subject != s.EnvironmentID {
		// Appendix A.2: a learning policy's sub is its environment URI.
		return reject(CodeContextMismatch)
	}
	pd := payloadDigest(p)
	if r := m.dedup(p.Issuer, p.JTI, pd); r != nil {
		if r.Ack != "" {
			return Result{}
		}
		return *r
	}
	m.remember(p.Issuer, p.JTI, pd)
	m.policy, m.policyDigest = &p, msg.ArtifactDigest
	return Result{}
}

func (m *Machine) authorized(controller string) bool {
	return m.policy != nil && slices.Contains(m.policy.ControllerIDs, controller)
}

// Register registers a verified manifest (Section 16.3). The artifact enters
// CANDIDATE on acknowledgment.
func (m *Machine) Register(msg Msg[core.LearningArtifact], now int64) Result {
	a := msg.Claims
	if err := ValidateArtifact(a); err != nil {
		return reject(CodeInvalidMessage)
	}
	if r := m.check(m.learningEnvelope(a.Audience, a.TenantID, "", a.IssuedAt, a.NotBefore, a.Expiry, maxManifestLifetime), now); r != nil {
		return *r
	}
	if !m.authorized(a.Issuer) {
		// Section 16.5: no installed policy lists the signer as a controller.
		return reject(CodeLearningRejected, ReasonControllerNotAuthorized)
	}
	pd := payloadDigest(a)
	if r := m.dedup(a.Issuer, a.JTI, pd); r != nil {
		return *r
	}
	body := bodyDigest(a)
	if prev, ok := m.byID[a.ArtifactID+"\x00"+a.Version]; ok {
		if prev.body == body {
			return ack(core.AckDuplicate)
		}
		return reject(CodeIDConflict)
	}
	// Sections 16.3 and 16.5: the outputs stay inside adaptive_fields, and
	// the model type and implementation are ones the policy permits. The
	// codes are listed in the order of the Section 16.5 table.
	var out []string
	for _, c := range a.OutputControls {
		if !slices.ContainsFunc(m.policy.AdaptiveFields, func(f core.AdaptiveControl) bool { return f.ControlID == c }) {
			out = []string{ReasonControlNotAdaptive}
		}
	}
	if !slices.Contains(m.policy.PermittedArtifactTypes, a.ModelType) || !slices.Contains(m.policy.PermittedImplementationIDs, a.ImplementationID) {
		out = append(out, ReasonImplementationNotPermitted)
	}
	if out != nil {
		return reject(CodeLearningRejected, out...)
	}
	rec := &artifactRec{digest: msg.ArtifactDigest, claims: a, body: body, state: core.StateCandidate}
	m.arts = append(m.arts, rec)
	m.byDigest[rec.digest] = rec
	m.byID[a.ArtifactID+"\x00"+a.Version] = rec
	for _, c := range a.IntendedContexts {
		if !slices.ContainsFunc(m.ctxs, func(x core.ReputationContext) bool { return ctxKey(x) == ctxKey(c) }) {
			m.ctxs = append(m.ctxs, c)
		}
	}
	m.remember(a.Issuer, a.JTI, pd)
	return ack(core.AckAccepted)
}

// bodyDigest is the identity of a manifest's content: its object digest
// without the claims that differ between two signings of the same manifest.
func bodyDigest(a core.LearningArtifact) core.Digest {
	a.JTI, a.IssuedAt, a.NotBefore, a.Expiry = "", 0, 0, 0
	return payloadDigest(a)
}

// transitions is the table of draft Section 16.5, by the state the artifact
// is in. An event whose expected_state and transition are not a row of it is
// invalid (Appendix A.2), which ValidateEvent checks.
var transitions = map[core.LifecycleState][]core.Transition{
	core.StateCandidate:  {core.TransitionEvaluated, core.TransitionRetired},
	core.StateEvaluated:  {core.TransitionShadow, core.TransitionRetired},
	core.StateShadow:     {core.TransitionActive, core.TransitionRetired, core.TransitionEvaluated},
	core.StateActive:     {core.TransitionFrozen, core.TransitionRolledBack, core.TransitionRetired},
	core.StateFrozen:     {core.TransitionEvaluated, core.TransitionRetired},
	core.StateRolledBack: {core.TransitionRetired},
}

// activeIn returns the artifact in force in every context of scope; ok is
// false when the contexts disagree.
func (m *Machine) activeIn(scope []core.ReputationContext) (cur *core.Digest, ok bool) {
	for i, c := range scope {
		var d *core.Digest
		if v, has := m.active[ctxKey(c)]; has {
			d = &v
		}
		if i > 0 && !sameDigest(cur, d) {
			return nil, false
		}
		cur = d
	}
	return cur, true
}

func covers(intended, scope []core.ReputationContext) bool {
	return !slices.ContainsFunc(scope, func(s core.ReputationContext) bool {
		return !slices.ContainsFunc(intended, func(i core.ReputationContext) bool { return ctxKey(i) == ctxKey(s) })
	})
}

// Event applies a verified lifecycle event (Sections 16.4 and 16.5). now is
// the service clock of the step. A rejected event changes nothing.
func (m *Machine) Event(msg Msg[core.LearningEvent], now int64) Result {
	e := msg.Claims
	if err := ValidateEvent(e); err != nil {
		return reject(CodeInvalidMessage)
	}
	if r := m.check(m.learningEnvelope(e.Audience, e.TenantID, e.EnvironmentID, e.IssuedAt, e.NotBefore, e.Expiry, maxEventLifetime), now); r != nil {
		return *r
	}
	if !m.authorized(e.Issuer) {
		// Section 16.5: no installed policy lists the signer as a controller.
		return reject(CodeLearningRejected, ReasonControllerNotAuthorized)
	}
	pd := payloadDigest(e)
	if r := m.dedup(e.Issuer, e.JTI, pd); r != nil {
		return *r
	}
	// Compare-and-swap on the policy digest, the expected state and the
	// expected previous artifact (Section 16.5, Appendix A.2): all are
	// verified before the transition is considered. An unregistered artifact
	// is in no expected_state.
	if e.PolicyDigest != m.policyDigest {
		return reject(CodeLearningRejected, ReasonVersionConflict)
	}
	art := m.byDigest[e.ArtifactDigest]
	if art == nil {
		return reject(CodeLearningRejected, ReasonVersionConflict)
	}
	if e.Subject != art.claims.ArtifactID {
		return reject(CodeInvalidMessage)
	}
	cur, consistent := m.activeIn(e.ScopeContexts)
	if art.state != e.ExpectedState || !consistent || !sameDigest(cur, e.ExpectedActiveDigest) {
		return reject(CodeLearningRejected, ReasonVersionConflict)
	}
	// Section 16.5: an event that leaves ACTIVE names every context its
	// artifact is in force in.
	if e.ExpectedState == core.StateActive {
		for k, d := range m.active {
			if d == art.digest && !slices.ContainsFunc(e.ScopeContexts, func(c core.ReputationContext) bool { return ctxKey(c) == k }) {
				return reject(CodeLearningRejected, ReasonVersionConflict)
			}
		}
	}
	reasons := m.gateReasons(art, e, now)
	if len(reasons) > 0 {
		return reject(CodeLearningRejected, reasons...)
	}
	m.apply(art, e, now)
	m.remember(e.Issuer, e.JTI, pd)
	return ack(core.AckAccepted)
}

func (m *Machine) expired(now int64) bool { return now >= m.policy.Expiry }

// gateReasons returns the reason codes that reject the transition, in the
// order of the Section 16.5 table; none when the policy permits it.
func (m *Machine) gateReasons(art *artifactRec, e core.LearningEvent, now int64) []string {
	set := map[string]bool{}
	p := m.policy
	// After the exp of the policy only FROZEN, ROLLED_BACK and RETIRED are
	// accepted.
	if m.expired(now) && !slices.Contains([]core.Transition{core.TransitionFrozen, core.TransitionRolledBack, core.TransitionRetired}, e.Transition) {
		set[ReasonPolicyExpired] = true
	}
	switch e.Transition {
	case core.TransitionEvaluated:
		if r := m.evaluationReason(art, e); r != "" {
			set[r] = true
		}
	case core.TransitionActive:
		if p.Mode == core.LearningObserve {
			set[ReasonObserveMode] = true
		}
		// An artifact awaiting the re-evaluation a correction requires has no
		// evaluation that counts (Section 16.5).
		if art.reevaluate || !m.gatesMet(art, now) {
			set[ReasonGateNotMet] = true
		}
		if !covers(art.claims.IntendedContexts, e.ScopeContexts) {
			set[ReasonContextNotIntended] = true
		}
	case core.TransitionRolledBack:
		if e.ActivateArtifactDigest != nil && !m.compatible(art, *e.ActivateArtifactDigest, e.ScopeContexts, now) {
			set[ReasonFallbackIncompatible] = true
		}
	}
	var out []string
	for _, r := range reasonOrder {
		if set[r] {
			out = append(out, r)
		}
	}
	return out
}

// evaluationReason checks the evaluation evidence of an EVALUATED event
// (Section 16.3): the evaluation must come from an evaluator the policy
// requires, other than the candidate's controller (the manifest's iss) and
// the event's signer.
func (m *Machine) evaluationReason(art *artifactRec, e core.LearningEvent) string {
	own := func(id string) bool { return id == e.Issuer || id == art.claims.Issuer }
	var resolved []string
	for _, ref := range e.EvaluationRefs {
		if ev, ok := m.cfg.Evaluations[ref]; ok {
			resolved = append(resolved, ev.EvaluatorID)
		}
	}
	for _, id := range resolved {
		if !own(id) && slices.Contains(m.policy.EvaluationPolicy.RequiredEvaluatorIDs, id) {
			return ""
		}
	}
	if len(resolved) > 0 && !slices.ContainsFunc(resolved, func(id string) bool { return !own(id) }) {
		return ReasonSelfEvaluated
	}
	return ReasonGateNotMet
}

func (m *Machine) gateFor(a core.LearningArtifact) (evalcase.Gate, bool) {
	for _, g := range m.cfg.Gates {
		if g.ArtifactID == a.ArtifactID && g.Version == a.Version {
			return g, true
		}
	}
	return evalcase.Gate{}, false
}

// gatesMet checks the release gates of Appendix A.2 for a promotion: the
// minimum independent tasks and observation duration, the immutable test
// suites, the metric bounds and the shadow duration.
func (m *Machine) gatesMet(art *artifactRec, now int64) bool {
	ep := m.policy.EvaluationPolicy
	g, ok := m.gateFor(art.claims)
	if !ok {
		return false
	}
	if g.IndependentTasks < ep.MinimumIndependentTasks || g.ObservationSeconds < ep.MinimumObservationSeconds ||
		now-art.shadowAt < ep.MinimumShadowSeconds {
		return false
	}
	for _, d := range ep.ImmutableTestSuiteDigests {
		if !slices.Contains(g.TestSuitesPassed, d) {
			return false
		}
	}
	for name, b := range ep.MetricBounds {
		v, ok := g.Metrics[name]
		if !ok || b.Direction == core.BoundUpper && v > b.Value || b.Direction == core.BoundLower && v < b.Value {
			return false
		}
	}
	return true
}

// compatible reports whether the artifact fb is a compatible rollback
// artifact for out (Section 16.5): the same base_revision and model_type, a
// permitted implementation, a completed shadow phase under the current
// policy digest, and intended contexts that cover the scope. An artifact
// awaiting the re-evaluation a correction requires does not meet condition 3.
func (m *Machine) compatible(out *artifactRec, fb core.Digest, scope []core.ReputationContext, now int64) bool {
	f := m.byDigest[fb]
	if f == nil || f == out || f.reevaluate {
		return false
	}
	return f.claims.BaseRevision == out.claims.BaseRevision && f.claims.ModelType == out.claims.ModelType &&
		slices.Contains(m.policy.PermittedImplementationIDs, f.claims.ImplementationID) &&
		(f.state == core.StateShadow || f.state == core.StateActive) && f.shadowPolicy == m.policyDigest &&
		now-f.shadowAt >= m.policy.EvaluationPolicy.MinimumShadowSeconds &&
		covers(f.claims.IntendedContexts, scope)
}

func (m *Machine) deactivate(art *artifactRec) {
	for k, d := range m.active {
		if d == art.digest {
			delete(m.active, k)
		}
	}
}

func (m *Machine) apply(art *artifactRec, e core.LearningEvent, now int64) {
	switch e.Transition {
	case core.TransitionEvaluated:
		art.state = core.StateEvaluated
		art.reevaluate = false
	case core.TransitionShadow:
		art.state = core.StateShadow
		art.shadowAt, art.shadowPolicy = now, m.policyDigest
	case core.TransitionActive:
		art.state = core.StateActive
		for _, c := range e.ScopeContexts {
			m.active[ctxKey(c)] = art.digest
		}
	case core.TransitionFrozen:
		art.state = core.StateFrozen
		m.deactivate(art)
	case core.TransitionRolledBack:
		art.state = core.StateRolledBack
		m.deactivate(art)
		if e.ActivateArtifactDigest != nil {
			f := m.byDigest[*e.ActivateArtifactDigest]
			f.state = core.StateActive
			for _, c := range e.ScopeContexts {
				m.active[ctxKey(c)] = f.digest
			}
		}
	case core.TransitionRetired:
		art.state = core.StateRetired
		art.reevaluate = false
		m.deactivate(art)
	}
}

// Report applies a verified outcome report as far as the learning service
// is concerned (Sections 14.3, 14.4, 14.6, 15.4 and 16.5): acknowledgment and
// deduplication, security holds, their clearance and the re-evaluation that a
// correction requires. Qualification into reputation is the reputation
// service's, and not modeled.
func (m *Machine) Report(msg Msg[core.OutcomeReport], now int64) Result {
	r := msg.Claims
	if err := ValidateReport(r); err != nil {
		return reject(CodeInvalidMessage)
	}
	rep := m.cfg.ReputationService
	if rep == nil {
		return reject(CodeContextMismatch)
	}
	env := envelope{aud: r.Audience, tenant: r.TenantID, iat: r.IssuedAt, nbf: r.NotBefore, exp: r.Expiry, maxLifetime: maxEventLifetime,
		environment: r.EnvironmentID, expectedAudience: rep.ServiceID, expectedTenant: rep.TenantID, expectedEnv: rep.EnvironmentID}
	if res := m.check(env, now); res != nil {
		return *res
	}
	// Appendix A.2: a report whose reporter_role the receiver has not
	// registered for its signer is acknowledged UNQUALIFIED and changes
	// nothing.
	registered := msg.ReporterRole != "" && msg.ReporterRole == string(r.ReporterRole)
	window := defaultIngestionWindow
	if m.policy != nil {
		window = m.policy.DataPolicy.IngestionWindowSeconds
	}
	if r.ObservedAt > now+m.cfg.ClockSkewSeconds || now-r.ObservedAt > window {
		return reject(CodeInvalidMessage)
	}
	pd := payloadDigest(r)
	if res := m.dedup(r.Issuer, r.JTI, pd); res != nil {
		return *res
	}
	if prev, ok := m.reports["id\x00"+r.EventID]; ok {
		_ = prev
		return reject(CodeIDConflict)
	}
	tuple := r.TaskID + "\x00" + r.OperationID + "\x00" + string(r.EventKind) + "\x00" + string(r.Dimension) + "\x00" + r.Issuer
	m.remember(r.Issuer, r.JTI, pd)
	m.reports["id\x00"+r.EventID] = &reportRec{task: r.TaskID, operation: r.OperationID, dimension: r.Dimension, reporter: r.Issuer, registered: registered}
	if !registered {
		// It casts no vote, so it does not take the tuple of a later
		// registered report either.
		return ack(core.AckAccepted)
	}
	if m.tuples[tuple] {
		return ack(core.AckDuplicate)
	}
	m.tuples[tuple] = true
	switch r.EventKind {
	case core.EventSecurity:
		// A confirmed incident comes from a security authority (Section 14.2).
		if msg.ReporterRole == string(core.ReporterSecurityAuthority) && r.Result == core.OutcomeFailure && !slices.Contains(m.holds, r.EventID) {
			m.holds = append(m.holds, r.EventID)
		}
	case core.EventRemediation:
		if m.policy != nil && slices.Contains(m.policy.HoldClearanceAuthorities, r.Issuer) {
			m.holds = slices.DeleteFunc(m.holds, func(id string) bool { return slices.Contains(r.EvidenceRefs, id) })
		}
	case core.EventCorrection:
		for _, id := range r.Supersedes {
			old := m.reports["id\x00"+id]
			if old == nil || !old.registered || old.task != r.TaskID || old.operation != r.OperationID || old.dimension != r.Dimension ||
				old.reporter != r.Issuer && msg.ReporterRole != string(core.ReporterSecurityAuthority) {
				continue
			}
			m.requireReevaluation(id)
		}
	}
	return ack(core.AckAccepted)
}

// requireReevaluation flags every ACTIVE or SHADOW artifact whose source
// data manifest includes the corrected event (Section 16.5).
func (m *Machine) requireReevaluation(event string) {
	for _, a := range m.arts {
		if a.state != core.StateActive && a.state != core.StateShadow {
			continue
		}
		if slices.Contains(m.cfg.SourceDataManifests[string(a.claims.SourceDataManifestDigest)], event) {
			a.reevaluate = true
		}
	}
}

// Assessment hands the service an LLM assessment (Section 16.6). Its output
// is untrusted data: it is validated against nothing the registry holds and
// changes nothing, and the step gets no answer.
func (m *Machine) Assessment(raw []byte) Result { return Result{} }

// State returns the registry state.
func (m *Machine) State() State {
	var s State
	for _, a := range m.arts {
		s.Artifacts = append(s.Artifacts, ArtifactState{Digest: a.digest, State: a.state})
		if a.reevaluate {
			s.Reevaluate = append(s.Reevaluate, a.digest)
		}
	}
	for _, c := range m.ctxs {
		as := ActiveState{Context: c}
		if d, ok := m.active[ctxKey(c)]; ok {
			as.Artifact = &d
		}
		s.Active = append(s.Active, as)
	}
	s.Holds = slices.Clone(m.holds)
	return s
}
