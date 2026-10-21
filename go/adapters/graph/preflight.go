package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/clock"
)

// AppRole is an entry of the allowlist of GR-18: an app role of a resource
// that the executor application may hold.
type AppRole struct {
	ResourceID string
	AppRoleID  string
}

// RBACRow is one output row of Test-ServicePrincipalAuthorization, each
// member the string the cmdlet prints [M9].
type RBACRow struct {
	RoleName             string `json:"RoleName"`
	GrantedPermissions   string `json:"GrantedPermissions"`
	AllowedResourceScope string `json:"AllowedResourceScope"`
	ScopeType            string `json:"ScopeType"`
	InScope              string `json:"InScope"`
}

// RBACAttestation is the operator-supplied record of one run of
// Test-ServicePrincipalAuthorization -Identity <app> -Resource <mailbox>
// (GR-19). Exchange Online exposes the test as a PowerShell cmdlet only [M9],
// so the preflight reads what the operator recorded; this is the limit the
// profile states for step 2.
type RBACAttestation struct {
	Identity string
	Resource string
	RanAt    time.Time
	Rows     []RBACRow
	// Ref is the opaque reference of the operator's immutable record.
	Ref string
}

// RBACSource gives the latest attestation for an executor application and a
// mailbox.
type RBACSource interface {
	Attestation(ctx context.Context, appID, mailboxID string) (RBACAttestation, error)
}

// ParseAttestation strict-parses the attestation file format: a JSON object
// with identity, resource, ran_at (Unix seconds) and rows.
func ParseAttestation(data []byte) (RBACAttestation, error) {
	var f struct {
		Identity string    `json:"identity"`
		Resource string    `json:"resource"`
		RanAt    *int64    `json:"ran_at"`
		Rows     []RBACRow `json:"rows"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || dec.More() {
		return RBACAttestation{}, errors.New("graph: the RBAC attestation is not a strict JSON object")
	}
	if f.Identity == "" || f.Resource == "" || f.RanAt == nil || f.Rows == nil {
		return RBACAttestation{}, errors.New("graph: the RBAC attestation needs identity, resource, ran_at and rows")
	}
	return RBACAttestation{Identity: f.Identity, Resource: f.Resource, RanAt: time.Unix(*f.RanAt, 0), Rows: f.Rows}, nil
}

// AttestationFile is an [RBACSource] that reads the operator's attestation
// file at Path for each preflight run.
type AttestationFile struct{ Path string }

// Attestation reads and parses the file. Its reference is the path.
func (f AttestationFile) Attestation(context.Context, string, string) (RBACAttestation, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return RBACAttestation{}, fmt.Errorf("graph: the RBAC attestation cannot be read: %w", adapter.ErrDependencyUnavailable)
	}
	att, err := ParseAttestation(data)
	if err != nil {
		return RBACAttestation{}, err
	}
	att.Ref = "file:" + f.Path
	return att, nil
}

// PreflightConfig configures the grant preflight of form A.
type PreflightConfig struct {
	// Auditor is the client credentials acquirer of the auditor identity,
	// which holds Application.Read.All [M7] and is never the executor or
	// the gateway application (GR-17).
	Auditor TokenAcquirer
	// RBAC gives step 2's attestation.
	RBAC RBACSource
	// Allowlist is the allowlist of GR-18. The reference is empty.
	Allowlist []AppRole
	// GraphServicePrincipalID is the object ID of the Microsoft Graph
	// service principal in the tenant; required with a non-empty
	// allowlist, which never names a Graph app role (GR-18, P5).
	GraphServicePrincipalID string
	// Interval is P and SettleWindow is W (GR-20). Zero is the reference.
	Interval, SettleWindow time.Duration
	// OnFailure, when set, receives each run that did not pass: the
	// operator alert of GR-21.
	OnFailure func(PreflightRun)
}

func (c *PreflightConfig) validate(executorApp string) error {
	switch {
	case c == nil:
		return errors.New("graph: form A needs the grant preflight (GR-16)")
	case c.Auditor == nil || c.Auditor.Grant() != GrantClientCredentials || !guidPattern.MatchString(c.Auditor.ClientID()):
		return errors.New("graph: the auditor is a client credentials acquirer (GR-17)")
	case c.Auditor.ClientID() == executorApp:
		return errors.New("graph: the auditor identity is never the executor application (GR-17)")
	case c.RBAC == nil:
		return errors.New("graph: no RBAC attestation source (GR-19)")
	case c.Interval < 0 || c.SettleWindow < 0:
		return errors.New("graph: negative preflight interval or settle window")
	case len(c.Allowlist) > 0 && !guidPattern.MatchString(c.GraphServicePrincipalID):
		return errors.New("graph: an allowlist needs the Graph service principal's object ID (GR-18)")
	}
	for _, e := range c.Allowlist {
		if e.ResourceID == c.GraphServicePrincipalID || e.ResourceID == "" || e.AppRoleID == "" {
			return errors.New("graph: the allowlist never holds a Microsoft Graph app role (GR-18, P5)")
		}
	}
	if c.Interval == 0 {
		c.Interval = DefaultPreflightInterval
	}
	if c.SettleWindow == 0 {
		c.SettleWindow = DefaultSettleWindow
	}
	return nil
}

// PreflightOutcome is the result of one run.
type PreflightOutcome string

const (
	PreflightPass   PreflightOutcome = "PASS"
	PreflightFail   PreflightOutcome = "FAIL"
	PreflightNotRun PreflightOutcome = "NOT_RUN"
)

// PreflightRun is one run of the preflight (GR-20).
type PreflightRun struct {
	// StartedAt is the start of step 1, the observation time of G3.
	StartedAt time.Time
	Outcome   PreflightOutcome
	// Findings say why a run did not pass.
	Findings []string
	// Ref is the opaque reference of the attestation the run read.
	Ref string
}

// preflightHistory keeps what the verdict needs: the latest run and the
// start of the current run of passes.
type preflightHistory struct {
	latest      *PreflightRun
	streakStart time.Time
}

// RunPreflight runs the grant preflight of the executor application once,
// now (GR-18 to GR-20), records the run, and on a run that does not pass
// discards the cached token B and calls OnFailure. A deployment runs it
// every P.
func (a *Adapter) RunPreflight(ctx context.Context) PreflightRun {
	if a.cfg.Form != FormApplication {
		return PreflightRun{StartedAt: a.now(), Outcome: PreflightNotRun, Findings: []string{"form D has no preflight"}}
	}
	run := a.preflight(ctx)
	a.mu.Lock()
	prev := a.runs.latest
	a.runs.latest = &run
	switch {
	case run.Outcome != PreflightPass:
		a.runs.streakStart = time.Time{}
		a.appToken = nil
	case prev == nil || prev.Outcome != PreflightPass || a.runs.streakStart.IsZero():
		a.runs.streakStart = run.StartedAt
	}
	a.mu.Unlock()
	if run.Outcome != PreflightPass && a.cfg.Preflight.OnFailure != nil {
		a.cfg.Preflight.OnFailure(run)
	}
	return run
}

func (a *Adapter) preflight(ctx context.Context) PreflightRun {
	pc := a.cfg.Preflight
	app := a.cfg.Acquirer.ClientID()
	run := PreflightRun{StartedAt: a.now(), Outcome: PreflightPass}
	notRun := func(why string) PreflightRun {
		run.Outcome, run.Findings = PreflightNotRun, append(run.Findings, why)
		return run
	}
	fail := func(why string) {
		run.Outcome, run.Findings = PreflightFail, append(run.Findings, why)
	}
	bs, err := a.bindings(ctx)
	if err != nil {
		return notRun("the executor registry cannot answer")
	}
	var mailboxes []string
	for _, b := range bs {
		if b.Realm == a.cfg.Realm && b.AppID == app && !slices.Contains(mailboxes, b.MailboxID) {
			mailboxes = append(mailboxes, b.MailboxID)
		}
	}
	switch {
	case len(mailboxes) == 0:
		return notRun("the executor application has no binding")
	case len(mailboxes) > 1 || !guidPattern.MatchString(mailboxes[0]):
		fail("the executor application is bound to more than one mailbox, or to none (GR-13, GR-14)")
		return run
	}
	// Step 1: every app role assignment of the executor application is in
	// the allowlist (GR-18).
	assignments, err := a.assignments(ctx, app)
	if err != nil {
		return notRun("step 1: " + err.Error())
	}
	for _, as := range assignments {
		if as.AppRoleID == "" || as.ResourceID == "" {
			fail("step 1: an app role assignment cannot be resolved")
			continue
		}
		if !slices.Contains(pc.Allowlist, AppRole(as)) {
			fail("step 1: app role " + as.AppRoleID + " of resource " + as.ResourceID + " is outside the allowlist")
		}
	}
	// Step 2: the one RBAC row GR-19 admits.
	att, err := pc.RBAC.Attestation(ctx, app, mailboxes[0])
	now := a.now()
	switch {
	case err != nil:
		return notRunUnlessFailed(run, "step 2: no attestation")
	case att.Identity != app || att.Resource != mailboxes[0]:
		return notRunUnlessFailed(run, "step 2: the attestation is for another application or mailbox")
	case att.RanAt.After(now.Add(clock.BaselineSkew)) || now.Sub(att.RanAt) > pc.Interval:
		return notRunUnlessFailed(run, "step 2: the attestation is not from this run's interval")
	}
	run.Ref = att.Ref
	if len(att.Rows) != 1 {
		fail(fmt.Sprintf("step 2: %d RBAC rows, want exactly one", len(att.Rows)))
		return run
	}
	r := att.Rows[0]
	switch {
	case r.RoleName != "Application Mail.Read" || r.GrantedPermissions != "Mail.Read":
		fail("step 2: the RBAC row is not Application Mail.Read with Mail.Read")
	case r.ScopeType == "Organization":
		fail("step 2: a scope of type Organization is in scope for every mailbox")
	case r.ScopeType != "CustomRecipientScope" && r.ScopeType != "AdministrativeUnit":
		fail("step 2: ScopeType " + r.ScopeType + " is not recognized (P9)")
	case r.InScope != "True":
		fail("step 2: InScope is not True")
	}
	return run
}

// notRunUnlessFailed keeps a failure that step 1 found; otherwise the run
// did not complete.
func notRunUnlessFailed(run PreflightRun, why string) PreflightRun {
	run.Findings = append(run.Findings, why)
	if run.Outcome != PreflightFail {
		run.Outcome = PreflightNotRun
	}
	return run
}

// assignment is the part of an appRoleAssignment that step 1 reads [M7].
type assignment struct {
	ResourceID string `json:"resourceId"`
	AppRoleID  string `json:"appRoleId"`
}

// maxPages bounds the pages of step 1.
const maxPages = 100

// assignments reads GET /v1.0/servicePrincipals(appId='{app}')/appRoleAssignments
// under the auditor's token, following every @odata.nextLink of Graph's
// origin until none is returned [M6, M7].
func (a *Adapter) assignments(ctx context.Context, app string) ([]assignment, error) {
	tok, err := a.cfg.Preflight.Auditor.Acquire(ctx, "")
	if err != nil {
		return nil, errors.New("the auditor has no token")
	}
	next := GraphOrigin + "/v1.0/servicePrincipals(appId='" + app + "')/appRoleAssignments"
	var out []assignment
	for page := 0; next != ""; page++ {
		if page == maxPages || !strings.HasPrefix(next, GraphOrigin+"/") {
			return nil, errors.New("the read does not end on Graph's origin")
		}
		var body struct {
			Value    *[]assignment `json:"value"`
			NextLink string        `json:"@odata.nextLink"`
		}
		if err := a.getJSON(ctx, next, tok, &body); err != nil || body.Value == nil {
			return nil, errors.New("the read of app role assignments has no answer")
		}
		out = append(out, *body.Value...)
		next = body.NextLink
	}
	return out, nil
}

// getJSON is a GET with the auditor's token only.
func (a *Adapter) getJSON(ctx context.Context, target string, tok Token, v any) error {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.value)
	req.Header.Set("User-Agent", "")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil || len(raw) > maxAnswer || resp.StatusCode != http.StatusOK {
		return errors.New("no answer")
	}
	return json.Unmarshal(raw, v)
}

// preflightVerdict is GR-21 for the latest run: PASS only when it passed,
// is not older than P, and the passes have lasted W; FAIL with
// EXECUTOR_MISMATCH when it failed; UNKNOWN with DEPENDENCY_UNAVAILABLE
// otherwise.
func (a *Adapter) preflightVerdict() verdict {
	unknown := verdict{adapter.VerdictUnknown, string(adapter.CodeDependencyUnavailable), SourcePreflight}
	a.mu.Lock()
	h := a.runs
	a.mu.Unlock()
	now := a.now()
	switch {
	case h.latest == nil || h.latest.Outcome == PreflightNotRun:
		return unknown
	case h.latest.Outcome == PreflightFail:
		return verdict{adapter.VerdictFail, CodeExecutorMismatch, SourcePreflight}
	case h.latest.StartedAt.After(now.Add(clock.BaselineSkew)) || now.Sub(h.latest.StartedAt) > a.cfg.Preflight.Interval:
		return unknown
	case h.streakStart.IsZero() || now.Sub(h.streakStart) < a.cfg.Preflight.SettleWindow:
		return unknown
	}
	return vPass
}
