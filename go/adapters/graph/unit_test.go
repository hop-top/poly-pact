package graph_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/oauth"
	"hop.top/pact-go/core"
)

// The gateway targets of the rows (profile section 2).
var (
	targetGD1 = uOrigin + "/mail/messages?" + fixedQuery
	targetGA1 = uOrigin + "/mailbox/messages?" + fixedQuery
)

func bg() context.Context { return context.Background() }

// delegatedRequest is a GD1 or GD2 request carrying token A, marked as
// having come through the enforcement point.
func delegatedRequest(target, tokenA string, extra map[string]string) *http.Request {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tokenA)
	for k, v := range extra {
		h.Set(k, v)
	}
	return oauth.Mark(gatewayRequest(target, h))
}

// runDelegated authenticates, maps and executes one form D request.
func runDelegated(b broker, target, tokenA, task string, extra map[string]string) (core.OperationContext, execution, error) {
	r := delegatedRequest(target, tokenA, extra)
	p, err := b.AuthenticateNative(bg(), r)
	if err != nil {
		return core.OperationContext{}, execution{}, fmt.Errorf("authenticate: %w", err)
	}
	op, err := b.MapOperation(bg(), delegatedRequest(target, tokenA, extra), p, revision)
	if err != nil {
		return core.OperationContext{}, execution{}, fmt.Errorf("map: %w", err)
	}
	return op, b.execute(bg(), execInput{req: delegatedRequest(target, tokenA, extra), principal: p, op: op, task: task, agent: uAgent}), nil
}

// runApplication maps and executes one form A request.
func runApplication(b broker, target string, extra map[string]string) (core.OperationContext, execution, error) {
	h := http.Header{}
	for k, v := range extra {
		h.Set(k, v)
	}
	p := workloadPrincipal()
	op, err := b.MapOperation(bg(), gatewayRequest(target, h.Clone()), p, revision)
	if err != nil {
		return core.OperationContext{}, execution{}, fmt.Errorf("map: %w", err)
	}
	return op, b.execute(bg(), execInput{req: gatewayRequest(target, h.Clone()), principal: p, op: op, task: uTask, agent: uAgent}), nil
}

// rbacOK is the attestation of the one RBAC row GR-19 admits.
func rbacOK(at int64) *attestation {
	return &attestation{Identity: uExecApp, Resource: uMailbox, RanAt: at, Rows: []rbacRow{{
		RoleName: "Application Mail.Read", GrantedPermissions: "Mail.Read", AllowedResourceScope: "Mail Digest Mailboxes",
		ScopeType: "CustomRecipientScope", InScope: "True",
	}}}
}

// preflightAt runs the broker's preflight with the clock at sec, step 1
// answering pages and step 2 the attestation att, and puts the clock back.
func preflightAt(w *unitWorld, b broker, sec int64, pages [][]map[string]any, att *attestation) {
	back := w.clk.Now()
	w.clk.Set(time.Unix(sec, 0))
	w.cloud.mu.Lock()
	w.cloud.pages = pages
	w.cloud.mu.Unlock()
	w.attest = att
	b.preflight(bg())
	w.clk.Set(back)
}

// settle runs passing preflights 7300 s and 100 s before now.
func settle(w *unitWorld, b broker) {
	now := w.clk.Now().Unix()
	preflightAt(w, b, now-7300, [][]map[string]any{{}}, rbacOK(now-7300))
	preflightAt(w, b, now-100, [][]map[string]any{{}}, rbacOK(now-100))
}

// grants counts the executor token calls by grant type.
func grants(w *unitWorld) (obo, cc int) {
	for _, c := range w.cloud.executorTokens() {
		switch c.GrantType {
		case grantOBO:
			obo++
		case grantCC:
			cc++
		}
	}
	return obo, cc
}

// checkNoFallback requires no client credentials request and no Graph call.
func checkNoFallback(f *failures, w *unitWorld) {
	if _, cc := grants(w); cc != 0 {
		f.add("%d client credentials requests after the OBO failure; the executor must never fall back (GR-11)", cc)
	}
	if n := len(w.cloud.graph()); n != 0 {
		f.add("%d Graph requests; want none (GR-11)", n)
	}
}

// checkDenialReport requires the AUTHORIZATION FAILURE none report of GR-30.
func checkDenialReport(f *failures, ex execution) {
	if ex.report == nil {
		f.add("no outcome report; want AUTHORIZATION FAILURE none (GR-30)")
		return
	}
	if ex.report.kind != core.EventAuthorization || ex.report.result != core.OutcomeFailure || ex.report.dimension != core.DimensionNone {
		f.add("report %s/%s/%s, want AUTHORIZATION/FAILURE/none (GR-30)", ex.report.kind, ex.report.result, ex.report.dimension)
	}
}

// checkNoSecret requires that no token or credential appears in what the
// execution returned (GR-31).
func checkNoSecret(f *failures, ex execution, values ...string) {
	var b strings.Builder
	b.WriteString(ex.wwwAuthenticate + "|" + ex.retryAfter + "|" + ex.pageToken)
	if ex.err != nil {
		b.WriteString("|" + ex.err.Error())
	}
	if ex.report != nil {
		b.WriteString("|" + ex.report.details + "|" + strings.Join(ex.report.evidence, "|"))
	}
	text := b.String()
	for _, v := range append(values, secrets...) {
		if v != "" && strings.Contains(text, v) {
			f.add("a credential appears in the execution's answer, error or report (GR-31)")
		}
	}
}

func oboError(status int, body map[string]any) func(tokenCall) *tokenAnswer {
	return func(c tokenCall) *tokenAnswer {
		if c.GrantType == grantOBO {
			return &tokenAnswer{Status: status, Body: body}
		}
		return nil
	}
}

func oboScope(set bool, scope string) func(tokenCall) *tokenAnswer {
	return func(c tokenCall) *tokenAnswer {
		if c.GrantType != grantOBO {
			return nil
		}
		body := map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": "graph-token-b-scoped-" + strings.Repeat("y", 16)}
		if set {
			body["scope"] = scope
		}
		return &tokenAnswer{Status: 200, Body: body}
	}
}

var claimsChallenge = `{"access_token":{"polids":{"essential":true,"values":["00aa00aa-bb11-cc22-dd33-44ee44ee44ee"]}}}`

// delegatedFailure runs GD1 against a token endpoint that answers the OBO
// request with status and body, and checks what GR-10 and GR-11 require of
// every failed exchange.
func delegatedFailure(t testing.TB, mk brokerFactory, script func(tokenCall) *tokenAnswer, wantStatus int, report bool) (execution, []string) {
	var f failures
	w := newUnitWorld(t, formDelegated)
	b := build(t, mk, w, &f)
	if b == nil {
		return execution{}, f
	}
	w.cloud.onToken = script
	tokenA := w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now())
	_, ex, err := runDelegated(b, targetGD1, tokenA, uTask, nil)
	if err != nil {
		f.add("%v", err)
		return ex, f
	}
	if ex.err == nil {
		f.add("executed after a failed OBO exchange")
	}
	if ex.status != wantStatus {
		f.add("gateway answer %d, want %d", ex.status, wantStatus)
	}
	checkNoFallback(&f, w)
	if obo, _ := grants(w); obo != 1 {
		f.add("%d OBO requests, want exactly one: no retry (GR-10, GR-11)", obo)
	}
	if report {
		checkDenialReport(&f, ex)
	} else if ex.report != nil && ex.report.result == core.OutcomeSuccess {
		f.add("a SUCCESS report after a failed exchange (GR-30)")
	}
	checkNoSecret(&f, ex, tokenA, claimsChallenge)
	return ex, f
}

var unitCases = []unitCase{
	{"GRAPH-03.graph-token", func(t testing.TB, mk brokerFactory) []string {
		// A token for Microsoft Graph sent as token A is refused by the
		// OAuth profile and never used as an OBO assertion (GR-5).
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		graphToken := w.cloud.tokenA(graphOrigin, "uti-graph", w.clk.Now())
		if _, err := b.AuthenticateNative(bg(), delegatedRequest(targetGD1, graphToken, nil)); err == nil {
			f.add("a token whose audience is Microsoft Graph authenticated")
		}
		// An executor handed the request anyway, mapped for the user,
		// refuses it before any token request.
		op, err := b.MapOperation(bg(), delegatedRequest(targetGD1, graphToken, nil), userPrincipal(), revision)
		if err != nil {
			return append(f, fmt.Sprintf("map: %v", err))
		}
		ex := b.execute(bg(), execInput{req: delegatedRequest(targetGD1, graphToken, nil), principal: userPrincipal(), op: op, task: uTask, agent: uAgent})
		if ex.err == nil {
			f.add("the executor ran a request whose token A does not authenticate")
		}
		if n := len(w.cloud.executorTokens()); n != 0 {
			f.add("%d token requests; the Graph token was sent as an assertion (GR-5)", n)
		}
		if n := len(w.cloud.graph()); n != 0 {
			f.add("%d Graph requests; want none", n)
		}
		return f
	}},
	{"GRAPH-04.interaction-required", func(t testing.TB, mk brokerFactory) []string {
		ex, f := delegatedFailure(t, mk, oboError(400, map[string]any{
			"error": "interaction_required", "error_description": "AADSTS50079: multifactor authentication required.",
			"error_codes": []int{50079}, "claims": claimsChallenge,
		}), http.StatusUnauthorized, true)
		want := `claims="` + base64.StdEncoding.EncodeToString([]byte(claimsChallenge)) + `"`
		if !strings.HasPrefix(ex.wwwAuthenticate, "Bearer ") || !strings.Contains(ex.wwwAuthenticate, `error="insufficient_claims"`) || !strings.Contains(ex.wwwAuthenticate, want) {
			f = append(f, fmt.Sprintf("WWW-Authenticate %q does not carry the claims challenge (GR-10)", ex.wwwAuthenticate))
		}
		return f
	}},
	{"GRAPH-04.interaction-no-claims", func(t testing.TB, mk brokerFactory) []string {
		ex, f := delegatedFailure(t, mk, oboError(400, map[string]any{"error": "interaction_required", "error_codes": []int{50076}}), http.StatusUnauthorized, true)
		if !strings.HasPrefix(ex.wwwAuthenticate, "Bearer ") || !strings.Contains(ex.wwwAuthenticate, `error="interaction_required"`) {
			f = append(f, fmt.Sprintf("WWW-Authenticate %q does not carry the error (GR-10)", ex.wwwAuthenticate))
		}
		return f
	}},
	{"GRAPH-05.consent-withdrawn", func(t testing.TB, mk brokerFactory) []string {
		_, f := delegatedFailure(t, mk, oboError(400, map[string]any{
			"error": "invalid_grant", "error_description": "AADSTS65001: The user or administrator has not consented to use the application.",
			"error_codes": []int{65001},
		}), http.StatusForbidden, true)
		return f
	}},
	{"GRAPH-05.user-disabled", func(t testing.TB, mk brokerFactory) []string {
		_, f := delegatedFailure(t, mk, oboError(400, map[string]any{"error": "invalid_grant", "error_codes": []int{50057}}), http.StatusForbidden, true)
		return f
	}},
	{"GRAPH-05.endpoint-unavailable", func(t testing.TB, mk brokerFactory) []string {
		_, f := delegatedFailure(t, mk, oboError(503, map[string]any{"error": "temporarily_unavailable"}), http.StatusServiceUnavailable, false)
		return f
	}},
	{"GRAPH-06.no-token-reuse", func(t testing.TB, mk brokerFactory) []string {
		// One exchange per operation, from that operation's own token A
		// (GR-7).
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		tokA1 := w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now())
		tokA2 := w.cloud.tokenA(uGatewayApp, "uti-0002", w.clk.Now())
		for _, tok := range []string{tokA1, tokA2} {
			if _, ex, err := runDelegated(b, targetGD1, tok, uTask, nil); err != nil || ex.err != nil {
				f.add("GD1: %v %v", err, ex.err)
			}
		}
		calls := w.cloud.executorTokens()
		if len(calls) != 2 || calls[0].Assertion != tokA1 || calls[1].Assertion != tokA2 {
			f.add("%d token requests; want one OBO request per operation with that operation's token A", len(calls))
		}
		g := w.cloud.graph()
		if len(g) != 2 || g[0].Authorization == g[1].Authorization {
			f.add("token B reused across operations (GR-7)")
		}
		return f
	}},
	{"GRAPH-06.obo-request", func(t testing.TB, mk brokerFactory) []string {
		// The OBO request of GR-6, by the gateway application, and nothing
		// else.
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		tokA := w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now())
		w.cloud.onToken = oboError(400, map[string]any{"error": "invalid_grant", "error_codes": []int{65001}})
		_, _, _ = runDelegated(b, targetGD1, tokA, uTask, nil)
		w.cloud.onToken = nil
		if _, ex, err := runDelegated(b, targetGD1, tokA, uTask, nil); err != nil || ex.err != nil {
			f.add("GD1: %v %v", err, ex.err)
		}
		for i, c := range w.cloud.executorTokens() {
			if c.Tenant != uTID || c.GrantType != grantOBO || c.RequestedTokenUse != "on_behalf_of" || c.ClientID != uGatewayApp || c.Scope != scopeMail || c.Assertion != tokA {
				f.add("token request %d: grant %q use %q client %q scope %q; want the OBO request of GR-6 only", i, c.GrantType, c.RequestedTokenUse, c.ClientID, c.Scope)
			}
		}
		return f
	}},
	{"GRAPH-07.scope-lacks-mail-read", func(t testing.TB, mk brokerFactory) []string {
		_, f := delegatedFailure(t, mk, oboScope(true, "https://graph.microsoft.com/User.Read"), http.StatusForbidden, true)
		return f
	}},
	{"GRAPH-07.scope-adds-readwrite", func(t testing.TB, mk brokerFactory) []string {
		_, f := delegatedFailure(t, mk, oboScope(true, "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite"), http.StatusForbidden, true)
		return f
	}},
	{"GRAPH-07.no-scope", func(t testing.TB, mk brokerFactory) []string {
		_, f := delegatedFailure(t, mk, oboScope(false, ""), http.StatusForbidden, true)
		return f
	}},
	{"GRAPH-08.graph-refuses", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		w.cloud.onGraph = func(graphCall) *graphAnswer {
			return &graphAnswer{Status: 403, Body: map[string]any{"error": map[string]any{"code": "ErrorAccessDenied"}}}
		}
		_, ex, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
		if err != nil {
			return append(f, err.Error())
		}
		if ex.err == nil || ex.status != http.StatusForbidden {
			f.add("Graph's refusal answered %d, want 403, final (GR-3)", ex.status)
		}
		if obo, cc := grants(w); obo != 1 || cc != 0 {
			f.add("%d OBO and %d client credentials requests; want one OBO request and no other credential (GR-11)", obo, cc)
		}
		if n := len(w.cloud.graph()); n != 1 {
			f.add("%d Graph requests; want one, no retry (GR-25)", n)
		}
		checkDenialReport(&f, ex)
		return f
	}},
	{"GRAPH-08.token-a-not-forwarded", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		tokA := w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now())
		_, ex, err := runDelegated(b, targetGD1, tokA, uTask, map[string]string{"X-Mailbox": uOtherMailbox, "Cookie": "session=abcdef0123", "Accept": "application/json"})
		if err != nil || ex.err != nil {
			return append(f, fmt.Sprintf("GD1: %v %v", err, ex.err))
		}
		g := w.cloud.graph()
		if len(g) != 1 {
			return append(f, fmt.Sprintf("%d Graph requests, want one", len(g)))
		}
		bearer := strings.TrimPrefix(g[0].Authorization, "Bearer ")
		if bearer == tokA {
			f.add("token A was sent to Graph (GR-8, RB-51)")
		}
		if who, ok := w.cloud.issuedTo(bearer); !ok || !strings.HasPrefix(who, uGatewayApp+"|"+grantOBO) {
			f.add("Graph received a bearer that is not the OBO token B of this operation")
		}
		if g[0].Path != "/v1.0/me/messages" || g[0].RawQuery != fixedQuery {
			f.add("downstream %s?%s, want /v1.0/me/messages?%s (section 2)", g[0].Path, g[0].RawQuery, fixedQuery)
		}
		for name := range g[0].Header {
			switch http.CanonicalHeaderKey(name) {
			case "Authorization", "Accept-Encoding", "User-Agent", "Connection":
			default:
				f.add("downstream header %s; only the executor's Authorization is sent (GR-25, RB-51)", name)
			}
		}
		checkNoSecret(&f, ex, tokA, bearer)
		return f
	}},
	{"GRAPH-09.other-task", func(t testing.TB, mk brokerFactory) []string {
		return continuationRefused(t, mk, "native-task:another-task", uAgent)
	}},
	{"GRAPH-09.other-agent", func(t testing.TB, mk brokerFactory) []string {
		return continuationRefused(t, mk, uTask, "https://agents.northwind.example/other-assistant")
	}},
	{"GRAPH-10.next-page", func(t testing.TB, mk brokerFactory) []string {
		// A next page is its own operation: a new OBO exchange and the
		// recorded link sent unchanged (GR-24, RB-56, RB-59).
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		w.cloud.onGraph = func(c graphCall) *graphAnswer {
			return &graphAnswer{Status: 200, Body: messagesPage(c.Path, c.RawQuery == fixedQuery)}
		}
		op1, ex1, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
		if err != nil || ex1.err != nil {
			return append(f, fmt.Sprintf("GD1: %v %v", err, ex1.err))
		}
		if len(ex1.pageToken) < 22 || len(ex1.pageToken) > 128 || strings.ContainsAny(ex1.pageToken, "+/=.~") {
			f.add("page token %q is not in the grammar of page_token (section 2)", ex1.pageToken)
		}
		if strings.Contains(ex1.pageToken, "skip") {
			f.add("the page token exposes the downstream link")
		}
		op2, ex2, err := runDelegated(b, uOrigin+"/mail/messages?page_token="+ex1.pageToken, w.cloud.tokenA(uGatewayApp, "uti-0002", w.clk.Now()), uTask, nil)
		if err != nil || ex2.err != nil {
			return append(f, fmt.Sprintf("GD2: %v %v", err, ex2.err))
		}
		if op1.OperationID == op2.OperationID {
			f.add("the second page has the first page's operation id; a receipt for one page would admit the other (RB-56)")
		}
		g := w.cloud.graph()
		if len(g) != 2 || g[1].Path != "/v1.0/me/messages" || g[1].RawQuery != fixedQuery+"&$skip=10" {
			f.add("the second Graph request is not the recorded link unchanged (RB-59)")
		}
		if obo, _ := grants(w); obo != 2 {
			f.add("%d OBO requests for two pages; want one per page (GR-7)", obo)
		}
		return f
	}},
	{"GRAPH-10.link-other-host", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		w.cloud.onGraph = func(c graphCall) *graphAnswer {
			page := messagesPage(c.Path, false)
			page["@odata.nextLink"] = "https://graph.microsoft.com.example/v1.0/me/messages?$select=id,subject,body&$top=10&$skip=10"
			return &graphAnswer{Status: 200, Body: page}
		}
		_, ex1, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
		if err != nil || ex1.err != nil {
			return append(f, fmt.Sprintf("GD1: %v %v", err, ex1.err))
		}
		if ex1.pageToken == "" {
			return append(f, "no page token: a continuation is recorded (RB-57) and refused only when followed (RB-58)")
		}
		_, ex2, err := runDelegated(b, uOrigin+"/mail/messages?page_token="+ex1.pageToken, w.cloud.tokenA(uGatewayApp, "uti-0002", w.clk.Now()), uTask, nil)
		if err == nil && ex2.err == nil {
			f.add("a continuation to graph.microsoft.com.example was followed (GR-24)")
		}
		if n := len(w.cloud.graph()); n != 1 {
			f.add("%d Graph requests; the second page must not be requested", n)
		}
		return f
	}},
	{"GRAPH-11.app-only-path", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formApplication)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		settle(w, b)
		_, ex, err := runApplication(b, targetGA1, nil)
		if err != nil || ex.err != nil {
			return append(f, fmt.Sprintf("GA1: %v %v", err, ex.err))
		}
		for _, c := range w.cloud.executorTokens() {
			if c.GrantType != grantCC || c.ClientID != uExecApp || c.Scope != scopeDefault || c.Assertion != "" {
				f.add("token request grant %q client %q scope %q; want the client credentials request of GR-15", c.GrantType, c.ClientID, c.Scope)
			}
		}
		for _, g := range w.cloud.graph() {
			if strings.HasPrefix(g.Path, "/v1.0/me/") || g.Path != "/v1.0/users/"+uMailbox+"/messages" || g.RawQuery != fixedQuery {
				f.add("downstream %s?%s; want only the registered mailbox, never /me (GR-14, GR-22)", g.Path, g.RawQuery)
			}
		}
		return f
	}},
	{"GRAPH-12.header-mailbox", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formApplication)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		settle(w, b)
		_, ex, err := runApplication(b, targetGA1, map[string]string{"X-Mailbox": uOtherMailbox})
		if err != nil || ex.err != nil {
			return append(f, fmt.Sprintf("GA1: %v %v", err, ex.err))
		}
		for _, g := range w.cloud.graph() {
			if g.Path != "/v1.0/users/"+uMailbox+"/messages" || len(g.Header.Values("X-Mailbox")) != 0 {
				f.add("downstream %s; a header changed the mailbox or was forwarded (GR-14)", g.Path)
			}
		}
		return f
	}},
	{"GRAPH-14.preflight-fails", func(t testing.TB, mk brokerFactory) []string {
		// A parallel grant found by a preflight stops form A at once and
		// discards the cached token B (GR-20, GR-21).
		var f failures
		w := newUnitWorld(t, formApplication)
		w.cloud.tokenLifetime = 86400
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		settle(w, b)
		if _, ex, err := runApplication(b, targetGA1, nil); err != nil || ex.err != nil {
			return append(f, fmt.Sprintf("GA1 before the grant: %v %v", err, ex.err))
		}
		grant := map[string]any{"appRoleId": "11111111-aaaa-4bbb-8ccc-000000000001", "resourceId": "c0ffee00-1111-4222-8333-444455556666",
			"resourceDisplayName": "Microsoft Graph", "principalId": uExecSP, "principalType": "ServicePrincipal"}
		preflightAt(w, b, uNow, [][]map[string]any{{grant}}, rbacOK(uNow))
		_, ex, err := runApplication(b, targetGA1, nil)
		if err != nil {
			f.add("GA1 after the grant: %v", err)
		} else if ex.err == nil || !ex.mismatch {
			f.add("GA1 after a failed preflight: err %v mismatch %v; want EXECUTOR_MISMATCH (GR-21)", ex.err, ex.mismatch)
		}
		if n := len(w.cloud.graph()); n != 1 {
			f.add("%d Graph requests; none after the failed preflight", n)
		}
		// Remediated and settled again: the old token B is gone.
		for _, at := range []int64{uNow + 300, uNow + 3900, uNow + 7500} {
			preflightAt(w, b, at, [][]map[string]any{{}}, rbacOK(at))
		}
		w.clk.Set(time.Unix(uNow+7600, 0))
		if _, ex, err := runApplication(b, targetGA1, nil); err != nil || ex.err != nil {
			f.add("GA1 after remediation: %v %v", err, ex.err)
		}
		if _, cc := grants(w); cc != 2 {
			f.add("%d client credentials requests; the token B cached before the failed preflight was used again (GR-20 b)", cc)
		}
		return f
	}},
	{"GRAPH-16.no-preflight", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formApplication)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		_, ex, err := runApplication(b, targetGA1, nil)
		if err == nil && (ex.err == nil || ex.status != http.StatusServiceUnavailable) {
			f.add("GA1 without a preflight answered %d; want 503, DEFERRED (GR-21)", ex.status)
		}
		if n := len(w.cloud.executorTokens()); n != 0 {
			f.add("%d token requests without a preflight", n)
		}
		if n := len(w.cloud.graph()); n != 0 {
			f.add("%d Graph requests without a preflight", n)
		}
		return f
	}},
	{"GRAPH-17.app-graph-refuses", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formApplication)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		settle(w, b)
		w.cloud.onGraph = func(graphCall) *graphAnswer {
			return &graphAnswer{Status: 403, Body: map[string]any{"error": map[string]any{"code": "ErrorAccessDenied"}}}
		}
		_, ex, err := runApplication(b, targetGA1, nil)
		if err != nil {
			return append(f, err.Error())
		}
		if ex.err == nil || ex.status != http.StatusForbidden {
			f.add("Graph's refusal answered %d, want 403, final", ex.status)
		}
		for _, c := range w.cloud.executorTokens() {
			if c.ClientID != uExecApp || c.GrantType != grantCC {
				f.add("token request of %s by %s; no other credential after a refusal (GR-11)", c.ClientID, c.GrantType)
			}
		}
		if n := len(w.cloud.graph()); n != 1 {
			f.add("%d Graph requests; want one, no retry", n)
		}
		checkDenialReport(&f, ex)
		return f
	}},
	{"GRAPH-20.both-actors", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		tokA := w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now())
		op, ex, err := runDelegated(b, targetGD1, tokA, uTask, nil)
		if err != nil || ex.err != nil {
			return append(f, fmt.Sprintf("GD1: %v %v", err, ex.err))
		}
		checkSuccessReport(&f, ex, uUser, "delegated-user", uGatewayApp, false)
		var page []json.RawMessage
		if json.Unmarshal(ex.messages, &page) != nil || len(page) != 2 {
			f.add("messages %s; want the two messages of the page", ex.messages)
		}
		out := b.CheckContext(bg(), checkID, adapter.CheckInput{Intent: core.Intent{TaskID: uTask}, Operation: op})
		if out.Result != adapter.VerdictPass || out.SourceID != sourceRegistry || out.SourceRef != "executor-registry:gd1:r7" {
			f.add("execution-identity-v1 %s source %q ref %q; want PASS from the executor registry with the binding record (GR-26)", out.Result, out.SourceID, out.SourceRef)
		}
		var bearer string
		if g := w.cloud.graph(); len(g) == 1 {
			bearer = strings.TrimPrefix(g[0].Authorization, "Bearer ")
		}
		checkNoSecret(&f, ex, tokA, bearer)
		return f
	}},
	{"GRAPH-20.empty-page", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		w.cloud.onGraph = func(graphCall) *graphAnswer {
			return &graphAnswer{Status: 200, Header: map[string]string{"request-id": "94fb3b52-452a-4535-a601-69e0a90e3aa2"}, Body: map[string]any{"value": []any{}}}
		}
		_, ex, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
		if err != nil || ex.err != nil {
			return append(f, fmt.Sprintf("GD1: %v %v", err, ex.err))
		}
		checkSuccessReport(&f, ex, uUser, "delegated-user", uGatewayApp, true)
		return f
	}},
	{"GRAPH-20.app-actors", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formApplication)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		settle(w, b)
		_, ex, err := runApplication(b, targetGA1, nil)
		if err != nil || ex.err != nil {
			return append(f, fmt.Sprintf("GA1: %v %v", err, ex.err))
		}
		checkSuccessReport(&f, ex, uWorkload, "registered-app-executor", uExecApp, false)
		checkNoSecret(&f, ex)
		return f
	}},
	{"GRAPH-22.throttled", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		w.cloud.onGraph = func(graphCall) *graphAnswer {
			return &graphAnswer{Status: 429, Header: map[string]string{"Retry-After": "10"}, Body: map[string]any{"error": map[string]any{"code": "TooManyRequests"}}}
		}
		_, ex, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
		if err != nil {
			return append(f, err.Error())
		}
		if ex.err == nil || ex.status != http.StatusServiceUnavailable || ex.retryAfter != "10" {
			f.add("429 answered %d Retry-After %q; want 503 with Retry-After 10 (GR-25)", ex.status, ex.retryAfter)
		}
		if n := len(w.cloud.graph()); n != 1 {
			f.add("%d Graph requests; one attempt per operation (GR-25)", n)
		}
		if ex.report != nil && ex.report.result == core.OutcomeSuccess {
			f.add("a SUCCESS report for a throttled operation (GR-30)")
		}
		return f
	}},
	{"GRAPH-22.registry-unavailable", func(t testing.TB, mk brokerFactory) []string {
		var f failures
		w := newUnitWorld(t, formDelegated)
		b := build(t, mk, w, &f)
		if b == nil {
			return f
		}
		tokA := w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now())
		r := delegatedRequest(targetGD1, tokA, nil)
		p := userPrincipal()
		op, err := b.MapOperation(bg(), r, p, revision)
		if err != nil {
			return append(f, err.Error())
		}
		w.registryDown = true
		ex := b.execute(bg(), execInput{req: delegatedRequest(targetGD1, tokA, nil), principal: p, op: op, task: uTask, agent: uAgent})
		if ex.err == nil || ex.status != http.StatusServiceUnavailable {
			f.add("execution with the registry down answered %d; want 503, DEFERRED (GR-26)", ex.status)
		}
		if n := len(w.cloud.executorTokens()); n != 0 {
			f.add("%d token requests with the registry down", n)
		}
		return f
	}},
}

// continuationRefused executes GD1, then GD2 with its page token under
// another task or agent, which RB-58 refuses with CONTEXT_MISMATCH.
func continuationRefused(t testing.TB, mk brokerFactory, task, agent string) []string {
	var f failures
	w := newUnitWorld(t, formDelegated)
	b := build(t, mk, w, &f)
	if b == nil {
		return f
	}
	w.cloud.onGraph = func(c graphCall) *graphAnswer {
		return &graphAnswer{Status: 200, Body: messagesPage(c.Path, true)}
	}
	_, ex1, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
	if err != nil || ex1.err != nil || ex1.pageToken == "" {
		return append(f, fmt.Sprintf("GD1: %v %v, page token %q", err, ex1.err, ex1.pageToken))
	}
	tokA := w.cloud.tokenA(uGatewayApp, "uti-0002", w.clk.Now())
	target := uOrigin + "/mail/messages?page_token=" + ex1.pageToken
	r := delegatedRequest(target, tokA, nil)
	p, err := b.AuthenticateNative(bg(), r)
	if err != nil {
		return append(f, err.Error())
	}
	op, err := b.MapOperation(bg(), delegatedRequest(target, tokA, nil), p, revision)
	if err != nil {
		return append(f, fmt.Sprintf("map GD2: %v", err))
	}
	ex := b.execute(bg(), execInput{req: delegatedRequest(target, tokA, nil), principal: p, op: op, task: task, agent: agent})
	if ex.err == nil || ex.code != adapter.CodeContextMismatch {
		f.add("a continuation of another task or agent: err %v code %q; want CONTEXT_MISMATCH (RB-58)", ex.err, ex.code)
	}
	if n := len(w.cloud.graph()); n != 1 {
		f.add("%d Graph requests; the second page must not be requested", n)
	}
	if obo, _ := grants(w); obo != 1 {
		f.add("%d OBO requests; none for a refused continuation", obo)
	}
	return f
}

// checkSuccessReport requires the EXECUTION SUCCESS reliability report of
// GR-30 that names both actors (GR-29); details is "empty" for an empty page
// (draft 14.5), and the actors are then in the executor record.
func checkSuccessReport(f *failures, ex execution, original, class, app string, empty bool) {
	if ex.report == nil {
		f.add("no outcome report for a completed page (GR-30)")
		return
	}
	r := ex.report
	if r.kind != core.EventExecution || r.result != core.OutcomeSuccess || r.dimension != core.DimensionReliability {
		f.add("report %s/%s/%s, want EXECUTION/SUCCESS/reliability (GR-30)", r.kind, r.result, r.dimension)
	}
	executor := oauth.Identifier(uIssuer, uTID, app)
	if empty {
		if r.details != "empty" {
			f.add("details %q for an empty page, want \"empty\" (draft 14.5)", r.details)
		}
	} else if !strings.Contains(r.details, original) || !strings.Contains(r.details, class) || !strings.Contains(r.details, executor) {
		f.add("details %q do not name the original actor %s and the downstream actor %s %s (GR-29)", r.details, original, class, executor)
	}
	if len(r.evidence) != 1 || !strings.Contains(r.evidence[0], "94fb3b52-452a-4535-a601-69e0a90e3aa2") || !strings.Contains(r.evidence[0], app) {
		f.add("evidence_refs %v do not reference the executor record with Graph's request-id (GR-29)", r.evidence)
	}
}
