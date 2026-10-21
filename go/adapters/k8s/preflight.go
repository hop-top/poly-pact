package k8s

import (
	"context"
	"slices"
	"strings"
	"time"
)

// subject is the user a preflight asks about: the user name, uid and groups
// the API server reports for the account (KR-15).
type subject struct {
	user, uid string
	groups    []string
}

func (s subject) key() string {
	return s.user + "\x00" + s.uid + "\x00" + strings.Join(s.groups, "\x00")
}

// preflightResult is a completed preflight of one subject.
type preflightResult struct {
	completedAt time.Time
	passed      bool
}

// forbiddenRow is one access of the forbidden list of KR-14.
type forbiddenRow struct {
	id                               string
	verbs                            []string
	groupResources                   [][2]string
	subresource                      string
	claimedNamespaces, allNamespaces bool
}

// forbidden is the list of KR-14, mapping revision pact-k8s-1.
var forbidden = []forbiddenRow{
	{id: "K-F1", verbs: []string{"get"}, groupResources: [][2]string{{"", "secrets"}}, claimedNamespaces: true, allNamespaces: true},
	{id: "K-F2", verbs: []string{"list", "watch"}, groupResources: [][2]string{{"", "secrets"}}, claimedNamespaces: true, allNamespaces: true},
	{id: "K-F3", verbs: []string{"patch", "update", "create", "delete", "deletecollection"}, groupResources: [][2]string{{"apps", "deployments"}}, claimedNamespaces: true},
	{id: "K-F4", verbs: []string{"list"}, groupResources: [][2]string{{"apps", "deployments"}, {"", "namespaces"}}, allNamespaces: true},
	{id: "K-F5", verbs: []string{"impersonate"}, groupResources: [][2]string{{"", "users"}, {"", "groups"}, {"", "serviceaccounts"}, {"authentication.k8s.io", "uids"}}, allNamespaces: true},
	{id: "K-F6", verbs: []string{"create"}, groupResources: [][2]string{{"", "serviceaccounts"}}, subresource: "token", claimedNamespaces: true, allNamespaces: true},
	{id: "K-F7", verbs: []string{"create"}, groupResources: [][2]string{{"", "pods"}}, claimedNamespaces: true},
	{id: "K-F7a", verbs: []string{"get", "create"}, groupResources: [][2]string{{"", "pods"}}, subresource: "exec", claimedNamespaces: true},
	{id: "K-F8", verbs: []string{"escalate", "bind"}, groupResources: [][2]string{{"rbac.authorization.k8s.io", "roles"}, {"rbac.authorization.k8s.io", "clusterroles"}}, allNamespaces: true},
	{id: "K-F9", verbs: []string{"*"}, groupResources: [][2]string{{"*", "*"}}, allNamespaces: true},
}

// ForbiddenAccesses returns every resource access the preflight asks about
// for the claimed namespaces, in the order of KR-14.
func ForbiddenAccesses(namespaces []string) []ResourceAttributes {
	var out []ResourceAttributes
	for _, row := range forbidden {
		var nss []string
		if row.claimedNamespaces {
			nss = append(nss, namespaces...)
		}
		if row.allNamespaces {
			nss = append(nss, "")
		}
		for _, gr := range row.groupResources {
			for _, verb := range row.verbs {
				for _, ns := range nss {
					out = append(out, ResourceAttributes{Namespace: ns, Verb: verb, Group: gr[0], Resource: gr[1], Subresource: row.subresource})
				}
			}
		}
	}
	return out
}

// preflightOutcome is the result of running a preflight.
type preflightOutcome int

const (
	preflightPassed preflightOutcome = iota
	preflightFailed
	preflightNotEstablished
)

// runPreflight asks the API server about every forbidden access of s
// (KR-14, KR-16): passed when each answer has allowed false and no
// evaluationError; failed when one has allowed true; not established when an
// answer has an evaluationError or a review fails.
func (a *Adapter) runPreflight(ctx context.Context, gw string, s subject) preflightOutcome {
	if s.user == "" || len(s.groups) == 0 {
		// A review without the account's groups is not a preflight (KR-15).
		return preflightNotEstablished
	}
	out := preflightPassed
	for _, ra := range ForbiddenAccesses(a.cfg.Namespaces) {
		st, err := a.api.accessReview(ctx, gw, SubjectAccessReviewSpec{User: s.user, UID: s.uid, Groups: slices.Clone(s.groups), ResourceAttributes: &ra})
		switch {
		case err != nil:
			return preflightNotEstablished
		case st.Allowed:
			out = preflightFailed
		case st.EvaluationError != "":
			if out == preflightPassed {
				out = preflightNotEstablished
			}
		}
	}
	return out
}

// ensurePreflight requires a passing preflight not older than P for the
// gateway account and for the account s (KR-17). A held passing result within
// P is used; otherwise the preflight runs now. A failed or not established
// preflight, and one that cannot run, are errors that wrap
// adapter.ErrDependencyUnavailable: no protected request is served on the
// strength of a stale or incomplete preflight.
func (a *Adapter) ensurePreflight(ctx context.Context, gw string, s subject) error {
	if !a.heldPassing(gatewayKey) {
		info, err := a.api.selfReview(ctx, gw)
		if err != nil {
			return dependency("the gateway account's self-review cannot complete")
		}
		if err := a.preflightOf(ctx, gw, gatewayKey, subject{user: info.Username, uid: info.UID, groups: info.Groups}); err != nil {
			return err
		}
	}
	if a.heldPassing(s.key()) {
		return nil
	}
	return a.preflightOf(ctx, gw, s.key(), s)
}

// gatewayKey holds the gateway account's preflight.
const gatewayKey = "\x00gateway"

func (a *Adapter) heldPassing(key string) bool {
	a.mu.Lock()
	r, ok := a.preflight[key]
	a.mu.Unlock()
	return ok && r.passed && a.cfg.Clock.Now().Sub(r.completedAt) <= a.cfg.PreflightInterval
}

func (a *Adapter) preflightOf(ctx context.Context, gw, key string, s subject) error {
	switch a.runPreflight(ctx, gw, s) {
	case preflightPassed:
		a.mu.Lock()
		a.preflight[key] = preflightResult{completedAt: a.cfg.Clock.Now(), passed: true}
		a.mu.Unlock()
		return nil
	case preflightFailed:
		a.mu.Lock()
		a.preflight[key] = preflightResult{completedAt: a.cfg.Clock.Now()}
		a.mu.Unlock()
		return dependency("the RBAC preflight failed (KR-16)")
	default:
		return dependency("the RBAC preflight is not established (KR-16)")
	}
}

// ResetPreflight forgets every held preflight, as KR-17 requires after a
// change to the registered accounts or the cluster entry.
func (a *Adapter) ResetPreflight() {
	a.mu.Lock()
	clear(a.preflight)
	a.mu.Unlock()
}
