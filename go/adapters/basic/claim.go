package basic

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
)

// ClaimSource is the source of an approved native path other than those the
// account database answers.
type ClaimSource = installed.ClaimSource

// ClaimRecord is one value of a [ClaimSource].
type ClaimRecord = installed.ClaimRecord

// ReadNativeClaim reads the value at nativePath for the claim context.
//
// [PathPrincipalID] and [PathPrincipalRoles] are facts of the principal and
// come from the account database: the principal ID of the account, and the
// native roles of the account through [Config.RoleMap], in the order the
// database gives them, without the roles the map does not name. Nothing the
// principal or the request asserts is a role. Both carry the database's own
// answer time as ObservedAt and StatusCheckedAt, and no SourceRef. Another
// path is read from its source in [Config.Claims]; a path with none is
// [adapter.ErrUnsupportedRequirement]. A source time later than now plus the
// skew, and a source that cannot answer, are
// [adapter.ErrDependencyUnavailable].
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	switch nativePath {
	case PathPrincipalID, PathPrincipalRoles:
		return a.accountClaim(ctx, nativePath, cc.Principal)
	}
	src, ok := a.cfg.Claims[nativePath]
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("basic: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.cfg.Clock.Now())
	if err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("basic: read claim: %w", err)
	}
	return c, nil
}

// accountClaim reads an approved path of the account database.
func (a *Adapter) accountClaim(ctx context.Context, path string, p adapter.Principal) (adapter.NativeClaim, error) {
	acct, err := a.cfg.Accounts.ByPrincipal(ctx, p.Realm, p.ID)
	switch {
	case errors.Is(err, ErrNoAccount):
		return adapter.NativeClaim{}, fmt.Errorf("basic: read claim: %w", err)
	case err != nil:
		return adapter.NativeClaim{}, dependency("read claim", err)
	}
	if err := a.checkSourceTimes("read claim", acct.AnsweredAt); err != nil {
		return adapter.NativeClaim{}, err
	}
	claim := adapter.NativeClaim{
		ObservedAt:      acct.AnsweredAt,
		StatusCheckedAt: acct.AnsweredAt,
		SourceID:        a.cfg.Accounts.SourceID(),
	}
	if path == PathPrincipalID {
		claim.Value = acct.Principal
	} else {
		claim.Value = a.translate(acct.Roles)
	}
	return claim, nil
}

// translate maps native role names to PACT role names through the approved
// translation, keeping the database's order and dropping duplicates and the
// roles the translation does not name (draft 8.4, 17.2).
func (a *Adapter) translate(native []string) []any {
	out := []any{}
	for _, n := range native {
		pact, ok := a.cfg.RoleMap[n]
		if !ok || pact == "" || slices.Contains(out, any(pact)) {
			continue
		}
		out = append(out, pact)
	}
	return out
}
