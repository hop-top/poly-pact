package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core/clock"
)

// sessionNamePattern is the RoleSessionName constraint of the AWS STS API
// Reference, AssumeRole: 2 to 64 characters of [\w+=,.@-] (AR-7).
var sessionNamePattern = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{2,64}$`)

// roleIDPattern is the form of a role unique ID: the prefix AROA of the IAM
// identifiers page, then upper-case letters and digits.
var roleIDPattern = regexp.MustCompile(`^AROA[A-Z0-9]+$`)

// AuthenticateNative authenticates the caller of the event r carries, from
// requestContext.authorizer.iam alone (AR-5): no header, query parameter or
// body member, and no other authorizer member, is an identity input (AR-6).
//
// The checks run in the order of AR-24. A request without an event did not
// come through API Gateway and is a native denial with NO_CREDENTIAL. An
// event that does not decode, or whose version is not 2.0, is
// [adapter.ErrInvalidMessage]. An event without IAM context is a native
// denial with NO_CREDENTIAL; an authorizer member besides iam, an incomplete
// IAM context, a principal that is not an assumed-role session of the
// configured partition (AR-7), a non-null cognitoIdentity, an account other
// than the API's, a role ID without a role entry, a role name that disagrees
// with the entry, and a session name outside the pattern or the entry's rule
// (AR-8, AR-10) are native denials with CREDENTIAL_REJECTED. A role table
// that cannot answer, and a configuration check that has not passed within
// the interval P or cannot complete (AR-3), are
// [adapter.ErrDependencyUnavailable].
//
// The principal and the workload are aws:{account}:{role-arn}:unreported
// ([WorkloadID]) in the gateway's realm. The session name, the access key,
// the caller ID and the organization never enter it (AR-10, IM-24). The
// attribute [AttrIAM] carries the account, the role ARN and the status time,
// requestContext.timeEpoch in seconds minus the propagation bound L (AR-25).
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	raw, ok := rawEvent(r)
	if !ok {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	ev, err := DecodeEvent(raw, a.cfg.MaxEventBytes)
	if err != nil {
		return adapter.Principal{}, err
	}
	if ev.Version != "2.0" || ev.RequestContext.TimeEpoch <= 0 {
		return adapter.Principal{}, fmt.Errorf("aws: authenticate: not a payload format 2.0 event: %w", adapter.ErrInvalidMessage)
	}
	c, err := iamContext(ev)
	if err != nil {
		return adapter.Principal{}, err
	}
	entry, err := a.caller(ctx, ev, c)
	if err != nil {
		return adapter.Principal{}, err
	}
	if err := a.configurationCheck(ctx); err != nil {
		return adapter.Principal{}, err
	}
	id := WorkloadID(entry.AccountID, entry.RoleARN)
	status := time.UnixMilli(ev.RequestContext.TimeEpoch).Truncate(time.Second).Add(-a.cfg.PropagationBound)
	return adapter.Principal{
		ID:              id,
		Realm:           a.cfg.Realm,
		Workload:        adapter.Workload(id),
		Mechanism:       Mechanism,
		AuthenticatedAt: a.cfg.Clock.Now(),
		Attributes: map[string]any{AttrIAM: map[string]any{
			"account_id":  entry.AccountID,
			"role_arn":    entry.RoleARN,
			"status_time": status.Unix(),
		}},
	}, nil
}

// rejected is the native denial with CREDENTIAL_REJECTED.
func rejected() error { return &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected} }

// caller applies AR-7 to AR-10 to the IAM context and returns the role entry
// of the caller.
func (a *Adapter) caller(ctx context.Context, ev Event, c IAMContext) (RoleEntry, error) {
	if c.AccountID == "" || c.UserArn == "" || c.UserID == "" || !cognitoAbsent(c.CognitoIdentity) {
		return RoleEntry{}, rejected()
	}
	account, roleName, session, ok := a.assumedRole(c.UserArn)
	if !ok || !sessionNamePattern.MatchString(session) {
		return RoleEntry{}, rejected()
	}
	if account != c.AccountID || account != ev.RequestContext.AccountID || account != a.cfg.AccountID {
		return RoleEntry{}, rejected()
	}
	roleID, _, ok := strings.Cut(c.UserID, ":")
	if !ok || !roleIDPattern.MatchString(roleID) {
		return RoleEntry{}, rejected()
	}
	entry, err := a.cfg.Roles.Role(ctx, roleID)
	switch {
	case errors.Is(err, ErrNoRole):
		return RoleEntry{}, rejected()
	case err != nil:
		return RoleEntry{}, fmt.Errorf("aws: authenticate: the role table cannot answer: %w", installed.Dependency(err))
	}
	if entry.RoleID != roleID || entry.AccountID != account || lastSegment(entry.RoleARN) != roleName ||
		!strings.HasPrefix(entry.RoleARN, "arn:"+a.cfg.Partition+":iam::"+account+":role/") {
		return RoleEntry{}, rejected()
	}
	if !entry.SessionName.admits(session) {
		return RoleEntry{}, rejected()
	}
	return entry, nil
}

// assumedRole parses arn:{partition}:sts::{account}:assumed-role/{role-name}/{role-session-name}
// in the configured partition (IAM identifiers page, AR-7). Every other ARN,
// such as an IAM user, the root user or a federated user, is not one.
func (a *Adapter) assumedRole(arn string) (account, roleName, session string, ok bool) {
	rest, found := strings.CutPrefix(arn, "arn:"+a.cfg.Partition+":sts::")
	if !found {
		return "", "", "", false
	}
	account, resource, found := strings.Cut(rest, ":")
	if !found || !accountPattern.MatchString(account) {
		return "", "", "", false
	}
	resource, found = strings.CutPrefix(resource, "assumed-role/")
	if !found {
		return "", "", "", false
	}
	roleName, session, found = strings.Cut(resource, "/")
	if !found || roleName == "" || strings.Contains(session, "/") {
		return "", "", "", false
	}
	return account, roleName, session, true
}

// lastSegment is the role name of a role ARN: the last segment of its
// path-qualified name.
func lastSegment(roleARN string) string {
	i := strings.LastIndex(roleARN, "/")
	if i < 0 {
		return ""
	}
	return roleARN[i+1:]
}

// configurationCheck serves a request only when the last completed check
// passed and is not older than P (AR-3). A failed check is reported as a
// dependency (profile open item O2), so that it fails closed.
func (a *Adapter) configurationCheck(ctx context.Context) error {
	rep, err := a.cfg.ConfigCheck.Last(ctx)
	if err != nil {
		return fmt.Errorf("aws: authenticate: the configuration check cannot complete: %w", installed.Dependency(err))
	}
	now := a.cfg.Clock.Now()
	switch {
	case rep.CompletedAt.IsZero():
		return fmt.Errorf("aws: authenticate: no configuration check has completed: %w", adapter.ErrDependencyUnavailable)
	case !rep.Passed:
		return fmt.Errorf("aws: authenticate: the last configuration check failed: %w", adapter.ErrDependencyUnavailable)
	case rep.CompletedAt.After(now.Add(clock.BaselineSkew)):
		return fmt.Errorf("aws: authenticate: the configuration check reports a time ahead of the clock: %w", adapter.ErrDependencyUnavailable)
	case now.Sub(rep.CompletedAt) > a.cfg.CheckInterval:
		return fmt.Errorf("aws: authenticate: the last configuration check is older than %s: %w", a.cfg.CheckInterval, adapter.ErrDependencyUnavailable)
	}
	return nil
}

// WorkloadID is the identifier of AR-9, the principal and the workload of a
// role: aws:{account}:{role-arn}:unreported, with every octet of the role
// ARN that is not unreserved written as %XX in upper-case hexadecimal
// (identity-mapping IM-2, section 3.3).
func WorkloadID(account, roleARN string) string {
	return "aws:" + account + ":" + escape(roleARN) + ":unreported"
}

// escape writes every octet that is not unreserved (RFC 3986, section 2.3)
// as %XX with upper-case hexadecimal digits.
func escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}
