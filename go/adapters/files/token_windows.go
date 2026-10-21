//go:build windows

package files

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// winToken is an access token handle with what the broker reads from it once.
type winToken struct {
	t      windows.Token
	user   string
	groups []string
	level  Level
	ref    string
}

// tokenStatistics is TOKEN_STATISTICS, member for member as the TOKEN_STATISTICS
// page declares it.
type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

// The group attributes the TOKEN_GROUPS page defines that the broker reads:
// a group is reported only when it is enabled for access checks, and never
// when it is a logon SID or a mandatory integrity SID.
const (
	groupEnabled   = 0x00000004
	groupLogonID   = 0xC0000000
	groupIntegrity = 0x00000020
)

// newWinToken reads the user, the enabled groups and the statistics of t. It
// takes ownership of t, and closes it when it fails. The impersonation level
// is read from the statistics, where the TOKEN_STATISTICS page says it is
// valid only for an impersonation token; a primary token gets LevelAnonymous, so that it is never
// impersonated (profile IA-6). Which kind QuerySecurityContextToken returns
// for a Negotiate context is open item OI-2.
func newWinToken(t windows.Token) (tok Token, err error) {
	defer func() {
		if err != nil {
			_ = t.Close()
		}
	}()
	u, err := t.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("files: token user: %w", err)
	}
	g, err := t.GetTokenGroups()
	if err != nil {
		return nil, fmt.Errorf("files: token groups: %w", err)
	}
	var st tokenStatistics
	var n uint32
	if err := windows.GetTokenInformation(t, windows.TokenStatistics, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &n); err != nil {
		return nil, fmt.Errorf("files: token statistics: %w", err)
	}
	wt := &winToken{t: t, user: u.User.Sid.String(), level: LevelAnonymous,
		ref: fmt.Sprintf("logon:%08x%08x/token:%08x%08x", uint32(st.AuthenticationID.HighPart), st.AuthenticationID.LowPart,
			uint32(st.TokenID.HighPart), st.TokenID.LowPart)}
	if st.TokenType == windows.TokenImpersonation && st.ImpersonationLevel <= uint32(LevelDelegation) {
		wt.level = Level(st.ImpersonationLevel)
	}
	for _, sa := range g.AllGroups() {
		if sa.Attributes&groupEnabled == 0 || sa.Attributes&groupLogonID == groupLogonID || sa.Attributes&groupIntegrity != 0 {
			continue
		}
		wt.groups = append(wt.groups, sa.Sid.String())
	}
	return wt, nil
}

func (t *winToken) User() string { return t.user }
func (t *winToken) Groups() []string {
	return append([]string(nil), t.groups...)
}
func (t *winToken) Level() Level { return t.level }
func (t *winToken) Ref() string  { return t.ref }
func (t *winToken) Close() error { return t.t.Close() }
