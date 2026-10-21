package ldap

import (
	"strconv"
	"strings"
	"time"
)

// The values of /principal/account_state (profile LR-20).
const (
	StateActive                 = "active"
	StateDisabled               = "disabled"
	StateLocked                 = "locked"
	StateExpired                = "expired"
	StatePasswordChangeRequired = "password_change_required"
	StateAbsent                 = "absent"
)

// The attributes of the OpenLDAP map: the password policy overlay's
// operational attributes (slapo-ppolicy(5); profile LR-22).
var openLDAPStateAttrs = []string{"pwdAccountLockedTime", "pwdReset", "pwdStartTime", "pwdEndTime"}

// The attributes of the Active Directory map (profile LR-21).
var adStateAttrs = []string{"userAccountControl", "msDS-User-Account-Control-Computed", "accountExpires", "pwdLastSet"}

// permanentLock is the pwdAccountLockedTime value of an account that "has been
// permanently locked and may only be unlocked by an administrator"
// (slapo-ppolicy(5)).
const permanentLock = "000001010000Z"

// The bits of the Active Directory map (profile LR-21).
const (
	uacAccountDisable    = 0x00000002
	uacDontExpirePasswd  = 0x00010000
	uacComputedLockout   = 0x00000010
	uacComputedPwExpired = 0x00800000
	accountNeverExpires  = 0x7FFFFFFFFFFFFFFF
)

func (r *realm) stateAttrs() []string {
	if r.Kind == KindActiveDirectory {
		return adStateAttrs
	}
	return openLDAPStateAttrs
}

// accountState maps the state attributes of e at the as-of instant to a value
// of LR-20: the first of disabled, locked, expired and
// password_change_required that applies, and active only when every rule is a
// definite negative (LR-23). An attribute that does not parse is an outage.
func (r *realm) accountState(e Entry, asOf time.Time) (string, error) {
	if r.Kind == KindActiveDirectory {
		return adState(e, asOf)
	}
	return openLDAPState(e, asOf)
}

// openLDAPState is the map pact-ldap-state-openldap-1 (LR-22). An attribute
// of the overlay that is absent is not set: the sentinel of the same read
// showed each of them, so the lookup account can read them (LR-14), and
// slapo-ppolicy(5) says of pwdStartTime that "if this attribute does not
// exist, then no restriction applies". Each is single-valued; two values do
// not parse.
func openLDAPState(e Entry, asOf time.Time) (string, error) {
	one := func(attr string) (string, bool, error) {
		v := e.Values(attr)
		switch len(v) {
		case 0:
			return "", false, nil
		case 1:
			return string(v[0]), true, nil
		}
		return "", false, outage("read claim", "a state attribute has more than one value")
	}
	locked, hasLock, err := one("pwdAccountLockedTime")
	if err != nil {
		return "", err
	}
	if hasLock {
		if locked == permanentLock {
			return StateDisabled, nil
		}
		return StateLocked, nil
	}
	for _, attr := range []string{"pwdEndTime", "pwdStartTime"} {
		v, ok, err := one(attr)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		t, err := parseGeneralizedTime(v)
		if err != nil {
			return "", outage("read claim", "a state attribute does not parse")
		}
		if attr == "pwdEndTime" && !t.After(asOf) || attr == "pwdStartTime" && t.After(asOf) {
			return StateExpired, nil
		}
	}
	reset, ok, err := one("pwdReset")
	if err != nil {
		return "", err
	}
	if ok {
		switch reset {
		case "TRUE":
			return StatePasswordChangeRequired, nil
		case "FALSE":
		default:
			return "", outage("read claim", "a state attribute does not parse")
		}
	}
	return StateActive, nil
}

// adState is the map pact-ldap-state-ad-1 (LR-21). Every attribute must be
// returned with one integer value.
func adState(e Entry, asOf time.Time) (string, error) {
	n := map[string]int64{}
	for _, attr := range adStateAttrs {
		v := e.Values(attr)
		if len(v) != 1 {
			return "", outage("read claim", "a state attribute is missing")
		}
		x, err := strconv.ParseInt(string(v[0]), 10, 64)
		if err != nil {
			return "", outage("read claim", "a state attribute does not parse")
		}
		n[attr] = x
	}
	uac, computed := n["userAccountControl"], n["msDS-User-Account-Control-Computed"]
	switch {
	case uac&uacAccountDisable != 0:
		return StateDisabled, nil
	case computed&uacComputedLockout != 0:
		return StateLocked, nil
	}
	if exp := n["accountExpires"]; exp != 0 && exp != accountNeverExpires && !fileTime(exp).After(asOf) {
		return StateExpired, nil
	}
	if n["pwdLastSet"] == 0 && uac&uacDontExpirePasswd == 0 || computed&uacComputedPwExpired != 0 {
		return StatePasswordChangeRequired, nil
	}
	return StateActive, nil
}

// fileTime converts a count of 100-nanosecond intervals since 1601-01-01 UTC
// (profile LR-21, accountExpires) to a time.
func fileTime(n int64) time.Time {
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	return time.Unix(epoch+n/10_000_000, n%10_000_000*100).UTC()
}

// parseGeneralizedTime parses the GeneralizedTime syntax of RFC 4517,
// section 3.3.13: century, year, month, day and hour, optional minute and
// second, an optional fraction, and Z or a differential.
func parseGeneralizedTime(s string) (time.Time, error) {
	digits := 0
	for digits < len(s) && s[digits] >= '0' && s[digits] <= '9' {
		digits++
	}
	var layout string
	switch digits {
	case 10:
		layout = "2006010215"
	case 12:
		layout = "200601021504"
	case 14:
		layout = "20060102150405"
	default:
		return time.Time{}, strconv.ErrSyntax
	}
	rest := s[digits:]
	frac := ""
	if strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, ",") {
		i := 1
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 1 {
			return time.Time{}, strconv.ErrSyntax
		}
		frac, rest = "."+rest[1:i], rest[i:]
	}
	t, err := time.Parse(layout, s[:digits])
	if err != nil {
		return time.Time{}, err
	}
	if frac != "" {
		f, err := strconv.ParseFloat("0"+frac, 64)
		if err != nil {
			return time.Time{}, err
		}
		unit := time.Hour
		switch digits {
		case 12:
			unit = time.Minute
		case 14:
			unit = time.Second
		}
		t = t.Add(time.Duration(f * float64(unit)))
	}
	switch {
	case rest == "Z":
		return t, nil
	case len(rest) == 3 || len(rest) == 5:
		sign := 1
		switch rest[0] {
		case '+':
		case '-':
			sign = -1
		default:
			return time.Time{}, strconv.ErrSyntax
		}
		hh, err := strconv.Atoi(rest[1:3])
		if err != nil || hh > 23 {
			return time.Time{}, strconv.ErrSyntax
		}
		mm := 0
		if len(rest) == 5 {
			if mm, err = strconv.Atoi(rest[3:5]); err != nil || mm > 59 {
				return time.Time{}, strconv.ErrSyntax
			}
		}
		off := time.Duration(sign) * (time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute)
		return t.Add(-off), nil
	}
	return time.Time{}, strconv.ErrSyntax
}
