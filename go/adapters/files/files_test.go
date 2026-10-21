package files_test

import (
	"strings"
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
)

// replaced are the common cases that a file broker cannot realize, each with
// the files case that shows the same property (profile section 10, "Replaced
// common cases"). The authenticate_native cases expect a principal or a
// denial reason that a Negotiate exchange cannot give: IA-8 derives the
// principal from the token's user SID. The authorize_native cases expect a
// decision member that the native open cannot carry: the access check answers
// allowed or denied, with no obligation, decision record, decision time or
// policy revision.
var replaced = map[string]adaptertest.Replacement{
	"COMMON-01.credential-wins": {
		By:     "FILES-12.identity-headers-ignored",
		Reason: "expects https://idp.acme.example/bob; IA-8 derives files:{domain-sid}:{user-sid} from the token of the completed exchange",
	},
	"COMMON-02.via-enforcement-point": {
		By:     "FILES-12.completed-exchange",
		Reason: "expects https://idp.acme.example/alice; IA-8 derives files:{domain-sid}:{user-sid} from the token of the completed exchange",
	},
	"COMMON-09.authenticate-realm": {
		By:     "FILES-12.other-domain",
		Reason: "expects a globex principal id that no token yields; the realm is the broker's configuration and another authority is another domain SID",
	},
	"COMMON-10.authenticate-error": {
		By:     "FILES-12.rejected-token",
		Reason: "pins CREDENTIAL_REJECTED for a bearer token and a cookie; the only credential is a Negotiate token, and a request without one is NO_CREDENTIAL (IA-1)",
	},
	"IDENT-01.authenticate": {
		By:     "FILES-12.other-account",
		Reason: "expects a basic: account identifier; another Windows account authenticates as its own SID (IA-8)",
	},
	"IDENT-02.authenticate": {
		By:     "FILES-12.other-domain",
		Reason: "expects an oauth: identifier of another tenant; under Negotiate another authority is another domain SID (IA-8)",
	},
	"IDENT-03.authenticate": {
		By:     "FILES-12.completed-exchange",
		Reason: "splits user and client; the broker's principal and workload are both the user's account (profile section 7)",
	},
	"IDENT-05.authenticate": {
		By:     "FILES-12.same-display-name",
		Reason: "expects a basic: account identifier; an account with the same display name authenticates as its own SID (IA-8)",
	},
	"COMMON-06.allow-no-execution": {
		By:     "FILES-03.read-granted",
		Reason: "expects an obligation on the allow; the native open answers allowed or denied and carries no obligation (ER-1)",
	},
	"COMMON-06.deny-unchanged": {
		By:     "FILES-03.access-denied",
		Reason: "expects an obligation on the denial; the native open answers allowed or denied and carries no obligation (ER-1)",
	},
	"COMMON-06.decision-provenance": {
		By:     "FILES-03.decision-provenance",
		Reason: "expects a decision record, a decision time and a policy revision from a policy source; the access check of the open reports none of them, and the decision names the open (ER-7)",
	},
}

// TestConformance runs the conformance suite, the common cases and the files
// cases of spec/v1.0/fixtures/adapters/files, with the replaced common cases
// declared. The profile supports workloads shared by several agents (section
// 7), so the shared cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, filesFactory, adaptertest.Options{Adapter: "files", SharedWorkloads: true, Replaced: replaced})
}

// TestFixtureWorlds loads the native state of every files case and checks
// what the cases rely on: each state parses strictly, and every registry
// entry names a path the file system holds.
func TestFixtureWorlds(t *testing.T) {
	fsys, err := adaptertest.DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := adaptertest.Load(fsys, "files")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range cases {
		if !strings.HasPrefix(c.ID, "FILES-") {
			continue
		}
		seen++
		w, err := loadWorld(c.NativeState)
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		for _, r := range w.st.Registry {
			if _, ok := w.objects[r.Path]; !ok {
				t.Errorf("%s: registry entry %s names %s, which the file system does not hold", c.ID, r.FileID, r.Path)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no files case loaded")
	}
}
