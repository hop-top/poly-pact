package abac_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/abac"
)

// The tests of this file are the execution-time rechecks of profile ABAC-21
// to ABAC-23 (cases ABAC-23 to ABAC-27 of profile section 10). Each admits the
// read of ABAC-02.control at 1792080000, when the device record was read 10 s
// earlier (F4 status_max_age 30) and the zone and time at the instant (F7 and
// F8 status_max_age 0).

const entryVersion = "abac-2026-10-01"

func admit(t *testing.T, f *fixture) abac.Admission {
	t.Helper()
	ad, err := f.a.Decide(context.Background(), f.p, f.op)
	if err != nil || !ad.Decision.Permits() {
		t.Fatalf("admission: %+v, %v", ad.Decision, err)
	}
	return ad
}

// setFact changes the record of path in the world's sources.
func setFact(t *testing.T, w *world, path string, value any, at int64, ref string) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for i := range w.st.Facts {
		if w.st.Facts[i].Path == path {
			w.st.Facts[i].Value, w.st.Facts[i].SourceRef = raw, ref
			w.st.Facts[i].ObservedAt, w.st.Facts[i].StatusCheckedAt = &at, &at
			return
		}
	}
	t.Fatalf("no fact %s", path)
}

// TestRecheckSameInstantStands is ABAC-26: a release within every
// status_max_age of the readings in force reads nothing again and keeps the
// decision in force.
func TestRecheckSameInstantStands(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", noExpectInput)
	ad := admit(t, f)
	next, err := f.a.Recheck(context.Background(), ad)
	if err != nil {
		t.Fatal(err)
	}
	if f.queries() != 1 || next.Decision.SourceRef != ad.Decision.SourceRef {
		t.Errorf("recheck at the admission instant made %d queries in all, decision %+v", f.queries(), next.Decision)
	}
}

// TestRecheckRereadsZoneAndTime: ten seconds later the zone and the time are
// past their bound of 0 and are read again; the device, read 20 s before, is
// within 30 and is not; a new decision is taken.
func TestRecheckRereadsZoneAndTime(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", noExpectInput)
	ad := admit(t, f)
	before, _ := ad.Reading(abac.PathDeviceCompliant)
	f.clk.Advance(10 * time.Second)
	next, err := f.a.Recheck(context.Background(), ad)
	if err != nil || !next.Decision.Permits() {
		t.Fatalf("recheck: %+v, %v", next.Decision, err)
	}
	if f.queries() != 2 {
		t.Errorf("%d queries, want a new one at the recheck", f.queries())
	}
	if tm, _ := next.Reading(abac.PathTime); tm.Value != f.clk.Now().Unix() {
		t.Errorf("time %v, want the recheck instant", tm.Value)
	}
	if dev, _ := next.Reading(abac.PathDeviceCompliant); !dev.StatusCheckedAt.Equal(before.StatusCheckedAt) {
		t.Error("the device was read again within its status_max_age")
	}
}

// TestRecheckDeviceNoLongerCompliant is ABAC-23: the device becomes
// non-compliant after admission and its status_max_age has elapsed; the
// reread gives a denial and the gateway discloses nothing.
func TestRecheckDeviceNoLongerCompliant(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", noExpectInput)
	ad := admit(t, f)
	f.clk.Advance(25 * time.Second)
	setFact(t, f.w, abac.PathDeviceCompliant, false, f.clk.Now().Unix(), "mdm:device:3a9c51e0:eval-2")
	next, err := f.a.Recheck(context.Background(), ad)
	if err != nil {
		t.Fatal(err)
	}
	if next.Decision.Effect != adapter.EffectDeny {
		t.Errorf("decision %s, want the policy's denial", next.Decision.Effect)
	}
	if err := abac.Gate(next.Decision, abac.Entry{CheckID: "c", PinnedVersion: entryVersion}); !errors.Is(err, abac.ErrNotPermitted) {
		t.Errorf("Gate = %v", err)
	}
}

// TestRecheckDoesNotRereadOtherFacts: a clearance lowered after admission is
// not seen at execution (profile section 9, decision-to-release window).
func TestRecheckDoesNotRereadOtherFacts(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", noExpectInput)
	ad := admit(t, f)
	f.clk.Advance(10 * time.Second)
	setFact(t, f.w, abac.PathClearance, "public", f.clk.Now().Unix(), "sec:clearance:00412:2")
	next, err := f.a.Recheck(context.Background(), ad)
	if err != nil || !next.Decision.Permits() {
		t.Fatalf("recheck: %+v, %v", next.Decision, err)
	}
	if c, _ := next.Reading(abac.PathClearance); c.Value != "confidential" {
		t.Errorf("clearance %v was read again", c.Value)
	}
}

// TestRecheckDeviceSourceDown is ABAC-25: the device source cannot answer at
// the recheck; nothing is disclosed.
func TestRecheckDeviceSourceDown(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", noExpectInput)
	ad := admit(t, f)
	f.clk.Advance(31 * time.Second)
	f.w.st.UnavailableSources = []string{"mdm-northstar"}
	_, err := f.a.Recheck(context.Background(), ad)
	if !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("Recheck = %v, want DEPENDENCY_UNAVAILABLE", err)
	}
}

// TestRecheckStaleReread: a reread device record that is itself older than
// its max_age gives an unknown decision, no disclosure.
func TestRecheckStaleReread(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", noExpectInput)
	ad := admit(t, f)
	f.clk.Advance(31 * time.Second)
	setFact(t, f.w, abac.PathDeviceCompliant, true, f.clk.Now().Unix()-301, "mdm:device:3a9c51e0:old")
	next, err := f.a.Recheck(context.Background(), ad)
	if err != nil || next.Decision.Effect != adapter.EffectUnknown {
		t.Errorf("Recheck = %+v, %v; want an unknown decision", next.Decision, err)
	}
	if f.queries() != 1 {
		t.Errorf("%d queries; a stale reread makes none", f.queries())
	}
}

// TestRecheckNewObligationsGovern is ABAC-27: the decision of the recheck
// replaces the one in force with its own obligations, and another version
// means the contract is no longer active.
func TestRecheckNewObligationsGovern(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", noExpectInput)
	var n atomic.Int32
	answers := []string{
		`{"type":"filter_fields","params":{"keep":["/title"]}}`,
		`{"type":"redact","params":{"paths":["/terms"]}}`,
	}
	versions := []string{entryVersion, entryVersion, "abac-2026-11-01"}
	f.w.pdp = startPDP(t, pdpState{SourceID: "pdp-northstar", DecisionPath: "pact/abac/decision"}, f.hooks, func(any) (int, string) {
		i := int(n.Add(1)) - 1
		obl := answers[min(i, len(answers)-1)]
		return http.StatusOK, fmt.Sprintf(`{"decision_id":"d-%d","result":{"allow":true,"obligations":[%s],"policy_version":%q}}`, i, obl, versions[i])
	})
	a, _, err := worldAdapter(f.w, f.clk)
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	entry := abac.Entry{CheckID: "c", PinnedVersion: entryVersion}
	ad := admit(t, f)
	f.clk.Advance(5 * time.Second)
	next, err := f.a.Recheck(context.Background(), ad)
	if err != nil || abac.Gate(next.Decision, entry) != nil {
		t.Fatalf("recheck: %+v, %v", next.Decision, err)
	}
	if len(next.Decision.Obligations) != 1 || next.Decision.Obligations[0].ID != "redact" || next.Decision.SourceRef != "d-1" {
		t.Errorf("obligations %+v of %s, want the recheck's redact", next.Decision.Obligations, next.Decision.SourceRef)
	}
	f.clk.Advance(5 * time.Second)
	third, err := f.a.Recheck(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	if err := abac.Gate(third.Decision, entry); !errors.Is(err, abac.ErrRequirementsChanged) {
		t.Errorf("another version at the recheck: Gate = %v", err)
	}
}

// movingZone is an environment whose zone map the test changes.
type movingZone struct {
	abac.Gateway
	zone *string
}

func (m movingZone) NetworkZone(ctx context.Context, peer netip.Addr) (adapter.NativeClaim, error) {
	c, err := m.Gateway.NetworkZone(ctx, peer)
	if err == nil {
		c.Value = *m.zone
	}
	return c, err
}

// TestRecheckZoneChanged is ABAC-24: the zone of the connection changes after
// admission; the reread gives a denial.
func TestRecheckZoneChanged(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", noExpectInput)
	zone := "corporate"
	src := worldFacts{f.w}
	a, err := abac.New(abac.Config{
		Realm: f.p.Realm, Origin: "https://gateway.northstar.example",
		Authenticator: stubAuth{}, Bindings: stubAuth{}, Subjects: src, Resources: src, Devices: src,
		Environment: movingZone{Gateway: abac.Gateway{SourceID: "gateway", Clock: f.clk,
			Zones: []abac.Zone{{Prefix: netip.MustParsePrefix("10.20.0.0/16"), Name: "corporate"}}}, zone: &zone},
		PDP:   abac.PDP{SourceID: "pdp-northstar", URL: f.w.pdp.URL, DecisionPath: "pact/abac/decision", Client: f.w.pdp.Client},
		Clock: f.clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	ad := admit(t, f)
	f.clk.Advance(time.Second)
	zone = "external"
	next, err := f.a.Recheck(context.Background(), ad)
	if err != nil || next.Decision.Effect != adapter.EffectDeny {
		t.Errorf("Recheck = %+v, %v; want the policy's denial", next.Decision, err)
	}
}
