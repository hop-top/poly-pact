package reputation_test

import (
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/learning"
	"hop.top/pact-go/runner/reputation"
)

// Threshold-behaviour properties of beta-decay-v1 (draft Sections 15.1 to
// 15.5, Appendix B.6 and Appendix E). Every expected number here comes from
// the draft's formula evaluated independently of the scorer; the 30-day
// half-life is written out as 2592000 seconds, not read from the package.

const (
	thT0       int64 = 1792080000
	thHalfLife       = 2592000.0
	thDay      int64 = 86400
	thGateway        = "https://gateway.example/finance"
	thAlice          = "https://identity.example/principals/alice"
	thOperator       = "https://identity.example/operators/acme"
)

// thFarm is the number of repeated reports of the farming cases: as many
// as keeps the provenance manifest under the 256 KiB the digest accepts.
const thFarm = 2000

// thSeeds are the fixed seeds of the property tests.
var thSeeds = []uint64{1, 2, 3, 20, 7000}

// thDecay is 2^(-age/2592000) with a negative age taken as 0: the decay of
// Section 15.3 written from the draft, not from the package.
func thDecay(t, observedAt int64) float64 {
	return math.Pow(2, -float64(max(t-observedAt, 0))/thHalfLife)
}

// thEffective is effective_weight = alpha + beta - 2 of dimension dim at t,
// summed from the draft's formula.
func thEffective(dim core.Dimension, t int64, events []reputation.Event) float64 {
	w := 0.0
	for _, e := range events {
		if e.Dimension == dim && (e.Result == core.OutcomeSuccess || e.Result == core.OutcomeFailure) {
			w += e.Weight * thDecay(t, e.ObservedAt)
		}
	}
	return w
}

func thUnits(n int, result core.OutcomeResult, dim core.Dimension, observedAt int64) []reputation.Event {
	out := make([]reputation.Event, n)
	for i := range out {
		out[i] = reputation.Event{ObservedAt: observedAt, Result: result, Weight: 1, Dimension: dim}
	}
	return out
}

// thHistory is a random history of n events on reliability, observed up to
// maxAge seconds before t0 (and up to 5 seconds after, the clock skew):
// successes of weight in (0, 1], the per-group cap, and failures of weight
// in [1, 5], with some UNKNOWN and off-dimension events mixed in.
func thHistory(r *rand.Rand, n int, maxAge int64) []reputation.Event {
	out := make([]reputation.Event, n)
	for i := range out {
		e := reputation.Event{ObservedAt: thT0 - r.Int64N(maxAge+1) + r.Int64N(6), Dimension: core.DimensionReliability}
		switch k := r.IntN(10); {
		case k < 6:
			e.Result, e.Weight = core.OutcomeSuccess, 1-r.Float64()
		case k < 8:
			e.Result, e.Weight = core.OutcomeFailure, 1+4*r.Float64()
		case k < 9:
			e.Result, e.Weight, e.Dimension = core.OutcomeUnknown, 1, core.DimensionNone
		default:
			e.Result, e.Weight, e.Dimension = core.OutcomeSuccess, 1, core.DimensionTaskQuality
		}
		out[i] = e
	}
	return out
}

// TestSparseHistoryNeverReachesConfidence5000 (Section 15.3: confidence is
// floor(10000 w / (w + 20)), so 5000 needs an effective weight of 20).
// Rejects: a scorer that rounds confidence instead of flooring, which turns
// 19.9999997 decayed units into 5000; one that counts reports instead of
// their decayed weight, which turns 20 month-old reports into 5000; and one
// whose decay is slower than a 30-day half-life.
func TestSparseHistoryNeverReachesConfidence5000(t *testing.T) {
	rel := core.DimensionReliability
	for _, tc := range []struct {
		name   string
		events []reputation.Event
		want   int64
	}{
		{"19 units at t", thUnits(19, core.OutcomeSuccess, rel, thT0), 4871},
		{"19 units at t and one observed 1 s earlier", append(thUnits(19, core.OutcomeSuccess, rel, thT0), thUnits(1, core.OutcomeSuccess, rel, thT0-1)...), 4999},
		{"20 reports one half-life old", thUnits(20, core.OutcomeSuccess, rel, thT0-30*thDay), 3333},
		{"20 units at t", thUnits(20, core.OutcomeSuccess, rel, thT0), 5000},
		{"10 successes and 10 failures at t", append(thUnits(10, core.OutcomeSuccess, rel, thT0), thUnits(10, core.OutcomeFailure, rel, thT0)...), 5000},
		{"40 reports one half-life old", thUnits(40, core.OutcomeSuccess, rel, thT0-30*thDay), 5000},
		{"5000 UNKNOWN and off-dimension reports", append(thUnits(2500, core.OutcomeUnknown, core.DimensionNone, thT0), thUnits(2500, core.OutcomeSuccess, core.DimensionTaskQuality, thT0)...), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reputation.Score(rel, thT0, tc.events).ConfidenceBPS; got != tc.want {
				t.Errorf("confidence %d, want %d", got, tc.want)
			}
		})
	}
	// Property: over random histories, confidence is below 5000 exactly when
	// the draft's effective weight is below 20.
	below, above := 0, 0
	for _, seed := range thSeeds {
		r := rand.New(rand.NewPCG(seed, 15))
		for range 400 {
			events := thHistory(r, 1+r.IntN(60), 120*thDay)
			w := thEffective(core.DimensionReliability, thT0, events)
			if math.Abs(w-20) < 1e-9 {
				continue
			}
			got := reputation.Score(core.DimensionReliability, thT0, events).ConfidenceBPS
			if (w < 20) != (got < 5000) {
				t.Fatalf("seed %d: effective weight %.12f gives confidence %d", seed, w, got)
			}
			if w < 20 {
				below++
			} else {
				above++
			}
		}
	}
	if below < 100 || above < 100 {
		t.Fatalf("%d sparse and %d dense histories: the property does not exercise both sides", below, above)
	}
}

// TestDecayMonotone (Section 15.3, Appendix E decay sensitivity at 7, 30
// and 90 days). Rejects: a decay that grows with elapsed time, one that
// weighs an observation later than t (within the clock skew) above its
// weight, and a half-life other than 30 days.
func TestDecayMonotone(t *testing.T) {
	for _, tc := range []struct {
		age  int64
		want float64
		conf int64
	}{
		// 2^(-7/30), 2^-1 and 2^-3; confidence of 20 unit reports that old.
		{7 * thDay, 0.8506671609508557, 4596},
		{30 * thDay, 0.5, 3333},
		{90 * thDay, 0.125, 1111},
	} {
		if d := reputation.Decay(thT0, thT0-tc.age); math.Abs(d-tc.want) > 1e-15 {
			t.Errorf("decay after %d days %v, want %v", tc.age/thDay, d, tc.want)
		}
		events := thUnits(20, core.OutcomeSuccess, core.DimensionReliability, thT0-tc.age)
		if c := reputation.Score(core.DimensionReliability, thT0, events).ConfidenceBPS; c != tc.conf {
			t.Errorf("20 units %d days old: confidence %d, want %d", tc.age/thDay, c, tc.conf)
		}
	}
	// An observation up to the 5-second clock skew after t has age 0: it
	// weighs its weight, never more.
	future := thUnits(1, core.OutcomeSuccess, core.DimensionReliability, thT0+5)
	if s := reputation.Score(core.DimensionReliability, thT0, future); s.Alpha != 2 {
		t.Errorf("a success observed 5 s after t: alpha %v, want 2", s.Alpha)
	}
	for _, seed := range thSeeds {
		r := rand.New(rand.NewPCG(seed, 30))
		for range 2000 {
			obs := thT0 - r.Int64N(400*thDay)
			// t1 is before the observation in about one draw in thirteen.
			t1 := obs - 30*thDay + r.Int64N(400*thDay)
			t2 := t1 + r.Int64N(200*thDay)
			d1, d2 := reputation.Decay(t1, obs), reputation.Decay(t2, obs)
			if d2 > d1 || d1 > 1 || d2 < 0 {
				t.Fatalf("seed %d: decay %v at %d, %v at %d of an observation at %d", seed, d1, t1, d2, t2, obs)
			}
		}
		for range 300 {
			events := thHistory(r, 1+r.IntN(40), 60*thDay)
			t1 := thT0 + r.Int64N(30*thDay)
			t2 := t1 + r.Int64N(90*thDay)
			s1 := reputation.Score(core.DimensionReliability, t1, events)
			s2 := reputation.Score(core.DimensionReliability, t2, events)
			if s2.Alpha > s1.Alpha || s2.Beta > s1.Beta || s2.ConfidenceBPS > s1.ConfidenceBPS {
				t.Fatalf("seed %d: later evaluation weighs more: %+v at %d, %+v at %d", seed, s1, t1, s2, t2)
			}
		}
	}
}

// TestPromotionMarginRejectsBoundaryEquality (Section 15.3: promotion
// policies use an explicit margin and do not rely on a rounding-boundary
// equality; Appendix E margins). Rejects: a promotion rule
// "score_bps >= 7500" with no margin. The vector
// floor-score-exact-7500-decayed has an exact score of 7500, which a
// correctly rounded power gives and Go's math.Pow, one unit in the last
// place low, gives as 7499: the bare rule decides it both ways.
func TestPromotionMarginRejectsBoundaryEquality(t *testing.T) {
	for _, tc := range []struct {
		th reputation.Threshold
		ok bool
	}{
		{reputation.Threshold{FloorBPS: 7500, MarginBPS: 0}, false},
		{reputation.Threshold{FloorBPS: 7500, MarginBPS: -1}, false},
		{reputation.Threshold{FloorBPS: 7500, MarginBPS: 1}, true},
		{reputation.Threshold{FloorBPS: 7500, MarginBPS: 100}, true},
		{reputation.Threshold{FloorBPS: 0, MarginBPS: 1}, true},
		{reputation.Threshold{FloorBPS: 9999, MarginBPS: 1}, true},
		{reputation.Threshold{FloorBPS: 10000, MarginBPS: 1}, false},
		{reputation.Threshold{FloorBPS: -1, MarginBPS: 1}, false},
	} {
		if err := tc.th.Validate(); (err == nil) != tc.ok {
			t.Errorf("%+v: Validate() = %v, want ok %v", tc.th, err, tc.ok)
		}
	}
	// The boundary vector: both values within tolerance of the exact 7500
	// give the same answer under the explicit margin, and not under the
	// bare equality rule.
	var vec *vector
	for _, v := range readVectors(t) {
		if v.ID == "floor-score-exact-7500-decayed" {
			vec = &v
		}
	}
	if vec == nil || vec.Expected.ScoreBPS != 7500 {
		t.Fatal("vector floor-score-exact-7500-decayed with expected score 7500 is missing")
	}
	bare := reputation.Threshold{FloorBPS: 7500}
	if bare.Met(7499) == bare.Met(7500) {
		t.Error("the bare rule should split the two admissible values; the test no longer shows the hazard")
	}
	margin := reputation.Threshold{FloorBPS: 7500, MarginBPS: reputation.ToleranceBPS}
	if margin.Met(7499) || margin.Met(7500) || margin.Met(7501) == false {
		t.Errorf("margin rule: met(7499) %v met(7500) %v met(7501) %v, want false false true", margin.Met(7499), margin.Met(7500), margin.Met(7501))
	}
	// Property: a valid rule that is met by a value is met only when every
	// recomputation within the tolerance still clears the floor.
	for _, seed := range thSeeds {
		r := rand.New(rand.NewPCG(seed, 75))
		for range 5000 {
			th := reputation.Threshold{FloorBPS: r.Int64N(10001), MarginBPS: r.Int64N(4)}
			v := r.Int64N(10001)
			if th.Validate() != nil {
				if th.MarginBPS >= reputation.ToleranceBPS && th.FloorBPS+th.MarginBPS <= 10000 {
					t.Fatalf("seed %d: %+v rejected", seed, th)
				}
				continue
			}
			if th.Met(v) != (v >= th.FloorBPS+th.MarginBPS) {
				t.Fatalf("seed %d: %+v Met(%d) = %v", seed, th, v, th.Met(v))
			}
			if th.Met(v) && v-reputation.ToleranceBPS < th.FloorBPS {
				t.Fatalf("seed %d: %+v met at %d, within tolerance of the floor", seed, th, v)
			}
		}
	}
}

// TestB6OnlyFromIndependentTasks (Appendix B.6, Sections 14.3, 14.5 and
// 15.3). Rejects: a snapshot that reaches the B.6 values from admission
// passes, from repeated operations of one task, or from task IDs that share
// one independence group (fast-path farming).
func TestB6OnlyFromIndependentTasks(t *testing.T) {
	b6 := []struct {
		dim               core.Dimension
		successes, fails  int
		score, confidence int64
	}{
		{core.DimensionReliability, 24, 1, 9259, 5555},
		{core.DimensionTaskQuality, 17, 1, 9000, 4736},
		{core.DimensionPolicyAdherence, 6, 0, 8750, 2307},
	}
	for _, d := range b6 {
		events := append(thUnits(d.successes, core.OutcomeSuccess, d.dim, thT0), thUnits(d.fails, core.OutcomeFailure, d.dim, thT0)...)
		if s := reputation.Score(d.dim, thT0, events); s.ScoreBPS != d.score || s.ConfidenceBPS != d.confidence {
			t.Errorf("%s: %d and %d, want B.6 %d and %d", d.dim, s.ScoreBPS, s.ConfidenceBPS, d.score, d.confidence)
		}
		// With unit weights at t, no other split of up to 100 successes and
		// 100 failures gives the printed pair.
		for s := range 101 {
			for f := range 101 {
				if s == d.successes && f == d.fails {
					continue
				}
				events := append(thUnits(s, core.OutcomeSuccess, d.dim, thT0), thUnits(f, core.OutcomeFailure, d.dim, thT0)...)
				if got := reputation.Score(d.dim, thT0, events); got.ScoreBPS == d.score && got.ConfidenceBPS == d.confidence {
					t.Errorf("%s: %d successes and %d failures also give B.6", d.dim, s, f)
				}
			}
		}
		// 7000 admission passes are dimension none: the empty history.
		if s := reputation.Score(d.dim, thT0, thUnits(7000, core.OutcomeSuccess, core.DimensionNone, thT0)); s.ScoreBPS != 5000 || s.ConfidenceBPS != 0 {
			t.Errorf("%s: 7000 admissions give %d and %d, want 5000 and 0", d.dim, s.ScoreBPS, s.ConfidenceBPS)
		}
	}

	rel := core.DimensionReliability
	t.Run("25 independent tasks", func(t *testing.T) {
		w := thNewWorld(t)
		for i := range 25 {
			res := core.OutcomeSuccess
			if i == 24 {
				res = core.OutcomeFailure
			}
			w.ingest(w.execution(fmt.Sprintf("b6-%04d", i), fmt.Sprintf("b6-%04d", i), "op", res, thT0, w.tmpl.Context))
		}
		w.wantStats(rel, 9259, 5555, 25, 25)
	})
	t.Run("7000 admissions", func(t *testing.T) {
		w := thNewWorld(t)
		// Repeated fast-path admissions of one task, each its own operation
		// so that none is a duplicate (Section 14.6 rule 4).
		for i := range 7000 {
			w.ingest(w.admission("fast-path", fmt.Sprintf("admission-%04d", i), thT0-20))
		}
		s := w.query(w.tmpl.Context, thT0)
		for _, d := range reputation.Dimensions {
			if got := thDim(s, d); got.ScoreBPS != 5000 || got.ConfidenceBPS != 0 || got.IndependentTasks != 0 || got.QualifiedEvents != 0 {
				t.Errorf("%s: %+v, want the empty history", d, got)
			}
		}
		if len(s.Manifest.QualifiedEventIDs) != 0 {
			t.Errorf("%d admissions listed in the provenance", len(s.Manifest.QualifiedEventIDs))
		}
	})
	t.Run("2000 operations of one task", func(t *testing.T) {
		w := thNewWorld(t)
		for i := range thFarm {
			w.ingest(w.execution("one", "one", fmt.Sprintf("op-%04d", i), core.OutcomeSuccess, thT0-20, w.tmpl.Context))
		}
		// One positive unit: alpha 2, beta 1.
		w.wantStats(rel, 6666, 476, 1, thFarm)
	})
	t.Run("2000 task ids in one independence group", func(t *testing.T) {
		w := thNewWorld(t)
		for i := range thFarm {
			w.ingest(w.execution(fmt.Sprintf("cycled-%04d", i), "shared", "op", core.OutcomeSuccess, thT0-20, w.tmpl.Context))
		}
		w.wantStats(rel, 6666, 476, 1, thFarm)
	})
}

// TestWrongContextContributesZero (Section 15.1: the baseline transfers no
// positive evidence between contexts). Rejects: a reputation service that
// pools the evidence of contexts sharing tenant, environment and agent, or
// that matches a context on some of its members only.
func TestWrongContextContributesZero(t *testing.T) {
	home := thNewWorld(t).tmpl.Context
	others := map[string]func(*core.ReputationContext){
		"purpose":  func(c *core.ReputationContext) { c.PurposeID = "https://policies.example/purposes/payroll/v1" },
		"action":   func(c *core.ReputationContext) { c.ActionClass = "payment.approve" },
		"resource": func(c *core.ReputationContext) { c.ResourceClass = "department-finance-payment" },
		"runtime":  func(c *core.ReputationContext) { c.RuntimeClass = "unmanaged-v1" },
		"all four": func(c *core.ReputationContext) {
			c.PurposeID, c.ActionClass, c.ResourceClass, c.RuntimeClass = "https://policies.example/purposes/payroll/v1", "payroll.write", "department-hr-payroll", "unmanaged-v1"
		},
	}
	for _, name := range slices.Sorted(maps.Keys(others)) {
		t.Run(name, func(t *testing.T) {
			other := home
			others[name](&other)
			w := thNewWorld(t)
			for i := range 30 {
				w.ingest(w.execution(fmt.Sprintf("h-%04d", i), fmt.Sprintf("h-%04d", i), "op", core.OutcomeSuccess, thT0-20, home))
			}
			s := w.query(other, thT0)
			for _, d := range reputation.Dimensions {
				if got := thDim(s, d); got.ScoreBPS != 5000 || got.ConfidenceBPS != 0 || got.IndependentTasks != 0 || got.QualifiedEvents != 0 {
					t.Errorf("%s in the other context: %+v, want the empty history", d, got)
				}
			}
			if len(s.Manifest.QualifiedEventIDs) != 0 {
				t.Errorf("%d reports of the home context listed", len(s.Manifest.QualifiedEventIDs))
			}
			if got := thDim(w.query(home, thT0), core.DimensionReliability); got.IndependentTasks != 30 {
				t.Errorf("home context: %+v, want 30 tasks", got)
			}
		})
	}
	// Property: interleaving reports of other contexts changes nothing in
	// the queried one; the snapshot equals that of the queried context's
	// reports alone.
	keys := slices.Sorted(maps.Keys(others))
	for _, seed := range thSeeds {
		r := rand.New(rand.NewPCG(seed, 151))
		mixed, alone := thNewWorld(t), thNewWorld(t)
		for i := range 40 {
			res := core.OutcomeSuccess
			if r.IntN(4) == 0 {
				res = core.OutcomeFailure
			}
			obs := thT0 - 20 - r.Int64N(6*thDay)
			id := fmt.Sprintf("m-%04d", i)
			if r.IntN(2) == 0 {
				mixed.ingest(mixed.execution(id, id, "op", res, obs, home))
				// The same report in both: the same event_id and jti.
				alone.n = mixed.n - 1
				alone.ingest(alone.execution(id, id, "op", res, obs, home))
				continue
			}
			ctx := home
			others[keys[r.IntN(len(keys))]](&ctx)
			mixed.ingest(mixed.execution(id, id, "op", res, obs, ctx))
		}
		a, b := mixed.query(home, thT0), alone.query(home, thT0)
		for _, d := range reputation.Dimensions {
			da, db := thDim(a, d), thDim(b, d)
			if da.ScoreBPS != db.ScoreBPS || da.ConfidenceBPS != db.ConfidenceBPS || da.IndependentTasks != db.IndependentTasks || da.QualifiedEvents != db.QualifiedEvents {
				t.Errorf("seed %d %s: %+v with other contexts, %+v without", seed, d, da, db)
			}
		}
		if !slices.Equal(a.Manifest.QualifiedEventIDs, b.Manifest.QualifiedEventIDs) {
			t.Errorf("seed %d: provenance differs", seed)
		}
	}
}

// TestFailureWeightAtMost5 (Section 15.3: a normal failure weighs 1, up to
// 5 under an approved severity rule; at most one positive unit per
// independent task group; Appendix A.3 data_policy). Rejects: a data
// policy whose maximum_failure_weight is above 5, a failure weighed above
// the policy's maximum, and a success above the one-unit group cap.
func TestFailureWeightAtMost5(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoFixtures, "learning", "happy-path", "policies", "finance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy core.LearningPolicy
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &policy); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		max, cap int64
		ok       bool
	}{{1, 1, true}, {5, 1, true}, {0, 1, false}, {6, 1, false}, {7000, 1, false}, {5, 2, false}} {
		p := policy
		p.DataPolicy.MaximumFailureWeight, p.DataPolicy.PositiveWeightCapPerTask = tc.max, tc.cap
		if err := learning.ValidatePolicy(p); (err == nil) != tc.ok {
			t.Errorf("maximum_failure_weight %d, positive cap %d: %v, want ok %v", tc.max, tc.cap, err, tc.ok)
		}
	}
	ev := func(res core.OutcomeResult, w float64) []reputation.Event {
		return []reputation.Event{{ObservedAt: thT0, Result: res, Weight: w, Dimension: core.DimensionReliability}}
	}
	for _, tc := range []struct {
		name   string
		max    int64
		events []reputation.Event
		ok     bool
	}{
		{"normal failure", 1, ev(core.OutcomeFailure, 1), true},
		{"approved severity 5", 5, ev(core.OutcomeFailure, 5), true},
		{"severity above the policy maximum", 3, ev(core.OutcomeFailure, 4), false},
		{"failure weight 6", 5, ev(core.OutcomeFailure, 6), false},
		{"policy maximum 6", 6, ev(core.OutcomeFailure, 1), false},
		{"policy maximum 0", 0, ev(core.OutcomeFailure, 1), false},
		{"capped success", 5, ev(core.OutcomeSuccess, 1), true},
		{"decayed success", 5, ev(core.OutcomeSuccess, 0.25), true},
		{"success above the group cap", 5, ev(core.OutcomeSuccess, 1.0000001), false},
		{"7000 units in one success", 5, ev(core.OutcomeSuccess, 7000), false},
		{"negative weight", 5, ev(core.OutcomeFailure, -1), false},
		{"NaN weight", 5, ev(core.OutcomeSuccess, math.NaN()), false},
		{"UNKNOWN weighs nothing", 5, ev(core.OutcomeUnknown, 9), true},
		{"empty history", 5, nil, true},
	} {
		if err := reputation.CheckWeights(tc.max, tc.events); (err == nil) != tc.ok {
			t.Errorf("%s: CheckWeights = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}

// thWorld builds an Oracle on the setup of reputation/context-no-transfer:
// the B.9 data policy, the executor of that case, a gateway, and native
// tasks and records the test adds.
type thWorld struct {
	t      *testing.T
	cfg    evalcase.OutcomesConfig
	native evalcase.OutcomesNative
	tmpl   core.OutcomeReport
	o      *reputation.Oracle
	queued []core.OutcomeReport
	n      int
}

func thNewWorld(t *testing.T) *thWorld {
	t.Helper()
	c, err := evalcase.ReadOutcomes(repoFixtures, "reputation/context-no-transfer")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, ok := c.Reports["execution-event-0001"]
	if !ok {
		t.Fatal("template report execution-event-0001 missing")
	}
	gw := string(core.ReporterGateway)
	cfg := c.Config
	cfg.Trust = append(slices.Clone(cfg.Trust), evalcase.TrustRecord{Iss: thGateway, Role: "reporter", ReporterRole: &gw})
	cfg.ExecutorClasses = nil
	return &thWorld{t: t, cfg: cfg, native: evalcase.OutcomesNative{Records: map[string]evalcase.NativeRecord{}}, tmpl: tmpl}
}

func (w *thWorld) task(id, group string) string {
	id = "native-task:" + id
	if _, ok := w.native.Task(id); !ok {
		w.native.Tasks = append(w.native.Tasks, evalcase.NativeTask{TaskID: id, AgentID: w.tmpl.Subject, OperatorID: thOperator,
			PrincipalID: thAlice, IndependenceGroup: "native-task-group:" + group, HolderJKT: evalcase.DefaultHolderJKT})
	}
	return id
}

func (w *thWorld) report(task, group, op string, observedAt int64) core.OutcomeReport {
	w.n++
	r := w.tmpl
	r.EventID = fmt.Sprintf("threshold-event-%05d", w.n)
	r.JTI = fmt.Sprintf("threshold-test-jti-%010d", w.n)
	r.TaskID, r.OperationID, r.ObservedAt = task, op, observedAt
	r.Attribution.NativeTaskRef, r.Attribution.IndependenceGroup = task, "native-task-group:"+group
	r.Supersedes = []string{}
	return r
}

// execution is an EXECUTION report of the executor on reliability, citing a
// native execution record of its task and operation.
func (w *thWorld) execution(task, group, op string, res core.OutcomeResult, observedAt int64, ctx core.ReputationContext) core.OutcomeReport {
	id := w.task(task, group)
	state, returned := "completed", "data"
	if res == core.OutcomeFailure {
		state = "failed"
	}
	ref := "native-execution-log:" + id + "/" + op
	rec := evalcase.NativeRecord{Kind: "execution", State: state, TaskID: id, OperationID: op, ObservedAt: observedAt,
		Executor: &evalcase.RecordExecutor{Class: "delegated-user", PrincipalID: thAlice}}
	if state == "completed" {
		rec.Returned = &returned
	}
	w.native.Records[ref] = rec
	w.cfg.ExecutorClasses = append(w.cfg.ExecutorClasses, evalcase.ExecutorClass{PrincipalID: thAlice, TaskID: id, OperationID: op, Class: "delegated-user"})
	r := w.report(id, group, op, observedAt)
	r.Result, r.EvidenceRefs, r.Context = res, []string{ref}, ctx
	return r
}

// admission is a gateway's ADMISSION SUCCESS report: an admission pass.
func (w *thWorld) admission(task, op string, observedAt int64) core.OutcomeReport {
	id := w.task(task, task)
	r := w.report(id, task, op, observedAt)
	r.Issuer, r.ReporterRole, r.EventKind, r.Result, r.Dimension = thGateway, core.ReporterGateway, core.EventAdmission, core.OutcomeSuccess, core.DimensionNone
	r.EvidenceRefs = []string{}
	return r
}

// ingest queues a report. The oracle copies the configuration and the task
// list when it is built, so it is built on the first query, once every
// native record exists.
func (w *thWorld) ingest(r core.OutcomeReport) {
	if w.o != nil {
		w.t.Fatal("ingest after query")
	}
	w.queued = append(w.queued, r)
}

func (w *thWorld) query(ctx core.ReputationContext, at int64) *reputation.Snapshot {
	w.t.Helper()
	if w.o == nil {
		w.o = reputation.NewOracle(w.cfg, w.native)
		for _, r := range w.queued {
			if a := w.o.Ingest(r, thT0); a.Ack != core.AckAccepted {
				w.t.Fatalf("%s: answer %+v, want ACCEPTED", r.EventID, a)
			}
		}
		for id, v := range w.o.Verdicts() {
			if v.Qualification != evalcase.Qualified {
				w.t.Fatalf("%s: %+v, want QUALIFIED", id, v)
			}
		}
	}
	s, code := w.o.Query(core.ReputationQuery{AgentID: w.tmpl.Subject, HolderJKT: evalcase.DefaultHolderJKT, Context: ctx, Audience: thGateway}, at)
	if s == nil {
		w.t.Fatalf("query refused %s", code)
	}
	return s
}

func (w *thWorld) wantStats(d core.Dimension, score, confidence, tasks, events int64) {
	w.t.Helper()
	got := thDim(w.query(w.tmpl.Context, thT0), d)
	if got.ScoreBPS != score || got.ConfidenceBPS != confidence || got.IndependentTasks != tasks || got.QualifiedEvents != events {
		w.t.Errorf("%s: %d %d, %d tasks, %d events; want %d %d, %d tasks, %d events", d,
			got.ScoreBPS, got.ConfidenceBPS, got.IndependentTasks, got.QualifiedEvents, score, confidence, tasks, events)
	}
}

func thDim(s *reputation.Snapshot, d core.Dimension) core.DimensionStats {
	switch d {
	case core.DimensionReliability:
		return s.Value.Dimensions.Reliability
	case core.DimensionTaskQuality:
		return s.Value.Dimensions.TaskQuality
	}
	return s.Value.Dimensions.PolicyAdherence
}
