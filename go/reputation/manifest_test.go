package reputation_test

import (
	"fmt"
	"testing"

	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/reputation"
)

// TestManifestDigest: Digest is the object_digest of draft Section 7.4 for
// any manifest core/digest accepts, escapes and non-ASCII included, and
// has no size limit: a manifest beyond the 256 KiB decode limit of Section
// 20.1 still has its digest.
func TestManifestDigest(t *testing.T) {
	for _, m := range []reputation.ProvenanceManifest{
		{QualifiedEventIDs: [][2]string{}, SupersededEventIDs: [][2]string{}, QualificationPolicyID: "pact-qualification-v1", ScoringPolicyRevision: "r", EvidenceCutoff: 1792080000},
		{QualifiedEventIDs: [][2]string{{"https://a.example/é", "jti \"\\\n\x01<>&"}, {"z", "€𝄞"}}, SupersededEventIDs: [][2]string{{"x", "y"}},
			QualificationPolicyID: "p\t", ScoringPolicyRevision: "ÿ", EvidenceCutoff: 0},
		{QualificationPolicyID: "p", ScoringPolicyRevision: "r", EvidenceCutoff: 9007199254740991},
	} {
		want, err := digest.ObjectDigest(toLists(m))
		if err != nil {
			t.Fatal(err)
		}
		got, err := m.Digest()
		if err != nil || got != want {
			t.Errorf("%+v: digest %s %v, want %s", m, got, err, want)
		}
	}
	big := reputation.ProvenanceManifest{QualificationPolicyID: "p", ScoringPolicyRevision: "r"}
	for i := range 5000 {
		big.QualifiedEventIDs = append(big.QualifiedEventIDs, [2]string{"https://executor.example/finance", fmt.Sprintf("jti-%022d", i)})
	}
	if _, err := digest.ObjectDigest(big); err == nil {
		t.Fatal("control: core/digest accepts the large manifest; the test no longer crosses its limit")
	}
	d, err := big.Digest()
	if err != nil || len(d) != 43 {
		t.Errorf("large manifest: %q %v", d, err)
	}
}

// toLists is m with nil lists as empty arrays, as Digest writes them.
func toLists(m reputation.ProvenanceManifest) reputation.ProvenanceManifest {
	if m.QualifiedEventIDs == nil {
		m.QualifiedEventIDs = [][2]string{}
	}
	if m.SupersededEventIDs == nil {
		m.SupersededEventIDs = [][2]string{}
	}
	return m
}
