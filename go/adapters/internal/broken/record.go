package broken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
)

// leakySigner signs outcome reports with a key of its own, for the defect that
// signs text the memory adapter would have cleaned.
type leakySigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func newLeakySigner(st memory.State) (*leakySigner, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &leakySigner{key: k, kid: st.Reporting.KID}, nil
}

func (l *leakySigner) sign(rep core.OutcomeReport) (string, error) {
	hdr, err := json.Marshal(map[string]string{"alg": "ES256", "kid": l.kid, "typ": "pact-outcome+jwt"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(rep)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(hdr) + "." + enc.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, l.key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc.EncodeToString(sig), nil
}

func (l *leakySigner) verify(jws string) error {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&l.key.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return errors.New("signature does not verify")
	}
	return nil
}

// RecordOutcome is the memory adapter's, with the recording defects.
func (b *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	visible := b.State().Visibility == "execution"
	switch {
	case b.on[NoVisibilityForAdmission] && o.EventKind == core.EventAdmission:
		return adapter.NoVisibility{Reason: "the adapter has no visibility"}, nil
	case b.on[NoVisibilityDespiteVisibility] && o.EventKind == core.EventExecution && visible:
		return adapter.NoVisibility{Reason: "the adapter has no visibility"}, nil
	case b.on[AssumeExecutionSuccess] && o.EventKind == core.EventExecution && !visible && b.executing != nil:
		// The adapter cannot see the execution and signs a success anyway.
		o.Result, o.Dimension = core.OutcomeSuccess, core.DimensionReliability
		return b.executing.RecordOutcome(ctx, o)
	}
	rec, err := b.Adapter.RecordOutcome(ctx, o)
	if err != nil || !b.on[LeakDetailsInReport] || b.leaky == nil {
		return rec, err
	}
	signed, ok := rec.(adapter.Signed)
	if !ok {
		return rec, nil
	}
	rep, err := decodeReport(signed.JWS)
	if err != nil {
		return nil, err
	}
	rep.Details = o.Details
	rep.EvidenceRefs = o.EvidenceRefs
	jws, err := b.leaky.sign(rep)
	if err != nil {
		return nil, err
	}
	return adapter.Signed{JWS: jws}, nil
}

func decodeReport(jws string) (core.OutcomeReport, error) {
	var rep core.OutcomeReport
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return rep, errors.New("not a compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return rep, err
	}
	return rep, json.Unmarshal(raw, &rep)
}
