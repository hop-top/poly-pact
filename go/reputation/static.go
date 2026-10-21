package reputation

import (
	"crypto/ecdsa"
	"errors"
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// Reporter is one trusted registration of a signer: its iss, the
// reporter_role it is registered for and its public keys. A signer
// registered for several roles has one Reporter per role.
type Reporter struct {
	Iss  string
	Role core.ReporterRole
	Keys []jws.JWK
}

// StaticRegistry is a Registry over fixed registrations.
type StaticRegistry []Reporter

// Registered implements Registry.
func (r StaticRegistry) Registered(iss string, role core.ReporterRole) bool {
	return slices.ContainsFunc(r, func(x Reporter) bool { return x.Iss == iss && x.Role == role })
}

// TrustedKeys returns the keys of every registration of the payload's iss,
// each kid once. The service verifies only outcome reports with it, whose
// signer role is reporter.
func (r StaticRegistry) TrustedKeys(req jws.KeyRequest) (*jws.KeySet, error) {
	var m map[string]any
	if err := strictjson.Unmarshal(req.Payload, strictjson.Limits{}, &m); err != nil {
		return nil, err
	}
	iss, _ := m["iss"].(string)
	var keys []jws.JWK
	for _, x := range r {
		if x.Iss != iss {
			continue
		}
		for _, k := range x.Keys {
			if !slices.ContainsFunc(keys, func(s jws.JWK) bool { return s.Kid == k.Kid }) {
				keys = append(keys, k)
			}
		}
	}
	return jws.NewKeySet(keys...)
}

// HolderJKT implements jws.KeyResolver: a report is never holder-signed.
func (StaticRegistry) HolderJKT(jws.KeyRequest) (core.Digest, error) {
	return "", errors.New("reputation: an outcome report is signed by its reporter")
}

// StaticTasks is a Tasks over a fixed list.
type StaticTasks []Task

// Task implements Tasks.
func (t StaticTasks) Task(id string) (Task, bool) {
	i := slices.IndexFunc(t, func(x Task) bool { return x.TaskID == id })
	if i < 0 {
		return Task{}, false
	}
	return t[i], true
}

// StaticRecords is a Records over a fixed map from reference to record.
type StaticRecords map[string]Record

// Record implements Records.
func (r StaticRecords) Record(ref string) (Record, bool) {
	x, ok := r[ref]
	return x, ok
}

// ES256Signer signs snapshots with an ES256 key whose kid the header names
// (draft Section 7.2).
type ES256Signer struct {
	Kid string
	Key *ecdsa.PrivateKey
}

// SignSnapshot implements Signer.
func (s ES256Signer) SignSnapshot(payload []byte) (string, error) {
	return jws.Sign(jws.Header{Typ: jws.TypReputation, Kid: s.Kid}, payload, s.Key)
}
