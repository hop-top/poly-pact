package memory

import (
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
)

// Factory is the adaptertest.Factory of the memory adapter. It builds the
// adapter from the common/1 native state of a case, with the clock of the
// suite. Its workloads are dedicated, the default.
func Factory(tb testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	return FactoryWith()(tb, env)
}

// FactoryWith returns the adaptertest.Factory of the memory adapter built with
// opts. The suite runs the adapter built with [WithSharedWorkloads] with
// adaptertest.Options.SharedWorkloads set.
func FactoryWith(opts ...Option) adaptertest.Factory {
	return func(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
		a, err := FromJSON(env.State, env.Clock, opts...)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		return SubjectOf(a), nil
	}
}

// SubjectOf wraps an adapter with the hooks that the suite needs.
func SubjectOf(a *Adapter) adaptertest.Subject {
	return adaptertest.Subject{
		Adapter:       a,
		Arrive:        Arrive,
		Credential:    a.Credential,
		VerifyOutcome: a.VerifyOutcome,
	}
}
