package basic

import (
	"context"
	"fmt"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
)

// RecordOutcome signs the observation as an outcome report (draft 14.1).
//
// The gateway reports what it observes: admission decisions and native
// authorization results. Execution is reported by the backend, so an
// EXECUTION observation gives NoVisibility, never an assumed success, unless
// [Config.ExecutionVisible] says the gateway observes it. Other event kinds
// are [adapter.ErrUnsupportedRequirement]. Free text and evidence references
// are cleaned of credential material first: credential header lines, Basic
// and Bearer values, compact JWS, and name=value pairs with a credential name
// (draft 19). The adapter holds no password, so a password that appears in
// none of those forms is not recognized.
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the gateway does not observe the execution of the read; the backend reports it", o, a.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("basic: %w", err)
	}
	return rec, nil
}
