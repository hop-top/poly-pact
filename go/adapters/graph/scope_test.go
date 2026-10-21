package graph_test

import (
	"testing"
	"time"

	"hop.top/pact-go/adapters/graph"
	"hop.top/pact-go/core/clock"
)

// TestOBOScopeNeedsAcceptedScopes: an OBO acquirer of a scope other than
// Mail.Read names the spellings its response may use; the default scope
// keeps the profile's (GR-8).
func TestOBOScopeNeedsAcceptedScopes(t *testing.T) {
	base := graph.AcquirerConfig{Tenant: uTID, ClientID: uGatewayApp, Auth: graph.ClientAuth{Secret: secretOBO}, Clock: clock.NewFake(time.Unix(uNow, 0))}
	if _, err := graph.NewOnBehalfOf(base); err != nil {
		t.Errorf("default scope: %v", err)
	}
	other := base
	other.Scope = "https://management.azure.com/.default"
	if _, err := graph.NewOnBehalfOf(other); err == nil {
		t.Error("another scope without accepted response scopes was accepted")
	}
	other.AcceptedScopes = []string{"https://management.azure.com/user_impersonation"}
	if _, err := graph.NewOnBehalfOf(other); err != nil {
		t.Errorf("another scope with accepted response scopes: %v", err)
	}
}
