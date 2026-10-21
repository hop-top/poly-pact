package holder

import (
	"fmt"
	"net/http"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
)

// OperationFromRequest derives the operation context of the baseline HTTP
// mapping (draft 10.2) from req, a request the agent is about to send with
// net/http, so that the contract request and the presentation bind the
// request the gateway will receive. It applies [binding.FromRequest], with
// the gateway's mapping cfg, to the request as the client writes it: the
// request-target is req.URL.RequestURI() and the Host line req.Host, or
// req.URL.Host when that is empty.
//
// The principal, action and resources are those the gateway's mapping
// derives for the request (draft 10.2); operationID and environmentID are
// set as given. The body is read once and replaced by an in-memory copy,
// with req.GetBody returning it too, so req can still be sent. A request the
// mapping refuses is ErrInvalidMessage, with the [*binding.RequestError] in
// its chain.
func OperationFromRequest(cfg binding.Config, req *http.Request, operationID, environmentID, principalID, action string, resources []string) (core.OperationContext, error) {
	if req == nil || req.URL == nil {
		return core.OperationContext{}, fmt.Errorf("%w: no request", ErrInvalidMessage)
	}
	wire := req.Clone(req.Context())
	wire.RequestURI = req.URL.RequestURI()
	if wire.Host == "" {
		wire.Host = req.URL.Host
	}
	op, err := binding.FromRequest(cfg, wire, principalID, action, resources)
	if wire.Body != req.Body {
		req.Body, req.GetBody = wire.Body, wire.GetBody
	}
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	op.OperationID, op.EnvironmentID = operationID, environmentID
	return op, nil
}
