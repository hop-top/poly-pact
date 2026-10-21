package conformance

import (
	"fmt"

	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/validator"
)

// Fixture is the first submission of the first exchange of an evaluation
// case, ready to evaluate: the validator replica the case's gateway runs,
// over its stores, and the evaluate request. A test replaces a store or
// changes the request to see what the validator makes of it.
type Fixture struct {
	Validator *validator.Validator
	Request   validator.Request
	// Clock is the validator's clock, held at the submission's start.
	Clock *clock.Fake
}

// Prepare builds the Fixture of the evaluation case in dir. The case's
// publisher has registered the contract's nonce in the replay store.
func Prepare(dir string) (*Fixture, error) {
	fixtures, id, err := Locate(dir)
	if err != nil {
		return nil, err
	}
	c, err := evalcase.Read(fixtures, id)
	if err != nil {
		return nil, err
	}
	keys, err := loadPrivateKeys(fixtures)
	if err != nil {
		return nil, err
	}
	x := c.Exchanges[0]
	if len(x.Submissions) == 0 {
		return nil, fmt.Errorf("%s: no submission", id)
	}
	g, err := buildGateway(fixtures, x, keys, newGatewayState())
	if err != nil {
		return nil, err
	}
	sub := x.Submissions[0]
	g.prepareSubmission(sub)
	v, req, err := g.validatorFor(sub, func() {})
	if err != nil {
		return nil, err
	}
	return &Fixture{Validator: v, Request: req, Clock: g.clk}, nil
}
