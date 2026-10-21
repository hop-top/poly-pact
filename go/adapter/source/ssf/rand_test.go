package ssf_test

import (
	"context"
	"crypto/rand"
	"errors"

	"hop.top/pact-go/adapter/source/ssf"
)

type ctxT = context.Context

// randReader is the entropy source of test signatures.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return rand.Read(p) }

func isUnknownKey(err error) bool { return errors.Is(err, ssf.ErrUnknownKey) }

func asErr(err error, target **ssf.Error) bool { return errors.As(err, target) }
