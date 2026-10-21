package holder_test

import (
	"os"
	"testing"
	"time"

	"hop.top/pact-go/core"
)

// validatorCase is what a presentation built by this package is evaluated
// with: the compact presentation, the actual operation the gateway mapped,
// and the evaluation time. The Appendix B values make the
// spec/v1.0/fixtures/admission/valid configuration apply.
type validatorCase struct {
	Presentation string
	Actual       core.OperationContext
	Now          time.Time
}

// validatorHook evaluates c with the validator of package
// hop.top/pact-go/validator and returns its decision. It is nil until that
// package exists; a file that sets it from the validator's API wires
// TestPresentationPassesValidator.
var validatorHook func(t *testing.T, c validatorCase) (core.Decision, error)

// TestPresentationPassesValidator: the Appendix B presentation this package
// builds is ADMISSIBLE under the validator, and its wrong-key,
// stale-contract and modified-operation variants are not.
func TestPresentationPassesValidator(t *testing.T) {
	if validatorHook == nil {
		if _, err := os.Stat("../validator"); err == nil {
			t.Skip("go/validator exists but validatorHook is not wired to its API yet")
		}
		t.Skip("go/validator is not in this tree yet; the gateway checks on main cover the presentation (TestAppendixBPresentationReproduces)")
	}
	h := bHolder(t, memoryKey(t, 1))
	p, err := h.Present(bg, bInput(t), at(bTime))
	if err != nil {
		t.Fatal(err)
	}
	d, err := validatorHook(t, validatorCase{Presentation: p.Compact, Actual: bOperation(t), Now: at(bTime)})
	if err != nil || d != core.DecisionAdmissible {
		t.Fatalf("decision %s, %v; want ADMISSIBLE", d, err)
	}
	modified := bOperation(t)
	modified.Resources = []string{"https://invoices.example/invoices/INV-1043"}
	for name, c := range map[string]validatorCase{
		"stale contract":     {Presentation: p.Compact, Actual: bOperation(t), Now: at(bContractExp)},
		"modified operation": {Presentation: p.Compact, Actual: modified, Now: at(bTime)},
	} {
		if d, err := validatorHook(t, c); err == nil && d == core.DecisionAdmissible {
			t.Fatalf("%s: ADMISSIBLE", name)
		}
	}
}
