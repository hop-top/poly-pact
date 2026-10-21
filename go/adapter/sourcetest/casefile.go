package sourcetest

import (
	"encoding/json"
	"errors"
	"fmt"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
)

// defaultNow is the time of a case that states none: 2026-10-15T16:00:00Z,
// the timestamp of the draft's worked example.
const defaultNow int64 = 1792080000

// Outcomes of a read.
const (
	outValue = "value"
	outError = "error"
)

// sourceCase is one case file.
type sourceCase struct {
	CaseVersion int             `json:"case_version"`
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Draft       []string        `json:"draft"`
	Now         *int64          `json:"now"`
	Source      json.RawMessage `json:"source"`
	Steps       []step          `json:"steps"`
	Reads       []read          `json:"reads"`
	MustNotCall []string        `json:"must_not_call"`
}

// step is one inbound message, delivered at At.
type step struct {
	At      *int64          `json:"at"`
	Inbound json.RawMessage `json:"inbound"`
	Expect  json.RawMessage `json:"expect"`
}

// read is one read_native_claim call, made at At.
type read struct {
	At         *int64                 `json:"at"`
	NativePath string                 `json:"native_path"`
	Principal  string                 `json:"principal"`
	Intent     *core.Intent           `json:"intent"`
	Operation  *core.OperationContext `json:"operation"`
	Expect     expectRead             `json:"expect"`
}

// expectRead is what a read must return. A member that is absent, or an
// empty string, is not checked; observed_at and status_checked_at are Unix
// seconds or null for the zero time, and value is compared as JSON data.
type expectRead struct {
	Outcome         string          `json:"outcome"`
	Value           json.RawMessage `json:"value"`
	ObservedAt      json.RawMessage `json:"observed_at"`
	StatusCheckedAt json.RawMessage `json:"status_checked_at"`
	SourceID        string          `json:"source_id"`
	ReasonCode      string          `json:"reason_code"`
}

// parseCase parses a case file strictly and checks the envelope.
func parseCase(b []byte) (*sourceCase, error) {
	var c sourceCase
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &c); err != nil {
		return nil, err
	}
	if c.Now == nil {
		n := defaultNow
		c.Now = &n
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *sourceCase) check() error {
	switch {
	case c.CaseVersion != 1:
		return fmt.Errorf("case_version %d, want 1", c.CaseVersion)
	case c.ID == "":
		return errors.New("no id")
	case c.Title == "":
		return errors.New("no title")
	case len(c.Draft) == 0:
		return errors.New("no draft sections")
	case len(c.Reads) == 0:
		return errors.New("no reads")
	}
	var src struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(c.Source, &src); err != nil || src.Model == "" {
		return errors.New("source is not an object with a model")
	}
	last := int64(-1)
	at := func(t *int64) int64 {
		if t == nil {
			return *c.Now
		}
		return *t
	}
	for i, s := range c.Steps {
		if len(s.Inbound) == 0 {
			return fmt.Errorf("steps[%d] has no inbound message", i)
		}
		t := at(s.At)
		if t < last {
			return fmt.Errorf("steps[%d] at %d is before the step before it", i, t)
		}
		last = t
	}
	for i, r := range c.Reads {
		switch {
		case r.NativePath == "":
			return fmt.Errorf("reads[%d] has no native_path", i)
		case r.Principal == "":
			return fmt.Errorf("reads[%d] has no principal", i)
		case r.Expect.Outcome != outValue && r.Expect.Outcome != outError:
			return fmt.Errorf("reads[%d] outcome %q is not %s or %s", i, r.Expect.Outcome, outValue, outError)
		}
		t := at(r.At)
		if t < last {
			return fmt.Errorf("reads[%d] at %d is before the step or read before it", i, t)
		}
		last = t
	}
	return nil
}

// model returns the model of the case's source.
func (c *sourceCase) model() string {
	var src struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(c.Source, &src)
	return src.Model
}
