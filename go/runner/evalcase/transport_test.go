package evalcase_test

import (
	"path/filepath"
	"testing"

	"hop.top/pact-go/runner/evalcase"
)

// TestSubmissionTransport: a submission's transport is the transport profile
// the presentation arrives over, https or stdio-ipc, by default https
// (spec/v1.0/fixtures/README.md, exchange.json; draft 13.3.1).
func TestSubmissionTransport(t *testing.T) {
	const id = "admission/valid"
	const pres = `"signed":"signed/presentation.jws","jti":"v6wxT-_cB0Ua8Xkqgcuu2g"`
	for _, tc := range []struct {
		body, want string
	}{
		{"", "https"},
		{`{"presentations":[{` + pres + `}]}`, "https"},
		{`{"presentations":[{` + pres + `,"transport":"https"}]}`, "https"},
		{`{"presentations":[{` + pres + `,"transport":"stdio-ipc"}]}`, "stdio-ipc"},
	} {
		root := caseTree(t, id)
		if tc.body != "" {
			writeFile(t, filepath.Join(root, id, "exchange.json"), []byte(tc.body))
		}
		c, err := evalcase.Load(root, id)
		if err != nil {
			t.Fatalf("%s: %v", tc.body, err)
		}
		if got := c.Exchanges[0].Submissions[0].Transport; got != tc.want {
			t.Errorf("%q: transport %q, want %q", tc.body, got, tc.want)
		}
	}
	for _, body := range []string{
		`{"presentations":[{` + pres + `,"transport":"http"}]}`,
		`{"presentations":[{` + pres + `,"transport":""}]}`,
		`{"presentations":[{` + pres + `,"transport":"HTTPS"}]}`,
	} {
		root := caseTree(t, id)
		writeFile(t, filepath.Join(root, id, "exchange.json"), []byte(body))
		_, err := evalcase.Load(root, id)
		wantErr(t, err, "exchange.json", "transport")
	}
	for _, tc := range []struct{ id, want string }{
		{"transport/https-contract-over-stdio-ipc", "stdio-ipc"},
		{"transport/stdio-ipc-contract-over-https", "https"},
	} {
		c, err := evalcase.Load(repoFixtures, tc.id)
		if err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		if got := c.Exchanges[0].Submissions[0].Transport; got != tc.want {
			t.Errorf("%s: transport %q, want %q", tc.id, got, tc.want)
		}
	}
}
