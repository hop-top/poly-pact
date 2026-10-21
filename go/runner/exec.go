package runner

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
)

// cmdResult is one run of an adapter command.
type cmdResult struct {
	Argv     []string
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	// Err is set when the command could not be started (no such file, not
	// executable); a nonzero exit is ExitCode, not Err.
	Err error
}

// runCmd runs argv without a shell. Standard input is the null device.
func runCmd(argv []string) cmdResult {
	res := cmdResult{Argv: argv}
	if len(argv) == 0 {
		res.Err = errors.New("empty command")
		return res
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res.Stdout = out.Bytes()
	res.Stderr = errb.Bytes()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
		} else {
			res.Err = err
		}
	}
	return res
}

// summary describes the run for a FAIL detail.
func (r cmdResult) summary() string {
	if r.Err != nil {
		return fmt.Sprintf("%q: %v", r.Argv, r.Err)
	}
	s := fmt.Sprintf("%q exited %d", r.Argv, r.ExitCode)
	if len(r.Stderr) > 0 {
		s += "; stderr: " + truncate(string(bytes.TrimSpace(r.Stderr)), 300)
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
