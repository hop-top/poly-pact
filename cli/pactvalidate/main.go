// Command pactvalidate is the conformance harness entry point of the
// reference validator (package hop.top/pact-go/validator): the evaluate and
// receipt commands of the conformance runner's adapter contract (package
// hop.top/pact-go/runner). It is a harness, not a user command: plain argv, no
// flags.
//
//	pactvalidate evaluate DIR [STATE]   print the responses to the case in DIR
//	pactvalidate receipt STATE ID       print the receipt whose jti is ID
//
// DIR is an evaluation case directory inside the fixture directory that holds
// manifest.json; STATE, the runner's scratch path, records the receipts of
// the evaluate command for the receipt command. With make, from the
// repository root:
//
//	go -C cli build -o "$PWD/bin/pactvalidate" ./pactvalidate
//	make conformance PACTC_ARGS='--capability jws-ed25519 --fixture admission/ \
//	  --evaluate-cmd "bin/pactvalidate evaluate {dir} {state}" \
//	  --receipt-cmd "bin/pactvalidate receipt {state} {id}"'
//
// Exit status: 0 after printing the responses; 1 when the case cannot be run;
// 2 on a usage error.
package main

import (
	"fmt"
	"io"
	"os"

	"hop.top/pact-go/validator/conformance"
)

const usage = "usage: pactvalidate evaluate DIR [STATE] | pactvalidate receipt STATE ID\n"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var err error
	switch {
	case len(args) >= 2 && len(args) <= 3 && args[0] == "evaluate":
		state := ""
		if len(args) == 3 {
			state = args[2]
		}
		err = conformance.Evaluate(args[1], state, stdout)
	case len(args) == 3 && args[0] == "receipt":
		err = conformance.Receipt(args[1], args[2], stdout)
	default:
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "pactvalidate:", err)
		return 1
	}
	return 0
}
