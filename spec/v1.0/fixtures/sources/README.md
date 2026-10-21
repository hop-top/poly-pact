# Membership and status source cases

These files are the language-neutral cases of membership and status sources that are not adapters: an integration that operates the receiving end of a protocol the identity system pushes, such as a SCIM 2.0 service provider, a directory push channel or a Shared Signals receiver. Such a source implements one function of draft section 17.1, `read_native_claim`, over the state it was pushed: the pushed messages are its change feed, and every read answers from the last pushed state (draft sections 9.2, 17.2 and 18; [../../profiles/freshness.md](../../profiles/freshness.md), sections 4.1 and 4.2). A case delivers a sequence of inbound messages to the source and then reads from it.

```
sources/
  README.md            this file
  <source>/*.json      the cases of one source, named by its protocol
```

Every case file is registered in [`../manifest.json`](../manifest.json) with kind `source-case` and scope `adapter`, under the id `sources/<source>/<file name without .json>`, with `expected` and `outcome` `null`: the case file carries its expectations inline ([../README.md](../README.md), Manifest). A source is described by its source document, an entry of kind `source` in [../../profiles/registry.json](../../profiles/registry.json), which defines the source's model (below) and lists its cases.

## Running the cases

In Go, the harness is the package `adapter/sourcetest` of the source repository:

```go
func TestConformance(t *testing.T) {
	sourcetest.Run(t, driver, sourcetest.Options{Source: "scim"})
}
```

The driver names the model it reads and builds a fresh source for each case. Other languages implement the loop below.

1. Read every `*.json` file of `sources/<source>`. Parse each with a strict parser: duplicate member names and unknown members are errors.
2. For each case, build a fresh source from `source`, with the clock held at the time of the first step, or of the first read when there is none.
3. Deliver each step in order, with the clock set to its `at`, and check the source's answer against the step's `expect`, as the source's model defines.
4. Make each read in order, with the clock set to its `at`, and check it (section Checks).
5. Check that no hook that `must_not_call` names has fired.

## Case file

| Member | Required | Meaning |
|---|---|---|
| `case_version` | yes | `1`. |
| `id` | yes | The case's label, such as `SCIM-03.disable`. |
| `title` | yes | One sentence. |
| `draft` | yes | The draft sections the case tests, as strings. |
| `now` | no | The case's reference time, Unix seconds; `1792080000` when absent. A step or read without `at` happens at `now`. |
| `source` | yes | An object with a string `model`, such as `scim/1`, and the source's configuration and seed state in the members its model defines. |
| `steps` | no | The inbound messages, in order: each `{at, inbound, expect}`. `inbound` is required; `inbound` and `expect` are per model, such as an HTTP request and its status. |
| `reads` | yes | One or more reads, in order: each `{at, native_path, principal, intent, operation, expect}`. |
| `must_not_call` | no | Names of hooks the source must not fire during the case, per model, such as `outbound` for a service provider, which never calls the identity system. |

The `at` of the steps and then of the reads never decreases.

A read calls `read_native_claim` with `native_path` and the context of draft section 17.1: `principal` is the identifier of the authenticated principal ([../../profiles/identity-mapping.md](../../profiles/identity-mapping.md), section 3.1), and `intent` and `operation`, optional, are an `Intent` and an `OperationContext`. Its `expect`:

| Member | Meaning |
|---|---|
| `outcome` | `value`: the read returns a claim. `error`: it returns an error. |
| `value` | The claim's value, compared as JSON data: object member order is ignored, array order is not (draft section 8.4). |
| `observed_at`, `status_checked_at` | Unix seconds, or `null` for a time the source does not give. |
| `source_id` | The source the claim names. |
| `reason_code` | For `error`, the error's draft 13.4 code, such as `MISSING_FIELD` for a principal the source holds no value for, `UNSUPPORTED_REQUIREMENT` for a path the source does not serve, or `DEPENDENCY_UNAVAILABLE` for a source that cannot answer. |

A member that is absent, or an empty string, is not checked.

## Checks

Besides what `expect` pins, every claim a read returns names its source, and neither of its times is later than the read's `at` plus the baseline clock skew of draft section 7.5 ("No source observation or status-check time may be later than now + clock_skew", draft Appendix A.2). An error that `reason_code` pins carries that code; the Go harness also requires it to wrap the sentinel of package `adapter` for that code. These are the checks [../adapters/README.md](../adapters/README.md) applies to `read_native_claim`.
