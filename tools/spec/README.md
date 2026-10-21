# tools/spec

Data for the spec checks of the Makefile.

| File | Used by |
|---|---|
| `requirements.txt` | the virtualenv `tools/spec/.venv` of `make spec-validate`, `make spec-examples` and `make spec-manifest` |
| `schema-dialect.json` | `make spec-validate`: the dialect that `spec/v1.0/schemas/pact.schema.json` must declare |
| `manifest-parity-cases.json` | `make spec-parity` (`scripts/check-manifest-parity.py`) and the ported manifest checkers |

## Manifest parity cases (format for ported checkers)

`manifest-parity-cases.json` lists broken copies of the spec tree, each made to trigger one rule of [spec/v1.0/fixtures/README.md](../../spec/v1.0/fixtures/README.md), and control copies that the rules allow. Every manifest checker reads the same table:

- `scripts/check-manifest-parity.py` (`make spec-parity`) runs the Python checks under `scripts/`, which stay the independent oracle, and `pactfix check manifest` on every copy. `--checker NAME=COMMAND` adds another checker, judged as `pactfix` is (see the script's help).
- A ported manifest module (TypeScript, Python) reads the table from its own test suite, applies each mutation to a scratch copy of the tree and checks its own result.

### What a checker does with a case

1. Copy `spec/v1.0/fixtures` (symbolic links kept as links), `spec/v1.0/spec-map.md` and `spec/v1.0/draft.md` into a scratch directory, at the same paths under a `spec/` directory.
2. Apply the steps of `mutation`, in order (below).
3. Run the checker on the copy. A case with a `rule` passes when the checker fails and reports that rule id, a rule id of `go/runner/manifest/problem.go`; a control (`rule` null) passes when the checker passes. A rule listed in `forbid` must not be reported. When `gap` is true the rule is one that only the Python oracle enforces: the checker must not report it.

The members `checker` and `label` are for the Python oracle only, which splits the rules between two scripts: `check-spec-manifest.py` prints the rule id, and `check-spec-map.py` prints the label of its check group instead (a `label` of null: it stops with exit status 2). A ported checker reports the rule id for both.

A step that does not fit the tree (no entry of the selected kind, a missing member, a `replace` string that does not occur, a file that exists already) is an error of the harness, not a result of the case.

### File

Strict JSON (the parse rules of draft Section 7.1, as `scripts/specjson.py` applies them), one object; unknown members are errors at every level.

| Member | Value |
|---|---|
| `version` | `1` |
| `cases` | array of cases, in the order the harness runs them |

A case:

| Member | Value |
|---|---|
| `id` | unique case name: lowercase ASCII letters, digits, `.` and `-` |
| `rule` | the rule id the copy triggers, or null for a control |
| `checker` | `manifest` (default) or `map`: the Python script that reports the rule; rule cases only |
| `label` | with `checker` `map` only, and required there: the check group label, or null |
| `forbid` | rule ids that the copy must not trigger (default none); rule cases only |
| `gap` | true for a rule only the Python oracle enforces (default false); rule cases only |
| `note` | free text |
| `mutation` | non-empty array of steps |

### Steps

Each step is an object with an `op` member. Steps run in order on one copy; each sees what the steps before it did.

A pointer is a JSON Pointer (RFC 6901) into the parsed `manifest.json`, with one addition: the segment after `/entries` may be an entry selector, `{kind}` for the first entry of that kind in file order or `{kind#n}` for the n-th (from 1). `/entries/{key}/path` is the path of the first `key` entry. The selectors of a step are resolved before the step runs.

| `op` | Members | Effect |
|---|---|---|
| `add`, `remove`, `replace`, `move`, `copy` | as in JSON Patch (RFC 6902): `path`, `value`, `from` | the JSON Patch operation on the manifest; `copy` takes an optional `apply` (transforms) for a string value |
| `insert-entry` | `set`, optional `like` | a new entry: a copy of the entry at the pointer `like` (or an empty object), with each member of `set` set to its value (an expression for a string, or a literal); inserted before the first entry whose id sorts after its id |
| `text` | `apply` | the transforms on the manifest text, which is from then on written as it stands |
| `write` | `file`, `text` | a new file with that text (UTF-8); parent directories created |
| `copy-file` | `source`, `file` | a new file with the text of `source` |
| `delete` | `file` | the file removed |
| `symlink` | `file`, `target` | a new symbolic link whose target is the string `target` |
| `map-group` | optional `group`, optional `status`, and one of `set_status` or `drop` (true) | the first row of the Fixture groups table of `spec/v1.0/spec-map.md` that has that group and that status gets the status `set_status`, or is removed |
| `map-line` | `line`, `text` | the one line of `spec/v1.0/spec-map.md` equal to `line` replaced by `text` |

File paths are `/`-separated and relative to `spec/v1.0/fixtures`. A file member (`file`, `source`) and the `group` of `map-group` are expressions:

- a JSON string, used as it is;
- `{"from": pointer, "apply": [transforms]}`: the string at the pointer, with the transforms applied (`apply` optional).

A transform is an array, its name then its arguments, applied left to right:

| Transform | Result |
|---|---|
| `["prepend", s]`, `["append", s]` | `s` added before or after |
| `["replace", old, new]` | every `old` replaced by `new`; `old` must occur |
| `["replace-first", old, new]` | the first `old` replaced by `new`; `old` must occur |
| `["upper"]`, `["lower"]` | ASCII letters changed to upper or lower case |
| `["dirname"]` | the text before the last `/`, which must occur |
| `["segment", n]` | the n-th `/`-separated segment, from 0 |

The manifest is written back when a manifest step ran, as two-space indented JSON with members in their order, non-ASCII characters as they are and a final newline: Python `json.dumps(doc, indent=2, ensure_ascii=False) + "\n"`, JavaScript `JSON.stringify(doc, null, 2) + "\n"`. The committed manifest is in that form already, so the text a `text` step starts from is the committed text with the changes of the steps before it. After a `text` step, no step may change the parsed manifest.

A Fixture groups row is a line of the section under the heading `## Fixture groups` that matches `^\| ([^|]+?) \|.*\| (planned|partial|landed) \|$`; the group is the first cell with backticks and spaces trimmed, the status the last cell.

### Example

The copy of `entry-path` with a backslash path, and a control that inserts a second key entry with its own key file:

```json
{
  "id": "path-backslash",
  "rule": "entry-path",
  "mutation": [
    {"op": "copy", "from": "/entries/{key}/path", "path": "/entries/{key}/path", "apply": [["replace", "/", "\\"]]}
  ]
},
{
  "id": "key-entry-null-expected",
  "rule": null,
  "mutation": [
    {"op": "copy-file", "source": {"from": "/entries/{key}/path"}, "file": {"from": "/entries/{key}/path", "apply": [["dirname"], ["append", "/zz-control.jwk.json"]]}},
    {"op": "insert-entry", "like": "/entries/{key}", "set": {"id": "keys/zz-control", "path": {"from": "/entries/{key}/path", "apply": [["dirname"], ["append", "/zz-control.jwk.json"]]}, "expected": null, "outcome": null}}
  ]
}
```

### Adding a case

A fixture change that alters a manifest rule adds the rule's case here in the same change ([docs/sdk/ports-plan.md](../../docs/sdk/ports-plan.md), section 5.4). A rule of `go/runner/manifest/problem.go` without a case, or a case naming a rule that file lacks, fails `make spec-parity`.
