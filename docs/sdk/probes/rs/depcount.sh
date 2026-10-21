#!/bin/sh
# One scratch crate per candidate dependency line, resolved with cargo metadata (nothing is built).
# usage: depcount.sh <empty-dir>
D=$1; mkdir -p "$D"
while IFS='|' read -r label dep; do
  mkdir -p "$D/$label/src"; touch "$D/$label/src/lib.rs"
  printf '[package]\nname = "dc-%s"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\n%b\n' "$label" "$dep" > "$D/$label/Cargo.toml"
  printf '%-24s ' "$label"; python3 "$(dirname "$0")/depstat.py" "$D/$label" 2>/dev/null
done <<'LIST'
p256-ecdsa|p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }
p256-probe|p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa", "pkcs8", "getrandom"] }
p256-default|p256 = "=0.14.0"
p256-013-jwk|p256 = { version = "=0.13.2", default-features = false, features = ["ecdsa", "jwk"] }
sha2|sha2 = "=0.11.1"
ring|ring = "=0.17.14"
base64|base64 = "=0.23.1"
serde_json|serde_json = "=1.0.154"
serde_json-fr|serde_json = { version = "=1.0.154", features = ["float_roundtrip"] }
serde_json-ap|serde_json = { version = "=1.0.154", features = ["arbitrary_precision"] }
serde-derive|serde = { version = "=1.0.229", features = ["derive"] }
serde_jcs|serde_jcs = "=0.2.0"
serde_json_canonicalizer|serde_json_canonicalizer = "=0.4.1"
ryu|ryu = "=1.0.23"
jsonschema-nodefault|jsonschema = { version = "=0.58.6", default-features = false }
jsonschema-default|jsonschema = "=0.58.6"
boon|boon = "=0.6.1"
sdk-set-no-schema|p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }\nsha2 = "=0.11.1"\nbase64 = "=0.23.1"\nserde_json = { version = "=1.0.154", features = ["float_roundtrip"] }
sdk-set-jsonschema|p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }\nsha2 = "=0.11.1"\nbase64 = "=0.23.1"\nserde_json = { version = "=1.0.154", features = ["float_roundtrip"] }\njsonschema = { version = "=0.58.6", default-features = false }
sdk-set-boon|p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }\nsha2 = "=0.11.1"\nbase64 = "=0.23.1"\nserde_json = { version = "=1.0.154", features = ["float_roundtrip"] }\nboon = "=0.6.1"
LIST
