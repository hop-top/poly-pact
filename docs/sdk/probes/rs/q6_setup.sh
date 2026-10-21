#!/bin/sh
# Q6 setup: a scratch layout shaped like the poly-cite one: <dir>/spec/v1.0/fixtures (outside) and <dir>/rs (the crate). Run with an empty dir.
# usage: q6_setup.sh <empty-dir>
D=$1; mkdir -p "$D/spec/v1.0/fixtures" "$D/rs/src" "$D/rs/tests" "$D/rs/schema" && cd "$D/rs" || exit 1
echo '{"k":1}' > ../spec/v1.0/fixtures/contract.json; cp ../spec/v1.0/fixtures/contract.json schema/contract.json
printf '[package]\nname = "q6-probe"\nversion = "0.0.0"\nedition = "2021"\nlicense = "MIT"\ndescription = "scratch"\nrepository = "https://example.invalid/q6"\n' > Cargo.toml
printf 'include = ["Cargo.toml", "src/**", "tests/**", "schema/**", "../spec/v1.0/fixtures/**"]\n' >> Cargo.toml
echo 'pub fn inside() -> &'"'"'static str { include_str!("../schema/contract.json") }' > src/lib.rs
