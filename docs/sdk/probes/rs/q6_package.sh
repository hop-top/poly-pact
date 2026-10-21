#!/bin/sh
# Q6: does cargo package pick up ../spec through `include`, and does include_str! of an outside path survive verification?
# usage: q6_package.sh <dir from q6_setup.sh>
cd "$1/rs" || exit 1; P=target/package/q6-probe-0.0.0.crate;
echo '== A: cargo package --list, include has ../spec/v1.0/fixtures/**'; cargo package --list --offline --allow-dirty 2>&1
echo '== B: cargo package, include_str! of an in-crate path'; cargo package --offline --allow-dirty 2>&1 | tail -1; tar tzf $P
echo '== C: src/lib.rs also include_str!s ../../spec/v1.0/fixtures/contract.json'
echo 'pub fn outside() -> &'"'"'static str { include_str!("../../spec/v1.0/fixtures/contract.json") }' >> src/lib.rs
cargo package --offline --allow-dirty 2>&1 | tail -8
echo '== D: the outside include_str! only in tests/contract.rs'
sed -i.bak '$d' src/lib.rs && rm src/lib.rs.bak; echo 'const _: &str = include_str!("../../spec/v1.0/fixtures/contract.json");' > tests/contract.rs
cargo package --offline --allow-dirty 2>&1 | tail -3; tar tzf $P | grep -c spec
rm -rf ../x && mkdir ../x && tar xzf $P -C ../x && cd ../x/q6-probe-0.0.0 && echo '-- cargo test in the unpacked package:' && cargo test --offline 2>&1 | tail -14
