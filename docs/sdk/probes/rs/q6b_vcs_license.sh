#!/bin/sh
# Q6 (git tree, readme and license-file outside the crate). usage: q6b_vcs_license.sh <dir already used by q6_package.sh>
cd "$1" || exit 1;
echo '# probe' > README.md; echo MIT > LICENSE; printf 'target/\nx/\n' > .gitignore
/usr/bin/git init -q . && /usr/bin/git add -A && /usr/bin/git -c user.name=probe -c user.email=probe@example.invalid commit -qm scratch
cd rs || exit 1
echo '== E: clean git tree, cargo package --list'; cargo package --list --offline 2>&1
sed -i.bak 's|^include = .*|&\nreadme = "../README.md"\nlicense-file = "../LICENSE"|; /^license = /d' Cargo.toml && rm Cargo.toml.bak
echo '== F: readme and license-file point outside the crate'; cargo package --list --offline --allow-dirty 2>&1
cargo package --offline --allow-dirty 2>&1 | tail -1; tar xzOf target/package/q6-probe-0.0.0.crate q6-probe-0.0.0/Cargo.toml | grep 'readme\|license'
