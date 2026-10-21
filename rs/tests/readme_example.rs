//! The Usage section of README.md: its Rust program is examples/sign_verify.rs
//! verbatim, and the example prints the output the README shows.

use std::path::Path;
use std::process::Command;

const OUTPUT: &str = "requirement-publisher publisher-1 {\"pact_version\":\"0.1\",\"jti\":\"contract-1\"}\n\
J0GfvClw7hrBhHyvkkriLn5ZbdWqmdwQtBHF_DZCYo4\n";

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The fenced blocks of the Usage section: (language, body).
fn usage_blocks() -> Vec<(String, String)> {
    let readme = std::fs::read_to_string(root().join("README.md")).unwrap();
    let usage = readme.split("\n## Usage\n").nth(1).unwrap().split("\n## ").next().unwrap();
    let mut blocks = Vec::new();
    let mut lines = usage.lines();
    while let Some(line) = lines.next() {
        if let Some(lang) = line.strip_prefix("```") {
            let body: Vec<&str> = lines.by_ref().take_while(|l| *l != "```").collect();
            blocks.push((lang.to_string(), body.join("\n") + "\n"));
        }
    }
    blocks
}

#[test]
fn readme_shows_the_example() {
    let blocks = usage_blocks();
    let program = std::fs::read_to_string(root().join("examples/sign_verify.rs")).unwrap();
    assert_eq!(blocks[0], ("rust".to_string(), program));
    assert_eq!(blocks[1], ("text".to_string(), OUTPUT.to_string()));
}

#[test]
fn example_prints_the_readme_output() {
    // The cargo that runs the tests builds and runs the example.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["run", "--quiet", "--locked", "--example", "sign_verify"])
        .current_dir(root())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), OUTPUT);
}
