use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use std::process::Command; // Run programs

#[test]
fn cli_tests() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("honeyaml")?;
    cmd.arg("--help");
    cmd.assert().success().stdout(predicate::str::contains("Print version"));

    let mut cmd = Command::cargo_bin("honeyaml")?;
    cmd.arg("-f /tmp/foo");
    cmd.assert().failure().stderr(predicate::str::contains("cannot read"));

    Ok(())
}