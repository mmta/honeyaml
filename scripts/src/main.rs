use version_compare::{ compare_to, Cmp };
use serde_derive::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
struct Config {
    package: Package,
}

#[derive(Deserialize)]
struct Package {
    version: String,
}

fn set_github_output(key: String, value: String) {
    let cmd_text = format!("echo {}={} >> $GITHUB_OUTPUT", key, value);
    Command::new("sh").arg("-c").arg(cmd_text).output().expect("failed to execute process");
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let path = &args[1];
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    let mut rel_tag = if let Ok(v) = std::env::var("REL_TAG") { v } else { "0".to_string() };
    rel_tag = rel_tag.replace("v", "");
    let should_release = compare_to(
        config.package.version.clone(),
        rel_tag,
        Cmp::Gt
    ).unwrap_or_default();
    println!("setting current_version to {}", config.package.version.clone());
    set_github_output("current_version".to_string(), config.package.version);
    println!("setting should_release to {}", should_release);
    set_github_output("should_release".to_string(), should_release.to_string());
    Ok(())
}