//! End-to-end loopback and subprocess fixtures are shared with the standalone smoke script.
#[test]
fn local_ping_scenarios() {
    let output = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/ping_local.py"))
        .arg(env!("CARGO_BIN_EXE_netme"))
        .output()
        .expect("local ping tests require python3 and curl >= 7.88");
    assert!(
        output.status.success(),
        "local ping fixtures failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
