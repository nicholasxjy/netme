use std::{
    io::{self, Read},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;

pub fn run(program: &str, args: &[&str]) -> Result<String, String> {
    run_timeout(program, args, Duration::from_secs(2))
}

pub fn run_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    let stdout = child.stdout.take().ok_or("missing stdout")?;
    let stderr = child.stderr.take().ok_or("missing stderr")?;
    // Drain both pipes even beyond the cap, so a verbose child cannot deadlock.
    let out = thread::spawn(move || bounded_read(stdout));
    let err = thread::spawn(move || bounded_read(stderr));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                break Err(format!("{program}: timeout"));
            }
            Err(e) => {
                let _ = child.kill();
                break Err(format!("{program}: {e}"));
            }
        }
    };
    let _ = child.wait();
    let stdout = out.join().map_err(|_| "stdout reader panicked")?;
    let stderr = err.join().map_err(|_| "stderr reader panicked")?;
    let status = status?;
    if !status.success() {
        return Err(format!(
            "{program}: {status}: {}",
            crate::model::clean(&String::from_utf8_lossy(&stderr.unwrap_or_default()))
        ));
    }
    String::from_utf8(stdout.map_err(|e| format!("{program}: {e}"))?)
        .map_err(|e| format!("{program}: {e}"))
}

fn bounded_read(mut stream: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buf = [0; 8192];
    let mut overflow = false;
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if bytes.len() + n <= OUTPUT_LIMIT {
            bytes.extend_from_slice(&buf[..n]);
        } else {
            overflow = true;
        }
    }
    if overflow {
        Err(io::Error::other("output exceeds 4 MiB"))
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_failure_and_timeout() {
        assert!(run("/netme/nonexistent", &[]).is_err());
        assert!(run("false", &[]).is_err());
        let now = Instant::now();
        assert!(run_timeout("sleep", &["2"], Duration::from_millis(30))
            .unwrap_err()
            .contains("timeout"));
        assert!(now.elapsed() < Duration::from_secs(1));
        assert!(bounded_read(io::repeat(b'x').take((OUTPUT_LIMIT + 1) as u64)).is_err());
    }
}
