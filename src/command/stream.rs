//! Bounded, nonblocking child IO. No shell, detached readers or unbounded queues.
use std::{
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub enum Message {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}
pub struct Process {
    child: Child,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    stdin: Option<ChildStdin>,
    input: Vec<u8>,
    written: usize,
    status: Option<ExitStatus>,
    terminated: bool,
}
pub fn nonblocking(fd: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: fcntl only updates the flags of a live descriptor owned by the caller.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
impl Process {
    pub fn spawn(
        program: &str,
        args: &[String],
        input: Vec<u8>,
        clean_proxy: bool,
    ) -> io::Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if clean_proxy {
            for key in [
                "https_proxy",
                "HTTPS_PROXY",
                "http_proxy",
                "HTTP_PROXY",
                "all_proxy",
                "ALL_PROXY",
                "no_proxy",
                "NO_PROXY",
                "CURL_HOME",
                "SSLKEYLOGFILE",
            ] {
                cmd.env_remove(key);
            }
        }
        let mut child = cmd.spawn()?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let stdin = child.stdin.take();
        let p = Self {
            child,
            stdout,
            stderr,
            stdin,
            input,
            written: 0,
            status: None,
            terminated: false,
        };
        nonblocking(p.stdout.as_ref().unwrap())?;
        nonblocking(p.stderr.as_ref().unwrap())?;
        nonblocking(p.stdin.as_ref().unwrap())?;
        Ok(p)
    }
    pub fn poll(&mut self) -> io::Result<Vec<Message>> {
        if let Some(input) = &mut self.stdin {
            if self.written < self.input.len() {
                match input.write(&self.input[self.written..]) {
                    Ok(n) => self.written += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                        self.written = self.input.len()
                    }
                    Err(e) => return Err(e),
                }
            }
            if self.written == self.input.len() {
                self.stdin = None;
                self.input.fill(0);
                self.input.clear();
            }
        }
        let mut messages = Vec::new();
        drain(&mut self.stderr, &mut messages, Message::Stderr)?;
        drain(&mut self.stdout, &mut messages, Message::Stdout)?;
        self.status = self.child.try_wait()?;
        Ok(messages)
    }
    pub fn finished(&self) -> Option<ExitStatus> {
        if self.stdout.is_none() && self.stderr.is_none() {
            self.status
        } else {
            None
        }
    }
    pub fn terminate(&mut self) {
        if self.terminated {
            return;
        }
        self.terminated = true;
        // Negative pid targets the entire group, including descendants holding pipes.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGTERM);
        }
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.wait();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.terminate();
        self.input.fill(0);
    }
}
fn drain<T: Read>(
    pipe: &mut Option<T>,
    messages: &mut Vec<Message>,
    wrap: fn(Vec<u8>) -> Message,
) -> io::Result<()> {
    let Some(reader) = pipe else {
        return Ok(());
    };
    // Fairness: at most 64 KiB per pipe per tick.
    for _ in 0..8 {
        let mut buf = vec![0; 8192];
        match reader.read(&mut buf) {
            Ok(0) => {
                *pipe = None;
                break;
            }
            Ok(n) => {
                buf.truncate(n);
                messages.push(wrap(buf));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Incremental line framing: never emit partial secrets split between reads.
pub struct Lines {
    bytes: Vec<u8>,
    limit: usize,
}
impl Lines {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: vec![],
            limit,
        }
    }
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<String>, &'static str> {
        let mut lines = vec![];
        for b in chunk {
            if *b == b'\n' {
                lines.push(
                    String::from_utf8_lossy(&self.bytes)
                        .trim_end_matches('\r')
                        .to_owned(),
                );
                self.bytes.clear();
            } else {
                if self.bytes.len() >= self.limit {
                    return Err("subprocess line exceeds limit");
                }
                self.bytes.push(*b);
            }
        }
        Ok(lines)
    }
    pub fn finish(&mut self) -> Option<String> {
        if self.bytes.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&std::mem::take(&mut self.bytes)).into_owned())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drain_both_pipes_and_reap_group() {
        let mut p = Process::spawn(
            "sh",
            &[
                "-c".into(),
                "i=0; while [ $i -lt 10000 ]; do echo out; echo err >&2; i=$((i+1)); done".into(),
            ],
            vec![],
            false,
        )
        .unwrap();
        let start = Instant::now();
        let mut n = [0, 0];
        loop {
            for m in p.poll().unwrap() {
                match m {
                    Message::Stdout(v) => n[0] += v.len(),
                    Message::Stderr(v) => n[1] += v.len(),
                }
            }
            if let Some(s) = p.finished() {
                assert!(s.success());
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(5));
        }
        assert_eq!(n, [40000, 40000]);
        let start = Instant::now();
        let p = Process::spawn(
            "sh",
            &["-c".into(), "sleep 30 & wait".into()],
            vec![],
            false,
        )
        .unwrap();
        drop(p);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn bounded_split_lines() {
        let mut l = Lines::new(20);
        assert!(l.push(b"Authoriz").unwrap().is_empty());
        assert_eq!(l.push(b"ation: x\r\n").unwrap(), ["Authorization: x"]);
        assert!(l.push(&[b'x'; 21]).is_err());
    }
}
