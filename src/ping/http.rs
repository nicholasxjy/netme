use super::{
    diagnose, event,
    proxy::{Kind, Proxy},
    target::Target,
    Context, Failure, PingOptions, Result,
};
use crate::command::stream::{Lines, Message, Process};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Seek, Write},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct Capabilities {
    http2: bool,
}
pub fn capabilities(c: &mut Context<'_>) -> Result<Capabilities> {
    let bytes = diagnose::collect(
        c,
        "curl",
        &["--disable".into(), "--version".into()],
        Duration::from_secs(2),
        16384,
    )
    .map_err(|e| {
        if e.code >= 128 || e.code == 0 {
            e
        } else {
            Failure::config("HTTP(S) requires system curl >= 7.88 with HTTP/HTTPS support")
        }
    })?;
    let text = String::from_utf8_lossy(&bytes);
    let version = text
        .lines()
        .next()
        .and_then(|s| s.split_whitespace().nth(1))
        .unwrap_or_default();
    let parts: Vec<u32> = version.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() < 2
        || (parts[0], parts[1]) < (7, 88)
        || !text.lines().any(|l| {
            l.starts_with("Protocols:")
                && l.split_whitespace().any(|s| s == "http")
                && l.split_whitespace().any(|s| s == "https")
        })
    {
        return Err(Failure::config("curl >= 7.88 with HTTP/HTTPS is required"));
    }
    let http2 = text
        .lines()
        .any(|l| l.starts_with("Features:") && l.split_whitespace().any(|s| s == "HTTP2"));
    c.emit("capability",format!("curl={version}; HTTP/1.1 available; HTTP/2={http2}; HTTP/3 disabled; TLS verification required"))?;
    c.emit("TLS","certificate/TLS/ALPN fields are shown only when supplied by curl; missing fields=unknown (backend-dependent)")?;
    Ok(Capabilities { http2 })
}
pub struct BodyFile {
    pub partial: PathBuf,
    final_path: PathBuf,
    file: File,
}
impl BodyFile {
    pub fn create(path: &Path) -> Result<Self> {
        let mut partial = path.as_os_str().to_os_string();
        partial.push(".partial");
        let partial = PathBuf::from(partial);
        if path
            .try_exists()
            .map_err(|_| Failure::config("cannot check output path"))?
        {
            return Err(Failure::config(
                "--output file already exists; refusing overwrite",
            ));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&partial)
            .map_err(|_| Failure::config("cannot create output .partial file (must not exist)"))?;
        Ok(Self {
            partial,
            final_path: path.to_owned(),
            file,
        })
    }
    fn reset(&mut self) -> Result<()> {
        self.file
            .set_len(0)
            .and_then(|_| self.file.rewind())
            .map_err(|_| Failure::incomplete("cannot reset partial body file"))
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.file
            .write_all(bytes)
            .map_err(|_| Failure::incomplete("body file write failed; output remains partial"))
    }
    fn complete(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|_| Failure::incomplete("body file sync failed; output remains partial"))?;
        // hard_link is atomic and fails if destination exists; rename could overwrite a racer.
        fs::hard_link(&self.partial, &self.final_path).map_err(|_| {
            Failure::incomplete("cannot publish body file without overwriting; remains partial")
        })?;
        fs::remove_file(&self.partial)
            .map_err(|_| Failure::incomplete("body saved but cannot remove partial link"))
    }
}
fn config_line(config: &mut String, name: &str, value: &str) {
    config.push_str(name);
    config.push_str(" = \"");
    for c in value.chars() {
        match c {
            '\\' => config.push_str("\\\\"),
            '"' => config.push_str("\\\""),
            '\n' => config.push_str("\\n"),
            '\r' => config.push_str("\\r"),
            '\t' => config.push_str("\\t"),
            _ => config.push(c),
        }
    }
    config.push_str("\"\n");
}
fn config(
    o: &PingOptions,
    target: &Target,
    proxy: Option<&Proxy>,
    addresses: &[SocketAddr],
    candidate: usize,
    http2: bool,
    remaining: Duration,
) -> String {
    let mut s = String::from("silent\nshow-error\nverbose\nno-buffer\ncompressed\n");
    config_line(&mut s, "url", target.url.as_str());
    config_line(&mut s, "request", "GET");
    config_line(&mut s, "proto", "=http,https");
    config_line(&mut s, "proto-redir", "=http,https");
    config_line(
        &mut s,
        "max-time",
        &format!("{:.3}", remaining.as_secs_f64()),
    );
    config_line(
        &mut s,
        "connect-timeout",
        &format!("{:.3}", o.connect_timeout.min(remaining).as_secs_f64()),
    );
    config_line(&mut s, "noproxy", "");
    if http2 && target.url.scheme() == "https" {
        s.push_str("http2\n");
    } else {
        s.push_str("http1.1\n");
    }
    if let Some(path) = &o.cacert {
        config_line(&mut s, "cacert", &path.to_string_lossy());
    }
    if let Some(p) = proxy {
        let addr = addresses[candidate];
        config_line(
            &mut s,
            "proxy",
            &format!(
                "{}://{addr}",
                if p.kind == Kind::Http {
                    "http"
                } else {
                    "socks5h"
                }
            ),
        );
        if p.authenticated() {
            config_line(
                &mut s,
                "proxy-user",
                &format!("{}:{}", p.username, p.password),
            );
        }
    } else {
        config_line(&mut s, "proxy", "");
        // libcurl's --resolve preserves Host, TLS verification name and SNI.
        if target.host.parse::<std::net::IpAddr>().is_err() {
            let candidates = addresses
                .iter()
                .map(|a| {
                    if a.is_ipv6() {
                        format!("[{}]", a.ip())
                    } else {
                        a.ip().to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            config_line(
                &mut s,
                "resolve",
                &format!("{}:{}:{candidates}", target.host, target.port),
            );
        }
    }
    // Body is stdout; verbose and the independently marked final JSON are stderr.
    config_line(&mut s, "write-out", "%{stderr}\nNETME_METRICS:%{json}\n");
    s
}
#[derive(Default)]
struct Headers {
    status: Option<u16>,
    location: Option<String>,
    block: usize,
    total: usize,
    response_started: bool,
    sent: bool,
    connected: bool,
    body_ready: bool,
    last_sensitive: bool,
    metrics: Option<serde_json::Value>,
}
impl Headers {
    fn line(&mut self, c: &mut Context<'_>, line: &str) -> Result<()> {
        if let Some(json) = line.strip_prefix("NETME_METRICS:") {
            self.metrics =
                Some(serde_json::from_str(json).map_err(|_| {
                    Failure::incomplete("invalid curl metrics (raw data suppressed)")
                })?);
            return Ok(());
        }
        if let Some(header) = line.strip_prefix("< ").or_else(|| line.strip_prefix("> ")) {
            let incoming = line.starts_with('<');
            self.total += header.len() + 2;
            self.block += header.len() + 2;
            if self.block > 65536 || self.total > 1024 * 1024 {
                return Err(Failure::failed(
                    "HTTP header limit exceeded (64 KiB/block, 1 MiB total)",
                ));
            }
            if incoming && header.starts_with("HTTP/") {
                if !self.response_started {
                    c.emit(
                        "first-byte",
                        "response header observed; exact curl TTFB follows in metrics",
                    )?;
                }
                self.response_started = true;
                self.status = header
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok());
                self.location = None;
                self.body_ready = false;
            }
            if !incoming {
                self.sent = true;
            }
            if header.is_empty() {
                self.block = 0;
                if incoming {
                    self.body_ready = true;
                }
                self.last_sensitive = false;
                return Ok(());
            }
            let safe = if header.starts_with([' ', '\t']) {
                "[folded header redacted]".into()
            } else {
                event::header(header)
            };
            self.last_sensitive = header
                .split_once(':')
                .is_some_and(|(name, _)| event::sensitive(name));
            if incoming {
                if let Some((key, value)) = header.split_once(':') {
                    if key.eq_ignore_ascii_case("location") {
                        if self.location.is_some() {
                            return Err(Failure::failed("multiple Location headers are ambiguous"));
                        }
                        self.location = Some(value.trim().to_owned());
                    }
                }
            }
            c.emit(if incoming { "response" } else { "request" }, safe)?;
            return Ok(());
        }
        if line == "<" || line == ">" {
            self.block = 0;
            self.body_ready |= line == "<";
            return Ok(());
        }
        if let Some(info) = line.strip_prefix("* ") {
            let info = info.trim();
            let phase = if info.starts_with("Trying ")
                || info.starts_with("Connected to ")
                || info.starts_with("connect to ")
            {
                if info.starts_with("Connected to ") {
                    self.connected = true;
                }
                Some("connection")
            } else if info.starts_with("CONNECT ")
                || info.starts_with("SOCKS5 ")
                || info.starts_with("Establish HTTP proxy tunnel")
            {
                self.connected = true;
                Some("proxy")
            } else if [
                "SSL connection using",
                "TLSv",
                "ALPN:",
                "Server certificate:",
                "subject:",
                "issuer:",
                "start date:",
                "expire date:",
                "SSL certificate verify",
                "SSL certificate verification",
            ]
            .iter()
            .any(|s| info.starts_with(s))
            {
                self.connected = true;
                Some("TLS")
            } else {
                None
            };
            if let Some(phase) = phase {
                c.emit(phase, info)?;
            }
        }
        // Never forward unknown verbose lines or curl errors (can contain credentials).
        Ok(())
    }
}
struct Body {
    preview: Vec<u8>,
    bytes: u64,
    last: Instant,
    started: Instant,
}
impl Body {
    fn new() -> Self {
        Self {
            preview: vec![],
            bytes: 0,
            last: Instant::now(),
            started: Instant::now(),
        }
    }
    fn chunk(
        &mut self,
        c: &mut Context<'_>,
        o: &PingOptions,
        bytes: &[u8],
        total: &mut u64,
        file: &mut Option<BodyFile>,
        save: bool,
    ) -> Result<()> {
        let allowed = if o.max_bytes == 0 {
            bytes.len()
        } else {
            bytes.len().min(o.max_bytes.saturating_sub(*total) as usize)
        };
        if self.bytes == 0 && !bytes.is_empty() {
            c.emit(
                "body",
                "receiving body stream (preview is bounded, download continues)",
            )?;
        }
        self.bytes += allowed as u64;
        *total += allowed as u64;
        let preview = allowed.min(o.preview_bytes.saturating_sub(self.preview.len()));
        self.preview.extend_from_slice(&bytes[..preview]);
        if save {
            if let Some(f) = file {
                f.write(&bytes[..allowed])?;
            }
        }
        if self.last.elapsed() >= Duration::from_millis(500) {
            self.last = Instant::now();
            c.emit(
                "progress",
                format!(
                    "decoded={} bytes cumulative={} bytes elapsed={:.3}s",
                    self.bytes,
                    total,
                    self.started.elapsed().as_secs_f64()
                ),
            )?;
        }
        if allowed < bytes.len() {
            return Err(Failure::incomplete(
                "HTTP cumulative body limit exceeded; transfer/output partial",
            ));
        }
        Ok(())
    }
    fn report(&self, c: &mut Context<'_>) -> Result<()> {
        c.emit(
            "body",
            format!(
                "decoded={} bytes; preview={} bytes (may contain business secrets); {}",
                self.bytes,
                self.preview.len(),
                event::preview(&self.preview)
            ),
        )
    }
}
struct Hop {
    status: u16,
    location: Option<String>,
}
#[allow(clippy::too_many_arguments)]
fn transfer(
    c: &mut Context<'_>,
    o: &PingOptions,
    target: &Target,
    proxy: Option<&Proxy>,
    addresses: &[SocketAddr],
    caps: &Capabilities,
    bytes: &mut u64,
    header_total: &mut usize,
    file: &mut Option<BodyFile>,
) -> Result<Hop> {
    for candidate in 0..if proxy.is_some() { addresses.len() } else { 1 } {
        c.check()?;
        c.emit("connection",format!("curl connection start; endpoint candidates={}; fresh connection; no resource retries",if proxy.is_some(){addresses[candidate].to_string()}else{addresses.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")}))?;
        let cfg = config(
            o,
            target,
            proxy,
            addresses,
            candidate,
            caps.http2,
            c.deadline.saturating_duration_since(Instant::now()),
        );
        let mut process = Process::spawn(
            "curl",
            &["--disable".into(), "--config".into(), "-".into()],
            cfg.into_bytes(),
            true,
        )
        .map_err(|_| Failure::config("cannot start curl"))?;
        let mut lines = Lines::new(1024 * 1024);
        let mut headers = Headers {
            total: *header_total,
            ..Default::default()
        };
        let mut body = Body::new();
        let mut pending = Vec::new();
        let result = (|| -> Result<i32> {
            loop {
                c.check()?;
                for message in process
                    .poll()
                    .map_err(|_| Failure::incomplete("curl pipe IO failed"))?
                {
                    match message {
                        Message::Stderr(data) => {
                            for line in lines.push(&data).map_err(Failure::incomplete)? {
                                headers.line(c, &line)?;
                            }
                        }
                        Message::Stdout(data) => {
                            if pending.len() + data.len() > 1024 * 1024 {
                                return Err(Failure::failed(
                                    "body arrived without bounded response headers",
                                ));
                            }
                            pending.extend(data);
                        }
                    }
                }
                if headers.body_ready && !pending.is_empty() {
                    let save = !(o.follow
                        && redirect(headers.status.unwrap_or(0))
                        && headers.location.is_some());
                    body.chunk(c, o, &pending, bytes, file, save)?;
                    pending.clear();
                }
                if let Some(status) = process.finished() {
                    if let Some(line) = lines.finish() {
                        headers.line(c, &line)?;
                    }
                    if !pending.is_empty() {
                        return Err(Failure::incomplete(
                            "missing response headers for received body",
                        ));
                    }
                    return Ok(status.code().unwrap_or(1));
                }
                c.pause()?;
            }
        })();
        *header_total = headers.total;
        body.report(c)?;
        let exit = result?;
        let metrics = headers.metrics.as_ref().ok_or_else(|| {
            Failure::incomplete("curl omitted final metrics; output remains partial")
        })?;
        metrics_event(c, metrics, body.bytes)?;
        if exit != 0 {
            // Only failure to establish TCP permits another proxy IP; never resend a request.
            if proxy.is_some()
                && exit == 7
                && !headers.connected
                && metrics.get("time_connect").and_then(|v| v.as_f64()) == Some(0.0)
                && !headers.sent
                && body.bytes == 0
                && candidate + 1 < addresses.len()
            {
                c.emit("connection","proxy TCP connection not established; trying next resolved proxy IP (never direct)")?;
                continue;
            }
            let reason = match exit {
                5 | 6 => "DNS failure",
                7 => "connection failure",
                18 => "truncated response",
                28 => "deadline exceeded",
                35 => "TLS handshake failure",
                60 | 77 => "TLS certificate verification/CA failure",
                97 => "proxy negotiation failure",
                _ => "request/transfer failure",
            };
            return Err(if matches!(exit, 18 | 28 | 23) {
                Failure::incomplete(format!(
                    "curl exit={exit}: {reason}; response/output partial"
                ))
            } else {
                Failure::failed(format!(
                    "curl exit={exit}: {reason}; no direct fallback or resource retry"
                ))
            });
        }
        let status = metrics
            .get("response_code")
            .or_else(|| metrics.get("http_code"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        if !(100..=599).contains(&status) {
            return Err(Failure::failed("no valid HTTP response status"));
        }
        return Ok(Hop {
            status,
            location: headers.location,
        });
    }
    Err(Failure::failed("all proxy connection candidates failed"))
}
fn metrics_event(c: &mut Context<'_>, v: &serde_json::Value, decoded: u64) -> Result<()> {
    let string = |key: &str| v.get(key).and_then(|v| v.as_str()).unwrap_or("unknown");
    let number = |key: &str| {
        v.get(key)
            .and_then(|v| v.as_f64())
            .map(|n| format!("{n:.6}"))
            .unwrap_or_else(|| "unknown".into())
    };
    if let (Ok(ip), Some(port)) = (
        string("remote_ip").parse(),
        v.get("remote_port").and_then(|v| v.as_u64()),
    ) {
        if port <= u16::MAX as u64 {
            c.endpoint(SocketAddr::new(ip, port as u16))?;
        }
    }
    c.emit("metrics",format!("HTTP/{} local={}:{} peer={}:{}; curl cumulative timings: connect={}s TLS/negotiation={}s pretransfer={}s first-byte={}s total={}s (not additive; proxy stages may be combined)",string("http_version"),string("local_ip"),number("local_port"),string("remote_ip"),number("remote_port"),number("time_connect"),number("time_appconnect"),number("time_pretransfer"),number("time_starttransfer"),number("time_total")))?;
    c.emit("metrics",format!("received body (encoded)={} bytes; decoded={decoded} bytes; download={} B/s; request={} bytes; TLS verify-result={} (0=success for TLS; not proof of TLS on HTTP)",number("size_download"),number("speed_download"),number("size_request"),number("ssl_verify_result")))
}
fn redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}
pub fn run(
    c: &mut Context<'_>,
    o: &PingOptions,
    proxy: Option<&Proxy>,
    mut addresses: Vec<SocketAddr>,
    caps: Capabilities,
    file: &mut Option<BodyFile>,
) -> Result<()> {
    let mut target = o.target.clone();
    let mut visited = HashSet::new();
    let mut bytes = 0;
    let mut header_total = 0;
    for hop in 0..=10 {
        c.hop = hop;
        c.check()?;
        c.redactor.url(&target.url);
        if !visited.insert(target.url.to_string()) {
            return Err(Failure::failed("redirect loop detected"));
        }
        c.emit(
            "HTTP",
            format!(
                "GET {}; connection={} (fresh per hop)",
                event::display_url(&target.url),
                hop + 1
            ),
        )?;
        let result = transfer(
            c,
            o,
            &target,
            proxy,
            &addresses,
            &caps,
            &mut bytes,
            &mut header_total,
            file,
        )?;
        if o.follow && redirect(result.status) {
            if let Some(location) = result.location {
                if hop == 10 {
                    return Err(Failure::failed("redirect limit (10) exceeded"));
                }
                let authority = location
                    .strip_prefix("//")
                    .or_else(|| location.split_once("://").map(|(_, rest)| rest));
                if location.is_empty()
                    || location.chars().any(char::is_control)
                    || authority.is_some_and(|a| {
                        a.split(['/', '?', '#'])
                            .next()
                            .unwrap_or_default()
                            .contains('@')
                    })
                {
                    return Err(Failure::failed("invalid redirect Location"));
                }
                let url = target
                    .url
                    .join(&location)
                    .map_err(|_| Failure::failed("invalid redirect Location"))?;
                let next = Target::parse(url.as_str()).map_err(|_| {
                    Failure::failed("redirect has invalid target/userinfo/protocol")
                })?;
                if !next.protocol.http() {
                    return Err(Failure::failed("redirect to non-HTTP(S) protocol refused"));
                }
                if target.url.scheme() == "https" && next.url.scheme() == "http" {
                    return Err(Failure::failed("HTTPS to HTTP downgrade refused"));
                }
                c.redactor.url(&next.url);
                c.emit(
                    "redirect",
                    format!(
                        "status={} {} -> {}",
                        result.status,
                        event::display_url(&target.url),
                        event::display_url(&next.url)
                    ),
                )?;
                if visited.contains(next.url.as_str()) {
                    return Err(Failure::failed("redirect loop detected"));
                }
                if let Some(f) = file {
                    f.reset()?;
                }
                c.emit("redirect", "auxiliary diagnostics are not repeated; earlier probes apply only to the initial preferred endpoint")?;
                addresses = c.prepare(o, &next, proxy, false)?;
                target = next;
                continue;
            }
        }
        if let Some(f) = file {
            f.complete()?;
            c.emit(
                "output",
                format!("complete final body saved: {}", f.final_path.display()),
            )?;
        }
        c.emit("result",format!("final={} status={} redirects={hop} cumulative-decoded={bytes} bytes; network responded",event::display_url(&target.url),result.status))?;
        if result.status >= 400 {
            return Err(Failure::failed(format!(
                "network responded; application HTTP status {} failed",
                result.status
            )));
        }
        return Ok(());
    }
    unreachable!()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stdin_configuration_is_quoted_and_not_shell() {
        let mut s = String::new();
        config_line(&mut s, "proxy-user", "u:p\"\\\n");
        assert_eq!(s, "proxy-user = \"u:p\\\"\\\\\\n\"\n");
    }
}
