use super::target::{Protocol, Target};
use std::{collections::HashSet, io::Write, path::PathBuf, time::Duration};

pub const HELP: &str = "netme ping — live resource-access diagnostics (no TTY required)
Usage: netme ping <target> [options]
Targets: domain/IP (HTTPS), http(s)://host/path, tcp://host:port,
         udp://host:port, icmp://host, trace://host. IPv6 ports require [].

Path:       --direct | --proxy URL (http, socks5, socks5h; optional user:password)
Diagnostics: --no-diagnose  --max-hops N (1-255)  --trace-timeout S (default 15)
Deadlines:  --timeout S (60)  --connect-timeout S (5)  --reply-timeout S (5)
Family:     --ipv4 | --ipv6 (local connections only, not proxy-side targets)
TCP/UDP:    --data TEXT | --data-hex HEX (no added newline; UDP requires data)
HTTP:       --no-follow  --cacert FILE  --preview-bytes N (4096; max 1 MiB)
            --max-bytes N (16 MiB; 0 = unlimited)  --output FILE
Capture:    --capture  --interface NAME  --pcap FILE (implies capture)
Display:    --ascii  --help (NO_COLOR respected; output is plain text)

Defaults send 3 ICMP probes and UDP traceroute probes BEFORE accessing the
resource. These probes describe only the preferred local connection endpoint,
not necessarily the resource path. --no-diagnose disables them.
Proxy order: explicit choice, https_proxy/HTTPS_PROXY, all_proxy/ALL_PROXY,
http_proxy/HTTP_PROXY, macOS manual proxy, direct. NO_PROXY is NOT used.
PAC is not executed. No fallback to direct. Both SOCKS5 spellings use remote
DNS. With a proxy only the PROXY is locally resolved/probed. Standalone ICMP
and trace require --direct if a proxy is configured.
Requires curl >= 7.88 for HTTP(S); ping/traceroute for auxiliary diagnostics.
Capture requires tcpdump permissions, never invokes sudo; --interface changes
capture only. Capture cannot reliably separate other processes using the same
endpoint; no TLS decryption or proxy-side visibility. --pcap preserves RAW
secrets (0600, no overwrite, max 100 MiB/100000 packets).
Headers/query values are redacted. Body previews, --output and --pcap may
contain secrets. Output is saved as FILE.partial until complete; files are
never overwritten. Redirects use new connections, max 10, no TLS downgrade.
HTTP headers: max 64 KiB/block, 1 MiB total. All waits have deadlines.
Exit: 0 success; 1 failure; 2 usage/capability; 3 unknown/incomplete;
      128+signal on termination. Auxiliary warnings do not fail a resource.
";

#[derive(Clone)]
pub struct PingOptions {
    pub target: Target,
    pub proxy: Option<String>,
    pub direct: bool,
    pub diagnose: bool,
    pub max_hops: u8,
    pub trace_timeout: Duration,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub reply_timeout: Duration,
    pub family: Option<bool>, // true = IPv6
    pub data: Option<Vec<u8>>,
    pub follow: bool,
    pub cacert: Option<PathBuf>,
    pub preview_bytes: usize,
    pub max_bytes: u64,
    pub output: Option<PathBuf>,
    pub capture: bool,
    pub interface: Option<String>,
    pub pcap: Option<PathBuf>,
    pub ascii: bool,
}
impl PingOptions {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Self>, String> {
        let args: Vec<_> = args.into_iter().collect();
        if args.iter().any(|s| s == "--help" || s == "-h") {
            let _ = write!(std::io::stdout(), "{HELP}");
            return Ok(None);
        }
        let mut o = Self {
            target: Target::parse("localhost").unwrap(),
            proxy: None,
            direct: false,
            diagnose: true,
            max_hops: 30,
            trace_timeout: Duration::from_secs(15),
            timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(5),
            reply_timeout: Duration::from_secs(5),
            family: None,
            data: None,
            follow: true,
            cacert: None,
            preview_bytes: 4096,
            max_bytes: 16 * 1024 * 1024,
            output: None,
            capture: false,
            interface: None,
            pcap: None,
            ascii: false,
        };
        let mut seen = HashSet::new();
        let mut target = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            if !arg.starts_with('-') {
                if target.replace(arg).is_some() {
                    return Err("exactly one target required".into());
                }
                continue;
            }
            if !seen.insert(arg.clone()) {
                return Err("duplicate option".into());
            }
            let mut value = || args.next().ok_or_else(|| format!("{arg} requires a value"));
            match arg.as_str() {
                "--proxy" => o.proxy = Some(value()?),
                "--direct" => o.direct = true,
                "--no-diagnose" => o.diagnose = false,
                "--max-hops" => {
                    o.max_hops = value()?
                        .parse::<u8>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or("--max-hops must be 1-255")?
                }
                "--timeout" => o.timeout = duration(&value()?)?,
                "--connect-timeout" => o.connect_timeout = duration(&value()?)?,
                "--reply-timeout" => o.reply_timeout = duration(&value()?)?,
                "--trace-timeout" => o.trace_timeout = duration(&value()?)?,
                "--ipv4" => o.family = Some(false),
                "--ipv6" => o.family = Some(true),
                "--data" => o.data = Some(value()?.into_bytes()),
                "--data-hex" => o.data = Some(hex(&value()?)?),
                "--no-follow" => o.follow = false,
                "--cacert" => o.cacert = Some(value()?.into()),
                "--preview-bytes" => {
                    o.preview_bytes = value()?
                        .parse()
                        .ok()
                        .filter(|n| *n <= 1024 * 1024)
                        .ok_or("preview limit must be 0-1048576")?
                }
                "--max-bytes" => {
                    o.max_bytes = value()?.parse().map_err(|_| "invalid byte limit")?
                }
                "--output" => o.output = Some(value()?.into()),
                "--capture" => o.capture = true,
                "--interface" => o.interface = Some(value()?),
                "--pcap" => {
                    o.capture = true;
                    o.pcap = Some(value()?.into());
                }
                "--ascii" => o.ascii = true,
                _ => return Err("unknown ping option; try netme ping --help".into()),
            }
        }
        o.target = Target::parse(&target.ok_or("target required; try netme ping --help")?)?;
        for (a, b) in [
            ("--direct", "--proxy"),
            ("--ipv4", "--ipv6"),
            ("--data", "--data-hex"),
        ] {
            if seen.contains(a) && seen.contains(b) {
                return Err(format!("{a} and {b} are mutually exclusive"));
            }
        }
        let p = o.target.protocol;
        for option in &seen {
            let valid = match option.as_str() {
                "--data" | "--data-hex" | "--reply-timeout" => {
                    matches!(p, Protocol::Tcp | Protocol::Udp)
                }
                "--no-follow" | "--cacert" | "--preview-bytes" | "--max-bytes" | "--output" => {
                    p.http()
                }
                "--no-diagnose" => !p.diagnostic(),
                "--max-hops" | "--trace-timeout" => {
                    p == Protocol::Trace || (!p.diagnostic() && o.diagnose)
                }
                "--interface" => o.capture,
                _ => true,
            };
            if !valid {
                return Err(format!("{option} is not applicable to this operation"));
            }
        }
        if p == Protocol::Udp && o.data.is_none() {
            return Err("UDP requires explicit --data or --data-hex (empty allowed)".into());
        }
        if o.data.as_ref().is_some_and(|d| d.len() > 65507) {
            return Err("payload exceeds 65507-byte limit".into());
        }
        if o.interface
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.starts_with('-') || s.chars().any(char::is_control))
        {
            return Err("invalid capture interface".into());
        }
        Ok(Some(o))
    }
}
fn duration(s: &str) -> Result<Duration, String> {
    let n: f64 = s
        .parse()
        .map_err(|_| "timeout must be positive seconds (max 86400)")?;
    if !n.is_finite() || !(0.001..=86400.).contains(&n) {
        return Err("timeout must be 0.001-86400 seconds".into());
    }
    Ok(Duration::from_secs_f64(n))
}
fn hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--data-hex requires pairs of hex digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex data".into()))
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validation() {
        for s in [
            "udp://localhost:1",
            "tcp://localhost:2 --no-follow",
            "host --ipv4 --ipv6",
            "host --direct --proxy x",
            "host --timeout NaN",
            "host --interface en0",
            "host --data x",
            "host --preview-bytes 1048577",
            "udp://host:2 --data-hex 0g",
        ] {
            assert!(
                PingOptions::parse(s.split_whitespace().map(str::to_owned)).is_err(),
                "{s}"
            );
        }
        let o = PingOptions::parse(["udp://host:2", "--data", ""].map(str::to_owned))
            .unwrap()
            .unwrap();
        assert_eq!(o.data, Some(vec![]));
    }
}
