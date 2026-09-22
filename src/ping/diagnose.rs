use super::{Context, Failure, PingOptions, Result};
use crate::command::stream::{Lines, Message, Process};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

pub fn collect(
    c: &mut Context<'_>,
    program: &str,
    args: &[String],
    timeout: Duration,
    limit: usize,
) -> Result<Vec<u8>> {
    c.check()?;
    let mut process = Process::spawn(program, args, vec![], false)
        .map_err(|_| Failure::config(format!("{program} unavailable")))?;
    let until = c.until(timeout);
    let mut bytes = vec![];
    loop {
        c.check()?;
        for message in process
            .poll()
            .map_err(|_| Failure::failed("subprocess IO failed"))?
        {
            if let Message::Stdout(data) = message {
                if bytes.len() + data.len() > limit {
                    return Err(Failure::failed("command output limit exceeded"));
                }
                bytes.extend(data);
            }
        }
        if let Some(status) = process.finished() {
            return if status.success() {
                Ok(bytes)
            } else {
                Err(Failure::failed(format!("{program} exited unsuccessfully")))
            };
        }
        if Instant::now() >= until {
            return Err(Failure::incomplete(format!("{program} deadline exceeded")));
        }
        c.pause()?;
    }
}
pub fn route(c: &mut Context<'_>, addr: SocketAddr) -> Result<()> {
    c.emit(
        "route",
        format!(
            "querying local route to {} (not proxy remote route)",
            addr.ip()
        ),
    )?;
    #[cfg(target_os = "macos")]
    let result = collect(
        c,
        "/sbin/route",
        &[
            "-n".into(),
            "get".into(),
            if addr.is_ipv6() { "-inet6" } else { "-inet" }.into(),
            addr.ip().to_string(),
        ],
        Duration::from_secs(2),
        16384,
    )
    .map(|v| mac_route(&String::from_utf8_lossy(&v)));
    #[cfg(not(target_os = "macos"))]
    let result = collect(
        c,
        "ip",
        &[
            "-j".into(),
            if addr.is_ipv6() { "-6" } else { "-4" }.into(),
            "route".into(),
            "get".into(),
            addr.ip().to_string(),
        ],
        Duration::from_secs(2),
        16384,
    )
    .map(|v| linux_route(&v));
    match result {
        Ok(line) => c.emit("route", line),
        Err(_) => {
            c.check()?;
            c.warning("local route lookup unavailable; interface/source/gateway=unknown")
        }
    }
}
#[cfg(any(target_os = "macos", test))]
fn mac_route(text: &str) -> String {
    let field = |name: &str| {
        text.lines()
            .filter_map(|s| s.trim().split_once(':'))
            .find_map(|(k, v)| (k == name).then_some(v.trim()))
            .unwrap_or("unknown")
    };
    format!(
        "interface={} source={} gateway={}",
        field("interface"),
        field("source"),
        field("gateway")
    )
}
#[cfg(any(not(target_os = "macos"), test))]
fn linux_route(bytes: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();
    let field = |name: &str| {
        v.get(0)
            .and_then(|v| v.get(name))
            .and_then(|s| s.as_str())
            .unwrap_or("unknown")
    };
    format!(
        "interface={} source={} gateway={}",
        field("dev"),
        field("prefsrc"),
        field("gateway")
    )
}
pub fn probe(c: &mut Context<'_>, o: &PingOptions, ip: IpAddr, trace: bool) -> Result<()> {
    let phase = if trace { "traceroute" } else { "ICMP" };
    c.emit(
        phase,
        format!(
            "start target={ip}; auxiliary path is independent of resource traffic; {}",
            if trace {
                "UDP probes, reverse DNS disabled; no response return-path inference"
            } else {
                "3 echo probes"
            }
        ),
    )?;
    let (program, args) = probe_command(o, ip, trace);
    c.check()?;
    let mut process = Process::spawn(program, &args, vec![], false).map_err(|_| {
        Failure::config(format!(
            "{program} missing/unavailable; install the diagnostic tool"
        ))
    })?;
    let until = c.until(if trace {
        o.trace_timeout
    } else {
        Duration::from_secs(5)
    });
    let mut out = Lines::new(8192);
    let mut err = Lines::new(8192);
    let mut received = false;
    let mut unreachable = false;
    let mut total = 0;
    loop {
        c.check()?;
        for message in process
            .poll()
            .map_err(|_| Failure::failed("diagnostic pipe failed"))?
        {
            let (lines, data) = match message {
                Message::Stdout(data) => (&mut out, data),
                Message::Stderr(data) => (&mut err, data),
            };
            total += data.len();
            if total > 1024 * 1024 {
                return Err(Failure::incomplete("diagnostic output exceeded limit"));
            }
            for line in lines.push(&data).map_err(Failure::incomplete)? {
                if line.trim().is_empty() {
                    continue;
                }
                let observation = classify(&line, ip, trace);
                received |= observation.0;
                unreachable |= observation.1;
                c.emit(phase, line)?;
            }
        }
        if let Some(status) = process.finished() {
            for line in [out.finish(), err.finish()].into_iter().flatten() {
                c.emit(phase, line)?;
            }
            if unreachable {
                return Err(Failure::failed(
                    "diagnostic reported destination unreachable",
                ));
            }
            if received && (trace || status.success()) {
                return c.emit(phase, "complete; replies observed (probe result only)");
            }
            return Err(Failure::incomplete(format!("{phase}: no conclusive destination reply; filtering, permission or reachability unknown")));
        }
        if Instant::now() >= until {
            return Err(Failure::incomplete(format!(
                "{phase} deadline exceeded; no complete diagnostic result"
            )));
        }
        c.pause()?;
    }
}
fn probe_command(o: &PingOptions, ip: IpAddr, trace: bool) -> (&'static str, Vec<String>) {
    let mut args = vec!["-n".into()];
    #[cfg(target_os = "macos")]
    let program = match (trace, ip.is_ipv6()) {
        (false, false) => "ping",
        (false, true) => "ping6",
        (true, false) => "traceroute",
        (true, true) => "traceroute6",
    };
    #[cfg(not(target_os = "macos"))]
    let program = {
        if ip.is_ipv6() {
            args.push("-6".into());
        }
        if trace {
            "traceroute"
        } else {
            "ping"
        }
    };
    if trace {
        args.extend([
            "-m".into(),
            o.max_hops.to_string(),
            "-q".into(),
            "1".into(),
            "-w".into(),
            "1".into(),
        ]);
    } else {
        args.extend(["-c".into(), "3".into()]);
    }
    args.push(ip.to_string());
    (program, args)
}
fn classify(line: &str, ip: IpAddr, trace: bool) -> (bool, bool) {
    if trace {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.first().is_some_and(|w| w.parse::<u8>().is_ok()) {
            let unreachable = words.iter().any(|w| w.starts_with('!'));
            let arrived = words
                .iter()
                .any(|w| w.trim_matches(['(', ')']).parse::<IpAddr>() == Ok(ip));
            return (arrived && !unreachable, unreachable);
        }
        (false, false)
    } else {
        (
            line.contains("bytes from") && (line.contains("icmp_seq") || line.contains("seq=")),
            line.to_ascii_lowercase().contains("unreachable"),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn platform_fixtures() {
        let ip = "127.0.0.1".parse().unwrap();
        for line in [
            "64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.054 ms",
            "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.020 ms",
        ] {
            assert_eq!(classify(line, ip, false), (true, false));
        }
        assert_eq!(
            classify(
                "3 packets transmitted, 0 received, 100% packet loss",
                ip,
                false
            ),
            (false, false)
        );
        assert_eq!(classify(" 1 127.0.0.1 0.053 ms", ip, true), (true, false));
        assert_eq!(classify(" 1 *", ip, true), (false, false));
        assert_eq!(classify(" 1 127.0.0.1 0.2 ms !H", ip, true), (false, true));
        assert!(mac_route(" interface: lo0\n gateway: 127.0.0.1\n").contains("source=unknown"));
        assert!(linux_route(br#"[{"dev":"lo","prefsrc":"127.0.0.1"}]"#).contains("gateway=unknown"));
    }
}
