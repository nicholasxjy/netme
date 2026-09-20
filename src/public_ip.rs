use std::{
    io::{self, Read},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub const URLS: [&str; 2] = ["https://api.ipify.org", "https://api6.ipify.org"];
#[derive(Clone, Debug)]
pub struct Probe {
    pub at: Instant,
    pub generation: u64,
    pub via_proxy: bool,
    pub result: Result<IpAddr, String>,
}
#[derive(Default)]
pub struct Cache {
    entries: [Option<Probe>; 2],
    proxy: Option<ureq::Proxy>,
}
impl Cache {
    pub fn query(&mut self, family: usize, generation: u64) -> Probe {
        let proxy = match configured_proxy() {
            Ok(proxy) => proxy,
            Err(error) => {
                return Probe {
                    at: Instant::now(),
                    generation,
                    via_proxy: true,
                    result: Err(error),
                }
            }
        };
        if proxy != self.proxy {
            self.entries = [None, None];
            self.proxy = proxy.clone();
        }
        self.query_with(family, generation, |family| {
            fetch_from(URLS[family], family, proxy.as_ref())
        })
    }
    fn query_with(
        &mut self,
        family: usize,
        generation: u64,
        request: impl FnOnce(usize) -> Result<IpAddr, String>,
    ) -> Probe {
        if let Some(probe) = &self.entries[family] {
            if probe.result.is_ok()
                && probe.generation == generation
                && probe.at.elapsed() < Duration::from_secs(60)
            {
                return probe.clone();
            }
        }
        let probe = Probe {
            at: Instant::now(),
            generation,
            via_proxy: self.proxy.is_some(),
            result: request(family),
        };
        self.entries[family] = Some(probe.clone());
        probe
    }
}

fn proxy(value: &str) -> Result<ureq::Proxy, String> {
    // ureq's SOCKS5 already resolves the target at the proxy, like socks5h.
    let value = value.trim().replacen("socks5h://", "socks5://", 1);
    ureq::Proxy::new(value).map_err(|_| "invalid or unsupported proxy configuration".into())
}
fn env_proxy(lookup: impl Fn(&str) -> Option<String>) -> Option<Result<ureq::Proxy, String>> {
    [
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "http_proxy",
        "HTTP_PROXY",
    ]
    .into_iter()
    .find_map(|key| {
        lookup(key)
            .filter(|s| !s.trim().is_empty())
            .map(|s| proxy(&s))
    })
}
fn configured_proxy() -> Result<Option<ureq::Proxy>, String> {
    if let Some(proxy) = env_proxy(|name| std::env::var(name).ok()) {
        return proxy.map(Some);
    }
    #[cfg(target_os = "macos")]
    {
        let settings = crate::command::run("/usr/sbin/scutil", &["--proxy"])
            .map_err(|_| "cannot read system proxy configuration")?;
        system_proxy(&settings)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(None)
    }
}
#[cfg(any(target_os = "macos", test))]
fn system_proxy(settings: &str) -> Result<Option<ureq::Proxy>, String> {
    let field = |name: &str| {
        settings
            .lines()
            // Only the effective global dictionary, not nested scoped service settings.
            .filter(|line| line.starts_with("  ") && !line.starts_with("    "))
            .filter_map(|line| line.trim().split_once(" : "))
            .find_map(|(key, value)| (key == name).then_some(value))
    };
    for (prefix, scheme) in [("HTTPS", "http"), ("HTTP", "http"), ("SOCKS", "socks5")] {
        if field(&format!("{prefix}Enable")) != Some("1") {
            continue;
        }
        let host = field(&format!("{prefix}Proxy"))
            .filter(|s| !s.is_empty() && !s.contains(['/', '@', ' ', '\t']))
            .ok_or("invalid system proxy host")?;
        let port = field(&format!("{prefix}Port"))
            .and_then(|p| p.parse::<u16>().ok())
            .filter(|p| *p != 0)
            .ok_or("invalid system proxy port")?;
        return proxy(&format!("{scheme}://{host}:{port}")).map(Some);
    }
    if field("ProxyAutoConfigEnable") == Some("1") || field("ProxyAutoDiscoveryEnable") == Some("1")
    {
        return Err(
            "automatic proxy configuration requires an explicit HTTPS_PROXY or ALL_PROXY".into(),
        );
    }
    Ok(None)
}

fn fetch_from(url: &str, family: usize, proxy: Option<&ureq::Proxy>) -> Result<IpAddr, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let via_proxy = proxy.is_some();
    let mut builder = ureq::AgentBuilder::new()
        .try_proxy_from_env(false) // The explicit choice above also handles system proxies.
        .redirects(0)
        .timeout(Duration::from_secs(5))
        .timeout_connect(Duration::from_secs(5))
        .resolver(move |name: &str| {
            let name = name.to_owned();
            let (tx, rx) = mpsc::sync_channel(1);
            // A timed-out OS resolver can finish DNS, but never send HTTP later.
            thread::spawn(move || {
                let addresses = name.to_socket_addrs().map(|a| {
                    // Resolve the PROXY on either family, even for an IPv6 egress query.
                    a.filter(|s| via_proxy || s.is_ipv6() == (family == 1))
                        .collect::<Vec<SocketAddr>>()
                });
                let _ = tx.send(addresses);
            });
            rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS deadline"))?
        });
    if let Some(proxy) = proxy {
        builder = builder.proxy(proxy.clone());
    }
    // Do not silently retry direct after a configured proxy fails; that leaks the real egress.
    let response = builder.build().get(url).call().map_err(|_| {
        if via_proxy {
            "proxy public IP request failed"
        } else {
            "direct public IP request failed"
        }
    })?;
    if response.status() != 200 {
        return Err(format!("HTTP {} (redirects disabled)", response.status()));
    }
    let mut text = String::new();
    response
        .into_reader()
        .take(65)
        .read_to_string(&mut text)
        .map_err(|_| "invalid IP response body")?;
    parse(&text, family)
}
fn parse(text: &str, family: usize) -> Result<IpAddr, String> {
    if text.len() > 64 {
        return Err("response exceeds 64 bytes".into());
    }
    let ip: IpAddr = text
        .trim()
        .parse()
        .map_err(|_| "response is not an IP address")?;
    if ip.is_ipv6() != (family == 1) {
        return Err("response has wrong address family".into());
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
    };

    #[test]
    fn strict_parse_and_network_aware_cache() {
        assert!(parse("1.2.3.4", 0).is_ok());
        assert!(parse("::1\n", 1).is_ok());
        assert!(parse("1.2.3.4", 1).is_err());
        assert!(parse("<html>1.2.3.4</html>", 0).is_err());
        assert!(parse(&"x".repeat(65), 0).is_err());
        let mut cache = Cache::default();
        let first = cache.query_with(0, 1, |_| Ok("198.51.100.7".parse().unwrap()));
        let second = cache.query_with(0, 1, |_| panic!("must not retry within 60 seconds"));
        assert_eq!(first.at, second.at);
        assert!(cache
            .query_with(0, 2, |_| Ok("1.2.3.4".parse().unwrap()))
            .result
            .is_ok());
        cache.entries[0].as_mut().unwrap().at = Instant::now() - Duration::from_secs(61);
        assert!(cache
            .query_with(0, 2, |_| Err("offline".into()))
            .result
            .is_err());
    }
    #[test]
    fn failed_query_can_be_retried_immediately() {
        let mut cache = Cache::default();
        assert!(cache
            .query_with(0, 1, |_| Err("offline".into()))
            .result
            .is_err());
        let retry = cache.query_with(0, 1, |_| Ok("198.51.100.7".parse().unwrap()));
        assert_eq!(retry.result.unwrap().to_string(), "198.51.100.7");
    }
    #[test]
    fn environment_precedence_system_fallback_and_invalid_config() {
        let selected = env_proxy(|name| match name {
            "https_proxy" => Some("http://127.0.0.1:7890".into()),
            "ALL_PROXY" => Some("socks5://127.0.0.1:7891".into()),
            _ => None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(selected, proxy("http://127.0.0.1:7890").unwrap());
        assert!(env_proxy(|_| None).is_none());
        assert!(
            env_proxy(|_| Some("unsupported://user:secret@proxy".into()))
                .unwrap()
                .unwrap_err()
                .contains("unsupported")
        );
        assert_eq!(
            proxy("socks5h://localhost:1080"),
            proxy("socks5://localhost:1080")
        );
        assert_eq!(system_proxy("<dictionary> {\n  HTTPSEnable : 1\n  HTTPSProxy : 127.0.0.1\n  HTTPSPort : 7890\n}\n").unwrap(), Some(selected));
        assert!(system_proxy("  HTTPEnable : 0\n    HTTPSEnable : 1\n")
            .unwrap()
            .is_none());
        assert!(
            system_proxy("  SOCKSEnable : 1\n  SOCKSProxy : localhost\n  SOCKSPort : 1080\n")
                .unwrap()
                .is_some()
        );
        assert!(
            system_proxy("  HTTPSEnable : 1\n  HTTPSProxy : localhost\n  HTTPSPort : 99999\n")
                .is_err()
        );
        assert!(system_proxy("  ProxyAutoConfigEnable : 1\n").is_err());
    }
    #[test]
    fn ipv6_response_through_ipv4_http_proxy_without_target_dns() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = BufReader::new(stream);
            let mut request = String::new();
            loop {
                let mut line = String::new();
                assert!(stream.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            assert!(
                request.starts_with("GET http://no-dns.invalid/ "),
                "{request}"
            );
            stream.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n2001:db8::1").unwrap();
        });
        let proxy = proxy(&format!("http://{address}")).unwrap();
        // Plain HTTP is a local test seam only; production URLS are HTTPS with TLS verification.
        let result = fetch_from("http://no-dns.invalid/", 1, Some(&proxy));
        assert_eq!(result.unwrap().to_string(), "2001:db8::1");
        server.join().unwrap();
    }
    #[test]
    fn https_uses_connect_and_reports_proxy_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = BufReader::new(stream);
            let mut first = String::new();
            stream.read_line(&mut first).unwrap();
            assert_eq!(first, "CONNECT no-dns.invalid:443 HTTP/1.1\r\n");
            loop {
                let mut line = String::new();
                assert!(stream.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
            }
            stream
                .get_mut()
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
        });
        let proxy = proxy(&format!("http://{address}")).unwrap();
        assert_eq!(
            fetch_from("https://no-dns.invalid/", 0, Some(&proxy)).unwrap_err(),
            "proxy public IP request failed"
        );
        server.join().unwrap();
    }
    #[test]
    fn broken_proxy_does_not_retry_direct_or_expose_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = dead.local_addr().unwrap();
        drop(dead);
        let proxy = proxy(&format!("http://user:secret@{address}")).unwrap();
        let error = fetch_from(&format!("http://{target}/"), 0, Some(&proxy)).unwrap_err();
        assert_eq!(error, "proxy public IP request failed");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    #[ignore = "explicit online check using the configured proxy; contacts ipify"]
    fn live_public_ip_proxy_smoke() {
        assert!(
            configured_proxy().unwrap().is_some(),
            "configure a proxy for this check"
        );
        let probe = Cache::default().query(0, 0);
        assert!(probe.via_proxy);
        assert!(
            probe.result.as_ref().is_ok_and(|ip| ip.is_ipv4()),
            "proxy query failed: {:?}",
            probe.result.as_ref().err()
        );
        eprintln!("HTTPS public IPv4 obtained via configured proxy (address omitted)");
    }
}
