use std::net::IpAddr;
use url::{Host, Url};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
    Tcp,
    Udp,
    Icmp,
    Trace,
}
impl Protocol {
    pub fn http(self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }
    pub fn diagnostic(self) -> bool {
        matches!(self, Self::Icmp | Self::Trace)
    }
}
#[derive(Clone, Debug)]
pub struct Target {
    pub url: Url,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
}
impl Target {
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.is_empty()
            || input.len() > 16384
            || input.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(
                "invalid target (empty, over 16 KiB, whitespace or control character)".into(),
            );
        }
        let expanded;
        let input = if input.contains("://") {
            input
        } else {
            expanded = if let Ok(ip) = input.parse::<IpAddr>() {
                match ip {
                    IpAddr::V6(ip) => format!("https://[{ip}]/"),
                    _ => format!("https://{ip}/"),
                }
            } else {
                format!("https://{input}")
            };
            &expanded
        };
        let authority = input
            .split_once("://")
            .ok_or("invalid target")?
            .1
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority.contains('@') || authority.contains('%') {
            return Err("resource userinfo and IPv6 zone IDs are not supported".into());
        }
        if authority.ends_with(':') {
            return Err("invalid target port".into());
        }
        let mut url = Url::parse(input)
            .map_err(|_| "invalid target URL or port (IPv6 ports require brackets)")?;
        let protocol = match url.scheme() {
            "http" => Protocol::Http,
            "https" => Protocol::Https,
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "icmp" => Protocol::Icmp,
            "trace" => Protocol::Trace,
            _ => return Err("unsupported target protocol".into()),
        };
        let raw_host = url.host_str().ok_or("target requires a host")?;
        let host = match Host::parse(raw_host).map_err(|_| "invalid target host")? {
            Host::Domain(s) => s,
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        };
        if host.is_empty() {
            return Err("target requires a host".into());
        }
        let port = if protocol.diagnostic() {
            if url.port().is_some() {
                return Err("ICMP/traceroute targets do not accept ports".into());
            }
            0
        } else {
            url.port_or_known_default()
                .ok_or("TCP/UDP targets require an explicit port")?
        };
        if port == 0 && !protocol.diagnostic() {
            return Err("port must be 1-65535".into());
        }
        if !protocol.http()
            && (!matches!(url.path(), "" | "/")
                || url.query().is_some()
                || url.fragment().is_some())
        {
            return Err("only HTTP(S) targets accept a path, query or fragment".into());
        }
        // Non-special URL schemes do not automatically apply IDNA.
        if !protocol.http() && host.parse::<IpAddr>().is_err() {
            url.set_host(Some(&host))
                .map_err(|_| "invalid target host")?;
        }
        url.set_fragment(None);
        Ok(Self {
            url,
            protocol,
            host,
            port,
        })
    }
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn targets() {
        for (s, h, p) in [
            ("example.com", "example.com", 443),
            ("example.com:8443/p?q=s#f", "example.com", 8443),
            ("::1", "::1", 443),
            ("https://[::1]:123/", "::1", 123),
            ("tcp://bücher.de:9", "xn--bcher-kva.de", 9),
        ] {
            let t = Target::parse(s).unwrap();
            assert_eq!(t.host, h);
            assert_eq!(t.port, p);
            assert!(t.url.fragment().is_none());
        }
        for s in [
            "",
            "ftp://host/",
            "https://u:p@host/",
            "tcp://host",
            "udp://host:0",
            "http://host:99999",
            "https://[fe80::1%25en0]/",
            "http://::1:4/",
            "tcp://host:2/path",
            "icmp://host:2",
            "host:",
            "http://host/\n",
        ] {
            assert!(Target::parse(s).is_err(), "{s}");
        }
    }
}
