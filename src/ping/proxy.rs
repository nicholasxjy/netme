use super::{
    event::{decode, display_url},
    Failure, PingOptions, Result,
};
use url::{Host, Url};

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Http,
    Socks,
}
#[derive(Clone)]
pub struct Proxy {
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub url: Url,
}
pub struct ProxySelection {
    pub proxy: Option<Proxy>,
    pub source: String,
}
impl ProxySelection {
    pub fn choose(options: &PingOptions) -> Result<Self> {
        if options.direct {
            return Ok(Self {
                proxy: None,
                source: "explicit --direct".into(),
            });
        }
        let config = if let Some(s) = &options.proxy {
            Some(crate::proxy::Config {
                value: s.clone(),
                source: "explicit --proxy".into(),
            })
        } else {
            crate::proxy::discover().map_err(Failure::config)?
        };
        let Some(config) = config else {
            return Ok(Self {
                proxy: None,
                source: "no configured proxy".into(),
            });
        };
        let proxy = Proxy::parse(&config.value)?;
        if options.target.protocol.diagnostic() {
            return Err(Failure::config(
                "standalone ICMP/traceroute cannot use a proxy; explicitly use --direct",
            ));
        }
        if options.target.protocol == super::target::Protocol::Udp && proxy.kind == Kind::Http {
            return Err(Failure::config(
                "HTTP proxies cannot relay UDP; use SOCKS5 or explicitly --direct",
            ));
        }
        Ok(Self {
            proxy: Some(proxy),
            source: config.source,
        })
    }
}
impl Proxy {
    pub fn parse(value: &str) -> Result<Self> {
        let bad = || Failure::config("invalid or unsupported proxy configuration");
        if value.len() > 4096
            || value.chars().any(char::is_control)
            || value
                .trim()
                .split_once("://")
                .is_some_and(|(_, rest)| rest.split('/').next().unwrap_or_default().ends_with(':'))
        {
            return Err(bad());
        }
        let url = Url::parse(value.trim()).map_err(|_| bad())?;
        let kind = match url.scheme() {
            "http" => Kind::Http,
            "socks5" | "socks5h" => Kind::Socks,
            _ => return Err(bad()),
        };
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err(bad());
        }
        let host = match Host::parse(url.host_str().ok_or_else(bad)?).map_err(|_| bad())? {
            Host::Domain(s) => s,
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        };
        let port = url
            .port()
            .unwrap_or(if kind == Kind::Http { 80 } else { 1080 });
        if port == 0 || host.contains('%') {
            return Err(bad());
        }
        let username = decode(url.username());
        let password = decode(url.password().unwrap_or_default());
        if username.len() > 255
            || password.len() > 255
            || username.contains(':')
            || username
                .chars()
                .chain(password.chars())
                .any(char::is_control)
        {
            return Err(bad());
        }
        Ok(Self {
            kind,
            host,
            port,
            username,
            password,
            url,
        })
    }
    pub fn display(&self) -> String {
        display_url(&self.url)
    }
    pub fn authenticated(&self) -> bool {
        !self.username.is_empty() || !self.password.is_empty()
    }
}
