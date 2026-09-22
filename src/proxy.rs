//! Configuration discovery only: each caller retains its own protocol policy.
#[derive(Clone)]
pub struct Config {
    pub value: String,
    pub source: String,
}

pub fn environment(lookup: impl Fn(&str) -> Option<String>) -> Option<Config> {
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
            .map(|value| Config {
                value,
                source: format!("environment {key}"),
            })
    })
}

pub fn discover() -> Result<Option<Config>, String> {
    if let Some(config) = environment(|name| std::env::var(name).ok()) {
        return Ok(Some(config));
    }
    #[cfg(target_os = "macos")]
    {
        let settings = crate::command::run("/usr/sbin/scutil", &["--proxy"])
            .map_err(|_| "cannot read system proxy configuration")?;
        system(&settings)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(None)
    }
}

#[cfg(any(target_os = "macos", test))]
pub fn system(settings: &str) -> Result<Option<Config>, String> {
    let field = |name: &str| {
        settings
            .lines()
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
        return Ok(Some(Config {
            value: format!("{scheme}://{host}:{port}"),
            source: "macOS manual proxy".into(),
        }));
    }
    if field("ProxyAutoConfigEnable") == Some("1") || field("ProxyAutoDiscoveryEnable") == Some("1")
    {
        return Err(
            "automatic proxy configuration requires an explicit HTTPS_PROXY or ALL_PROXY".into(),
        );
    }
    Ok(None)
}
