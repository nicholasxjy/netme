use crate::{
    command,
    model::{clean, Interface, Route},
};
use serde_json::Value;

pub fn metadata() -> Result<Vec<Interface>, String> {
    let text = command::run("ip", &["-j", "-d", "address", "show"])
        .map_err(|e| format!("{e}; install iproute2"))?;
    let mut interfaces = parse_interfaces(&text)?;
    for i in &mut interfaces {
        if i.name.contains('/') || i.name.contains("..") {
            continue;
        }
        let path = format!("/sys/class/net/{}", i.name);
        if std::path::Path::new(&format!("{path}/wireless")).exists() {
            i.kind = "Wi-Fi".into();
        }
        // sysfs values are kernel-reported Mb/s, not measured throughput.
        i.speed = std::fs::read_to_string(format!("{path}/speed"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n > 0 && *n < u32::MAX as u64)
            .and_then(|n| n.checked_mul(1_000_000));
    }
    Ok(interfaces)
}

pub fn wifi(interfaces: &mut [Interface]) {
    for i in interfaces
        .iter_mut()
        .filter(|i| i.wireless() && i.up == Some(true))
    {
        // Optional iw only reads the current link; never starts a wireless scan.
        if let Ok(text) = command::run("iw", &["dev", &i.name, "link"]) {
            apply_wifi(&text, i);
        }
    }
}
fn apply_wifi(text: &str, interface: &mut Interface) {
    for line in text.lines().map(str::trim) {
        if let Some(freq) = line
            .strip_prefix("freq:")
            .and_then(|s| s.trim().parse::<u32>().ok())
        {
            interface.band = match freq {
                2400..=2500 => Some("2.4 GHz"),
                4900..=5900 => Some("5 GHz"),
                5925..=7125 => Some("6 GHz"),
                _ => None,
            }
            .map(str::to_string);
        }
        if let Some(rate) = line.strip_prefix("tx bitrate:") {
            let mut words = rate.split_whitespace();
            interface.speed = words
                .next()
                .and_then(|n| n.parse::<f64>().ok())
                .filter(|n| n.is_finite() && *n > 0.)
                .filter(|_| words.next() == Some("MBit/s"))
                .map(|n| (n * 1_000_000.) as u64);
        }
    }
}

pub fn default_route(v6: bool) -> Result<Option<Route>, String> {
    parse_routes(&command::run(
        "ip",
        &[
            "-j",
            if v6 { "-6" } else { "-4" },
            "route",
            "show",
            "default",
        ],
    )?)
}

pub fn parse_interfaces(text: &str) -> Result<Vec<Interface>, String> {
    let rows: Vec<Value> =
        serde_json::from_str(text).map_err(|e| format!("ip address JSON: {e}"))?;
    rows.into_iter()
        .map(|v| {
            Ok(Interface {
                name: clean(v["ifname"].as_str().ok_or("ip address: missing ifname")?),
                kind: clean(
                    v["linkinfo"]["info_kind"]
                        .as_str()
                        .or(v["link_type"].as_str())
                        .unwrap_or("unknown"),
                ),
                up: v["flags"]
                    .as_array()
                    .map(|f| f.iter().any(|s| s == "UP") && v["operstate"] != "DOWN"),
                addresses: v["addr_info"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|a| {
                        a["local"]
                            .as_str()
                            .map(|s| format!("{}/{}", clean(s), a["prefixlen"]))
                    })
                    .collect(),
                ..Default::default()
            })
        })
        .collect()
}

pub fn parse_routes(text: &str) -> Result<Option<Route>, String> {
    let mut rows: Vec<Value> =
        serde_json::from_str(text).map_err(|e| format!("ip route JSON: {e}"))?;
    rows.sort_by_key(|r| r["metric"].as_u64().unwrap_or(0));
    let Some(v) = rows.first() else {
        return Ok(None);
    };
    if matches!(
        v["type"].as_str(),
        Some("unreachable" | "blackhole" | "prohibit" | "throw")
    ) {
        return Ok(None);
    }
    Ok(Some(Route {
        interface: clean(
            v["dev"]
                .as_str()
                .ok_or("ip route: no single interface (possibly multipath)")?,
        ),
        gateway: v["gateway"].as_str().map(clean),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hardware_routes_and_optional_wireless() {
        let rows = parse_interfaces(r#"[{"ifname":"eth0","flags":["UP"],"operstate":"UP","link_type":"ether","addr_info":[{"local":"192.0.2.1","prefixlen":24}]},{"ifname":"veth0","link_type":"ether","linkinfo":{"info_kind":"veth"}},{"ifname":"tun0","linkinfo":{"info_kind":"tun"}}]"#).unwrap();
        assert!(rows[0].hardware());
        assert!(!rows[1].hardware());
        assert!(!rows[2].hardware());
        assert_eq!(rows[0].title(), "Ethernet Adapter (eth0)");
        let route = parse_routes(
            r#"[{"dev":"tun0","gateway":"10.0.0.1","metric":1},{"dev":"eth0","metric":20}]"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(route.interface, "tun0");
        assert!(parse_routes(r#"[{"type":"unreachable"}]"#)
            .unwrap()
            .is_none());
        assert!(parse_routes("[]").unwrap().is_none());
        assert!(parse_routes("bad").is_err());
        let mut wifi = Interface::default();
        apply_wifi(
            "freq: 5180\n tx bitrate: 866.7 MBit/s VHT-MCS 9\n",
            &mut wifi,
        );
        assert_eq!(wifi.band.as_deref(), Some("5 GHz"));
        assert_eq!(wifi.speed, Some(866_700_000));
    }
}
