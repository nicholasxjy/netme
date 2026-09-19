use crate::{
    command,
    model::{clean, Interface, Route},
};
use std::collections::HashMap;

pub fn metadata() -> Result<Vec<Interface>, String> {
    let text = command::run("/sbin/ifconfig", &["-a"])?;
    let hardware = command::run("/usr/sbin/networksetup", &["-listallhardwareports"])?;
    Ok(parse_interfaces(&text, &hardware))
}

pub fn parse_interfaces(text: &str, hardware: &str) -> Vec<Interface> {
    let mut names = HashMap::new();
    let mut port = "";
    for line in hardware.lines() {
        if let Some(s) = line.strip_prefix("Hardware Port: ") {
            port = s;
        }
        if let Some(s) = line.strip_prefix("Device: ") {
            names.insert(s, port);
        }
    }
    let mut rows = Vec::<Interface>::new();
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) {
            if let Some((name, flags)) = line.split_once(": flags=") {
                rows.push(Interface {
                    name: clean(name),
                    kind: clean(names.get(name).copied().unwrap_or("virtual")),
                    up: Some(flags.split(['<', ',', '>']).any(|s| s == "UP")),
                    ..Default::default()
                });
            }
            continue;
        }
        let Some(row) = rows.last_mut() else { continue };
        let words: Vec<_> = line.split_whitespace().collect();
        match words.as_slice() {
            ["inet" | "inet6", address, ..] => row.addresses.push(clean(address)),
            ["status:", "inactive", ..] => row.up = Some(false),
            ["media:", ..] => {
                row.speed = words.iter().find_map(|s| {
                    let s = s.trim_start_matches('(');
                    let digits = s
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect::<String>();
                    if s[digits.len()..].starts_with("base") {
                        digits.parse::<u64>().ok()?.checked_mul(1_000_000)
                    } else {
                        None
                    }
                });
            }
            _ => {}
        }
    }
    rows
}

pub fn wifi(interfaces: &mut [Interface]) {
    // Local system metadata, no sudo/private framework or guessed channel/bandwidth.
    if let Ok(text) = command::run("/usr/sbin/system_profiler", &["SPAirPortDataType", "-json"]) {
        apply_wifi(&text, interfaces);
    }
}
fn apply_wifi(text: &str, interfaces: &mut [Interface]) {
    let Ok(data) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    for section in data["SPAirPortDataType"].as_array().into_iter().flatten() {
        for info in section["spairport_airport_interfaces"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let Some(row) = interfaces
                .iter_mut()
                .find(|i| Some(i.name.as_str()) == info["_name"].as_str() && i.wireless())
            else {
                continue;
            };
            let network = &info["spairport_current_network_information"];
            row.speed = network["spairport_network_rate"]
                .as_f64()
                .or_else(|| network["spairport_network_rate"].as_str()?.parse().ok())
                .filter(|n| n.is_finite() && *n > 0.)
                .map(|n| (n * 1_000_000.) as u64);
            row.band = network["spairport_network_channel"]
                .as_str()
                .and_then(|channel| {
                    ["2.4", "5", "6"]
                        .into_iter()
                        .find(|band| channel.contains(&format!("({band}GHz")))
                        .map(|band| format!("{band} GHz"))
                });
        }
    }
}

pub fn default_route(v6: bool) -> Result<Option<Route>, String> {
    let args = if v6 {
        vec!["-n", "get", "-inet6", "default"]
    } else {
        vec!["-n", "get", "default"]
    };
    match command::run("/sbin/route", &args) {
        Ok(text) => parse_route(&text),
        Err(e) if e.contains("not in table") || e.contains("Network is unreachable") => Ok(None),
        Err(e) => Err(e),
    }
}
pub fn parse_route(text: &str) -> Result<Option<Route>, String> {
    let field = |label: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(label))
            .map(str::trim)
    };
    if field("flags:").is_some_and(|s| s.contains("REJECT") || s.contains("BLACKHOLE")) {
        return Ok(None);
    }
    Ok(Some(Route {
        interface: clean(field("interface:").ok_or("route: missing interface")?),
        gateway: field("gateway:")
            .filter(|s| !s.starts_with("link#"))
            .map(clean),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hardware_cards_wifi_metadata_and_routes() {
        let mut rows = parse_interfaces(
            "en0: flags=1<UP,RUNNING> mtu 1500\n\tinet 192.0.2.1 netmask 0xff\n\tstatus: active\nen4: flags=1<UP> mtu 1500\n\tmedia: autoselect (1000baseT <full-duplex>)\n\tstatus: inactive\nbridge0: flags=1<UP> mtu 1500\nutun2: flags=1<UP> mtu 1500\nen1: flags=1<UP> mtu 1500\n",
            "Hardware Port: Wi-Fi\nDevice: en0\nHardware Port: Ethernet Adapter (en4)\nDevice: en4\nHardware Port: Thunderbolt Bridge\nDevice: bridge0\nHardware Port: Thunderbolt 1\nDevice: en1\n",
        );
        assert!(rows[0].wireless());
        assert_eq!(rows[1].title(), "Ethernet Adapter (en4)");
        assert_eq!(rows[1].speed, Some(1_000_000_000));
        assert_eq!(rows[1].up, Some(false));
        assert!(!rows[2].hardware());
        assert!(!rows[3].hardware());
        assert!(rows[4].hardware());
        apply_wifi(
            r#"{"SPAirPortDataType":[{"spairport_airport_interfaces":[{"_name":"en0","spairport_current_network_information":{"spairport_network_rate":866,"spairport_network_channel":"153 (5GHz, 80MHz)"}}]}]}"#,
            &mut rows,
        );
        assert_eq!(rows[0].speed, Some(866_000_000));
        assert_eq!(rows[0].band.as_deref(), Some("5 GHz"));
        assert_eq!(
            parse_route("interface: en0\ngateway: 192.0.2.254\n")
                .unwrap()
                .unwrap()
                .gateway
                .as_deref(),
            Some("192.0.2.254")
        );
        assert_eq!(
            parse_route("interface: en0\ngateway: link#4\n")
                .unwrap()
                .unwrap()
                .gateway,
            None
        );
        assert!(parse_route("interface: en0\nflags: <REJECT>\n")
            .unwrap()
            .is_none());
        assert!(parse_route("").is_err());
        apply_wifi(
            r#"{"SPAirPortDataType":[{"spairport_airport_interfaces":[{"_name":"en0"}]}]}"#,
            &mut rows,
        );
        assert_eq!(rows[0].speed, None);
        assert_eq!(rows[0].band, None);
    }
}
