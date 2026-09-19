use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

/// Strip controls (including OSC/CSI introducers) before displaying external text.
pub fn clean(text: &str) -> String {
    text.chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(512)
        .collect()
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Bytes {
    pub rx: Option<u64>,
    pub tx: Option<u64>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rate {
    pub rx: Option<f64>,
    pub tx: Option<f64>,
}

#[derive(Clone, Debug, Default)]
pub struct Interface {
    pub name: String,
    pub identity: String,
    pub kind: String,
    pub up: Option<bool>,
    pub addresses: Vec<String>,
    pub speed: Option<u64>, // OS-reported bit/s, never inferred from traffic
    pub band: Option<String>,
    pub rate: Rate,
}
impl Interface {
    pub fn wireless(&self) -> bool {
        self.kind == "Wi-Fi"
    }
    pub fn hardware(&self) -> bool {
        self.wireless()
            || matches!(self.kind.as_str(), "ether" | "Ethernet")
            || self.kind.starts_with("Ethernet ")
            || (self.kind.starts_with("Thunderbolt ") && self.kind != "Thunderbolt Bridge")
    }
    pub fn title(&self) -> String {
        if self.kind == "ether" || self.kind == "Ethernet" {
            format!("Ethernet Adapter ({})", self.name)
        } else {
            self.kind.clone()
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub interface: String,
    pub gateway: Option<String>,
}
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub interfaces: Vec<Interface>,
    pub defaults: [Option<Route>; 2],
    pub generation: u64,
}

#[derive(Default)]
pub struct Meter {
    previous: HashMap<String, (Instant, Bytes)>,
}
impl Meter {
    pub fn sample(&mut self, key: String, at: Instant, bytes: Bytes) -> Rate {
        let old = self.previous.insert(key, (at, bytes));
        let Some((before, counters)) = old else {
            return Rate::default();
        };
        let seconds = at.saturating_duration_since(before).as_secs_f64();
        if seconds == 0. {
            return Rate::default();
        }
        // A reset in either direction invalidates the whole baseline.
        if matches!((bytes.rx, counters.rx), (Some(a), Some(b)) if a < b)
            || matches!((bytes.tx, counters.tx), (Some(a), Some(b)) if a < b)
        {
            return Rate::default();
        }
        Rate {
            rx: bytes
                .rx
                .zip(counters.rx)
                .map(|(a, b)| (a - b) as f64 / seconds),
            tx: bytes
                .tx
                .zip(counters.tx)
                .map(|(a, b)| (a - b) as f64 / seconds),
        }
    }
    pub fn retain(&mut self, keys: &[String]) {
        let keys: HashSet<_> = keys.iter().collect();
        self.previous.retain(|k, _| keys.contains(k));
    }
}

/// Decimal units match the compact menu-style display; unknown is never zero.
pub fn quantity(value: Option<f64>, bits: bool) -> String {
    let Some(mut n) = value.filter(|n| n.is_finite() && *n >= 0.) else {
        return "—".into();
    };
    let units = if bits {
        ["b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"]
    } else {
        ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
    };
    let mut index = 0;
    while n >= 1000. && index < units.len() - 1 {
        n /= 1000.;
        index += 1;
    }
    let precision = if n < 10. {
        2
    } else if n < 100. {
        1
    } else {
        0
    };
    format!("{n:.precision$} {}", units[index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn baseline_reset_missing_identity_and_elapsed() {
        let mut meter = Meter::default();
        let at = Instant::now();
        let bytes = |n| Bytes {
            rx: Some(n),
            tx: Some(n),
        };
        assert_eq!(meter.sample("a".into(), at, bytes(100)), Rate::default());
        assert_eq!(
            meter
                .sample("a".into(), at + Duration::from_secs(2), bytes(300))
                .rx,
            Some(100.)
        );
        assert_eq!(
            meter.sample("a".into(), at + Duration::from_secs(3), bytes(1)),
            Rate::default()
        );
        assert_eq!(
            meter.sample("a".into(), at + Duration::from_secs(4), Bytes::default()),
            Rate::default()
        );
        assert_eq!(
            meter.sample("a".into(), at + Duration::from_secs(5), bytes(999)),
            Rate::default()
        );
        assert_eq!(
            meter.sample(
                "new-identity".into(),
                at + Duration::from_secs(6),
                bytes(999)
            ),
            Rate::default()
        );
        meter.retain(&[]);
        assert_eq!(meter.sample("a".into(), at, bytes(999)), Rate::default());
    }

    #[test]
    fn screenshot_units_and_safe_text() {
        for (value, bits, expected) in [
            (None, false, "—"),
            (Some(0.), false, "0.00 B/s"),
            (Some(94_300.), false, "94.3 KB/s"),
            (Some(5_300.), false, "5.30 KB/s"),
            (Some(866_000_000.), true, "866 Mb/s"),
            (Some(0.), true, "0.00 b/s"),
            (Some(f64::NAN), false, "—"),
        ] {
            assert_eq!(quantity(value, bits), expected);
        }
        assert_eq!(clean("\x1b\x07x\n\u{202e}"), "x");
    }
}
