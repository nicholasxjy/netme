#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod linux;
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub mod macos;
#[cfg(target_os = "linux")]
use linux as native;
#[cfg(target_os = "macos")]
use macos as native;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("netme supports macOS and Linux only");

use crate::model::*;
use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    time::{Duration, Instant},
};
use sysinfo::Networks;

#[derive(Default)]
pub struct Sampler {
    networks: Networks,
    meter: Meter,
    snapshot: Snapshot,
    metadata: HashMap<String, Interface>,
    metadata_checked: Option<Instant>,
    wifi_checked: Option<Instant>,
    names: HashSet<String>,
    fingerprint: String,
}
impl Sampler {
    pub fn sample(&mut self) -> Snapshot {
        self.networks.refresh(true);
        let names: HashSet<_> = self.networks.keys().cloned().collect();
        let changed = self.names != names;
        if self
            .metadata_checked
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(5))
            || changed
        {
            // Failed metadata is unknown, not indefinitely retained as current.
            let mut rows = native::metadata().unwrap_or_default();
            let wifi_changed = rows.iter().filter(|i| i.wireless()).any(|i| {
                self.metadata
                    .get(&i.name)
                    .is_none_or(|old| old.up != i.up || old.addresses != i.addresses)
            });
            if changed
                || wifi_changed
                || self
                    .wifi_checked
                    .is_none_or(|t| t.elapsed() >= Duration::from_secs(30))
            {
                if rows.iter().any(|i| i.wireless() && i.up == Some(true)) {
                    native::wifi(&mut rows);
                }
                self.wifi_checked = Some(Instant::now());
            } else {
                for row in rows
                    .iter_mut()
                    .filter(|i| i.wireless() && i.up == Some(true))
                {
                    if let Some(old) = self.metadata.get(&row.name) {
                        row.speed = old.speed;
                        row.band = old.band.clone();
                    }
                }
            }
            self.metadata = rows.into_iter().map(|i| (i.name.clone(), i)).collect();
            for (index, v6) in [false, true].into_iter().enumerate() {
                self.snapshot.defaults[index] = native::default_route(v6).ok().flatten();
            }
            self.metadata_checked = Some(Instant::now());
            self.names = names;
        }
        // Sample counters and their monotonic clock together, after slow metadata commands.
        self.networks.refresh(true);
        let at = Instant::now();
        let mut interfaces = Vec::new();
        let mut keys = Vec::new();
        for (name, data) in &self.networks {
            let mut row = self
                .metadata
                .get(name)
                .cloned()
                .unwrap_or_else(|| Interface {
                    name: clean(name),
                    ..Default::default()
                });
            let index = CString::new(name.as_str())
                .ok()
                .map(|s| {
                    // SAFETY: CString remains valid and NUL-terminated for this read-only call.
                    unsafe { libc::if_nametoindex(s.as_ptr()) }
                })
                .unwrap_or(0);
            row.identity = format!("{index}:{}", data.mac_address());
            row.addresses = data.ip_networks().iter().map(ToString::to_string).collect();
            row.addresses.sort();
            let key = format!("{}:{}", name, row.identity);
            row.rate = self.meter.sample(
                key.clone(),
                at,
                Bytes {
                    rx: Some(data.total_received()),
                    tx: Some(data.total_transmitted()),
                },
            );
            keys.push(key);
            interfaces.push(row);
        }
        self.meter.retain(&keys);
        interfaces.sort_by_key(|i| (i.wireless(), i.title(), i.name.clone()));
        let fingerprint = format!(
            "{:?}|{:?}",
            self.snapshot.defaults,
            interfaces
                .iter()
                .map(|i| (&i.name, &i.identity, &i.addresses, i.up))
                .collect::<Vec<_>>()
        );
        if fingerprint != self.fingerprint {
            self.snapshot.generation += 1;
            self.fingerprint = fingerprint;
        }
        self.snapshot.interfaces = interfaces;
        self.snapshot.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Explicit opt-in; only local loopback traffic, no public IP requests.
    #[test]
    #[ignore = "live ordinary-permission platform smoke test"]
    fn live_loopback_smoke() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            thread,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let mut sampler = Sampler::default();
        sampler.sample();
        client.write_all(&[7; 1024]).unwrap();
        server.read_exact(&mut [0; 1024]).unwrap();
        thread::sleep(Duration::from_millis(100));
        let snapshot = sampler.sample();
        assert!(!snapshot.interfaces.is_empty());
        assert!(snapshot
            .interfaces
            .iter()
            .any(|i| i.name.starts_with("lo") && i.rate.rx.is_some_and(|n| n > 0.)));
        eprintln!(
            "live smoke: {} interfaces; loopback traffic measured",
            snapshot.interfaces.len()
        );
    }
}
