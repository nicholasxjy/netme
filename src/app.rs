use crate::{
    model::*,
    platform,
    public_ip::{self, Probe},
    ui,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io::{self, IsTerminal},
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(Debug, PartialEq)]
pub struct Options {
    pub interval: u64,
    pub ascii: bool,
}

#[derive(Clone, Default)]
pub struct Data {
    pub snapshot: Snapshot,
    pub probes: [Option<Probe>; 2],
}
pub struct App {
    pub live: Data,
    frozen: Option<Data>,
    pub cursor: usize,
    pub confirm: bool,
    pub public_pending: bool,
    public_queued: bool,
    pub ascii: bool,
    pub color: bool,
    pub interval: u64,
}
impl App {
    pub fn new(options: Options) -> Self {
        Self {
            live: Data::default(),
            frozen: None,
            cursor: 0,
            confirm: false,
            public_pending: false,
            public_queued: false,
            ascii: options.ascii,
            color: std::env::var_os("NO_COLOR").is_none()
                && std::env::var("TERM").unwrap_or_default() != "dumb",
            interval: options.interval,
        }
    }
    pub fn data(&self) -> &Data {
        self.frozen.as_ref().unwrap_or(&self.live)
    }
    pub fn frozen(&self) -> bool {
        self.frozen.is_some()
    }
    pub fn interfaces(&self) -> Vec<&Interface> {
        self.data()
            .snapshot
            .interfaces
            .iter()
            .filter(|i| i.hardware())
            .collect()
    }
    pub fn receive(&mut self, snapshot: Snapshot) {
        let selected = self.interfaces().get(self.cursor).map(|i| i.name.clone());
        self.live.snapshot = snapshot;
        if let Some(index) = self
            .interfaces()
            .iter()
            .position(|i| Some(&i.name) == selected.as_ref())
        {
            self.cursor = index;
        }
        self.clamp();
    }
    pub fn primary_interface(&self) -> Option<&Interface> {
        let snapshot = &self.data().snapshot;
        snapshot
            .defaults
            .iter()
            .flatten()
            .find_map(|r| snapshot.interfaces.iter().find(|i| i.name == r.interface))
            .or_else(|| {
                snapshot
                    .interfaces
                    .iter()
                    .find(|i| i.hardware() && i.up == Some(true))
            })
            .or_else(|| snapshot.interfaces.iter().find(|i| i.hardware()))
    }
    pub fn internal_ip(&self) -> Option<String> {
        let interface = self.primary_interface()?;
        let ipv6 = self.data().snapshot.defaults[0].is_none()
            && self.data().snapshot.defaults[1].is_some();
        let mut addresses: Vec<IpAddr> = interface
            .addresses
            .iter()
            .filter_map(|s| s.split('/').next()?.split('%').next()?.parse().ok())
            .filter(|ip: &IpAddr| !ip.is_unspecified() && !ip.is_loopback())
            .collect();
        addresses.sort_by_key(|ip| {
            (
                ip.is_ipv6() != ipv6,
                matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local()),
            )
        });
        addresses.first().map(ToString::to_string)
    }
    pub fn router_ip(&self) -> Option<&str> {
        let interface = self.primary_interface()?;
        self.data()
            .snapshot
            .defaults
            .iter()
            .flatten()
            .find(|r| r.interface == interface.name)?
            .gateway
            .as_deref()
    }
    fn external_probe(&self) -> Option<&Probe> {
        self.data()
            .probes
            .iter()
            .flatten()
            .find(|p| p.generation == self.data().snapshot.generation && p.result.is_ok())
    }
    pub fn external_source(&self) -> Option<&str> {
        self.external_probe()
            .map(|p| if p.via_proxy { "proxy" } else { "direct" })
    }
    pub fn external_ip(&self) -> String {
        if let Some(ip) = self.external_probe().and_then(|p| p.result.as_ref().ok()) {
            return ip.to_string();
        }
        if self.public_pending && !self.frozen() {
            return "…".into();
        }
        self.data()
            .probes
            .iter()
            .flatten()
            .find(|p| p.generation == self.data().snapshot.generation)
            .map(|p| {
                if p.via_proxy {
                    "proxy failed"
                } else {
                    "unavailable"
                }
            })
            .unwrap_or("p: query")
            .into()
    }
    fn take_public_request(&mut self) -> Option<u64> {
        // Generation zero is the placeholder before the first sampler result. A query
        // tagged with it would be discarded as soon as the real network arrives.
        if !self.public_queued || self.live.snapshot.generation == 0 {
            return None;
        }
        self.public_queued = false;
        Some(self.live.snapshot.generation)
    }
    fn clamp(&mut self) {
        self.cursor = self.cursor.min(self.interfaces().len().saturating_sub(1));
    }
    pub fn key(&mut self, key: KeyEvent) -> Action {
        if key.kind == KeyEventKind::Release {
            return Action::None;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        if self.confirm {
            match key.code {
                KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                    self.confirm = false;
                    if !self.public_pending {
                        self.public_pending = true;
                        self.public_queued = true;
                    }
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => self.confirm = false,
                _ => {}
            }
            return Action::None;
        }
        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Down | KeyCode::Char('j') => self.cursor = self.cursor.saturating_add(1),
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::PageDown => self.cursor = self.cursor.saturating_add(3),
            KeyCode::PageUp => self.cursor = self.cursor.saturating_sub(3),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.interfaces().len().saturating_sub(1),
            KeyCode::Char(' ') => {
                if self.frozen.take().is_none() {
                    self.frozen = Some(self.live.clone());
                }
            }
            KeyCode::Char('p') if !self.public_pending => self.confirm = true,
            _ => {}
        }
        self.clamp();
        Action::None
    }
}
#[derive(Debug, PartialEq)]
pub enum Action {
    None,
    Quit,
}

enum Reply {
    Public(usize, Probe),
    PublicDone,
}
struct Workers {
    stop: Arc<AtomicBool>,
    sampler: Option<JoinHandle<()>>,
    auxiliary: Option<JoinHandle<()>>,
    snapshots: Receiver<Snapshot>,
    requests: SyncSender<u64>,
    replies: Receiver<Reply>,
}
impl Workers {
    fn start(interval: u64, stop: Arc<AtomicBool>) -> Self {
        let (tx, snapshots) = mpsc::sync_channel(1);
        let (requests, rx) = mpsc::sync_channel(1);
        let (reply, replies) = mpsc::sync_channel(4);
        let sampling_stop = stop.clone();
        let sampler = thread::spawn(move || {
            let mut sampler = platform::Sampler::default();
            while !sampling_stop.load(Ordering::Relaxed) {
                let started = std::time::Instant::now();
                let _ = tx.try_send(sampler.sample());
                while started.elapsed() < Duration::from_secs(interval)
                    && !sampling_stop.load(Ordering::Relaxed)
                {
                    thread::sleep(Duration::from_millis(50));
                }
            }
        });
        let auxiliary_stop = stop.clone();
        let auxiliary = thread::spawn(move || {
            let mut cache = public_ip::Cache::default();
            while !auxiliary_stop.load(Ordering::Relaxed) {
                let Ok(generation) = rx.recv_timeout(Duration::from_millis(100)) else {
                    continue;
                };
                for family in 0..2 {
                    if auxiliary_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let _ = reply.try_send(Reply::Public(family, cache.query(family, generation)));
                }
                let _ = reply.try_send(Reply::PublicDone);
            }
        });
        Self {
            stop,
            sampler: Some(sampler),
            auxiliary: Some(auxiliary),
            snapshots,
            requests,
            replies,
        }
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.sampler.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.auxiliary.take() {
            let _ = handle.join();
        }
    }
}

struct TerminalGuard;
fn restore() {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
}
impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let guard = Self;
        execute!(io::stdout(), EnterAlternateScreen, crossterm::cursor::Hide)?;
        Ok(guard)
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}

pub fn run(options: Options) -> Result<(), Box<dyn std::error::Error>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("interactive TTY required; try netme --help".into());
    }
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGQUIT,
    ] {
        signal_hook::flag::register(signal, stop.clone())?;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        previous(info);
    }));
    let mut app = App::new(options);
    let workers = Workers::start(app.interval, stop.clone());
    // Guard drops first: restore the terminal even while a bounded command exits.
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if workers.sampler.as_ref().is_some_and(|h| h.is_finished())
            || workers.auxiliary.as_ref().is_some_and(|h| h.is_finished())
        {
            return Err("collector worker stopped unexpectedly".into());
        }
        for snapshot in workers.snapshots.try_iter() {
            app.receive(snapshot);
        }
        for reply in workers.replies.try_iter() {
            match reply {
                Reply::Public(family, probe) => app.live.probes[family] = Some(probe),
                Reply::PublicDone => app.public_pending = false,
            }
        }
        if let Some(generation) = app.take_public_request() {
            if workers.requests.try_send(generation).is_err() {
                app.public_pending = false;
            }
        }
        terminal.draw(|f| ui::draw(f, &app))?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app.key(key) {
                    Action::Quit => break,
                    Action::None => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::monitor_options as options;
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    #[test]
    fn cli_validation() {
        for args in [
            vec!["--interval", "0"],
            vec!["--interval", "61"],
            vec!["--interval", "1.5"],
            vec!["--bad"],
            vec!["--interval"],
        ] {
            assert!(options(args.into_iter().map(String::from)).is_err());
        }
        assert_eq!(
            options(["--ascii", "--interval", "2"].map(String::from)).unwrap(),
            Some(Options {
                interval: 2,
                ascii: true
            })
        );
    }
    #[test]
    fn scrolling_pin_and_explicit_consent() {
        let mut app = App::new(Options {
            interval: 1,
            ascii: false,
        });
        app.live.snapshot.interfaces = (0..7)
            .map(|n| Interface {
                name: format!("en{n}"),
                kind: "Ethernet".into(),
                ..Default::default()
            })
            .collect();
        app.key(key(KeyCode::End));
        assert_eq!(app.cursor, 6);
        app.key(key(KeyCode::Char('j')));
        assert_eq!(app.cursor, 6);
        app.key(key(KeyCode::Home));
        assert_eq!(app.cursor, 0);
        app.key(key(KeyCode::Char(' ')));
        app.receive(Snapshot {
            generation: 42,
            ..Default::default()
        });
        assert_ne!(app.data().snapshot.generation, 42);
        app.key(key(KeyCode::Char(' ')));
        assert_eq!(app.data().snapshot.generation, 42);
        assert_eq!(app.cursor, 0);
        assert_eq!(app.key(key(KeyCode::Char('p'))), Action::None);
        assert!(app.confirm && !app.public_pending);
        app.key(key(KeyCode::Esc));
        assert!(!app.public_pending);
        app.key(key(KeyCode::Char('p')));
        assert_eq!(app.key(key(KeyCode::Char('y'))), Action::None);
        assert!(app.public_pending);
        assert_eq!(app.take_public_request(), Some(42));
        assert_eq!(app.take_public_request(), None);
        assert_eq!(app.key(key(KeyCode::Char('q'))), Action::Quit);
    }
    #[test]
    fn early_public_query_waits_for_the_first_network_snapshot() {
        let mut app = App::new(Options {
            interval: 1,
            ascii: false,
        });
        assert_eq!(app.take_public_request(), None); // No startup traffic.
        app.key(key(KeyCode::Char('p')));
        app.key(key(KeyCode::Esc));
        assert_eq!(app.take_public_request(), None); // Cancellation stays offline.
        app.key(key(KeyCode::Char('p')));
        app.key(key(KeyCode::Enter));
        assert!(app.public_pending);
        assert_eq!(app.take_public_request(), None); // Not generation zero.
        assert_eq!(app.external_ip(), "…");
        app.receive(Snapshot {
            generation: 1,
            ..Default::default()
        });
        let generation = app.take_public_request().unwrap();
        assert_eq!(generation, 1);
        assert_eq!(app.take_public_request(), None); // Dispatch only once.
        app.live.probes[0] = Some(Probe {
            at: std::time::Instant::now(),
            generation,
            via_proxy: true,
            result: Ok("198.51.100.7".parse().unwrap()),
        });
        assert_eq!(app.external_ip(), "198.51.100.7"); // Visible before IPv6 finishes.
        app.live.snapshot.generation = 2;
        app.public_pending = false;
        assert_eq!(app.external_ip(), "p: query"); // Never show a stale network result.
        assert_eq!(app.take_public_request(), None); // No automatic retry.
    }
    #[test]
    fn public_result_source_pending_failure_and_stale_state() {
        let mut app = App::new(Options {
            interval: 1,
            ascii: false,
        });
        app.public_pending = true;
        assert_eq!(app.external_ip(), "…");
        app.live.probes[0] = Some(Probe {
            at: std::time::Instant::now(),
            generation: 0,
            via_proxy: true,
            result: Ok("198.51.100.7".parse().unwrap()),
        });
        assert_eq!(app.external_ip(), "198.51.100.7");
        assert_eq!(app.external_source(), Some("proxy"));
        app.public_pending = false;
        app.live.probes[0].as_mut().unwrap().result = Err("failed".into());
        assert_eq!(app.external_ip(), "proxy failed");
        assert_eq!(app.external_source(), None);
        app.live.snapshot.generation = 1;
        assert_eq!(app.external_ip(), "p: query");
    }
    #[test]
    fn default_path_is_not_a_sum_or_guessed_router() {
        let mut app = App::new(Options {
            interval: 1,
            ascii: false,
        });
        app.live.snapshot.interfaces = vec![
            Interface {
                name: "en0".into(),
                kind: "Wi-Fi".into(),
                up: Some(true),
                addresses: vec!["fe80::1%en0/64".into(), "192.0.2.1/24".into()],
                ..Default::default()
            },
            Interface {
                name: "tun0".into(),
                addresses: vec!["fd00::1/64".into()],
                ..Default::default()
            },
        ];
        app.live.snapshot.defaults[0] = Some(Route {
            interface: "en0".into(),
            gateway: Some("192.0.2.254".into()),
        });
        assert_eq!(app.interfaces().len(), 1);
        assert_eq!(app.internal_ip().as_deref(), Some("192.0.2.1"));
        assert_eq!(app.router_ip(), Some("192.0.2.254"));
        app.live.snapshot.defaults = [
            None,
            Some(Route {
                interface: "tun0".into(),
                gateway: None,
            }),
        ];
        assert_eq!(app.primary_interface().unwrap().name, "tun0");
        assert_eq!(app.internal_ip().as_deref(), Some("fd00::1"));
        assert_eq!(app.router_ip(), None);
        assert_eq!(app.external_ip(), "p: query");
    }
}
