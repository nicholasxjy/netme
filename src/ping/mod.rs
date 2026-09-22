//! Noninteractive diagnostics. Only observed facts become events.
mod capture;
mod diagnose;
pub mod event;
mod http;
mod net;
mod options;
mod proxy;
mod target;

use event::{EventSink, Redactor, TraceEvent};
pub use options::PingOptions;
use proxy::{Proxy, ProxySelection};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use target::{Protocol, Target};

pub type Result<T> = std::result::Result<T, Failure>;
#[derive(Debug)]
pub struct Failure {
    pub code: i32,
    pub message: String,
}
impl Failure {
    pub fn config(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
    pub fn incomplete(message: impl Into<String>) -> Self {
        Self {
            code: 3,
            message: message.into(),
        }
    }
}
pub struct PingOutcome {
    pub code: i32,
}
pub struct Context<'a> {
    sink: &'a mut dyn EventSink,
    start: Instant,
    pub deadline: Instant,
    sequence: u64,
    pub hop: usize,
    pub redactor: Redactor,
    signal: Arc<AtomicUsize>,
    registrations: Vec<signal_hook::SigId>,
    pub capture: Option<capture::Capture>,
    pub record_incomplete: bool,
    pub diagnostic_time: Duration,
    pub resource_time: Duration,
    pub actual_endpoint: Option<SocketAddr>,
    pub preferred: Option<SocketAddr>,
    pub warnings: usize,
}
impl<'a> Context<'a> {
    fn new(o: &PingOptions, sink: &'a mut dyn EventSink) -> Result<Self> {
        let start = Instant::now();
        let signal = Arc::new(AtomicUsize::new(0));
        let mut c = Self {
            sink,
            start,
            deadline: start + o.timeout,
            sequence: 0,
            hop: 0,
            redactor: Redactor::default(),
            signal,
            registrations: vec![],
            capture: None,
            record_incomplete: false,
            diagnostic_time: Duration::ZERO,
            resource_time: Duration::ZERO,
            actual_endpoint: None,
            preferred: None,
            warnings: 0,
        };
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            c.registrations.push(
                signal_hook::flag::register_usize(sig, c.signal.clone(), sig as usize)
                    .map_err(|_| Failure::config("cannot install signal handlers"))?,
            );
        }
        c.redactor.url(&o.target.url);
        Ok(c)
    }
    pub fn emit(&mut self, phase: &'static str, message: impl AsRef<str>) -> Result<()> {
        self.sequence += 1;
        let e = TraceEvent {
            sequence: self.sequence,
            elapsed: self.start.elapsed(),
            phase,
            hop: self.hop,
            message: self.redactor.clean(message.as_ref()),
        };
        self.sink.event(&e).map_err(|e| Failure {
            code: if e.kind() == std::io::ErrorKind::BrokenPipe {
                0
            } else {
                3
            },
            message: "output closed; stopping".into(),
        })
    }
    pub fn warning(&mut self, message: impl AsRef<str>) -> Result<()> {
        self.warnings += 1;
        self.emit("warning", message)
    }
    pub fn check(&mut self) -> Result<()> {
        let signal = self.signal.load(Ordering::Relaxed);
        if signal != 0 {
            return Err(Failure {
                code: 128 + signal as i32,
                message: format!("cancelled by signal {signal}"),
            });
        }
        if Instant::now() >= self.deadline {
            return Err(Failure::incomplete(
                "overall deadline exceeded; operation incomplete",
            ));
        }
        self.capture_tick()
    }
    fn capture_tick(&mut self) -> Result<()> {
        if let Some(mut cap) = self.capture.take() {
            let result = cap.poll();
            self.record_incomplete |= cap.incomplete;
            self.capture = Some(cap);
            for line in result {
                self.emit("capture", line)?;
            }
        }
        Ok(())
    }
    pub fn pause(&mut self) -> Result<()> {
        self.check()?;
        thread::sleep(Duration::from_millis(10));
        self.check()
    }
    pub fn until(&self, duration: Duration) -> Instant {
        self.deadline.min(Instant::now() + duration)
    }
    pub fn endpoint(&mut self, endpoint: SocketAddr) -> Result<()> {
        self.actual_endpoint = Some(endpoint);
        self.emit("connection", format!("actual peer={endpoint}"))?;
        if self.preferred.is_some_and(|p| p.ip() != endpoint.ip()) {
            self.warning("actual peer differs from preferred address; auxiliary probes do NOT describe this connection")?;
        }
        Ok(())
    }
    pub fn capture_endpoint(&mut self, addr: SocketAddr) -> Result<()> {
        self.check()?;
        if let Some(mut cap) = self.capture.take() {
            let result = cap.endpoint(addr, self.until(Duration::from_secs(3)), &self.signal);
            self.capture = Some(cap);
            result?;
        }
        Ok(())
    }
    pub fn prepare(
        &mut self,
        o: &PingOptions,
        target: &Target,
        proxy: Option<&Proxy>,
        auxiliary: bool,
    ) -> Result<Vec<SocketAddr>> {
        let (host, port) = proxy.map_or((target.host.as_str(), target.port), |p| {
            (p.host.as_str(), p.port)
        });
        if let Some(cap) = &mut self.capture {
            cap.name(host);
        }
        let addresses = net::resolve(self, host, port, o.family, o.connect_timeout)?;
        for addr in &addresses {
            self.capture_endpoint(*addr)?;
        }
        self.preferred = Some(addresses[0]);
        diagnose::route(self, addresses[0])?;
        if auxiliary && o.diagnose {
            let started = Instant::now();
            for trace in [false, true] {
                if let Err(error) = diagnose::probe(self, o, addresses[0].ip(), trace) {
                    self.check()?;
                    self.warning(format!(
                        "auxiliary {}: {} (resource access will continue)",
                        if trace { "traceroute" } else { "ICMP" },
                        error.message
                    ))?;
                }
            }
            self.diagnostic_time += started.elapsed();
        }
        Ok(addresses)
    }
}
impl Drop for Context<'_> {
    fn drop(&mut self) {
        for id in self.registrations.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

pub fn run(options: PingOptions, sink: &mut dyn EventSink) -> PingOutcome {
    let mut c = match Context::new(&options, sink) {
        Ok(c) => c,
        Err(e) => return PingOutcome { code: e.code },
    };
    let result = execute(&options, &mut c);
    // Stop/reap captures even on deadlines and signal paths. Do not send more probes.
    if let Some(mut capture) = c.capture.take() {
        for line in capture.finish() {
            let _ = c.emit("capture", line);
        }
        c.record_incomplete |= capture.incomplete;
    }
    let mut code = match result {
        Ok(()) => 0,
        Err(e) => {
            if e.code != 0 {
                let _ = c.emit("result", &e.message);
            }
            e.code
        }
    };
    if code == 0 && c.record_incomplete {
        code = 3;
    }
    let signal = c.signal.load(Ordering::Relaxed);
    if signal != 0 {
        code = 128 + signal as i32;
    }
    if let Err(e) = c.emit("summary",format!("exit={code}; resource={:.3}s auxiliary={:.3}s wall={:.3}s warnings={}; peer={}; recording={}",
        c.resource_time.as_secs_f64(), c.diagnostic_time.as_secs_f64(),c.start.elapsed().as_secs_f64(),c.warnings,
        c.actual_endpoint.map(|a|a.to_string()).unwrap_or_else(||"unknown".into()), if c.record_incomplete {"incomplete"} else if options.capture {"no known loss"} else {"disabled"})) { if signal == 0 { code = e.code; } }
    PingOutcome { code }
}
fn execute(o: &PingOptions, c: &mut Context<'_>) -> Result<()> {
    c.emit(
        "input",
        format!(
            "target={} protocol={:?}; timeout={:.3}s connect={:.3}s preview={} max-body={}",
            event::display_url(&o.target.url),
            o.target.protocol,
            o.timeout.as_secs_f64(),
            o.connect_timeout.as_secs_f64(),
            o.preview_bytes,
            o.max_bytes
        ),
    )?;
    let selection = ProxySelection::choose(o)?;
    net::validate_payload(o, selection.proxy.as_ref())?;
    if let Some(p) = &selection.proxy {
        c.redactor.url(&p.url);
        c.redactor.secret(&p.username);
        c.redactor.secret(&p.password);
        c.emit("proxy",format!("{} via {}; endpoint={}; origin DNS=proxy; remote IP/route/timing=unobservable; no direct fallback",if p.kind == proxy::Kind::Http {"HTTP proxy"} else {"SOCKS5 proxy"},selection.source,p.display()))?;
    } else {
        c.emit(
            "proxy",
            format!(
                "direct; source={}; DNS=local system resolver",
                selection.source
            ),
        )?;
    }
    c.check()?;
    let capabilities = if o.target.protocol.http() {
        Some(http::capabilities(c)?)
    } else {
        None
    };
    if let Some(path) = &o.cacert {
        std::fs::File::open(path).map_err(|_| Failure::config("cannot read --cacert file"))?;
    }
    let mut output = o
        .output
        .as_ref()
        .map(|p| http::BodyFile::create(p))
        .transpose()?;
    if let Some(file) = &output {
        c.emit(
            "output",
            format!(
                "body may contain secrets; partial file={}",
                file.partial.display()
            ),
        )?;
    }
    if o.capture {
        c.emit("capture","starting before DNS; endpoint/name correlation is NOT process attribution; no TLS decryption; absent DNS/FIN proves nothing")?;
        if o.pcap.is_some() {
            c.emit(
                "capture",
                "WARNING: raw PCAPNG retains unredacted payloads and secrets (0600, no overwrite)",
            )?;
        }
        c.capture = Some(capture::Capture::start(
            o,
            c.until(Duration::from_secs(3)),
            &c.signal,
        )?);
    }
    let addresses = c.prepare(
        o,
        &o.target,
        selection.proxy.as_ref(),
        !o.target.protocol.diagnostic(),
    )?;
    let started = Instant::now();
    let result = match o.target.protocol {
        Protocol::Http | Protocol::Https => http::run(
            c,
            o,
            selection.proxy.as_ref(),
            addresses,
            capabilities.unwrap(),
            &mut output,
        ),
        Protocol::Tcp => net::tcp(c, o, selection.proxy.as_ref(), &addresses),
        Protocol::Udp => net::udp(c, o, selection.proxy.as_ref(), &addresses),
        Protocol::Icmp | Protocol::Trace => diagnose::probe(
            c,
            o,
            addresses[0].ip(),
            o.target.protocol == Protocol::Trace,
        ),
    };
    c.resource_time += started.elapsed();
    result
}
