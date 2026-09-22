//! Optional passive capture. Raw bytes never go to the event sink.
use super::{Failure, PingOptions, Result};
use crate::command::stream::{Lines, Message, Process};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use hickory_proto::op::{Message as DnsMessage, MessageType};
use pcap_file::{
    pcap::{PcapPacket, PcapParser},
    pcapng::{
        blocks::{
            enhanced_packet::EnhancedPacketBlock,
            interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
        },
        PcapNgWriter,
    },
    DataLink, Endianness, PcapError,
};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};
const MAX_PACKET: usize = 262144;
const MAX_PACKETS: u64 = 100000;
const MAX_FILE: u64 = 100 * 1024 * 1024;

struct Session {
    process: Process,
    bytes: Vec<u8>,
    parser: Option<PcapParser>,
    lines: Lines,
    endpoint: Option<IpAddr>,
    interface_id: Option<u32>,
    ready: bool,
    stopped: bool,
}
impl Session {
    fn start(interface: &str, endpoint: Option<IpAddr>) -> Result<Self> {
        let filter = endpoint
            .map(|ip| format!("host {ip} or icmp or icmp6"))
            .unwrap_or_else(|| "port 53".into());
        let mut args = vec![
            "-n".into(),
            "-U".into(),
            "-s".into(),
            "0".into(),
            "-i".into(),
            interface.into(),
            "-w".into(),
            "-".into(),
        ];
        #[cfg(target_os = "macos")]
        if interface.starts_with("pktap") {
            args.extend(["-y".into(), "RAW".into()]);
        }
        args.push(filter);
        let process = Process::spawn("tcpdump", &args, vec![], false).map_err(|_| {
            Failure::config(
                "capture requires tcpdump and capture permissions; netme never invokes sudo",
            )
        })?;
        Ok(Self {
            process,
            bytes: vec![],
            parser: None,
            lines: Lines::new(8192),
            endpoint,
            interface_id: None,
            ready: false,
            stopped: false,
        })
    }
    fn read(&mut self) -> std::result::Result<(Vec<PcapPacket<'static>>, Vec<String>), String> {
        let mut logs = vec![];
        for message in self.process.poll().map_err(|_| "capture pipe failed")? {
            match message {
                Message::Stdout(bytes) => {
                    if self.bytes.len() + bytes.len() > MAX_PACKET + 65536 {
                        return Err("capture buffer overflow".into());
                    }
                    self.bytes.extend(bytes);
                }
                Message::Stderr(bytes) => {
                    for line in self.lines.push(&bytes).map_err(str::to_owned)? {
                        if line.contains("listening on") {
                            self.ready = true;
                        }
                        if line.contains("packets dropped by kernel")
                            || line.contains("packets dropped by interface")
                        {
                            let n = line
                                .split_whitespace()
                                .next()
                                .and_then(|s| s.parse::<u64>().ok());
                            logs.push(format!(
                                "capture drop counter={}",
                                n.map(|n| n.to_string()).unwrap_or_else(|| "unknown".into())
                            ));
                        }
                        if line.to_ascii_lowercase().contains("permission") {
                            return Err("tcpdump permission denied; grant capture permission externally (no automatic sudo)".into());
                        }
                    }
                }
            }
        }
        let packets = decode_records(&mut self.bytes, &mut self.parser)?;
        if self.parser.is_some() {
            self.ready = true;
        }
        if self.process.finished().is_some() && !self.stopped {
            return Err("tcpdump stopped unexpectedly; verify tool/interface/permissions".into());
        }
        Ok((packets, logs))
    }
}
fn decode_records(
    bytes: &mut Vec<u8>,
    parser: &mut Option<PcapParser>,
) -> std::result::Result<Vec<PcapPacket<'static>>, String> {
    if parser.is_none() {
        if bytes.len() < 24 {
            return Ok(vec![]);
        }
        let (rest, p) = PcapParser::new(bytes).map_err(|_| "invalid PCAP header")?;
        if p.header().snaplen as usize > MAX_PACKET || !supported(p.header().datalink) {
            return Err("unsupported capture link type/snapshot length".into());
        }
        let used = bytes.len() - rest.len();
        bytes.drain(..used);
        *parser = Some(p);
    }
    let p = parser.as_ref().unwrap();
    let mut packets = vec![];
    let mut offset = 0;
    while bytes.len() - offset >= 16 {
        let raw: [u8; 4] = bytes[offset + 8..offset + 12].try_into().unwrap();
        let len = match p.header().endianness {
            Endianness::Little => u32::from_le_bytes(raw),
            Endianness::Big => u32::from_be_bytes(raw),
        } as usize;
        if len > MAX_PACKET {
            return Err("malicious/oversized PCAP record length".into());
        }
        match p.next_packet(&bytes[offset..]) {
            Ok((rest, packet)) => {
                offset = bytes.len() - rest.len();
                packets.push(PcapPacket::new_owned(
                    packet.timestamp,
                    packet.orig_len,
                    packet.data.into_owned(),
                ));
            }
            Err(PcapError::IncompleteBuffer) => break,
            Err(_) => return Err("invalid/truncated PCAP record".into()),
        }
    }
    bytes.drain(..offset);
    Ok(packets)
}
fn supported(link: DataLink) -> bool {
    matches!(
        link,
        DataLink::ETHERNET
            | DataLink::RAW
            | DataLink::NULL
            | DataLink::LOOP
            | DataLink::LINUX_SLL
            | DataLink::LINUX_SLL2
            | DataLink::IPV4
            | DataLink::IPV6
    )
}

pub struct Capture {
    sessions: Vec<Session>,
    interface: String,
    pub incomplete: bool,
    stopped: bool,
    writer: Option<PcapNgWriter<File>>,
    interfaces: u32,
    file_bytes: u64,
    packets: u64,
    correlator: Correlator,
    pending: Vec<String>,
}
impl Capture {
    pub fn start(o: &PingOptions, until: Instant, signal: &AtomicUsize) -> Result<Self> {
        let interface = o.interface.clone().unwrap_or_else(|| {
            if cfg!(target_os = "macos") {
                "pktap,all"
            } else {
                "any"
            }
            .into()
        });
        let writer = o
            .pcap
            .as_ref()
            .map(|path| {
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|_| Failure::config("cannot create --pcap file (must not exist)"))?;
                PcapNgWriter::new(file).map_err(|_| Failure::config("cannot write PCAPNG header"))
            })
            .transpose()?;
        let mut c = Self {
            sessions: vec![],
            interface,
            incomplete: false,
            stopped: false,
            writer,
            interfaces: 0,
            file_bytes: 28,
            packets: 0,
            correlator: Correlator::default(),
            pending: vec![],
        };
        c.add(None, until, signal)?;
        Ok(c)
    }
    pub fn name(&mut self, host: &str) {
        if host.parse::<IpAddr>().is_err() {
            self.correlator.names.insert(normalize(host));
        }
    }
    pub fn endpoint(
        &mut self,
        addr: SocketAddr,
        until: Instant,
        signal: &AtomicUsize,
    ) -> Result<()> {
        let ip = addr.ip();
        self.correlator
            .ports
            .entry(ip)
            .or_default()
            .insert(addr.port());
        if self.sessions.iter().any(|s| s.endpoint == Some(ip)) || self.stopped {
            return Ok(());
        }
        // Session cap bounds descriptors even under hostile multi-address DNS/redirects.
        if self.sessions.len() >= 128 {
            self.fail("capture session limit reached");
            return Ok(());
        }
        if let Err(e) = self.add(Some(ip), until, signal) {
            if e.code >= 128 {
                return Err(e);
            }
            self.fail("new endpoint capture unavailable; recording incomplete");
        }
        Ok(())
    }
    fn add(
        &mut self,
        endpoint: Option<IpAddr>,
        until: Instant,
        signal: &AtomicUsize,
    ) -> Result<()> {
        let session = Session::start(&self.interface, endpoint)?;
        self.sessions.push(session);
        loop {
            let sig = signal.load(Ordering::Relaxed);
            if sig != 0 {
                return Err(Failure {
                    code: 128 + sig as i32,
                    message: "capture startup cancelled".into(),
                });
            }
            let events = self.poll();
            self.pending.extend(events);
            if self.incomplete {
                return Err(Failure::config("capture preflight failed: check tcpdump, interface and permissions; no automatic sudo"));
            }
            if self.sessions.last().is_some_and(|s| s.ready) {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(Failure::config(
                    "capture startup deadline; no probes were sent for this endpoint",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn fail(&mut self, reason: &str) {
        self.incomplete = true;
        self.stopped = true;
        self.pending.push(format!("INCOMPLETE: {reason}"));
        for session in &mut self.sessions {
            if !session.stopped {
                session.stopped = true;
                session.process.terminate();
            }
        }
    }
    pub fn poll(&mut self) -> Vec<String> {
        let mut output = std::mem::take(&mut self.pending);
        if self.stopped {
            return output;
        }
        for index in 0..self.sessions.len() {
            let result = self.sessions[index].read();
            let (packets, logs) = match result {
                Ok(v) => v,
                Err(e) => {
                    self.fail(&e);
                    break;
                }
            };
            for log in logs {
                if log != "capture drop counter=0" {
                    self.incomplete = true;
                }
                output.push(log);
            }
            let Some(parser) = &self.sessions[index].parser else {
                continue;
            };
            let link = parser.header().datalink;
            if self.writer.is_some() && self.sessions[index].interface_id.is_none() {
                let mut block = InterfaceDescriptionBlock::new(link, MAX_PACKET as u32);
                block.options.push(InterfaceDescriptionOption::IfTsResol(9));
                match self.writer.as_mut().unwrap().write_pcapng_block(block) {
                    Ok(n) => {
                        self.file_bytes += n as u64;
                        self.sessions[index].interface_id = Some(self.interfaces);
                        self.interfaces += 1;
                    }
                    Err(_) => {
                        self.fail("PCAPNG interface write failed");
                        break;
                    }
                }
            }
            for packet in packets {
                let summary =
                    self.correlator
                        .summarize(link, &packet.data, self.sessions[index].endpoint);
                let summary = match summary {
                    Ok(Some(s)) => s,
                    Ok(None) => continue,
                    Err(()) => {
                        self.incomplete = true;
                        continue;
                    }
                };
                if self.packets >= MAX_PACKETS {
                    self.fail("100000 associated-packet limit reached");
                    break;
                }
                self.packets += 1;
                if packet.orig_len as usize > packet.data.len() {
                    self.incomplete = true;
                    output.push("associated packet truncated by capture".into());
                }
                output.push(format!(
                    "packet-time={}.{:09} len={} captured={} {summary}",
                    packet.timestamp.as_secs(),
                    packet.timestamp.subsec_nanos(),
                    packet.orig_len,
                    packet.data.len()
                ));
                if let Some(writer) = &mut self.writer {
                    if self.file_bytes + packet.data.len() as u64 + 36 > MAX_FILE {
                        self.fail("100 MiB PCAPNG file limit reached");
                        break;
                    }
                    let block = EnhancedPacketBlock {
                        interface_id: self.sessions[index].interface_id.unwrap(),
                        timestamp: packet.timestamp,
                        original_len: packet.orig_len,
                        data: Cow::Borrowed(&packet.data),
                        options: vec![],
                    };
                    match writer.write_pcapng_block(block) {
                        Ok(n) => self.file_bytes += n as u64,
                        Err(_) => {
                            self.fail(
                                "PCAPNG write failed (disk/full/permissions); raw file partial",
                            );
                            break;
                        }
                    }
                }
            }
            if self.stopped {
                break;
            }
        }
        if self.correlator.incomplete && !self.incomplete {
            output.push("DNS association/reassembly limit or gap; recording INCOMPLETE".into());
            self.incomplete = true;
        }
        output.append(&mut self.pending);
        output
    }
    pub fn finish(&mut self) -> Vec<String> {
        let mut output = vec![];
        if !self.stopped {
            for s in &mut self.sessions {
                s.stopped = true;
                s.process.terminate();
            }
            // Drain pipe tails and tcpdump drop counters after termination.
            for _ in 0..16 {
                output.extend(self.poll());
                if self.sessions.iter().all(|s| s.process.finished().is_some()) {
                    break;
                }
            }
            if self
                .sessions
                .iter()
                .any(|s| !s.bytes.is_empty() || s.process.finished().is_none())
            {
                self.incomplete = true;
                output.push("capture pipe tail truncated/unavailable".into());
            }
        }
        self.stopped = true;
        if let Some(writer) = &mut self.writer {
            if writer.get_mut().sync_all().is_err() {
                self.incomplete = true;
                output.push("PCAPNG sync failed; raw file partial".into());
            }
        }
        output.push(format!("associated packets={} raw-file={} bytes; {}; missing DNS does not prove cache use; missing FIN does not prove failure",self.packets,self.file_bytes,if self.incomplete{"recording INCOMPLETE"}else{"no known capture loss"}));
        output
    }
}
#[derive(Default)]
struct Correlator {
    names: HashSet<String>,
    ports: HashMap<IpAddr, HashSet<u16>>,
    transactions: HashMap<(SocketAddr, SocketAddr, u16), String>,
    tcp: HashMap<(SocketAddr, SocketAddr), (u32, Vec<u8>)>,
    incomplete: bool,
}
fn normalize(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}
impl Correlator {
    fn flow(&self, from: SocketAddr, to: SocketAddr, endpoint: Option<IpAddr>) -> bool {
        endpoint.is_some_and(|ip| {
            self.ports.get(&ip).is_some_and(|ports| {
                (from.ip() == ip && ports.contains(&from.port()))
                    || (to.ip() == ip && ports.contains(&to.port()))
            })
        })
    }
    fn dns(&mut self, src: SocketAddr, dst: SocketAddr, data: &[u8]) -> Option<String> {
        let message = DnsMessage::from_vec(data).ok()?;
        let key = if message.message_type() == MessageType::Query {
            (src, dst, message.id())
        } else {
            (dst, src, message.id())
        };
        let questions: Vec<_> = message
            .queries()
            .iter()
            .map(|q| (normalize(&q.name().to_utf8()), q.query_type()))
            .collect();
        let name = questions
            .iter()
            .find(|(n, _)| self.names.contains(n))
            .map(|(n, _)| n.clone());
        if message.message_type() == MessageType::Query {
            let name = name?;
            if self.transactions.len() >= 4096 {
                self.incomplete = true;
                self.transactions.clear();
            }
            self.transactions.insert(key, name.clone());
            Some(format!(
                "DNS query id={} {name} types={:?}",
                message.id(),
                questions.iter().map(|(_, t)| t).collect::<Vec<_>>()
            ))
        } else {
            let name = self.transactions.get(&key)?;
            if !questions.is_empty() && !questions.iter().any(|(q, _)| q == name) {
                return None;
            }
            let name = self.transactions.remove(&key)?;
            let addresses: Vec<_> = message
                .answers()
                .iter()
                .filter_map(|r| match r.data() {
                    hickory_proto::rr::RData::A(ip) => Some(ip.to_string()),
                    hickory_proto::rr::RData::AAAA(ip) => Some(ip.to_string()),
                    _ => None,
                })
                .collect();
            Some(format!(
                "DNS response id={} name={name} rcode={} addresses={}",
                message.id(),
                message.response_code(),
                addresses.join(",")
            ))
        }
    }
    fn summarize(
        &mut self,
        link: DataLink,
        data: &[u8],
        endpoint: Option<IpAddr>,
    ) -> std::result::Result<Option<String>, ()> {
        let packet = packet(link, data)?;
        let (src, dst) = match packet.net.as_ref() {
            Some(NetSlice::Ipv4(p)) => (
                IpAddr::V4(p.header().source_addr()),
                IpAddr::V4(p.header().destination_addr()),
            ),
            Some(NetSlice::Ipv6(p)) => (
                IpAddr::V6(p.header().source_addr()),
                IpAddr::V6(p.header().destination_addr()),
            ),
            _ => return Ok(None),
        };
        let associated = endpoint.is_some_and(|ip| ip == src || ip == dst);
        match packet.transport {
            Some(TransportSlice::Udp(p)) => {
                let from = SocketAddr::new(src, p.source_port());
                let to = SocketAddr::new(dst, p.destination_port());
                if endpoint.is_none() && (from.port() == 53 || to.port() == 53) {
                    return Ok(self.dns(from, to, p.payload()));
                }
                let trace_probe = endpoint == Some(to.ip()) && (33434..=33689).contains(&to.port());
                Ok((self.flow(from, to, endpoint) || trace_probe)
                    .then(|| format!("UDP {from} -> {to} length={}", p.length())))
            }
            Some(TransportSlice::Tcp(p)) => {
                let from = SocketAddr::new(src, p.source_port());
                let to = SocketAddr::new(dst, p.destination_port());
                if endpoint.is_none()
                    && (from.port() == 53 || to.port() == 53)
                    && !p.payload().is_empty()
                {
                    if self.tcp.len() >= 128 {
                        self.incomplete = true;
                        self.tcp.clear();
                    }
                    let state = self
                        .tcp
                        .entry((from, to))
                        .or_insert((p.sequence_number(), vec![]));
                    if state.0 != p.sequence_number() {
                        // Duplicate segments cannot be attributed twice; gaps/out-of-order
                        // segments are not guessed into a DNS message.
                        self.incomplete = true;
                        return Ok(None);
                    }
                    if state.1.len() + p.payload().len() > 65537 {
                        self.tcp.remove(&(from, to));
                        return Err(());
                    }
                    state.0 = state.0.wrapping_add(p.payload().len() as u32);
                    state.1.extend(p.payload());
                    let mut messages = Vec::new();
                    while state.1.len() >= 2 {
                        let len = u16::from_be_bytes([state.1[0], state.1[1]]) as usize;
                        if state.1.len() < len + 2 {
                            break;
                        }
                        messages.push(state.1[2..len + 2].to_vec());
                        state.1.drain(..len + 2);
                    }
                    let summaries: Vec<_> = messages
                        .iter()
                        .filter_map(|message| self.dns(from, to, message))
                        .collect();
                    return Ok((!summaries.is_empty()).then(|| summaries.join("; ")));
                }
                let flags = [
                    (p.syn(), "SYN"),
                    (p.ack(), "ACK"),
                    (p.fin(), "FIN"),
                    (p.rst(), "RST"),
                    (p.psh(), "PSH"),
                    (p.urg(), "URG"),
                ]
                .into_iter()
                .filter_map(|(yes, s)| yes.then_some(s))
                .collect::<Vec<_>>()
                .join(",");
                Ok(self.flow(from, to, endpoint).then(|| {
                    format!(
                        "TCP {from} -> {to} flags={flags} seq={} ack={} window={}",
                        p.sequence_number(),
                        p.acknowledgment_number(),
                        p.window_size()
                    )
                }))
            }
            Some(TransportSlice::Icmpv4(p)) => Ok(icmp_summary(
                src,
                dst,
                p.slice(),
                p.payload(),
                endpoint,
                associated,
                false,
            )),
            Some(TransportSlice::Icmpv6(p)) => Ok(icmp_summary(
                src,
                dst,
                p.slice(),
                p.payload(),
                endpoint,
                associated,
                true,
            )),
            _ => Ok(None),
        }
    }
}
fn packet(link: DataLink, data: &[u8]) -> std::result::Result<SlicedPacket<'_>, ()> {
    if link == DataLink::ETHERNET {
        return SlicedPacket::from_ethernet(data).map_err(|_| ());
    }
    let offset = match link {
        DataLink::NULL | DataLink::LOOP => 4,
        DataLink::LINUX_SLL => 16,
        DataLink::LINUX_SLL2 => 20,
        DataLink::RAW | DataLink::IPV4 | DataLink::IPV6 => 0,
        _ => return Err(()),
    };
    SlicedPacket::from_ip(data.get(offset..).ok_or(())?).map_err(|_| ())
}
fn quoted_ips(data: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match data.first()? >> 4 {
        4 if data.len() >= 20 => Some((
            Ipv4Addr::new(data[12], data[13], data[14], data[15]).into(),
            Ipv4Addr::new(data[16], data[17], data[18], data[19]).into(),
        )),
        6 if data.len() >= 40 => Some((
            Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?).into(),
            Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?).into(),
        )),
        _ => None,
    }
}
fn icmp_summary(
    src: IpAddr,
    dst: IpAddr,
    header: &[u8],
    payload: &[u8],
    endpoint: Option<IpAddr>,
    associated: bool,
    v6: bool,
) -> Option<String> {
    let kind = *header.first()?;
    let code = *header.get(1)?;
    let error = if v6 {
        kind < 128
    } else {
        matches!(kind, 3 | 4 | 5 | 11 | 12)
    };
    let quoted = if error { quoted_ips(payload) } else { None };
    let quoted_match =
        quoted.is_some_and(|(src, dst)| endpoint.is_some_and(|ip| ip == src || ip == dst));
    if (error && !quoted_match) || (!error && !associated) {
        return None;
    }
    Some(format!(
        "ICMP{} {src} -> {dst} type={kind} code={code}{}",
        if v6 { "v6" } else { "" },
        quoted
            .map(|(s, d)| format!(" quoted-original={s}->{d}"))
            .unwrap_or_default()
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    #[test]
    fn link_types_and_payload_suppression() {
        let builder = PacketBuilder::ipv4([127, 0, 0, 1], [127, 0, 0, 2], 64)
            .tcp(123, 80, 42, 4096)
            .syn();
        let mut raw = vec![];
        builder.write(&mut raw, b"Authorization: secret").unwrap();
        for (link, offset) in [
            (DataLink::RAW, 0),
            (DataLink::NULL, 4),
            (DataLink::LOOP, 4),
            (DataLink::LINUX_SLL, 16),
            (DataLink::LINUX_SLL2, 20),
        ] {
            let mut data = vec![0; offset];
            data.extend(&raw);
            let mut correlator = Correlator::default();
            correlator
                .ports
                .insert("127.0.0.2".parse().unwrap(), HashSet::from([80]));
            let s = correlator
                .summarize(link, &data, Some("127.0.0.2".parse().unwrap()))
                .unwrap()
                .unwrap();
            assert!(s.contains("SYN"));
            assert!(!s.contains("secret"));
            assert!(Correlator::default()
                .summarize(link, &data, Some("1.2.3.4".parse().unwrap()))
                .unwrap()
                .is_none());
            for n in 0..offset + 20 {
                assert!(packet(link, &data[..n]).is_err());
            }
        }
    }
    #[test]
    fn bounded_pcap_and_pcapng_roundtrip() {
        use pcap_file::{pcap::PcapWriter, pcapng::PcapNgReader};
        let mut writer = PcapWriter::new(vec![]).unwrap();
        writer
            .write_packet(&PcapPacket::new(Duration::from_secs(10), 3, b"abc"))
            .unwrap();
        let mut bytes = writer.into_writer();
        let mut parser = None;
        assert_eq!(decode_records(&mut bytes, &mut parser).unwrap().len(), 1);
        bytes.extend([0; 16]);
        bytes[8..12].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(decode_records(&mut bytes, &mut parser).is_err());
        let mut writer = PcapNgWriter::new(vec![]).unwrap();
        writer
            .write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::RAW, 65535))
            .unwrap();
        writer
            .write_pcapng_block(EnhancedPacketBlock {
                interface_id: 0,
                timestamp: Duration::from_secs(1),
                original_len: 3,
                data: Cow::Borrowed(b"abc"),
                options: vec![],
            })
            .unwrap();
        let data = writer.into_inner();
        let mut reader = PcapNgReader::new(data.as_slice()).unwrap();
        assert!(reader.next_block().unwrap().is_ok());
        assert!(reader.next_block().unwrap().is_ok());
    }
}
