use super::{
    event,
    proxy::{Kind, Proxy},
    Context, Failure, PingOptions, Result,
};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    os::fd::{AsRawFd, FromRawFd},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub fn resolve(
    c: &mut Context<'_>,
    host: &str,
    port: u16,
    family: Option<bool>,
    timeout: Duration,
) -> Result<Vec<SocketAddr>> {
    c.check()?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        if family.is_some_and(|v6| ip.is_ipv6() != v6) {
            return Err(Failure::failed(
                "literal endpoint conflicts with local address-family constraint",
            ));
        }
        c.emit("DNS", format!("{ip}: IP literal; resolution skipped"))?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    c.emit(
        "DNS",
        format!("resolving {host}; system resolver; candidate order preserved"),
    )?;
    let start = Instant::now();
    let until = c.until(timeout);
    let host = host.to_owned();
    let (tx, rx) = mpsc::sync_channel(1);
    // A late resolver may finish its OS lookup but owns no socket/request continuation.
    thread::spawn(move || {
        let _ = tx.send(
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|a| a.collect::<Vec<_>>()),
        );
    });
    let addresses = loop {
        c.check()?;
        match rx.try_recv() {
            Ok(a) => break a.map_err(|_| Failure::failed("system DNS resolution failed"))?,
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(Failure::failed("resolver stopped"))
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if Instant::now() >= until {
            return Err(Failure::failed("DNS deadline exceeded"));
        }
        c.pause()?;
    };
    let mut out = vec![];
    for addr in addresses {
        if family.is_none_or(|v6| addr.is_ipv6() == v6) && !out.contains(&addr) {
            out.push(addr);
        }
    }
    if out.is_empty() {
        return Err(Failure::failed(
            "DNS returned no candidates in requested address family",
        ));
    }
    for (i, addr) in out.iter().enumerate() {
        c.emit(
            "DNS",
            format!(
                "candidate={} address={addr} elapsed={:.3}s",
                i + 1,
                start.elapsed().as_secs_f64()
            ),
        )?;
    }
    Ok(out)
}

pub fn connect(
    c: &mut Context<'_>,
    addresses: &[SocketAddr],
    timeout: Duration,
) -> Result<TcpStream> {
    let until = c.until(timeout);
    let start = Instant::now();
    for (i, addr) in addresses.iter().enumerate() {
        c.check()?;
        if Instant::now() >= until {
            break;
        }
        c.emit(
            "connection",
            format!("TCP attempt={} endpoint={addr}", i + 1),
        )?;
        match connect_one(c, *addr, until) {
            Ok(stream) => {
                c.endpoint(*addr)?;
                c.emit(
                    "connection",
                    format!(
                        "TCP connected local={} peer={addr} elapsed={:.3}s",
                        stream
                            .local_addr()
                            .map_err(|_| Failure::failed("local socket address unavailable"))?,
                        start.elapsed().as_secs_f64()
                    ),
                )?;
                return Ok(stream);
            }
            Err(e) => {
                if e.code != 1 {
                    return Err(e);
                }
                c.emit("connection", e.message)?;
            }
        }
    }
    Err(Failure::failed(
        "all TCP connection candidates failed (no resource data sent)",
    ))
}
fn connect_one(c: &mut Context<'_>, addr: SocketAddr, until: Instant) -> Result<TcpStream> {
    // SAFETY: initialized platform sockaddr structures, valid lengths; sole fd ownership
    // transfers immediately to TcpStream so all failure paths close it.
    let stream = unsafe {
        let fd = libc::socket(
            if addr.is_ipv6() {
                libc::AF_INET6
            } else {
                libc::AF_INET
            },
            libc::SOCK_STREAM,
            0,
        );
        if fd < 0 {
            return Err(Failure::failed("cannot create TCP socket"));
        }
        let stream = TcpStream::from_raw_fd(fd);
        stream
            .set_nonblocking(true)
            .map_err(|_| Failure::failed("cannot set nonblocking socket"))?;
        let rc = match addr {
            SocketAddr::V4(a) => {
                let mut raw: libc::sockaddr_in = std::mem::zeroed();
                raw.sin_family = libc::AF_INET as _;
                #[cfg(target_os = "macos")]
                {
                    raw.sin_len = std::mem::size_of_val(&raw) as _;
                }
                raw.sin_port = a.port().to_be();
                raw.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
                libc::connect(
                    fd,
                    (&raw as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&raw) as _,
                )
            }
            SocketAddr::V6(a) => {
                let mut raw: libc::sockaddr_in6 = std::mem::zeroed();
                raw.sin6_family = libc::AF_INET6 as _;
                #[cfg(target_os = "macos")]
                {
                    raw.sin6_len = std::mem::size_of_val(&raw) as _;
                }
                raw.sin6_port = a.port().to_be();
                raw.sin6_addr.s6_addr = a.ip().octets();
                libc::connect(
                    fd,
                    (&raw as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of_val(&raw) as _,
                )
            }
        };
        if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(Failure::failed("TCP connect rejected by OS"));
        }
        stream
    };
    loop {
        c.check()?;
        let mut pfd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 0) } > 0 {
            if stream
                .take_error()
                .map_err(|_| Failure::failed("TCP connect status unavailable"))?
                .is_some()
            {
                return Err(Failure::failed("TCP connection refused/unreachable"));
            }
            if stream.peer_addr().is_ok() {
                return Ok(stream);
            }
        }
        if Instant::now() >= until {
            return Err(Failure::failed("TCP connect timeout"));
        }
        c.pause()?;
    }
}
fn io_wait<T>(
    c: &mut Context<'_>,
    until: Instant,
    mut operation: impl FnMut() -> io::Result<T>,
) -> Result<T> {
    loop {
        c.check()?;
        if Instant::now() >= until {
            return Err(Failure::incomplete("reply/IO deadline exceeded"));
        }
        match operation() {
            Ok(v) => return Ok(v),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                c.pause()?
            }
            Err(e) => return Err(Failure::failed(format!("socket IO failed: {}", e.kind()))),
        }
    }
}
fn write(c: &mut Context<'_>, s: &mut TcpStream, mut data: &[u8], until: Instant) -> Result<()> {
    while !data.is_empty() {
        let n = io_wait(c, until, || s.write(data))?;
        if n == 0 {
            return Err(Failure::failed("socket closed during send"));
        }
        data = &data[n..];
    }
    Ok(())
}
fn read_exact(
    c: &mut Context<'_>,
    s: &mut TcpStream,
    data: &mut [u8],
    until: Instant,
) -> Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let n = io_wait(c, until, || s.read(&mut data[offset..]))?;
        if n == 0 {
            return Err(Failure::failed(
                "proxy closed connection during negotiation",
            ));
        }
        offset += n;
    }
    Ok(())
}
pub fn tcp(
    c: &mut Context<'_>,
    o: &PingOptions,
    proxy: Option<&Proxy>,
    addresses: &[SocketAddr],
) -> Result<()> {
    let mut stream = connect(c, addresses, o.connect_timeout)?;
    let until = c.until(o.connect_timeout);
    if let Some(p) = proxy {
        match p.kind {
            Kind::Http => http_connect(c, &mut stream, p, &o.target.authority(), until)?,
            Kind::Socks => {
                socks_auth(c, &mut stream, p, until)?;
                socks_command(c, &mut stream, 1, &o.target.host, o.target.port, until)?;
            }
        }
    }
    let Some(data) = &o.data else {
        return c.emit(
            "result",
            "TCP connection succeeded; no application data sent",
        );
    };
    let until = c.until(o.reply_timeout);
    c.emit(
        "request",
        format!("sending {} TCP bytes once (no added newline)", data.len()),
    )?;
    write(c, &mut stream, data, until)?;
    let mut buffer = vec![0; 65536];
    let n = io_wait(c, until, || stream.read(&mut buffer))?;
    c.emit(
        "response",
        format!(
            "sample={n} bytes; NOT a complete application message; {}",
            event::preview(&buffer[..n.min(4096)])
        ),
    )?;
    c.emit("result", "TCP access completed")
}
fn http_connect(
    c: &mut Context<'_>,
    s: &mut TcpStream,
    p: &Proxy,
    authority: &str,
    until: Instant,
) -> Result<()> {
    c.emit("proxy", format!("CONNECT {authority} HTTP/1.1"))?;
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if p.authenticated() {
        let credentials = base64(format!("{}:{}", p.username, p.password).as_bytes());
        c.redactor.secret(&credentials);
        request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
        c.emit("proxy", "Proxy-Authorization: [redacted]")?;
    }
    request.push_str("\r\n");
    write(c, s, request.as_bytes(), until)?;
    let mut bytes = vec![];
    let mut byte = [0];
    // Read only the header: do not consume bytes from the established tunnel.
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 65536 {
            return Err(Failure::failed("CONNECT response exceeds 64 KiB"));
        }
        read_exact(c, s, &mut byte, until)?;
        bytes.push(byte[0]);
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Failure::failed("invalid CONNECT headers"))?;
    let first = text.lines().next().unwrap_or_default();
    let status = first
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());
    for line in text.lines().filter(|s| !s.is_empty()) {
        c.emit(
            "proxy",
            if line.starts_with([' ', '\t']) {
                "[folded header redacted]".into()
            } else {
                event::header(line)
            },
        )?;
    }
    if !first.starts_with("HTTP/1.") || status != Some(200) {
        return Err(Failure::failed(
            "HTTP CONNECT rejected (no direct fallback)",
        ));
    }
    c.emit(
        "proxy",
        "CONNECT established; proxy-to-origin IP/route/timing unobservable",
    )
}
fn socks_auth(c: &mut Context<'_>, s: &mut TcpStream, p: &Proxy, until: Instant) -> Result<()> {
    c.emit("proxy", "SOCKS5 method negotiation started")?;
    let method = if p.authenticated() { 2 } else { 0 };
    write(c, s, &[5, 1, method], until)?;
    let mut response = [0; 2];
    read_exact(c, s, &mut response, until)?;
    if response != [5, method] {
        return Err(Failure::failed("SOCKS5 method rejected or malformed"));
    }
    if method == 2 {
        c.emit(
            "proxy",
            "SOCKS5 username/password authentication (redacted)",
        )?;
        let mut auth = vec![1, p.username.len() as u8];
        auth.extend(p.username.as_bytes());
        auth.push(p.password.len() as u8);
        auth.extend(p.password.as_bytes());
        write(c, s, &auth, until)?;
        auth.fill(0);
        read_exact(c, s, &mut response, until)?;
        if response != [1, 0] {
            return Err(Failure::failed("SOCKS5 authentication rejected"));
        }
    }
    c.emit("proxy", "SOCKS5 negotiation accepted")
}
fn address(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut data = vec![];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            data.push(1);
            data.extend(a.octets());
        }
        Ok(IpAddr::V6(a)) => {
            data.push(4);
            data.extend(a.octets());
        }
        Err(_) => {
            if host.len() > 255 || host.is_empty() {
                return Err(Failure::config("SOCKS5 domain length invalid"));
            }
            data.extend([3, host.len() as u8]);
            data.extend(host.as_bytes());
        }
    }
    data.extend(port.to_be_bytes());
    Ok(data)
}
fn socks_command(
    c: &mut Context<'_>,
    s: &mut TcpStream,
    command: u8,
    host: &str,
    port: u16,
    until: Instant,
) -> Result<(String, u16)> {
    c.emit(
        "proxy",
        format!(
            "SOCKS5 {} target={host}:{port}; target DNS remote",
            if command == 3 {
                "UDP ASSOCIATE"
            } else {
                "CONNECT"
            }
        ),
    )?;
    let mut data = vec![5, command, 0];
    data.extend(address(host, port)?);
    write(c, s, &data, until)?;
    let mut response = [0; 4];
    read_exact(c, s, &mut response, until)?;
    if response[0] != 5 || response[2] != 0 {
        return Err(Failure::failed("malformed SOCKS5 command response"));
    }
    if response[1] != 0 {
        return Err(Failure::failed(format!(
            "SOCKS5 command rejected code={}",
            response[1]
        )));
    }
    let n = match response[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0];
            read_exact(c, s, &mut n, until)?;
            n[0] as usize
        }
        _ => return Err(Failure::failed("invalid SOCKS5 address type")),
    };
    let mut bytes = vec![0; n + 2];
    read_exact(c, s, &mut bytes, until)?;
    let host = decode_host(response[3], &bytes[..n])?;
    let port = u16::from_be_bytes([bytes[n], bytes[n + 1]]);
    c.emit(
        "proxy",
        format!("SOCKS5 accepted bound={host}:{port}; remote path unobservable"),
    )?;
    Ok((host, port))
}
fn decode_host(kind: u8, bytes: &[u8]) -> Result<String> {
    match kind {
        1 if bytes.len() == 4 => {
            Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
        }
        4 if bytes.len() == 16 => {
            Ok(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()).to_string())
        }
        3 if !bytes.is_empty() => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| Failure::failed("invalid SOCKS5 domain")),
        _ => Err(Failure::failed("malformed SOCKS5 address")),
    }
}
pub fn validate_payload(o: &PingOptions, proxy: Option<&Proxy>) -> Result<()> {
    if o.target.protocol == super::target::Protocol::Udp
        && proxy.is_some()
        && o.data.as_ref().map_or(0, Vec::len) + address(&o.target.host, o.target.port)?.len() + 3
            > 65507
    {
        return Err(Failure::config(
            "SOCKS5 encapsulated datagram exceeds 65507 bytes",
        ));
    }
    Ok(())
}

pub fn udp(
    c: &mut Context<'_>,
    o: &PingOptions,
    proxy: Option<&Proxy>,
    addresses: &[SocketAddr],
) -> Result<()> {
    let data = o.data.as_ref().unwrap();
    let mut control = None;
    let (socket, peer, wire) = if let Some(p) = proxy {
        let mut tcp = connect(c, addresses, o.connect_timeout)?;
        let until = c.until(o.connect_timeout);
        socks_auth(c, &mut tcp, p, until)?;
        let ip = tcp
            .local_addr()
            .map_err(|_| Failure::failed("control local address unavailable"))?
            .ip();
        // The relay may have a different family from the control connection.
        // RFC 1928 permits all-zero client address/port when not yet known.
        let (mut host, port) = socks_command(
            c,
            &mut tcp,
            3,
            if ip.is_ipv6() { "::" } else { "0.0.0.0" },
            0,
            until,
        )?;
        if port == 0 {
            return Err(Failure::failed("SOCKS5 relay returned port zero"));
        }
        if host.parse::<IpAddr>().is_ok_and(|a| a.is_unspecified()) {
            host = tcp.peer_addr().unwrap().ip().to_string();
            c.emit(
                "proxy",
                "wildcard relay address replaced with control peer IP",
            )?;
        }
        if let Some(cap) = &mut c.capture {
            cap.name(&host);
        }
        let relay = resolve(c, &host, port, o.family, o.connect_timeout)?[0];
        let socket = UdpSocket::bind(if relay.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .map_err(|_| Failure::failed("UDP relay socket bind failed"))?;
        c.capture_endpoint(relay)?;
        let mut wire = vec![0, 0, 0];
        wire.extend(address(&o.target.host, o.target.port)?);
        wire.extend(data);
        if wire.len() > 65507 {
            return Err(Failure::config(
                "SOCKS5 encapsulated datagram exceeds 65507 bytes",
            ));
        }
        control = Some(tcp);
        (socket, relay, wire)
    } else {
        let peer = addresses[0];
        let bind = if peer.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        (
            UdpSocket::bind(bind).map_err(|_| Failure::failed("UDP bind failed"))?,
            peer,
            data.clone(),
        )
    };
    c.check()?;
    socket
        .set_nonblocking(true)
        .map_err(|_| Failure::failed("UDP nonblocking failed"))?;
    socket
        .connect(peer)
        .map_err(|_| Failure::failed("UDP peer selection failed"))?;
    c.endpoint(peer)?;
    c.emit(
        "connection",
        format!(
            "UDP peer selected local={} peer={peer}; NOT a handshake",
            socket.local_addr().unwrap()
        ),
    )?;
    c.emit(
        "request",
        format!(
            "sending ONE UDP datagram: payload={} wire={} bytes{}",
            data.len(),
            wire.len(),
            if proxy.is_some() {
                "; SOCKS5 encapsulated"
            } else {
                ""
            }
        ),
    )?;
    let until = c.until(o.reply_timeout);
    let n = io_wait(c, until, || socket.send(&wire))?;
    if n != wire.len() {
        return Err(Failure::failed("short UDP send"));
    }
    let mut buffer = vec![0; 65536];
    let n = loop {
        c.check()?;
        if Instant::now() >= until {
            return Err(Failure::incomplete(
                "UDP: no response received; service state UNKNOWN (not open/closed)",
            ));
        }
        if let Some(tcp) = &control {
            match tcp.peek(&mut [0]) {
                Ok(0) => return Err(Failure::failed("SOCKS5 UDP control connection closed")),
                Ok(_) => {
                    return Err(Failure::failed(
                        "unexpected data on SOCKS5 UDP control connection",
                    ))
                }
                Err(e) if e.kind() != io::ErrorKind::WouldBlock => {
                    return Err(Failure::failed("SOCKS5 UDP control connection failed"))
                }
                _ => {}
            }
        }
        match socket.recv(&mut buffer) {
            Ok(n) => break n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => c.pause()?,
            Err(e) => return Err(Failure::failed(format!("UDP receive error: {}", e.kind()))),
        }
    };
    let payload = if proxy.is_some() {
        let (host, port, payload) = decode_datagram(&buffer[..n])?;
        if port != o.target.port
            || (o.target.host.parse::<IpAddr>().is_ok() && host != o.target.host)
            || (host.parse::<IpAddr>().is_err()
                && !host
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(o.target.host.trim_end_matches('.')))
        {
            return Err(Failure::failed(
                "SOCKS5 UDP response source does not match target",
            ));
        }
        c.emit(
            "proxy",
            format!("SOCKS5 UDP decapsulated source={host}:{port}"),
        )?;
        payload
    } else {
        &buffer[..n]
    };
    c.emit(
        "response",
        format!(
            "one UDP response: wire={n} payload={} bytes; {}",
            payload.len(),
            event::preview(&payload[..payload.len().min(4096)])
        ),
    )?;
    drop(control);
    c.emit("result", "UDP response received (one exchange, no retries)")
}
fn decode_datagram(bytes: &[u8]) -> Result<(String, u16, &[u8])> {
    if bytes.len() < 4 || bytes[..2] != [0, 0] {
        return Err(Failure::failed("malformed SOCKS5 UDP header"));
    }
    if bytes[2] != 0 {
        return Err(Failure::failed("SOCKS5 UDP fragmentation is unsupported"));
    }
    let (start, n) = match bytes[3] {
        1 => (4, 4),
        4 => (4, 16),
        3 if bytes.len() > 4 => (5, bytes[4] as usize),
        _ => return Err(Failure::failed("invalid SOCKS5 UDP address type")),
    };
    if bytes.len() < start + n + 2 {
        return Err(Failure::failed("truncated SOCKS5 UDP address"));
    }
    let host = decode_host(bytes[3], &bytes[start..start + n])?;
    let port = u16::from_be_bytes([bytes[start + n], bytes[start + n + 1]]);
    Ok((host, port, &bytes[start + n + 2..]))
}
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for c in bytes.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | c.get(2).copied().unwrap_or(0) as u32;
        for i in 0..4 {
            result.push(if i > c.len() {
                '='
            } else {
                TABLE[((n >> (18 - i * 6)) & 63) as usize] as char
            });
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn socks_wire_and_bounds() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        for host in ["1.2.3.4", "::1", "no-dns.invalid"] {
            let mut data = vec![0, 0, 0];
            data.extend(address(host, 123).unwrap());
            data.extend(b"hello");
            let (h, p, b) = decode_datagram(&data).unwrap();
            assert_eq!(h, host);
            assert_eq!(p, 123);
            assert_eq!(b, b"hello");
            data[2] = 1;
            assert!(decode_datagram(&data).is_err());
            for n in 0..data.len() - 5 {
                assert!(decode_datagram(&data[..n]).is_err());
            }
        }
        assert!(address(&"x".repeat(256), 1).is_err());
    }
}
