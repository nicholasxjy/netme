#!/usr/bin/env python3
"""Local-only end-to-end fixtures. No DNS/public traffic except system localhost lookup.
The committed TLS key is public test data; never use it for a real service.
"""
import base64
import contextlib
import gzip
import http.server
import json
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

BINARY = os.path.abspath(sys.argv[1])
FIXTURES = Path(__file__).parent / "fixtures"
ENV = {k: v for k, v in os.environ.items() if k.lower() not in
       ("https_proxy", "http_proxy", "all_proxy", "no_proxy")}
ENV["NO_COLOR"] = "1"
COUNT = 0


def check(name, condition=True):
    global COUNT
    assert condition, name
    COUNT += 1
    print("PASS", name, flush=True)


def cmd(target, *flags, direct=True):
    return [BINARY, "ping", target, "--timeout", "4", "--connect-timeout", "1",
            "--no-diagnose"] + (["--direct"] if direct else []) + list(flags)


def run(target, *flags, code=0, direct=True, env=None):
    result = subprocess.run(cmd(target, *flags, direct=direct), env=env or ENV,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=8)
    text = result.stdout.decode("utf-8", "replace")
    assert result.returncode == code, (target, flags, result.returncode, text)
    assert "\x1b" not in text, text
    return text


def exact(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise AssertionError(("short read", n, data))
        data += chunk
    return data


def headers(s):
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        data += exact(s, 1)
        assert len(data) < 65536
    return data


@contextlib.contextmanager
def tcp_server(handler, count=1):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(6)
    errors = []

    def serve():
        try:
            for _ in range(count):
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(5)
                    handler(stream)
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        listener.close()
        thread.join(6)
        assert not thread.is_alive(), "fixture thread leaked"
        assert not errors, errors


class HTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counts = {}
    lock = threading.Lock()
    cross = ""

    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.lock:
            self.counts[self.path] = self.counts.get(self.path, 0) + 1
        path = self.path.split("?")[0]
        body, status, extra = b"hello local resource\n", 200, []
        if path == "/redirect":
            status, body, extra = 302, b"INTERMEDIATE-DO-NOT-SAVE", [("Location", "/final?token=redirect-secret")]
        elif path == "/loop":
            status, extra = 301, [("Location", "/loop")]
        elif path.startswith("/chain/"):
            status, extra = 307, [("Location", "/chain/" + str(int(path.rsplit("/", 1)[1]) + 1))]
        elif path == "/bad-location":
            status, extra = 302, [("Location", "file:///etc/passwd")]
        elif path == "/userinfo":
            status, extra = 302, [("Location", "http://user:location-secret@localhost/")]
        elif path == "/downgrade":
            status, extra = 302, [("Location", "http://127.0.0.1:1/")]
        elif path == "/cross":
            status, extra = 308, [("Location", self.cross)]
        elif path == "/error":
            status, body = 503, b"application-failure-body"
        elif path == "/gzip":
            body, extra = gzip.compress(b"decompressed-body" * 1000), [("Content-Encoding", "gzip")]
        elif path == "/binary":
            body = bytes(range(256))
        elif path == "/large":
            body = b"x" * 100000
        elif path == "/control":
            body = b"hello\x1b[31m\x00"
            extra = [("X-Terminal", "\x1b[31m")]
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
            return
        elif path == "/short":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"partial-body")
            return
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "session=cookie-secret")
        self.send_header("X-Api-Key", "header-secret")
        self.send_header("Connection", "close")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if path == "/slow":
            time.sleep(1)
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


@contextlib.contextmanager
def http_server(tls=False):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
    server.daemon_threads = True
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(FIXTURES / "localhost-cert.pem", FIXTURES / "localhost-key.pem")
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield ("https" if tls else "http") + f"://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def cli_http(tmp):
    result = subprocess.run([BINARY, "ping", "--help"], env={**ENV, "PATH": str(tmp)}, capture_output=True)
    check("ping help works without TTY/tools/network", result.returncode == 0 and b"Usage:" in result.stdout)
    for target, flags in [("udp://host:1", []), ("https://u:cli-secret@host/", []),
                          ("host:99999", []), ("http://[::1%25lo0]/", []),
                          ("host", ["--data", "x"]), ("host", ["--ipv4", "--ipv6"]),
                          ("host", ["--max-bytes", "bad"]), ("host", ["--proxy", "invalid://user:cli-secret@host"])]:
        r = subprocess.run([BINARY, "ping", target] + flags, env=ENV, capture_output=True)
        assert r.returncode == 2 and b"cli-secret" not in r.stdout + r.stderr
    check("invalid CLI/configuration rejected before probes; no credential errors")
    with http_server() as base, http_server() as second:
        HTTP.cross = second + "/final"
        text = run(base + "/?token=query-secret", "--ascii")
        assert "query-secret" not in text and "cookie-secret" not in text and "header-secret" not in text
        assert "request" in text and "first-byte" in text and "actual peer=" in text and "metrics" in text
        check("real HTTP stages, full redacted headers, query redaction, non-TTY ASCII")
        text = run(base.replace("127.0.0.1", "localhost"), "--ipv4")
        check("system localhost DNS pinned into curl", "candidate=1" in text and "system resolver" in text)
        output = tmp / "body"
        text = run(base + "/redirect", "--output", str(output))
        check("relative redirects and final-only output", "redirects=1" in text and output.read_bytes() == b"hello local resource\n" and not Path(str(output) + ".partial").exists() and "redirect-secret" not in text)
        text = run(base + "/cross")
        check("cross-origin redirect on a new connection", "[hop=1]" in text and "redirects=1" in text)
        run(base + "/loop", code=1)
        run(base + "/chain/0", code=1)
        run(base + "/bad-location", code=1)
        assert "location-secret" not in run(base + "/userinfo", code=1)
        check("redirect loops, limits, unsafe protocol and userinfo refused")
        text = run(base + "/redirect", "--no-follow")
        check("no-follow reads intermediate response", "status=302" in text and "INTERMEDIATE-DO-NOT-SAVE" in text)
        text = run(base + "/error", code=1)
        check("4xx/5xx body retained with application failure", "application-failure-body" in text and "network responded" in text)
        run(base + "/large", "--max-bytes", "0", "--preview-bytes", "0")
        text = run(base + "/gzip", "--preview-bytes", "16")
        check("compressed body continues after preview", "decoded=17000" in text and "preview=16" in text)
        assert "binary hex" in run(base + "/binary")
        assert "hello world" in run(base + "/chunked")
        assert "\\u{1b}" in run(base + "/control")
        check("binary, chunked and terminal-control bodies")
        partial = tmp / "limited"
        run(base + "/large", "--max-bytes", "8192", "--output", str(partial), code=3)
        check("max-byte truncation uses partial file", not partial.exists() and Path(str(partial) + ".partial").stat().st_size == 8192)
        run(base + "/short", code=3)
        run(base, "--output", str(output), code=2)
        check("early disconnect and no-overwrite output")
        p = subprocess.Popen(cmd(base + "/slow"), env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        start = time.monotonic()
        lines = []
        while True:
            line = p.stdout.readline()
            assert line, b"".join(lines)
            lines.append(line)
            if b"first-byte" in line:
                break
        check("events arrive before delayed body/completion", p.poll() is None and time.monotonic() - start < 0.9)
        p.communicate(timeout=5)
        assert p.returncode == 0
        for sig in (signal.SIGINT, signal.SIGTERM):
            p = subprocess.Popen(cmd(base + "/slow"), env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            while b"first-byte" not in p.stdout.readline():
                assert p.poll() is None
            p.send_signal(sig)
            p.communicate(timeout=3)
            check(f"signal {sig} terminates resource and returns 128+signal", p.returncode == 128 + sig)
        args = cmd(base + "/slow")
        args[args.index("--timeout") + 1] = "0.2"
        p = subprocess.run(args, env=ENV, capture_output=True, timeout=3)
        check("overall timeout prevents late completion", p.returncode == 3)
        p = subprocess.Popen(cmd(base + "/slow"), env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stdout.close()
        p.wait(timeout=3)
        check("closed output pipe exits quietly", p.returncode == 0 and p.stderr.read() == b"")
    with http_server(tls=True) as base:
        run(base, code=1)
        text = run(base, "--cacert", str(FIXTURES / "localhost-cert.pem"))
        check("local trusted TLS and certificate rejection", "TLS" in text and "status=200" in text)
        run(base + "/downgrade", "--cacert", str(FIXTURES / "localhost-cert.pem"), code=1)
        check("HTTPS downgrade refused")


def socks_address(s):
    kind = exact(s, 1)[0]
    length = {1: 4, 4: 16}.get(kind)
    if kind == 3:
        length = exact(s, 1)[0]
    assert length is not None
    host = exact(s, length)
    return kind, host, struct.unpack("!H", exact(s, 2))[0]


def socks_start(s, auth=False, reject=False):
    version, n = exact(s, 2)
    assert version == 5
    methods = exact(s, n)
    method = 2 if auth else 0
    assert method in methods
    s.sendall(bytes([5, method]))
    if auth:
        assert exact(s, 1) == b"\x01"
        user = exact(s, exact(s, 1)[0])
        password = exact(s, exact(s, 1)[0])
        assert user == b"fixture-user" and password == b"proxy-secret"
        s.sendall(bytes([1, int(reject)]))
        if reject:
            return None
    version, command, reserved = exact(s, 3)
    assert (version, reserved) == (5, 0)
    return command, socks_address(s)


def proxies_tcp_udp(tmp):
    def http_proxy(s):
        request = headers(s)
        assert request.startswith(b"GET http://no-dns.invalid/")
        assert b"Proxy-Authorization: Basic " in request
        s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nproxied")
    with tcp_server(http_proxy) as port:
        text = run("http://no-dns.invalid/?token=remote-secret", "--proxy", f"http://fixture-user:proxy-secret@127.0.0.1:{port}", direct=False)
        check("HTTP proxy uses remote target DNS and hides credentials", "proxied" in text and "resolving no-dns.invalid" not in text and "proxy-secret" not in text and "remote-secret" not in text and "fixture-user" not in text)

    def reject_connect(s):
        assert headers(s).startswith(b"CONNECT no-dns.invalid:443 HTTP/1.1")
        s.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
    with tcp_server(reject_connect) as port:
        text = run("https://no-dns.invalid/", "--proxy", f"http://127.0.0.1:{port}", direct=False, code=1)
        check("CONNECT 407 rejection without direct fallback", "407" in text)

    def socks_http(s):
        command, (kind, host, port) = socks_start(s, auth=True)
        assert (command, kind, host, port) == (1, 3, b"no-dns.invalid", 80)
        s.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
        headers(s)
        s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nsocksbody")
    for scheme in ("socks5", "socks5h"):
        with tcp_server(socks_http) as port:
            text = run("http://no-dns.invalid/", "--proxy", f"{scheme}://fixture-user:proxy-secret@127.0.0.1:{port}", "--ipv4", direct=False)
            assert "socksbody" in text and "proxy-secret" not in text
    check("both SOCKS spellings use proxy DNS with authentication")

    # A failed proxy must never touch a reachable direct target, even with NO_PROXY=*.
    with socket.socket() as target, socket.socket() as dead:
        target.bind(("127.0.0.1", 0)); target.listen(); target.settimeout(0.1)
        dead.bind(("127.0.0.1", 0)); dead_port = dead.getsockname()[1]; dead.close()
        run(f"http://127.0.0.1:{target.getsockname()[1]}/", "--proxy", f"http://u:proxy-secret@127.0.0.1:{dead_port}", direct=False, code=1, env={**ENV, "NO_PROXY": "*"})
        try:
            target.accept()
            raise AssertionError("direct fallback!")
        except socket.timeout:
            pass
    check("broken proxy never falls back direct, NO_PROXY ignored")

    def connect_echo(s):
        assert headers(s).startswith(b"CONNECT no-dns.invalid:123 HTTP/1.1")
        s.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        assert exact(s, 4) == b"test"
        s.sendall(b"connect-echo")
    with tcp_server(connect_echo) as port:
        text = run("tcp://no-dns.invalid:123", "--data", "test", "--proxy", f"http://fixture-user:proxy-secret@127.0.0.1:{port}", direct=False)
        check("native TCP CONNECT authentication and one response sample", "connect-echo" in text and "NOT a complete" in text and "proxy-secret" not in text)

    def socks_echo(s):
        command, (kind, host, port) = socks_start(s, auth=True)
        assert (command, kind, host, port) == (1, 4, socket.inet_pton(socket.AF_INET6, "::1"), 123)
        s.sendall(b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + b"\x00\x01")
        assert exact(s, 4) == b"test"
        s.sendall(b"socks-tcp")
    with tcp_server(socks_echo) as port:
        text = run("tcp://[::1]:123", "--data", "test", "--ipv4", "--proxy", f"socks5://fixture-user:proxy-secret@127.0.0.1:{port}", direct=False)
        check("IPv4 SOCKS proxy accesses IPv6 target without local family restriction", "socks-tcp" in text)

    def no_data(s):
        assert s.recv(1) == b"", "TCP connect-only sent unsolicited payload"
    with tcp_server(no_data) as port:
        run(f"tcp://127.0.0.1:{port}")
    check("TCP connect-only sends no application bytes")

    def echo(s):
        assert exact(s, 3) == b"abc"
        s.sendall(b"tcp-echo")
    with tcp_server(echo) as port:
        assert "tcp-echo" in run(f"tcp://127.0.0.1:{port}", "--data-hex", "616263")
    check("direct native TCP with exact hex payload")

    def auth_reject(s):
        assert socks_start(s, auth=True, reject=True) is None
    with tcp_server(auth_reject) as port:
        run("tcp://no-dns.invalid:123", "--proxy", f"socks5://fixture-user:proxy-secret@127.0.0.1:{port}", direct=False, code=1)
    check("SOCKS authentication rejection")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0)); udp.settimeout(3)
        seen = []
        def echo_udp():
            data, addr = udp.recvfrom(65536); seen.append(data); udp.sendto(b"udp-echo", addr)
        t = threading.Thread(target=echo_udp); t.start()
        assert "udp-echo" in run(f"udp://127.0.0.1:{udp.getsockname()[1]}", "--data", "")
        t.join(); assert seen == [b""]
        udp.settimeout(0.1)
        try:
            udp.recvfrom(65536); raise AssertionError("UDP retry")
        except socket.timeout:
            pass
        text = run(f"udp://127.0.0.1:{udp.getsockname()[1]}", "--data", "one", "--reply-timeout", "0.1", code=3)
        assert "UNKNOWN" in text
        check("direct UDP: explicit empty datagram, single send, unknown on silence")

    for fragment in (False, True):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
            relay.bind(("127.0.0.1", 0)); relay.settimeout(3)
            def associate(s):
                command, _ = socks_start(s, auth=True)
                assert command == 3
                # Wildcard address must be replaced with the control peer.
                s.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00" + struct.pack("!H", relay.getsockname()[1]))
                data, addr = relay.recvfrom(65536)
                assert data.startswith(b"\x00\x00\x00\x03\x0eno-dns.invalid\x00\x7b") and data.endswith(b"ping")
                response = b"\x00\x00" + bytes([int(fragment)]) + b"\x01\xc0\x00\x02\x01\x00\x7bresponse"
                relay.sendto(response, addr)
                assert s.recv(1) == b""  # control stays alive until exchange ends
            with tcp_server(associate) as port:
                text = run("udp://no-dns.invalid:123", "--data", "ping", "--proxy", f"socks5://fixture-user:proxy-secret@127.0.0.1:{port}", direct=False, code=1 if fragment else 0)
                assert "fragmentation" in text if fragment else "decapsulated" in text
    check("SOCKS5 UDP ASSOCIATE, wildcard relay, remote DNS, control lifetime, fragment refusal")


def fake_tools(tmp):
    tools = tmp / "tools"; tools.mkdir()
    def executable(name, content):
        p = tools / name; p.write_text(content); p.chmod(0o700); return p
    executable("ping", "#!/bin/sh\necho 'ping: Operation not permitted' >&2\nexit 2\n")
    executable("traceroute", "#!/bin/sh\necho ' 1 *'\nexit 1\n")
    env = {**ENV, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", "")}
    with http_server() as base:
        args = cmd(base); args.remove("--no-diagnose")
        r = subprocess.run(args, env=env, capture_output=True, timeout=6)
        check("failed auxiliary diagnostics warn but do not block resource", r.returncode == 0 and b"warning" in r.stdout and b"status=200" in r.stdout)
        executable("tcpdump", "#!/bin/sh\necho 'tcpdump: permission denied' >&2\nexit 1\n")
        before = HTTP.counts.get("/capture-check", 0)
        text = run(base + "/capture-check", "--capture", env=env, code=2)
        check("capture permission failure occurs before resource traffic", HTTP.counts.get("/capture-check", 0) == before and "no automatic sudo" in text)
        pcap = tmp / "already.pcapng"; pcap.write_bytes(b"keep")
        run(base, "--pcap", str(pcap), env=env, code=2)
        check("raw capture refuses existing files", pcap.read_bytes() == b"keep")
        # Synthetic tcpdump stream tests capture framing, association, raw storage,
        # timestamps and drop reporting without granting capture permissions.
        capture_port = base.rsplit(":", 1)[1]
        executable("tcpdump", f'''#!{sys.executable}
import os, signal, struct, sys, time

def finish(*args):
    os.write(2, (os.environ.get("FIXTURE_DROPS", "0") + " packets dropped by kernel\\n").encode())
    sys.exit(0)
signal.signal(signal.SIGTERM, finish)
os.write(2, b"tcpdump: listening on fixture\\n")
os.write(1, struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101))
if sys.argv[-1] != "port 53":
    if os.environ.get("FIXTURE_BAD_LENGTH"):
        os.write(1, struct.pack("<IIII", 123, 456000, 0xffffffff, 0xffffffff))
    else:
        payload = b"CAPTURE-SECRET-PAYLOAD"
        def ip(body, proto, src, dst):
            return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(body), 1, 0, 64, proto, 0, src, dst) + body
        tcp = struct.pack("!HHIIBBHHH", 45678, {capture_port}, 1, 2, 0x50, 0x12, 4096, 0, 0) + payload
        packet = ip(tcp, 6, b"\\x7f\\x00\\x00\\x02", b"\\x7f\\x00\\x00\\x01")
        error = ip(b"\\x03\\x03\\x00\\x00\\x00\\x00\\x00\\x00" + packet[:28], 1, b"\\x7f\\x00\\x00\\x03", b"\\x7f\\x00\\x00\\x02")
        for data in (packet, error):
            os.write(1, struct.pack("<IIII", 123, 456000, len(data), len(data)) + data)
while True: time.sleep(1)
''')
        saved = tmp / "packets.pcapng"
        text = run(base, "--pcap", str(saved), env=env)
        raw = saved.read_bytes()
        assert raw[:4] == b"\x0a\x0d\x0d\x0a" and b"CAPTURE-SECRET-PAYLOAD" in raw
        assert "CAPTURE-SECRET-PAYLOAD" not in text and "packet-time=123.456000000" in text
        assert "seq=1 ack=2 window=4096" in text and "quoted-original=" in text
        assert saved.stat().st_mode & 0o777 == 0o600
        check("capture packet association, preserved timestamps, safe summaries and 0600 PCAPNG")
        text = run(base, "--capture", env={**env, "FIXTURE_DROPS": "7"}, code=3)
        check("capture drops make successful resource recording incomplete", "drop counter=7" in text and "status=200" in text)
        text = run(base, "--capture", env={**env, "FIXTURE_BAD_LENGTH": "1"}, code=3)
        check("malicious capture record length is bounded; resource continues", "INCOMPLETE" in text and "status=200" in text)
    # A fake curl checks the streamed orchestration lifecycle without sockets.
    real_curl = subprocess.check_output(["which", "curl"], env=ENV, text=True).strip()
    child_pid = tmp / "child.pid"
    executable("curl", f'''#!/bin/sh
if [ "$2" = "--version" ]; then exec "{real_curl}" --disable --version; fi
sleep 30 &
echo $! > "{child_pid}"
wait
''')
    args = cmd("http://127.0.0.1:1/"); args[args.index("--timeout") + 1] = "0.2"
    r = subprocess.run(args, env=env, capture_output=True, timeout=3)
    assert r.returncode == 3 and child_pid.exists()
    pid = int(child_pid.read_text())
    for _ in range(30):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        # Linux may expose a short-lived zombie reparented to init, but it must not run.
        stat = Path(f"/proc/{pid}/stat")
        assert stat.exists() and ") Z " in stat.read_text(), "subprocess descendant still running"
    check("deadline kills resource child process group, including descendants")


def main():
    with tempfile.TemporaryDirectory(prefix="netme-ping-tests-") as directory:
        tmp = Path(directory)
        cli_http(tmp)
        proxies_tcp_udp(tmp)
        fake_tools(tmp)
    print(f"{COUNT} local-only ping scenarios passed")


if __name__ == "__main__":
    main()
