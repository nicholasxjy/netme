# netme

A network-monitoring TUI for macOS and Linux, inspired by btop: it uses the terminal background, thin borders, and compact, aligned columns, with blue for downloads and green for uploads. No filled GUI-style cards, simulated buttons, or special fonts are required.

`netme ping <target>` also provides noninteractive, live resource-access diagnostics. It is separate from the monitor and does not enter the TUI.

The interface content and monitoring features remain unchanged:

- Top **DOWNLOAD / UPLOAD**: real-time transfer rates for the default network route.
- **interfaces**: download/upload rates, link bandwidth, and type/band for Ethernet Adapter, Thunderbolt, and Wi-Fi interfaces.
- Bottom **Internal / Router / External**: local addresses, the default gateway, and public egress addresses; External indicates `proxy` or `direct`.

No historical charts, processes, sockets, or extra diagnostic panels are shown, and `nettop` / `ss` are never launched. Only local hardware interfaces are listed, with no hardcoded devices or addresses; loopback, bridge, and VPN interfaces are excluded from hardware rows.

## Installation

### From crates.io (recommended)

Install [Rust and Cargo](https://rustup.rs/), then install the latest release of [netme from crates.io](https://crates.io/crates/netme):

```sh
cargo install netme --locked
```

To install version **0.0.1** specifically:

```sh
cargo install netme --version 0.0.1 --locked
```

Cargo installs the executable to `~/.cargo/bin` by default. Make sure this directory, or the `bin` directory of your custom Cargo installation root, is on your `PATH`. Verify the installation with:

```sh
netme --version
```

Linux requires `iproute2`; `iw` is optional for Wi-Fi link information. macOS uses built-in networking tools. Running netme does not require sudo.

### From source

Alternatively, clone the repository and install from the local checkout:

```sh
git clone https://github.com/nicholasxjy/netme.git
cd netme
cargo install --path . --locked
```

## Usage

Run netme in an interactive terminal on macOS or Linux:

```sh
netme              # Start monitoring with a 1-second refresh interval
netme --interval 2 # 1–60 seconds; default: 1 second
netme --ascii      # ASCII characters and borders
NO_COLOR=1 netme   # No colors
netme --help
```

A terminal size of **80×24** is recommended: wide layouts use a compact interface table and a horizontal network path; narrow layouts use two-line interface rows and a vertical path. **72×24** can also display seven interfaces in full. The minimum size is **44×16**; shorter layouts support scrolling, and IPv6 addresses wrap automatically. The layout uses the terminal width rather than imitating a centered GUI window.

| Key | Action |
| --- | --- |
| `↑` / `↓`, `k` / `j` | Move the selection / scroll interfaces |
| `Home` / `End`, `PageUp` / `PageDown` | Jump to the first or last interface / move by page |
| `Space` | Freeze / resume the display; the border shows pinned while background sampling continues |
| `p` | Query the External IP; confirm with `y` / Enter, cancel with `n` / Esc |
| `q` / `Ctrl-C` | Quit |

## Resource diagnostics: `netme ping`

```sh
netme ping example.com                         # HTTPS; uses configured proxy policy
netme ping example.com:8443/path?key=value     # HTTPS with explicit port/path
netme ping https://example.com --no-diagnose   # Skip auxiliary probes
netme ping http://127.0.0.1:8000 --direct       # Explicitly bypass proxy configuration
netme ping 'https://[::1]:8443/' --direct --cacert local-ca.pem
netme ping tcp://localhost:9000 --direct       # Connect only; no application data
netme ping tcp://localhost:9000 --direct --data 'hello'
netme ping udp://localhost:9000 --direct --data-hex 010203
netme ping udp://example.com:9000 --data '' --proxy socks5h://localhost:1080
netme ping icmp://localhost --direct
netme ping trace://localhost --direct --max-hops 5
netme ping https://example.com --output response.bin
netme ping https://example.com --capture       # Packet summaries only
netme ping https://example.com --pcap trace.pcapng
netme ping --help                             # No TTY or network required
```

**Unlike monitor startup, a ping command intentionally sends traffic.** By default it sends three ICMP echo probes and UDP traceroute probes to the preferred connection endpoint before accessing the resource. Disable these with `--no-diagnose`. Filtered, unavailable or unprivileged auxiliary probes produce warnings, not a failed resource result. Standalone `icmp://` and `trace://` operations use the diagnostic as their main result.

### Dependencies and output

HTTP(S) requires **curl 7.88 or newer**, with HTTP and HTTPS support. Auxiliary diagnostics use system `ping` and `traceroute` (`ping6`/`traceroute6` for IPv6 on macOS); capture requires `tcpdump`. macOS includes these tools. On Debian/Ubuntu:

```sh
sudo apt-get install curl iputils-ping traceroute tcpdump iproute2
```

The command never invokes sudo or changes capture permissions. Missing optional probe tools only warn; explicitly requested capture must pass its startup check before DNS/resource probes. Capture privileges must be arranged separately by the user.

Output is flushed as work happens, with a sequence number, monotonic relative time, stage and redirect-hop number. It shows proxy selection, actual system DNS candidates in order, local route information, auxiliary probe replies/hops, resource connection/negotiation, request/response headers, body progress and final metrics. Plain text works in pipes, with `NO_COLOR`; `--ascii` escapes non-ASCII characters. Progress is limited to once per 500 ms.

Only observed facts are reported. Ordinary socket/curl events are **not** synthetic TCP SYN/ACK packets. A probe to the preferred address is not proof of the resource's path; a different actual peer is identified. Redirects use fresh connections and do not repeat auxiliary probes. Curl timings are labelled cumulative/combined where proxy/TLS phases cannot be separated. Unknown route, certificate or backend fields remain unknown; no response return path is inferred.

### Proxy and DNS policy

Explicit `--proxy URL` or `--direct` takes precedence over the [monitor's discovery order](#public-ip-and-proxies). They are mutually exclusive. HTTP and SOCKS5 proxies support username/password authentication. **Both `socks5://` and `socks5h://` use proxy-side target DNS.** `NO_PROXY` never bypasses a configured proxy, PAC is not executed, and failures never fall back to direct access.

With a proxy, only the **proxy endpoint** is locally resolved, routed and probed. SOCKS UDP relay addresses are resolved when necessary. Origin-side IPs, DNS timing and routes are unobservable unless the protocol reports them. `--ipv4` / `--ipv6` constrain local endpoint connections, not the target family behind a proxy. Standalone ICMP/traceroute cannot use these proxies: explicitly pass `--direct` when a proxy is configured. HTTP proxies cannot relay UDP.

For direct HTTP, the actual system DNS result is passed to curl with `--resolve`, preserving Host, SNI and certificate validation names. Curl ignores curlrc and inherited proxy settings; dynamic configuration and credentials use stdin, not shell interpolation or child command-line arguments. Only recognized verbose events and selected metrics are displayed; raw verbose/JSON output is never forwarded.

### Protocol behavior, limits and files

- Bare domains, IPv4 and IPv6 default to HTTPS. IPv6 ports need brackets. IDNs are normalized. Invalid ports, unknown schemes, resource userinfo and IPv6 zone IDs are rejected before probes; HTTP fragments are not sent. Inapplicable or conflicting options are errors.
- HTTP performs GET, verifies TLS (optional `--cacert`, no insecure switch), negotiates supported HTTP/2 for HTTPS, and does not enable HTTP/3 or browser subresources. It follows 301/302/303/307/308 at most 10 times; `--no-follow` disables this. Loops, unsafe protocols and HTTPS-to-HTTP downgrades are refused. HTTP 4xx/5xx bodies are still read, with a distinct application-failure result.
- TCP without data stops after connection/proxy negotiation. `--data TEXT` or `--data-hex HEX` sends one payload and samples the first response segment, **not a complete application message**. Text has no added newline.
- UDP requires explicit data (empty is allowed), sends exactly one datagram and waits for one response, without retries. Socket peer selection is **not a handshake**. Silence means **service state unknown**, not an open/closed port. SOCKS5 UDP keeps its control connection alive, validates encapsulation and refuses fragmentation. Raw input is bounded to 65,507 bytes; SOCKS UDP encapsulation must also fit that bound.

| Limit | Default / option |
| --- | --- |
| Whole command | 60 s, `--timeout S` |
| DNS/connection stage | 5 s, `--connect-timeout S`, bounded by total deadline |
| ICMP | 3 probes, at most 5 s |
| Traceroute | 30 hops (`--max-hops N`), one probe/hop, 1 s wait, 15 s total (`--trace-timeout S`) |
| TCP response / UDP reply | 5 s, `--reply-timeout S` |
| HTTP preview | 4 KiB, `--preview-bytes N`, at most 1 MiB |
| Cumulative decoded HTTP body | 16 MiB, `--max-bytes N`; `0` removes only the byte limit |
| HTTP headers | 64 KiB/block, 1 MiB total |
| Associated capture | 100,000 packets; raw PCAPNG at most 100 MiB |

Reaching the preview limit does **not** stop downloading. Text previews escape controls; binary previews use bounded hex. Metrics distinguish encoded received body bytes from decoded bytes. `--output FILE` saves only the final response body: work in progress and failed/truncated transfers remain `FILE.partial`, and completed bodies are published without overwriting existing files. No automatic resource retry is performed; unsuccessful pre-connection address candidates may be tried without resending a resource request.

### Capture and sensitive information

`--capture` displays associated packet metadata only: traditional DNS queries/answers, addresses/ports, TCP flags/sequence/ack/window, lengths and ICMP (errors use the quoted original IP packet). Capture starts before DNS, and endpoint sessions start before endpoint traffic. Packet timestamps are separate from the event's log-receipt time. Linux defaults to `any`; macOS defaults to `pktap,all` with RAW link type. `--interface NAME` chooses capture interfaces **only**, not request routing.

Association is bounded by names, transactions and endpoints, **not reliable process attribution**: other processes using the same endpoint can appear. Capture does not decrypt TLS, reveal a proxy's remote path, or prove that missing DNS was cached or missing FIN indicates failure. Drops, parser/recording limits and capture failures mark the record incomplete; resource access can still finish.

**`--pcap FILE` explicitly enables raw, unredacted PCAPNG storage, including original payloads.** It uses mode 0600, refuses existing files, and combines capture sessions with their link types/timestamps. Logs redact proxy userinfo, authorization/cookie/token/API-key headers and URL query values, and escape terminal/bidirectional controls. **Body previews, body files and raw packet files can still contain business secrets.** Do not share them without inspection. The committed localhost certificate/key under `tests/fixtures/` are public test material, never production credentials.

Exit codes: `0` main operation succeeded; `1` definite network/proxy/TLS/HTTP/transfer failure; `2` arguments/configuration/required capability; `3` unknown or incomplete operation/recording. Auxiliary warnings do not change a successful resource result. Termination returns `128 + signal` (Ctrl-C: 130); a closed output pipe stops work quietly. Child process groups are terminated and reaped on completion, timeout, signals and errors.

## Public IP and Proxies

Public IP queries require confirmation: no public internet requests are made at startup. Press `p` and confirm to query `api.ipify.org` / `api6.ipify.org` over HTTPS.

Proxy selection order:

1. The first nonempty environment variable: `https_proxy`, `HTTPS_PROXY`, `all_proxy`, `ALL_PROXY`, `http_proxy`, `HTTP_PROXY`.
2. If no environment proxy is set, macOS reads the active manual HTTPS, HTTP, and SOCKS proxy settings from `scutil --proxy`.
3. **Connect directly only when no proxy is configured.** An invalid proxy or a failed request displays `proxy failed`; the application never silently bypasses the proxy and exposes the direct egress address. PAC / automatic proxy discovery cannot be executed directly; provide an explicit proxy environment variable instead.

HTTP CONNECT and SOCKS proxies are supported (`socks5h://` uses remote DNS). For example:

```sh
HTTPS_PROXY=http://127.0.0.1:7890 netme
ALL_PROXY=socks5h://127.0.0.1:7890 netme
```

- Queries report the public egress address of the proxy / current connection, not the public IP of every process. Configured proxies take precedence; `NO_PROXY` is not used to bypass them.
- A proxy with an IPv4 address can be used to query its IPv6 egress address; the proxy's address family is not incorrectly restricted to the family being queried.
- TLS verification remains enabled, redirects are disabled, each request has a 5-second timeout, and responses are limited to 64 bytes with IP address family validation. Proxy credentials are never shown in the interface or error messages.
- Successful results are cached for 60 seconds. Changes to the network generation or proxy configuration invalidate the cache. Failed queries do not reuse cached results; press `p` and confirm again to retry immediately. There are no automatic retries. IPv4 results appear as soon as they succeed, without waiting for IPv6.
- Before a query or after a network change, the display shows `p: query`; while querying, it shows `…`; failures show `proxy failed` / `unavailable`. If a query is confirmed immediately after startup, it waits for the first network sample to avoid incorrectly treating the result as data from an old network.

## Measurement Details

- Cumulative interface counters come from `sysinfo`; rates are calculated using the actual elapsed interval from a monotonic clock. The first sample, counter resets, and interface identity changes display `—` rather than fabricated zero values. B/s, KB/s, and MB/s use decimal units.
- The top display uses the IPv4 default route, then the IPv6 default route, then an online hardware interface. Physical interface and tunnel traffic are not double-counted.
- Link bandwidth and Wi-Fi bands use only system-reported values. Disconnected interfaces show `0.00 b/s`; unknown values remain unknown. Metadata refreshes approximately every 5 seconds, and Wi-Fi link information approximately every 30 seconds, with earlier refreshes when connectivity changes.
- Internal / Router values correspond to the default route; unknown gateways are not guessed. A VPN default route may differ from the visible hardware interfaces.
- Sampling and requests run on worker threads without blocking the interface. The terminal is restored on normal exit, errors, panics, and SIGTERM/INT/HUP/QUIT; cleanup is not possible after SIGKILL.

## Validation

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked live_loopback_smoke -- --ignored --nocapture
cargo build --locked
python3 tests/tty_smoke.py target/debug/netme
python3 tests/ping_local.py target/debug/netme  # Also run by cargo test; requires python3/curl
python3 tests/ping_smoke.py target/debug/netme  # Real loopback auxiliary probes
# Optional, only after arranging capture permissions (no automatic sudo):
NETME_CAPTURE_SMOKE=1 python3 tests/ping_smoke.py target/debug/netme
# Optional: live HTTPS query through a proxy; contacts ipify without printing the returned IP
cargo test --locked live_public_ip_proxy_smoke -- --ignored --nocapture
```

The default tests do not access the public internet. Proxy tests use a local mock CONNECT service to verify IPv6 queries through an IPv4 proxy, no DNS requests for the target, no direct-connection fallback on failure, and no credential leaks in errors. Layout tests cover thin borders and an unfilled background, all existing fields, compact / wide layouts, scrolling, ASCII / NO_COLOR, IPv6, and the confirmation dialog.

See [VALIDATION.md](VALIDATION.md) for actual local validation results.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.
