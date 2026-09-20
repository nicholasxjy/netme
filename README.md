# netme

A network-monitoring TUI for macOS and Linux, inspired by btop: it uses the terminal background, thin borders, and compact, aligned columns, with blue for downloads and green for uploads. No filled GUI-style cards, simulated buttons, or special fonts are required.

The interface content and monitoring features remain unchanged:

- Top **DOWNLOAD / UPLOAD**: real-time transfer rates for the default network route.
- **interfaces**: download/upload rates, link bandwidth, and type/band for Ethernet Adapter, Thunderbolt, and Wi-Fi interfaces.
- Bottom **Internal / Router / External**: local addresses, the default gateway, and public egress addresses; External indicates `proxy` or `direct`.

No historical charts, processes, sockets, or extra diagnostic panels are shown, and `nettop` / `ss` are never launched. Only local hardware interfaces are listed, with no hardcoded devices or addresses; loopback, bridge, and VPN interfaces are excluded from hardware rows.

## Usage

```sh
cargo install --path . --locked
netme
netme --interval 2   # 1–60 seconds; default: 1 second
netme --ascii       # ASCII characters and borders
NO_COLOR=1 netme    # No colors
netme --help
```

A terminal size of **80×24** is recommended: wide layouts use a compact interface table and a horizontal network path; narrow layouts use two-line interface rows and a vertical path. **72×24** can also display seven interfaces in full. The minimum size is **44×16**; shorter layouts support scrolling, and IPv6 addresses wrap automatically. The layout uses the terminal width rather than imitating a centered GUI window.

Linux requires `iproute2`; `iw` is optional for Wi-Fi link information. macOS uses built-in networking tools. No sudo is required.

| Key | Action |
| --- | --- |
| `↑` / `↓`, `k` / `j` | Move the selection / scroll interfaces |
| `Home` / `End`, `PageUp` / `PageDown` | Jump to the first or last interface / move by page |
| `Space` | Freeze / resume the display; the border shows pinned while background sampling continues |
| `p` | Query the External IP; confirm with `y` / Enter, cancel with `n` / Esc |
| `q` / `Ctrl-C` | Quit |

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
# Optional: live HTTPS query through a proxy; contacts ipify without printing the returned IP
cargo test --locked live_public_ip_proxy_smoke -- --ignored --nocapture
```

The default tests do not access the public internet. Proxy tests use a local mock CONNECT service to verify IPv6 queries through an IPv4 proxy, no DNS requests for the target, no direct-connection fallback on failure, and no credential leaks in errors. Layout tests cover thin borders and an unfilled background, all existing fields, compact / wide layouts, scrolling, ASCII / NO_COLOR, IPv6, and the confirmation dialog.

See [VALIDATION.md](VALIDATION.md) for actual local validation results.
