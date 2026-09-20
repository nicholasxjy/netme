# Changelog

All notable changes to netme are documented in this file.

## [0.0.1] - 2026-09-20

Initial release on crates.io.

### Added

- A btop-inspired network-monitoring TUI for macOS and Linux, with real-time download/upload rates, hardware interface details, and local, gateway, and public egress addresses.
- Responsive terminal layouts, interface scrolling, display pinning, ASCII borders, and `NO_COLOR` support.
- Configurable refresh intervals from 1 to 60 seconds, with no sudo required to run the monitor.
- Confirmation-based public IPv4/IPv6 lookups with HTTP CONNECT and SOCKS proxy support, environment and macOS system proxy selection, and no direct fallback when a configured proxy fails.
- Network-aware public IP caching, TLS verification, bounded requests, and independent IPv4/IPv6 results.
- Unit tests, loopback and terminal smoke tests, and CI checks for macOS and Linux.
- English documentation covering crates.io installation, version-specific installation, source installation, usage, and proxy configuration.

### Fixed

- Public IP queries confirmed immediately after startup now wait for the first network sample, preventing valid results from being discarded as stale.
- Failed public IP queries can be retried immediately after confirmation without reusing cached results; the interface shows `p: query` before a query or after a network change.

[0.0.1]: https://crates.io/crates/netme/0.0.1
