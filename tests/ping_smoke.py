#!/usr/bin/env python3
"""Real ordinary-permission loopback tools; optional explicit capture permission test."""
import http.server
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "8")
        self.end_headers()
        self.wfile.write(b"loopback")

    def log_message(self, *args):
        pass


def main():
    binary = os.path.abspath(sys.argv[1])
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/"
    try:
        result = subprocess.run(
            [binary, "ping", target, "--direct", "--timeout", "15",
             "--max-hops", "2", "--trace-timeout", "2"],
            capture_output=True, timeout=20,
        )
        text = result.stdout.decode("utf-8", "replace")
        assert result.returncode == 0, (text, result.stderr)
        assert "ICMP" in text and "traceroute" in text and "status=200" in text
        print("PASS real loopback diagnostics + HTTP (auxiliary warnings allowed)")
        if os.environ.get("NETME_CAPTURE_SMOKE") == "1":
            with tempfile.TemporaryDirectory(prefix="netme-capture-smoke-") as directory:
                path = Path(directory) / "loopback.pcapng"
                result = subprocess.run(
                    [binary, "ping", target, "--direct", "--no-diagnose",
                     "--timeout", "10", "--pcap", str(path)],
                    capture_output=True, timeout=15,
                )
                assert result.returncode == 0, (result.stdout, result.stderr)
                assert path.read_bytes().startswith(b"\x0a\x0d\x0d\x0a")
                assert b"packet-time=" in result.stdout
                print("PASS explicitly enabled real capture permissions/PCAPNG smoke")
        else:
            print("SKIP real capture permissions (set NETME_CAPTURE_SMOKE=1 explicitly)")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
