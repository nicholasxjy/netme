#!/usr/bin/env python3
"""No external packages or public traffic: exercise real PTY restoration."""
import errno
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time


def run_case(binary, label, keys=None, termination=None, size=(24, 80), color=False):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", *size, 0, 0))
    env = {**os.environ, "TERM": "xterm-256color", "NO_COLOR": "1"}
    if color:
        env.pop("NO_COLOR")
    child = subprocess.Popen(
        [binary] + ([] if color else ["--ascii"]),
        stdin=slave, stdout=slave, stderr=slave, env=env,
    )
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 20
    try:
        while child.poll() is None and time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    output.extend(os.read(master, 65536))
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                assert len(output) < 4 * 1024 * 1024, "excessive TUI output"
            # Ratatui may skip spaces with cursor moves; match a single word.
            ready = b"DOWNLOAD" in output or b"Resize" in output
            if not sent and ready and b"\x1b[?1049h" in output:
                if termination:
                    child.send_signal(termination)
                else:
                    assert keys is not None
                    os.write(master, keys)
                sent = True
        assert sent, f"{label}: never entered TUI: {output[-1000:]!r}"
        assert child.poll() is not None, f"{label}: exit timed out"
        assert child.returncode == 0, f"{label}: exit {child.returncode}: {output[-1000:]!r}"
        assert termios.tcgetattr(slave) == before, f"{label}: terminal mode not restored"
        for removed in (b"processes", b"connections", b"route / selected", b"Tab panels"):
            assert removed not in output, f"{label}: obsolete content {removed!r}"
        if color:
            assert b"38;2;" in output, f"{label}: missing terminal accent colors"
            assert b"48;2;" not in output, f"{label}: GUI-style backgrounds returned"
        print(f"PASS {label}: content, exit and termios restored")
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        os.close(master)
        os.close(slave)


def main():
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/debug/netme")
    result = subprocess.run([binary], input=b"", capture_output=True, check=False)
    assert result.returncode != 0 and b"TTY required" in result.stderr
    for arg in ("--help", "--version"):
        assert subprocess.run([binary, arg], capture_output=True, check=False).returncode == 0
    run_case(binary, "scroll, pin and cancel public request", keys=b"jjk  pnq")
    run_case(binary, "btop-style colors", keys=b"q", color=True)
    run_case(binary, "compact", keys=b"jjjkq", size=(24, 72))
    run_case(binary, "narrow", keys=b"q", size=(24, 52))
    run_case(binary, "undersized", keys=b"q", size=(10, 40))
    run_case(binary, "Ctrl-C", keys=b"\x03")
    run_case(binary, "SIGTERM", termination=signal.SIGTERM)
    run_case(binary, "SIGHUP", termination=signal.SIGHUP)


if __name__ == "__main__":
    main()
