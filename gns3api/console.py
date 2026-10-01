"""Raw-socket telnet client for GNS3 node consoles.

Console automation must survive two protocol quirks: telnet IAC negotiation
bytes interleaved with shell output (filtered in ``_strip_iac``), and a
fresh session replaying its boot banner (drained passively on connect, see
``Console._passive_drain``).

Observed in practice against at least one GNS3 compute's console proxy:
a connection tolerates exactly ONE outbound command line before the server
resets it (reproduces with a bare socket, no telnet-option replies, on both
alpine- and debian-based node images -- not specific to either). So every
function here opens a fresh connection per command instead of reusing one
``Console`` across multiple sends; see ``_exec_once``.
"""
from __future__ import annotations

import base64
import hashlib
import re
import socket
import time

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")

# sized so that "printf '%s' '<chunk>'" stays under the ~255-byte canonical
# PTY line limit on debinet-style consoles
CHUNK_SIZE = 120


def _strip_iac_filter(data: bytes, pending: bytes) -> tuple[bytes, bytes]:
    """Removes telnet IAC sequences; caller keeps the unterminated tail."""
    b = pending + data
    out = bytearray()
    i = 0
    n = len(b)
    while i < n:
        c = b[i]
        if c != 0xFF:
            out.append(c)
            i += 1
            continue
        if i + 1 >= n:
            pending = b[i:]
            break
        cmd = b[i + 1]
        if cmd == 0xFF:
            out.append(0xFF)
            i += 2
        elif cmd in (0xFB, 0xFC, 0xFD, 0xFE):
            if i + 2 >= n:
                pending = b[i:]
                break
            i += 3
        elif cmd == 0xFA:
            j = b.find(b"\xF0", i + 2)
            if j == -1:
                pending = b[i:]
                break
            i = j + 1
        else:
            i += 2
    return bytes(out), pending


class Console:
    """Single-session telnet client for a node console."""

    def __init__(self, host: str, port: int, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.buf = b""
        self._pending = b""

    def connect(self) -> "Console":
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(0.2)
        return self

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self) -> "Console":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    def _recv(self) -> bytes:
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            return b""
        if not data:
            raise ConnectionError("console closed")
        clean, self._pending = _strip_iac_filter(data, self._pending)
        return clean

    def send_line(self, line: str) -> None:
        self.sock.sendall(line.encode() + b"\n")

    def read_until(self, marker: bytes, timeout: float) -> tuple[bool, str]:
        """Waits for ``marker`` in the stream; returns (found, text so far)."""
        deadline = time.time() + timeout
        buf = self.buf
        while time.time() < deadline:
            idx = buf.find(marker)
            if idx != -1:
                consumed, rest = buf[: idx + len(marker)], buf[idx + len(marker):]
                self.buf = rest
                return True, consumed.decode(errors="replace")
            try:
                buf += self._recv()
            except ConnectionError:
                self.buf = buf
                return False, buf.decode(errors="replace")
        self.buf = buf
        return False, buf.decode(errors="replace")

    def _passive_drain(self, timeout: float = 0.4) -> None:
        """Clears a stale session banner WITHOUT sending anything -- an
        active probe command would itself consume this connection's one
        tolerated outbound line (see module docstring)."""
        self.buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.buf += self._recv()
            except ConnectionError:
                break
        self.buf = b""

    def exec(self, command: str, timeout: float = 30.0) -> str:
        """Runs one shell command on a freshly-connected console and returns
        its output (echoed command line and completion marker both
        stripped). This must be the ONLY command sent on `self`'s connection
        (see module docstring) -- callers needing several commands should
        open a new Console (or use `exec_once`) per command."""
        self._passive_drain()
        tag = f"X{time.time_ns() % 937:03d}"
        self.send_line(f"{command}; echo {tag}$?{tag}")
        ok, out = self.read_until((tag + "0" + tag).encode(), timeout)
        if not ok:
            # read_until() swallows a mid-stream ConnectionError and returns
            # whatever partial output it had -- surface that as a failure
            # instead of handing the caller silently-truncated output, so a
            # retry wrapper (e.g. Gns3Client._console_retry) can catch it.
            raise ConnectionError(
                f"exec({command!r}) did not complete within {timeout}s - stream tail: {out[-160:]!r}"
            )
        cleaned = _ANSI_RE.sub("", out)
        body = cleaned.split("\n", 1)[-1]  # drop the echoed command line
        # the marker is "{tag}{exitcode}{tag}" -- cut at its FIRST occurrence
        # (not rfind: that would land between the two tag copies and leave
        # the exit-code digit glued onto the real output, silently
        # corrupting anything that must match byte-for-byte, e.g. base64).
        idx = body.find(tag)
        if idx != -1:
            body = body[:idx]
        return body


def exec_once(host: str, port: int, command: str, timeout: float = 30.0) -> str:
    """Opens a fresh connection, runs exactly one command, closes. The
    building block for any multi-step console operation (see push_file/
    pull_file below) now that one connection only tolerates one command."""
    with Console(host, port) as con:
        return con.exec(command, timeout=timeout)


def push_file(
    host: str,
    port: int,
    path: str,
    content: str,
    mode: int | None = None,
    timeout: float = 120.0,
) -> str:
    """Writes ``content`` to ``path`` through a console session (base64
    chunked transport, works for any path, /root included). Returns a
    short summary of the written size."""
    payload = base64.b64encode(content.encode()).decode()
    chunks = [payload[i:i + CHUNK_SIZE] for i in range(0, len(payload), CHUNK_SIZE)]
    tmp = f"/tmp/.gns3api-{time.time_ns() % 9973:04d}.b64"

    # Each step below is its OWN connection -- see module docstring. This
    # costs a reconnect per chunk (noticeably slower than one persistent
    # session would be), but a persistent session is not reliable here.
    exec_once(host, port, f"rm -f {tmp}", timeout)
    for chunk in chunks:
        exec_once(host, port, f"printf '%s' '{chunk}' >> {tmp}", timeout)

    expected = str(len(payload))
    out = exec_once(host, port, f"wc -c <{tmp}", timeout)
    if expected not in out:
        raise RuntimeError(f"upload size mismatch (want {expected} base64 bytes, got {out!r}) - {path}")

    decode_cmd = f"base64 -d {tmp} > {path} && rm -f {tmp}"
    if mode is not None:
        decode_cmd = f"base64 -d {tmp} > {path} && chmod {mode:o} {path} && rm -f {tmp}"
    exec_once(host, port, decode_cmd, timeout)

    out = exec_once(host, port, f"wc -c <{path}", timeout)
    if str(len(content)) not in out:
        raise RuntimeError(f"after-write size check failed for {path} - got {out!r}")

    return f"written {path}: {len(content)} bytes" + (f" (mode {mode:o})" if mode else "")


def pull_file(host: str, port: int, path: str, timeout: float = 60.0) -> str:
    """Reads ``path`` through a console session (any path, /root included).
    The node base64-encodes the file into one output line, so binary
    content survives the transport; the caller receives the decoded text."""
    out = exec_once(host, port, f"base64 -w0 {path} 2>/dev/null", timeout)
    # bracketed-paste toggles (esc[?2004l) ride along inside long output
    # echo -- without stripping them the payload misaligns
    payload = "".join(out.split())
    if not payload:
        raise RuntimeError(f"{path} unreadable or empty on the node")
    return base64.b64decode(payload).decode()


def pull_file_chunked(
    host: str, port: int, path: str, timeout: float = 180.0, page: int = 100,
) -> str:
    """Page-window pull: base64 with line wrapping, fetched through one
    ``exec_once`` per step, immune to the bracketed-paste/wrap corruption
    class that hits big one-line pulls (the whole payload never rides a
    single console line or a single connection).

    Markers embed '#' which is outside the base64 alphabet, so payload text
    can never fabricate or truncate a marker match; each page opens with a
    '#START#' window so a wrapped echoed command line can never leak into
    the base64. The reassembled content is verified against a node-side
    md5 before returning - a mismatch raises instead of handing back
    silently corrupted data."""
    staged = f"/tmp/.gns3api-{time.time_ns() % 9973:04d}.b64"
    try:
        exec_once(host, port, f"base64 -w {page} {path} > {staged}", timeout)

        nl_out = exec_once(host, port, f"wc -l < {staged}", timeout)
        numbers = re.findall(r"(\d+)", nl_out)
        if not numbers:
            raise RuntimeError(f"could not count b64 lines for {path}: {nl_out!r}")
        nlines = int(numbers[0])

        md5_out = exec_once(host, port, f"md5sum {path} | cut -d' ' -f1", timeout)
        node_md5_m = re.search(r"([0-9a-f]{32})", md5_out)
        node_md5 = node_md5_m.group(1) if node_md5_m else None

        parts = []
        for start in range(1, nlines + 1, page):
            end = min(start + page - 1, nlines)
            out = exec_once(
                host, port,
                f"echo '#START#'; sed -n '{start},{end}p' {staged}", timeout)
            # everything up to the LAST '#START#' is echoed-command residue
            # (the echoed command itself contains the literal); the payload
            # is pure base64 so '#' can never occur inside it
            parts.append(out[out.rfind("#START#") + len("#START#"):])
    finally:
        exec_once(host, port, f"rm -f {staged}", timeout)

    payload = "".join("".join(_ANSI_RE.sub("", p).split()) for p in parts)
    content = base64.b64decode(payload).decode()
    if node_md5:
        local_md5 = hashlib.md5(content.encode()).hexdigest()
        if local_md5 != node_md5:
            raise RuntimeError(
                f"integrity mismatch on {path}: node {node_md5} != local {local_md5}; "
                f"decoded head: {content[:60]!r}")
    return content
