"""zerocl frontend: ALB/modern-CDN front end in front of the blog backend.

Single-threaded selectors loop, stdlib only. It models the strict, raw-piping
side of the H-V (hidden-visible) discrepancy this lab teaches:

  - a client request's header block ends at the first CRLFCRLF;
  - a field name must match ^[A-Za-z0-9-]+$ immediately followed by ':': no
    OWS before the colon, no obs-fold continuation lines. Nonconforming
    header lines are IGNORED (obfuscated Content-Length forms become
    invisible), so the front end sees a bodyless request and considers its
    side done after forwarding the header block bytes verbatim;
  - plain Content-Length is honored normally for framing client reads;
  - no headers are added or rewritten upstream, and the response reader does
    NO HEAD special-casing (this lab's choreography relies on it).

Upstream: one pooled keep-alive connection (pool size 1) with FIFO request
slotting and no per-request rebalancing, so the attacker and the scripted
admin poll share the single poisonable upstream slot. Forwarding is gated:
at most one registered expectation in flight per slot; fully-framed client
requests held by the gate resume in the order they completed client-side.
Responses are attributed positionally: one arriving when nobody is awaiting
is banked as overflow debt, and new requests are served from overflow before
their own queue position - the response-queue shift the desync exploits.

A forwarded request that gets no response within RESPONSE_TIMEOUT answers
504 (the naive 0.CL deadlock observable) and resets the upstream slot.
"""

import os
import selectors
import socket
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 80
UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "backend")
UPSTREAM_PORT = 8000
UPSTREAM_IDLE_CAP = 120  # must exceed the 5s bot period (brief §4)
RESPONSE_TIMEOUT = 10.0  # forwarded request without a response -> 504
RX_CHUNK = 262144
RESP_504 = (
    "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n"
    "Connection: keep-alive\r\n\r\n"
).encode("latin-1")


def log(*parts: object) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts} fe]", *parts, flush=True)


def parse_request_head(block: bytes) -> tuple[str, str, int]:
    """Strict FE parse of one client header block.

    Returns (method, target, declared_body_length). Header lines whose name
    fails the strict form (any line beginning with whitespace, i.e. obs-fold
    continuations, or OWS before the colon) are IGNORED, never joined, so no
    obfuscated Content-Length is honored here.
    """
    lines = block.split(b"\r\n")
    text = [ln.decode("latin-1") for ln in lines if ln]
    if not text or not text[0]:
        raise ValueError("empty head")
    parts = text[0].split(" ")
    if len(parts) != 3:
        raise ValueError(f"bad request line: {text[0]!r}")
    method, target, version = parts
    if not version.startswith("HTTP/1."):
        raise ValueError(f"unrecognized version: {version!r}")

    declared = 0
    for line in text[1:]:
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            continue  # obfuscated form: invisible to this front end
        if not all(ch.isalnum() or ch == "-" for ch in name):
            continue
        if name.lower() == "content-length" and value.strip().isdigit():
            declared = int(value.strip())
    return method, target, declared


def response_body_length(head_block: bytes) -> int:
    """The FE's response framing: read the declared body, no HEAD exception."""
    for line in head_block.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        if name.strip().lower() == b"content-length" and value.strip().isdigit():
            return int(value.strip())
    return 0


class Client:
    """One client TCP connection (attacker or scripted admin poll)."""

    def __init__(self, sock: socket.socket, selector) -> None:
        self.sock = sock
        self.sel = selector
        self.rx = b""                  # raw bytes not yet framed
        self.pending = bytearray()     # response bytes waiting to be written
        self.stage = "idle"            # idle | body | closed
        self.body_left = 0


class Front:
    def __init__(self) -> None:
        self.sel = selectors.DefaultSelector()
        self.server: socket.socket | None = None
        self.clients: dict[socket.socket, Client] = {}
        self.up_sock: socket.socket | None = None
        self.up_rx = b""
        self.up_out = bytearray()      # bytes pending write to the upstream
        # Response framing state on the upstream socket.
        self.resp_state = "head"       # head | body
        self.resp_want = 0
        self.resp_buf = bytearray()
        self.resp_head = b""
        # Positional bookkeeping on the single poisonable slot.
        self.await_fifo: list[tuple[Client, str]] = []  # (conn, method)
        self.overflow: list[bytes] = []
        # Fully-framed client requests held until the slot frees.
        self.held: list[tuple[Client, bytes, str, int]] = []  # (conn, head, method, declared)
        self.has_inflight = False
        self.inflight_since = 0.0
        self.idle_since = time.monotonic()

    # ------------------------------------------------------------ lifecycle
    def upstream_open(self) -> bool:
        if self.up_sock is not None:
            return True
        try:
            sock = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=5)
        except OSError as exc:
            log("upstream open failed:", exc)
            return False
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.up_sock = sock
        self.up_rx = b""
        self.up_out = bytearray()
        self.resp_state = "head"
        self.resp_want = 0
        self.resp_buf = bytearray()
        self.resp_head = b""
        self.sel.register(sock, selectors.EVENT_READ | selectors.EVENT_WRITE)
        log("upstream opened")
        return True

    def arm_upstream_write(self) -> None:
        """Re-arm WRITE interest whenever outbound upstream bytes exist."""
        if self.up_sock is not None and self.up_out:
            try:
                self.sel.modify(
                    self.up_sock, selectors.EVENT_READ | selectors.EVENT_WRITE
                )
            except (KeyError, ValueError, OSError):
                pass

    def upstream_ensure(self) -> bool:
        if self.up_sock is not None:
            return True
        return self.upstream_open()

    def upstream_close_stalled(self) -> None:
        if self.up_sock is not None:
            try:
                self.sel.unregister(self.up_sock)
            except (KeyError, ValueError):
                pass
            try:
                self.up_sock.close()
            except OSError:
                pass
            self.up_sock = None

    # ------------------------------------------------------------ clients
    def close_client(self, conn: Client) -> None:
        try:
            self.sel.unregister(conn.sock)
        except (KeyError, ValueError):
            pass
        try:
            conn.sock.close()
        except OSError:
            pass
        self.clients.pop(conn.sock, None)
        conn.stage = "closed"
        self.held = [h for h in self.held if h[0] is not conn]
        self.await_fifo = [(c, m) for c, m in self.await_fifo if c is not conn]

    def accept(self) -> None:
        assert self.server is not None
        try:
            sock, _addr = self.server.accept()
        except OSError:
            return
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client = Client(sock, self.sel)
        self.clients[sock] = client
        self.sel.register(sock, selectors.EVENT_READ)
        log("client connected", sock.getpeername())

    def drop(self, conn: Client) -> None:
        conn.stage = "closed"
        self.close_client(conn)

    # ------------------------------------------------------------ client side
    def client_readable(self, sock: socket.socket, conn: Client) -> None:
        try:
            chunk = sock.recv(RX_CHUNK)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self.drop(conn)
            return
        if not chunk:
            self.drop(conn)
            return
        conn.rx += chunk
        self.frame_client(conn)

    def frame_client(self, conn: Client) -> None:
        """Advance the client's framing and slot complete requests FIFO."""
        while True:
            if conn.stage == "body":
                take = min(len(conn.rx), conn.body_left)
                if take:
                    conn.body_left -= take
                    self.up_out += conn.rx[:take]
                    conn.rx = conn.rx[take:]
                if conn.body_left == 0:
                    conn.stage = "idle"
                else:
                    return  # that conn's socket is still mid-body
            if conn.stage != "idle":
                return
            if b"\r\n\r\n" not in conn.rx:
                return
            head_end = conn.rx.find(b"\r\n\r\n") + 4
            head_block = conn.rx[:head_end]
            conn.rx = conn.rx[head_end:]
            try:
                method, target, declared = parse_request_head(head_block)
            except ValueError as exc:
                log("closed malformed head:", exc)
                self.drop(conn)
                return
            if target.split("?", 1)[0] == "/__health":
                conn.pending += (
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    "Connection: keep-alive\r\n\r\nok"
                ).encode("latin-1")
                self.sel.modify(conn.sock, selectors.EVENT_READ | selectors.EVENT_WRITE)
                continue
            if self.has_inflight:
                self.held.append((conn, head_block, method, declared))
                log(f"held {method} (slot busy)")
                return
            self.start_forward(conn, head_block, method, declared)

    def start_forward(self, conn: Client, head_block: bytes, method: str, declared: int) -> None:
        if not self.upstream_ensure():
            self.drop(conn)
            return
        self.await_fifo.append((conn, method))
        self.has_inflight = True
        self.inflight_since = time.monotonic()
        self.up_out += head_block
        conn.stage = "body" if declared else "idle"
        conn.body_left = declared
        log(f"forwarded {method} declared_body={declared} await={len(self.await_fifo)}")

    # ------------------------------------------------------------ upstream side
    def upstream_readable(self) -> None:
        assert self.up_sock is not None
        try:
            chunk = self.up_sock.recv(RX_CHUNK)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self.stall()
            return
        if not chunk:
            self.stall()
            return
        self.up_rx += chunk
        self.parse_responses()

    def parse_responses(self) -> None:
        """Frame complete response records and route them positionally."""
        while True:
            if self.resp_state == "head":
                if b"\r\n\r\n" not in self.up_rx:
                    return
                head_end = self.up_rx.find(b"\r\n\r\n") + 4
                head_block = self.up_rx[:head_end]
                self.up_rx = self.up_rx[head_end:]
                want = response_body_length(head_block)
                self.resp_head = head_block
                self.resp_buf = bytearray()
                if want == 0:
                    self.complete_response()
                    continue
                self.resp_state = "body"
                self.resp_want = want
                continue
            take = min(len(self.up_rx), self.resp_want - len(self.resp_buf))
            if take:
                self.resp_buf += self.up_rx[:take]
                self.up_rx = self.up_rx[take:]
            if len(self.resp_buf) >= self.resp_want:
                self.complete_response()
            else:
                return  # wait for the rest of the body

    def complete_response(self) -> None:
        frame = self.resp_head + bytes(self.resp_buf)
        self.resp_state = "head"
        self.resp_want = 0
        self.resp_buf = bytearray()
        self.resp_head = b""
        if self.await_fifo:
            conn, _method = self.await_fifo.pop(0)
            if self.overflow:
                # Serve the oldest banked frame first; the fresh frame
                # becomes new overflow debt (the response-queue shift).
                self.overflow.append(frame)
                conn.pending += self.overflow.pop(0)
            else:
                conn.pending += frame
            self.flush_client(conn)
            self.has_inflight = False
            self.release_gate()
            return
        self.overflow.append(frame)
        self.has_inflight = False
        self.release_gate()

    def release_gate(self) -> None:
        """After a delivery clears the slot, resume the oldest held request."""
        if self.has_inflight or self.await_fifo or not self.held:
            return
        conn, head_block, method, declared = self.held.pop(0)
        if conn.stage == "closed":
            self.release_gate()
            return
        self.start_forward(conn, head_block, method, declared)
        # The conn may already have buffered body/pipelined bytes that were
        # never drained while it sat held; push them now.
        self.frame_client(conn)

    def flush_client(self, conn: Client) -> None:
        try:
            self.sel.modify(conn.sock, selectors.EVENT_READ | selectors.EVENT_WRITE)
        except (KeyError, ValueError, OSError):
            pass

    def stall(self) -> None:
        """504 everyone awaiting and reset the poisoned slot."""
        while self.await_fifo:
            conn, _method = self.await_fifo.pop(0)
            conn.pending += RESP_504
            self.flush_client(conn)
        self.upstream_close_stalled()
        self.has_inflight = False
        self.release_gate()

    def upstream_writable(self) -> None:
        assert self.up_sock is not None
        try:
            sent = self.up_sock.send(bytes(self.up_out))
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self.stall()
            return
        del self.up_out[:sent]
        if not self.up_out:
            self.sel.modify(self.up_sock, selectors.EVENT_READ)

    # ------------------------------------------------------------ housekeeping
    def housekeeping(self) -> None:
        now = time.monotonic()
        # Forwarded request with no response within the deadline -> 504 all
        # awaiters and reset the slot (the naive 0.CL deadlock observable).
        if self.has_inflight and self.up_sock is not None:
            if now - self.inflight_since >= RESPONSE_TIMEOUT:
                log("response timeout: 504 to awaiting heads")
                self.stall()
                return
        # The upstream slot must outlive the 5s bot period (brief §4), so the
        # idle cap is generous; a long fully-idle stretch decays to a closed
        # upstream so each grading run starts from a clean BE connection.
        busy = (
            self.has_inflight
            or self.await_fifo
            or self.held
            or self.overflow
            or self.up_out
            or self.up_rx
            or self.resp_state != "head"
            or self.resp_buf
        )
        if self.up_sock is None or busy:
            self.idle_since = now
        elif now - self.idle_since >= UPSTREAM_IDLE_CAP:
            log("upstream idle past cap; closing slot")
            self.upstream_close_stalled()
            self.idle_since = now


def main() -> None:
    front = Front()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(64)
    server.setblocking(False)
    front.server = server
    front.sel.register(server, selectors.EVENT_READ)
    log("listening on", LISTEN_HOST, LISTEN_PORT)
    while True:
        try:
            events = front.sel.select(timeout=0.2)
        except InterruptedError:
            continue
        for key, mask in events:
            sock = key.fileobj
            if front.up_sock is not None and sock is front.up_sock:
                if mask & selectors.EVENT_WRITE:
                    front.upstream_writable()
                if mask & selectors.EVENT_READ:
                    front.upstream_readable()
            elif sock is server:
                front.accept()
            else:
                conn = front.clients.get(sock)
                if conn is None or conn.stage == "closed":
                    continue
                if mask & selectors.EVENT_READ:
                    front.client_readable(sock, conn)
                if mask & selectors.EVENT_WRITE and conn.pending:
                    try:
                        sent = sock.send(bytes(conn.pending))
                        del conn.pending[:sent]
                    except (BlockingIOError, InterruptedError):
                        pass
                    except OSError:
                        front.drop(conn)
                        continue
                    if not conn.pending:
                        front.sel.modify(sock, selectors.EVENT_READ)
        front.housekeeping()
        front.arm_upstream_write()


if __name__ == "__main__":
    main()
