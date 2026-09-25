"""zerocl backend: IIS/ASP.NET-flavored blog behind the strict front end.

Raw-socket HTTP/1.1 server, stdlib only. Its parser is deliberately TOLERANT
where the front end is strict; that tolerance is the live H-V (hidden-visible)
split this lab teaches:

  - header lines split on CRLF; a line starting with SP/HTAB is an obs-fold
    continuation and is JOINED onto the previous header's value;
  - a field name is the text left of the first colon with OWS stripped on
    both sides. A name that carried OWS before the colon is TAINTED and its
    Content-Length is ignored for framing, so the space-before-colon lab
    form (`Content-Length : 44`) is dead on BOTH sides and cannot smuggle.
    The honored obfuscated form is the obs-fold continuation
    (`Content-length:` NL `  44`) -- invisible to the strict front end,
    honored here: the live H-V split;
  - duplicate untainted Content-Length headers must agree; Transfer-Encoding
    is rejected everywhere.

Routing: `POST /static/*` and `/to/admin` (any method, body unread) are
early-response gadgets: they answer without reading the promised body and
leave the connection open, so the framing keeps counting the unread "body"
bytes off the stream. Every other route reads its declared body first. HEAD
answers with GET headers and zero body bytes, declared `Content-Length: 0`
(deliberate simplification: keeps proxy response framing unstuck while the
smuggled HEAD shifts the response queue).

Each parsed request's raw byte-span is logged to stdout in consumption order
and mirrored to /state/rawlog; remote graders string-match this raw
received-bytes log for the solver-supplied smuggle marker.
"""

import os
import socket
import threading
import time

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))
KEEPALIVE_TIMEOUT = 300  # exceeds the FE idle tolerance (120s) and the 5s bot period
RAWLOG_PATH = os.environ.get("RAWLOG", "/state/rawlog")

FLAG = os.environ["FLAG"]

_slot_counter = 0
_slot_lock = threading.Lock()


class Reject(Exception):
    """Parser rejected the request: answer 400 and close the connection."""


def parse_head(
    block: bytes,
) -> tuple[str, str, list[tuple[str, str]], set[int]]:
    """Parse one request header block with backend tolerance.

    Returns (method, target, headers, tainted) with names OWS-stripped and
    obs-fold continuation lines joined into the previous header's value.
    `tainted` holds indices of headers whose field name carried OWS before
    the colon; resolve_length ignores those when framing the body.
    """
    lines = block.split(b"\r\n")
    text = [ln.decode("latin-1") for ln in lines if ln]
    if not text:
        raise Reject("empty head")
    parts = text[0].split(" ")
    if len(parts) != 3:
        raise Reject(f"bad request line: {text[0]!r}")
    method, target, version = parts
    if not version.startswith("HTTP/1."):
        raise Reject(f"unrecognized version: {version!r}")

    headers: list[tuple[str, str]] = []
    tainted: set[int] = set()
    for line in text[1:]:
        if line[0] in (" ", "\t"):
            if not headers:
                raise Reject("continuation before any header")
            headers[-1] = (headers[-1][0], f"{headers[-1][1]} {line.strip()}")
            continue
        raw_name, _, value = line.partition(":")
        name = raw_name.strip()
        if raw_name != name:
            tainted.add(len(headers))
        headers.append((name, value.strip()))
    return method, target, headers, tainted


def resolve_length(header_pairs: list[tuple[str, str]], tainted: set[int]) -> int:
    """Resolve the honored body length (the H-V visible length).

    OWS-tainted Content-Length fields are invisible here; only clean fields
    (including obs-fold-joined values) count, so the lab's space-before-colon
    form frames identically on both proxy sides and cannot desync.
    """
    te = [v for n, v in header_pairs if n.lower() == "transfer-encoding"]
    if te:
        raise Reject("transfer-encoding not supported")
    cls = [
        v.strip()
        for i, (n, v) in enumerate(header_pairs)
        if n.lower() == "content-length" and i not in tainted
    ]
    if not cls:
        return 0
    for value in cls:
        if not value.isdigit():
            raise Reject(f"unparseable content-length: {value!r}")
    if len(set(cls)) > 1:
        raise Reject(f"conflicting content-length: {cls}")
    return int(cls[0])


def is_gadget(method: str, target: str) -> bool:
    """Early-response gadgets answer before the promised body is read."""
    path = target.split("?", 1)[0]
    if method == "POST" and path.startswith("/static/"):
        return True
    if path.startswith("/to/admin"):
        return True
    return False


def write_response(
    sock: socket.socket,
    code: int,
    reason: str,
    body: bytes,
    extra: list[tuple[str, str]] | None = None,
    head_only: bool = False,
) -> None:
    length = 0 if head_only else len(body)
    head = (
        f"HTTP/1.1 {code} {reason}\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: {length}\r\n"
    )
    for name, value in extra or ():
        head += f"{name}: {value}\r\n"
    head += "Content-Type: text/html; charset=utf-8\r\n\r\n"
    sock.sendall(head.encode("latin-1") + (b"" if head_only else body))


def _redirect_response(sock: socket.socket) -> None:
    head = (
        "HTTP/1.1 302 Found\r\n"
        "Connection: keep-alive\r\n"
        "Location: /admin\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    sock.sendall(head.encode("latin-1"))


def _render_search(referer: str) -> bytes:
    """Reflect Referer un-encoded (the live reflected sink)."""
    return (
        "<!doctype html><html><head><title>blog search</title></head>"
        "<body><h1>blog search</h1>"
        "<em>Coming from</em> <code>" + referer + "</code>"
        "<p><a href='/'>home</a></p></body></html>"
    ).encode()


def route_request(
    sock: socket.socket,
    method: str,
    target: str,
    header_pairs: list[tuple[str, str]],
    body: bytes,
) -> None:
    headers = {name.lower(): value for name, value in header_pairs}
    head_only = method == "HEAD"
    path, _, query = target.partition("?")
    params: dict[str, str] = {}
    for chunk in query.split("&"):
        if not chunk:
            continue
        key, _, value = chunk.partition("=")
        params[key] = value

    if path == "/__health":
        write_response(sock, 200, "OK", b"ok\n", head_only=head_only)
        return
    if path == "/" and method in ("GET", "HEAD", "OPTIONS"):
        page = (
            "<!doctype html><html><head><title>corp blog</title></head>"
            "<body><h1>corp blog</h1>"
            "<p>latest: <a href='/post?postId=1'>post 1</a></p>"
            "<p><a href='/search'>search</a></p>"
            "<p><a href='/admin'>admin</a></p>"
            "</body></html>"
        )
        if method == "OPTIONS":
            write_response(sock, 200, "OK", b"allow: GET, HEAD, OPTIONS\n")
        else:
            write_response(sock, 200, "OK", page.encode(), head_only=head_only)
        return
    if path == "/search" and method in ("GET", "POST", "HEAD"):
        write_response(
            sock, 200, "OK", _render_search(headers.get("referer", "")),
            head_only=head_only,
        )
        return
    if path == "/post" and method in ("GET", "HEAD"):
        if "postId" not in params:
            write_response(sock, 400, "Bad Request", b"postId required\n", head_only=head_only)
            return
        page = (
            "<!doctype html><html><head><title>post</title></head>"
            "<body><h1>post</h1><p>id " + params["postId"] + "</p></body></html>"
        )
        write_response(sock, 200, "OK", page.encode(), head_only=head_only)
        return
    if path == "/admin" and method in ("GET", "HEAD"):
        cookie = headers.get("cookie", "")
        if cookie == f"session={FLAG}":
            page = (
                "<!doctype html><html><head><title>admin</title></head>"
                "<body><h1>admin</h1><p>flag: " + FLAG + "</p></body></html>"
            )
            write_response(sock, 200, "OK", page, head_only=head_only)
        else:
            write_response(
                sock, 403, "Forbidden", b"admin only: bad session\n", head_only=head_only
            )
        return
    write_response(sock, 404, "Not Found", b"not found\n", head_only=head_only)


def rawlog(line: str) -> None:
    """Mirror one raw received-bytes log line to the state volume so remote
    graders can string-match the smuggle marker without docker log access."""
    try:
        with open(RAWLOG_PATH, "a", encoding="latin-1") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def recv_exact(sock: socket.socket, buf: bytes, want_total: int) -> bytes:
    while len(buf) < want_total:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("peer closed mid-stream")
        buf += chunk
    return buf


def handle_conn(sock: socket.socket) -> None:
    """Per-connection loop with a byte-accumulator framing state.

    `owed` is the connection's framing debt: body bytes that the last
    request's honored Content-Length promised but no route consumed yet.
    The gadget routes leave that debt open; the stream keeps counting it
    off before the next head is framed (the converted CL.0).
    """
    global _slot_counter
    with _slot_lock:
        _slot_counter += 1
        slot = _slot_counter
    peer = f"{sock.getpeername()[0]}:{sock.getpeername()[1]}"
    spill = b""
    owed = 0
    try:
        while True:
            if owed:
                buf = recv_exact(sock, spill, owed)
                # Only `owed` bytes belong to the promised body; any overshoot
                # is the start of the next head (the pipelined smuggled bytes).
                spill = buf[owed:]
                owed = 0
            # Frame the next request head.
            while b"\r\n\r\n" not in spill:
                chunk = sock.recv(65536)
                if not chunk:
                    raise ConnectionError("peer closed mid-head")
                spill += chunk
            head_end = spill.find(b"\r\n\r\n") + 4
            head_block, rest = spill[:head_end], spill[head_end:]
            if len(head_block) < 8:
                raise Reject("no request line")
            try:
                method, target, header_pairs, tainted = parse_head(head_block)
                length = resolve_length(header_pairs, tainted)
            except Reject as exc:
                print(f"[slot{slot}] REJECT {exc}", flush=True)
                write_response(sock, 400, "Bad Request", b"malformed request\n")
                return
            ts = time.strftime("%H:%M:%S")
            if is_gadget(method, target):
                line = f"[{ts} slot{slot}] GADGET from={peer} raw={head_block!r}"
                print(line, flush=True)
                rawlog(line)
                if target.split("?", 1)[0].startswith("/to/admin"):
                    _redirect_response(sock)
                else:
                    write_response(sock, 200, "OK", b"static asset served early\n")
                owed = length  # framing still expects these body bytes
                spill = b""
                continue
            if len(rest) < length:
                rest = recv_exact(sock, rest, length)
            body, spill = rest[:length], rest[length:]
            line = (
                f"[{ts} slot{slot}] REQ method={method} target={target} from={peer} "
                f"raw={(head_block + body)!r}"
            )
            print(line, flush=True)
            rawlog(line)
            route_request(sock, method, target, header_pairs, body)
    except Reject as exc:
        try:
            write_response(sock, 400, "Bad Request", b"malformed request\n")
        except OSError:
            pass
    except (ConnectionError, TimeoutError, OSError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def serve() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(64)
    print(f"[backend] listening on {HOST}:{PORT}", flush=True)
    while True:
        conn, _addr = server.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    serve()
